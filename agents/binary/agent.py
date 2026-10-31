"""
agents/binary/agent.py

Binary analysis agent (FR-3). Static checks only — nothing here executes
the target file. Two checks:

  1. Hardcoded secrets — extracts readable strings from the file (via the
     `strings` tool) and regex-matches them against known secret shapes
     (AWS keys, private key headers, generic api_key/secret/password
     assignments, Slack tokens).

  2. Unsafe function calls — for ELF binaries, lists the external
     (dynamically-linked) functions the binary calls (via `nm -D
     --undefined-only`) and flags any that are known to be unsafe
     (strcpy, gets, system, etc). Non-ELF files or statically-linked
     binaries simply produce an empty function list — not an error.

`job.target` can be either:
  - a LOCAL FILE PATH — analyzed directly, no network touched, no
    ScopedExecutor needed.
  - an http(s):// URL — e.g. a downloadable binary the web agent found
    while crawling (an installer, firmware, an app). In that case an
    `executor` (core.scoped_executor.ScopedExecutor) IS required: the URL
    is downloaded through executor.download(), which scope-checks it the
    same way every other network access in this project is checked,
    before any analysis happens on the downloaded bytes.
"""

from __future__ import annotations

import re
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from common.contracts import Evidence, FindingOut, Job, JobResult
from core.scoped_executor import ScopedExecutor
from core.tool_engine import ToolEngine

# name -> (compiled regex, human-readable description)
SECRET_PATTERNS: dict[str, tuple[re.Pattern, str]] = {
    "aws_access_key_id": (
        re.compile(r"AKIA[0-9A-Z]{16}"),
        "AWS Access Key ID",
    ),
    "private_key_header": (
        re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        "Private key material",
    ),
    "slack_token": (
        re.compile(r"xox[baprs]-[0-9a-zA-Z-]{10,48}"),
        "Slack token",
    ),
    "generic_secret_assignment": (
        re.compile(
            r"(?i)(api[_-]?key|secret|token|password)['\"]?\s*[:=]\s*['\"][A-Za-z0-9_\-/+]{8,}['\"]"
        ),
        "Hardcoded secret-like assignment",
    ),
}

# function name -> why it's considered unsafe
UNSAFE_FUNCTIONS: dict[str, str] = {
    "strcpy": "No bounds checking — classic buffer overflow vector. Use strncpy.",
    "strcat": "No bounds checking — classic buffer overflow vector. Use strncat.",
    "gets": "Never bounds-checks input. Removed from C11 for this reason. Use fgets.",
    "sprintf": "No bounds checking on the output buffer. Use snprintf.",
    "vsprintf": "No bounds checking on the output buffer. Use vsnprintf.",
    "system": "Runs a shell command — command injection risk if any part of the input is attacker-influenced.",
    "popen": "Runs a shell command — command injection risk if any part of the input is attacker-influenced.",
    "exec": "Can allow arbitrary code execution if arguments are attacker-influenced.",
    "scanf": "No bounds checking on string input (%s). Use fgets + sscanf instead.",
}


def run(
    job: Job,
    tool_engine: ToolEngine | None = None,
    executor: ScopedExecutor | None = None,
) -> JobResult:
    """
    Execute a binary-analysis job. `job.target` is either a local file
    path or an http(s) URL (see module docstring). Raises FileNotFoundError
    / ValueError for a bad local path, DownloadError for a failed/oversized
    download, and ValueError if a URL target is given without an
    `executor` — these are all setup problems, not "nothing found".
    """
    engine = tool_engine or ToolEngine()

    if _is_url(job.target):
        if executor is None:
            raise ValueError(
                f"job.target {job.target!r} is a URL — an executor is required "
                f"to download it (scope-checked) before it can be analyzed"
            )
        path = _download_to_temp_file(executor, job.target)
    else:
        path = _validate_path(job.target)

    findings: list[FindingOut] = []
    findings.extend(_check_secrets(engine, path))
    findings.extend(_check_unsafe_functions(engine, path))

    return JobResult(job_id=job.job_id, status="completed", findings=findings)


def _is_url(target: str) -> bool:
    return target.startswith("http://") or target.startswith("https://")


def _download_to_temp_file(executor: ScopedExecutor, url: str) -> str:
    data = executor.download(url)

    # Keep the original filename where possible (shows up in finding
    # descriptions / evidence) instead of a random temp name.
    basename = Path(urlparse(url).path).name or "downloaded_binary"
    tmp_dir = tempfile.mkdtemp(prefix="cart_binary_")
    dest = Path(tmp_dir) / basename
    dest.write_bytes(data)
    return str(dest)


def _validate_path(target: str) -> str:
    resolved = Path(target).resolve()
    if not resolved.exists():
        raise FileNotFoundError(f"binary target not found: {target!r}")
    if not resolved.is_file():
        raise ValueError(f"binary target is not a regular file: {target!r}")
    return str(resolved)


def _check_secrets(engine: ToolEngine, path: str) -> list[FindingOut]:
    raw = engine.run("strings", target=path)
    parsed = engine.parse("strings", raw)
    strings_list = parsed.get("strings", [])

    findings: list[FindingOut] = []
    seen: set[str] = set()  # avoid duplicate findings for the same matched text

    for line in strings_list:
        for secret_type, (pattern, description) in SECRET_PATTERNS.items():
            match = pattern.search(line)
            if match:
                matched_text = match.group(0)
                dedup_key = f"{secret_type}:{matched_text}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                findings.append(
                    FindingOut(
                        finding_type="hardcoded_secret",
                        description=f"{description} found hardcoded in {Path(path).name}",
                        host=None,
                        evidence=Evidence(
                            kind="strings_match",
                            summary=f"{secret_type}: {_redact(matched_text)}",
                        ),
                    )
                )

    return findings


def _check_unsafe_functions(engine: ToolEngine, path: str) -> list[FindingOut]:
    try:
        raw = engine.run("nm", target=path)
        parsed = engine.parse("nm", raw)
    except Exception:
        # Not every file is an ELF binary with dynamic symbols (could be a
        # script, a statically-linked binary, etc). Nothing to flag from
        # this check in that case — not an error.
        return []

    functions = set(parsed.get("functions", []))

    findings: list[FindingOut] = []
    for func_name, reason in UNSAFE_FUNCTIONS.items():
        if func_name in functions:
            findings.append(
                FindingOut(
                    finding_type="unsafe_function_call",
                    description=f"Binary calls unsafe function '{func_name}()' in {Path(path).name}",
                    host=None,
                    evidence=Evidence(
                        kind="nm_undefined_symbol",
                        summary=f"{func_name}() — {reason}",
                    ),
                )
            )

    return findings


def _redact(secret: str, keep: int = 4) -> str:
    """Show enough of a matched secret to confirm the finding without
    putting the full value in evidence/reports."""
    if len(secret) <= keep * 2:
        return "*" * len(secret)
    return f"{secret[:keep]}{'*' * (len(secret) - keep * 2)}{secret[-keep:]}"
