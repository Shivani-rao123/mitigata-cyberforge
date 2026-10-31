"""
agents/binary/agent.py

Binary analysis agent (FR-3). Static checks only — nothing here executes
the target file. Two checks:

  1. Hardcoded secrets — prefers gitleaks (hundreds of vetted rules for
     cloud/CI/VCS credentials, private keys, JWTs, DB connection strings,
     plus entropy-based detection for secrets that match no known
     pattern) via the config-driven `gitleaks` tool entry. If gitleaks
     isn't installed/configured, falls back to extracting readable
     strings (via the `strings` tool) and regex-matching them against a
     small hand-written set of secret shapes (AWS keys, private key
     headers, generic api_key/secret/password assignments, Slack
     tokens) — a real but much narrower net than gitleaks's. Either path
     produces the same `hardcoded_secret` finding_type; the evidence
     `kind` ("gitleaks_match" vs "strings_match") tells a report reader
     which method actually found it.

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

import tempfile
from pathlib import Path
from urllib.parse import urlparse

from common.contracts import Evidence, FindingOut, Job, JobResult
from common.redact import redact
from common.secret_patterns import SECRET_PATTERNS
from core.scoped_executor import ScopedExecutor
from core.tool_engine import ToolEngine, ToolNotConfigured, ToolNotInstalled

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
    """Prefers gitleaks; falls back to the regex-based check below if
    gitleaks isn't installed/configured on this machine. A gitleaks
    failure for any OTHER reason (e.g. it ran but crashed, or produced
    output that doesn't parse — core/parsers/gitleaks.py raises
    ValueError for that rather than returning []) is NOT swallowed into
    the same fallback: that would silently hide a real tool failure
    behind a much weaker check and make "gitleaks is broken" look
    identical to "gitleaks found nothing", which is exactly the kind of
    false-negative this project's Verify/False-alarm scoring targets
    want to avoid."""
    try:
        return _check_secrets_gitleaks(engine, path)
    except (ToolNotInstalled, ToolNotConfigured):
        return _check_secrets_regex(engine, path)


def _check_secrets_gitleaks(engine: ToolEngine, path: str) -> list[FindingOut]:
    """Runs gitleaks against a `strings` extraction of `path`, not the raw
    file itself.

    Confirmed against a live gitleaks install: pointing `gitleaks detect
    --source` directly at a compiled binary finds NOTHING even when a
    secret is sitting right there as a plain ASCII string inside it —
    gitleaks checks that a file's content is valid UTF-8 text before
    scanning it at all, and a binary's raw bytes almost never pass that
    check, so the whole file is silently skipped. The regex fallback
    below already runs `strings` first for exactly this reason; gitleaks
    needs the same treatment. Scanning real source/text files through
    `strings` first is harmless — printable text passes through
    unchanged — so this is always safe, not just a binary-only path.
    """
    raw_strings = engine.run("strings", target=path)
    strings_text = "\n".join(engine.parse("strings", raw_strings).get("strings", []))

    tmp_dir = tempfile.mkdtemp(prefix="cart_gitleaks_")
    strings_path = Path(tmp_dir) / (Path(path).name + ".strings.txt")
    strings_path.write_text(strings_text)

    raw = engine.run("gitleaks", target=str(strings_path))
    leaks = engine.parse("gitleaks", raw)

    findings: list[FindingOut] = []
    seen: set[str] = set()  # avoid duplicate findings for the same matched secret

    for leak in leaks:
        dedup_key = f"{leak['rule']}:{leak['secret']}"
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        # leak['file']/['line'] point at the temp strings extraction, not
        # anything the user recognizes — reference the real binary name
        # instead and drop the line number (meaningless outside that
        # extraction).
        findings.append(
            FindingOut(
                finding_type="hardcoded_secret",
                description=f"{leak['description']} found in {Path(path).name}",
                host=None,
                evidence=Evidence(
                    kind="gitleaks_match",
                    summary=f"{leak['rule']}: {redact(leak['secret'])}",
                ),
            )
        )

    return findings


def _check_secrets_regex(engine: ToolEngine, path: str) -> list[FindingOut]:
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
                            summary=f"{secret_type}: {redact(matched_text)}",
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
