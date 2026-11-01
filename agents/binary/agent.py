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

import hashlib
import re
import tempfile
import threading
from pathlib import Path
from urllib.parse import unquote, urlparse

from common.contracts import Evidence, FindingOut, Job, JobResult
from common.redact import redact
from common.secret_patterns import SECRET_PATTERNS
from core.scoped_executor import ScopedExecutor
from core.tool_engine import ToolEngine, ToolNotConfigured, ToolNotInstalled

# Binary-looking filename token found anywhere in a (decoded) URL — e.g.
# the "agent.bin" in "index.php?file=agent.bin" — not just urlparse's own
# path basename. Mirrors agents/web/agent.py's BINARY_EXTENSIONS list: a
# file-manager-style download link routinely serves the real file
# through a fixed script path (index.php, download.php, ...) while the
# actual filename rides in a query-string value instead. See
# _filename_from_url() below — this was a confirmed, real miss: such a
# download was saved locally (and so reported) as "index.php", not the
# binary it actually was.
_BINARY_FILENAME_RE = re.compile(
    r"([\w.\-]+\.(?:exe|dll|bin|so|apk|deb|rpm|msi|dmg|sh))(?:[/?&#]|$)",
    re.IGNORECASE,
)


class SeenBinaryHashes:
    """Thread-safe set of sha256 digests of binary content already
    analyzed within one run. core/orchestrator.py creates exactly ONE
    instance per run_target() call and shares it across every binary-
    agent job dispatched in that run (including concurrent ones, hence
    the lock) — letting run() below (see its `seen_hashes` kwarg) detect
    when a job's content is byte-identical to one already analyzed
    earlier in the SAME run, and skip re-emitting the same findings a
    second/third time.

    Confirmed, real-world trigger: the same binary fixture reachable via
    three distinct download links produced the same hardcoded-secret and
    unsafe-function findings three times over in one report — not three
    different binaries, one binary counted three times.

    Not persisted/shared across separate run_target() calls or
    processes, by design — a genuinely identical binary legitimately
    analyzed in two unrelated scans should still be reported both times;
    this is purely a within-one-run, "don't re-walk the exact bytes you
    already walked" optimization."""

    def __init__(self) -> None:
        self._seen: set[str] = set()
        self._lock = threading.Lock()

    def add_if_new(self, digest: str) -> bool:
        """Returns True the first time `digest` is seen by this tracker,
        False on every call after that (for the same digest)."""
        with self._lock:
            if digest in self._seen:
                return False
            self._seen.add(digest)
            return True


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
    seen_hashes: SeenBinaryHashes | None = None,
) -> JobResult:
    """
    Execute a binary-analysis job. `job.target` is either a local file
    path or an http(s) URL (see module docstring). Raises FileNotFoundError
    / ValueError for a bad local path, DownloadError for a failed/oversized
    download, and ValueError if a URL target is given without an
    `executor` — these are all setup problems, not "nothing found".

    `seen_hashes`, when given (core/orchestrator.py passes one shared
    instance per run_target() call), short-circuits analysis with a
    single `duplicate_binary_skipped` finding when this job's content is
    byte-identical to one already analyzed earlier in the same run — see
    SeenBinaryHashes's own docstring for why this exists. None (the
    default) disables the check entirely, matching every caller before
    this parameter existed (main.py, run_pipeline.py's direct --agent
    binary path, every existing test).
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

    if seen_hashes is not None:
        digest = hashlib.sha256(Path(path).read_bytes()).hexdigest()
        if not seen_hashes.add_if_new(digest):
            return JobResult(
                job_id=job.job_id,
                status="completed",
                findings=[
                    FindingOut(
                        finding_type="duplicate_binary_skipped",
                        description=(
                            f"{Path(path).name} is byte-identical to a binary already analyzed "
                            "earlier in this run (reached via a different link) — skipped to "
                            "avoid reporting the same secrets/unsafe-function findings again"
                        ),
                        host=None,
                        evidence=Evidence(kind="content_hash", summary=f"sha256:{digest}"),
                    )
                ],
            )

    findings: list[FindingOut] = []
    findings.extend(_check_secrets(engine, path))
    findings.extend(_check_unsafe_functions(engine, path))
    findings.extend(_check_credential_pairs(engine, path))

    return JobResult(job_id=job.job_id, status="completed", findings=findings)


def _is_url(target: str) -> bool:
    return target.startswith("http://") or target.startswith("https://")


def _filename_from_url(url: str) -> str:
    """Prefers a binary-looking filename found anywhere in the decoded
    URL (see _BINARY_FILENAME_RE's own comment) over the URL's path
    basename, falling back to the path basename when no such token is
    found, then a generic placeholder. The LAST match wins when more
    than one is present — the closer-to-the-end token is the one an
    actual "?...&file=name.ext"-style download convention means."""
    decoded = unquote(url)
    matches = _BINARY_FILENAME_RE.findall(decoded)
    if matches:
        return matches[-1]
    return Path(urlparse(url).path).name or "downloaded_binary"


def _download_to_temp_file(executor: ScopedExecutor, url: str) -> str:
    data = executor.download(url)

    # Keep the original filename where possible (shows up in finding
    # descriptions / evidence) instead of a random temp name.
    basename = _filename_from_url(url)
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


# Case-insensitive field-NAME patterns for one half of a credential pair
# — a plain "name=value" / "name: value" assignment pulled out of
# `strings` output. Kept separate from both halves of
# common/secret_patterns.py's generic_secret_assignment (which only
# matches the password-ish side, and reports it standalone) since these
# need to be PAIRED UP with each other afterwards, not individually
# flagged.
_USERNAME_ASSIGNMENT_RE = re.compile(r"(?i)\b(?:username|user|uname|login)\s*[:=]\s*([^\s'\"]{1,64})")
_PASSWORD_ASSIGNMENT_RE = re.compile(r"(?i)\b(?:password|passwd|pwd|pass)\s*[:=]\s*([^\s'\"]{1,64})")

# How many `strings`-output entries apart a username assignment and a
# password assignment can be and still count as "the same credential
# pair". A hardcoded test/demo account embedded in a binary as one
# contiguous blob — e.g. a C string literal "username=admin\npassword=
# S3cr3t!" — gets split by `strings` at the (non-printable) newline
# into two ADJACENT list entries, not one; this window catches that
# real case without pairing two assignments that just happen to appear
# somewhere in the same binary with no actual relationship.
_CREDENTIAL_PAIR_WINDOW = 3


def _check_credential_pairs(engine: ToolEngine, path: str) -> list[FindingOut]:
    """
    Looks for a username assignment and a password assignment sitting
    close together in the binary's extracted strings and reports them
    as ONE credential_pair_found finding per pair — the missing link a
    real review flagged: "binary has hardcoded creds -> those creds
    should get tried against a login form found elsewhere -> a
    successful login should lead to a flag", which needed this agent to
    surface a credential as a PAIR, not two unrelated-looking secret
    hits. core/pipeline.py reads these findings back out (via
    evidence.raw_ref) across an entire run and feeds them into
    verification/verifier.py's login-probe step as extra candidates,
    on top of the handful of generic weak-credential guesses it already
    tries.

    Unlike every other finding this agent produces, evidence.raw_ref
    deliberately carries the FULL, UNREDACTED "username:password" pair
    — evidence.summary (what a human/report actually sees) stays
    redacted. See common/contracts.py's Evidence docstring: raw_ref is
    exactly "anything sensitive goes here, never embedded in summary" —
    and here it's read back out programmatically (not just stored for a
    report), which is exactly what raw_ref is for.

    Only matches username-then-password order within the window (not
    password-then-username) — a known, deliberate narrowing to keep
    this check simple and low-false-positive; a lab whose planted
    credential blob happens to list password first won't be caught by
    this pairing (its two halves would still show up separately via
    _check_secrets's generic_secret_assignment match, just not paired).
    """
    try:
        raw = engine.run("strings", target=path)
    except Exception:
        return []
    strings_list = engine.parse("strings", raw).get("strings", [])

    findings: list[FindingOut] = []
    seen_pairs: set[tuple[str, str]] = set()

    for i, line in enumerate(strings_list):
        user_match = _USERNAME_ASSIGNMENT_RE.search(line)
        if not user_match:
            continue
        username = user_match.group(1)

        for other in strings_list[i + 1 : i + 1 + _CREDENTIAL_PAIR_WINDOW]:
            pass_match = _PASSWORD_ASSIGNMENT_RE.search(other)
            if not pass_match:
                continue
            password = pass_match.group(1)
            dedup_key = (username, password)
            if dedup_key in seen_pairs:
                break
            seen_pairs.add(dedup_key)

            findings.append(
                FindingOut(
                    finding_type="credential_pair_found",
                    description=(
                        f"Username/password pair found hardcoded together in "
                        f"{Path(path).name} — candidate for login testing"
                    ),
                    host=None,
                    evidence=Evidence(
                        kind="strings_credential_pair",
                        summary=f"username={username}, password={redact(password)}",
                        raw_ref=f"{username}:{password}",
                    ),
                )
            )
            break  # one password match per username assignment is enough

    return findings
