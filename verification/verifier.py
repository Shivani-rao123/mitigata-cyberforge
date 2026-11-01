"""
verification/verifier.py

FR-6: the verification engine. Takes a finding dict shaped like a
core/db.py `findings` row (has at least finding_type, description,
evidence_summary) and decides whether it's "confirmed" or
"false_positive" — moving it out of the merely-"flagged" state an agent
left it in.

Only one finding_type needs an ACTIVE re-probe: default_creds_found. A
web-agent login form is only a *candidate* for weak/default credentials
until something actually tries them (userflow.md's own Step 5 ->
Step 6 example: a flagged login form becomes "Exploitation" only once
credentials are confirmed to work). Doing that probe needs a real write
request against the target, which is why core/scoped_executor.py grew
http_post() alongside this module.

Every other finding_type this project emits is already a direct,
deterministic observation at discovery time (nmap's own port-state
output, a regex match against content the agent itself just fetched,
headers read straight off a real HTTP response) — there's nothing
further to go verify, so those auto-confirm. See reporting/ptes.py's
own docstring for the same split described from the PTES-tagging side.
"""

from __future__ import annotations

import ast
import re
from urllib.parse import urljoin, urlparse

from common.flag_patterns import FLAG_PATTERNS
from core.scoped_executor import ScopedExecutor

# Mirrors agents/web/agent.py's own PASSWORD_FIELD_NAMES exactly — kept
# as a separate copy rather than importing from agents/web/agent.py so
# this module has no dependency on agent internals, only on the
# description/evidence TEXT FORMAT agents/web/agent.py's
# _check_login_forms() actually emits (parsed below). If that format
# ever changes, the regexes below need updating together with it.
PASSWORD_FIELD_NAMES = {"password", "passwd", "pwd", "pass"}

# Common username-ish field names. Not matched against any real-world
# spec — just the handful of names a hackathon-scope login form is
# realistically going to use. A field matching neither this set nor
# PASSWORD_FIELD_NAMES is left blank in the POST body, which is a known
# limitation: a form with e.g. a required CSRF token field will fail
# every probe and correctly end up false_positive (never silently
# "confirmed" on broken input) rather than crash.
USERNAME_FIELD_NAMES = {"username", "user", "uname", "login", "email"}

# A short, deliberately small list of weak/default credential pairs to
# try — this is a pentest engine confirming a FLAGGED candidate, not a
# brute-force tool. Stops at the first pair that looks like a success.
WEAK_CREDENTIAL_PAIRS: list[tuple[str, str]] = [
    ("admin", "admin"),
    ("admin", "password"),
    ("root", "root"),
    ("admin", ""),
]

# Phrases that show up on the re-rendered login page of a failed login
# attempt on a huge range of real apps. Used only as a secondary signal
# (see _looks_like_successful_login) — a redirect away from the login
# page is the primary signal and is checked first.
_FAILURE_KEYWORDS = ("invalid", "incorrect", "denied", "failed", "wrong password", "login failed")

_REDIRECT_STATUSES = (301, 302, 303, 307, 308)

# Matches the EXACT text agents/web/agent.py's _check_login_forms()
# generates:
#   f"Login form found at {page['url']} "
#   f"(action={form.get('action') or page['url']}) — "
#   f"candidate for default-credential testing"
_DESCRIPTION_RE = re.compile(r"Login form found at (?P<url>\S+) \(action=(?P<action>\S+)\)")

# Matches the EXACT text agents/web/agent.py's _check_login_forms()
# generates for evidence.summary:
#   f"GET {page['url']} -> {page.get('status')}, "
#   f"form fields: {sorted(form.get('inputs', []))}"
_EVIDENCE_FIELDS_RE = re.compile(r"form fields:\s*(\[.*\])\s*$")


class UnparsableFinding(Exception):
    """Raised when a default_creds_found finding's description/evidence
    doesn't match the format agents/web/agent.py is known to emit —
    rather than guessing, verify_finding() lets this propagate so a
    format drift gets noticed instead of silently mis-verifying."""


def _parse_login_form_finding(finding: dict) -> tuple[str, str, list[str]]:
    """Returns (login_page_url, action_url, field_names) parsed out of a
    default_creds_found finding's description + evidence_summary."""
    description = finding.get("description") or ""
    match = _DESCRIPTION_RE.search(description)
    if match is None:
        raise UnparsableFinding(f"couldn't parse login URL/action out of description: {description!r}")
    login_page_url = match.group("url")
    action = match.group("action")
    action_url = urljoin(login_page_url, action)

    evidence_summary = finding.get("evidence_summary") or ""
    fields_match = _EVIDENCE_FIELDS_RE.search(evidence_summary)
    if fields_match is None:
        raise UnparsableFinding(
            f"couldn't parse form fields out of evidence_summary: {evidence_summary!r}"
        )
    try:
        field_names = ast.literal_eval(fields_match.group(1))
    except (ValueError, SyntaxError) as exc:
        raise UnparsableFinding(f"form fields list wasn't valid: {fields_match.group(1)!r}") from exc

    return login_page_url, action_url, list(field_names)


def _build_payload(field_names: list[str], username: str, password: str) -> dict[str, str]:
    payload: dict[str, str] = {}
    for field in field_names:
        lower = field.lower()
        if lower in PASSWORD_FIELD_NAMES:
            payload[field] = password
        elif lower in USERNAME_FIELD_NAMES:
            payload[field] = username
        else:
            # Unknown field (a CSRF token, a hidden "remember me", etc.)
            # — left blank rather than guessed at. A form that actually
            # requires it will reject every attempt, correctly landing
            # on false_positive instead of a lucky/wrong "confirmed".
            payload[field] = ""
    return payload


def _looks_like_successful_login(response: dict, login_page_url: str) -> bool:
    """Heuristic, not a guarantee: a redirect whose target isn't the
    login page itself is the strongest signal a real app gives for
    "that worked" (most login forms either re-render themselves with an
    error on failure, or redirect only on success). Falls back to a
    plain 200 response with none of the common failure phrases in it —
    weaker, but still better than treating every 200 as a failure."""
    status = response.get("status", 0)
    if status in _REDIRECT_STATUSES:
        headers = response.get("headers", {}) or {}
        # Headers arrive as a plain dict (RealScopedExecutor converts
        # requests' CaseInsensitiveDict away) — look up "Location"
        # case-insensitively rather than assuming the server sent that
        # exact casing.
        location = next((v for k, v in headers.items() if k.lower() == "location"), "")
        login_path = urlparse(login_page_url).path
        redirect_path = urlparse(urljoin(login_page_url, location)).path
        if redirect_path and redirect_path != login_path:
            return True
        return False  # redirected right back to the login page — a failure pattern
    if status == 200:
        body_lower = (response.get("body") or "").lower()
        return not any(keyword in body_lower for keyword in _FAILURE_KEYWORDS)
    return False


def _check_for_flag_after_login(
    executor: ScopedExecutor, login_page_url: str, cookies: dict
) -> str | None:
    """
    Post-login follow-up, direct response to a real review flag:
    "binary creds -> login -> a flag endpoint" was never demonstrated.
    Re-fetches the login page's own site (its host root — the simplest,
    always-available "something only reachable once authenticated might
    now show up here" probe, since this project has no general-purpose
    authenticated re-crawl) WITH the session cookies the successful
    login just produced, and scans the response for a planted flag
    using the exact same common/flag_patterns.py patterns
    agents/web/agent.py's own _check_planted_flags() uses. Returns the
    full flag text (never redacted — same reasoning as
    common/flag_patterns.py's own docstring) or None if nothing matched
    or the re-fetch itself failed.

    Deliberately narrow: ONE authenticated GET, not a full authenticated
    re-crawl of the site (this project's executor has no session-aware
    crawl() at all — see http_get()'s own docstring on why cookies are
    passed per-call, never stored). A flag that's only reachable via a
    specific authenticated link/path (not the site root) won't be found
    by this — a known, deliberate scope limit, not a silent gap.
    """
    if not cookies:
        return None
    site_root = f"{urlparse(login_page_url).scheme}://{urlparse(login_page_url).netloc}/"
    response = executor.http_get(site_root, cookies=cookies)
    body = response.get("body", "")
    if not body:
        return None
    for _flag_type, (pattern, _description) in FLAG_PATTERNS.items():
        match = pattern.search(body)
        if match:
            return match.group(0)
    return None


def _verify_default_creds_found(
    finding: dict, executor: ScopedExecutor, extra_credentials: list[tuple[str, str]] | None = None
) -> dict:
    try:
        login_page_url, action_url, field_names = _parse_login_form_finding(finding)
    except UnparsableFinding as exc:
        # Can't probe what we can't parse. Leave it flagged rather than
        # guessing either way — false_positive would wrongly discard a
        # real candidate, confirmed would wrongly promote an unverified
        # one.
        return {"status": "flagged", "evidence_summary": f"verification skipped: {exc}"}

    # Real, discovered credentials (e.g. agents/binary/agent.py's
    # credential_pair_found, collected across the whole run by
    # core/pipeline.py) are tried BEFORE the generic weak-credential
    # guesses — they're actual evidence from this same engagement, not
    # a blind guess, so they both deserve first shot and make for a
    # much more convincing "found in binary -> works here" story in the
    # evidence text when they succeed.
    candidate_pairs = list(extra_credentials or []) + WEAK_CREDENTIAL_PAIRS

    for username, password in candidate_pairs:
        payload = _build_payload(field_names, username, password)
        response = executor.http_post(action_url, payload)
        if response.get("status") == 0:
            # http_post itself failed (connection error, etc.) — not
            # evidence either way, try the next credential pair.
            continue
        if _looks_like_successful_login(response, login_page_url):
            evidence_summary = f"POST {action_url} with {username}:{password} -> {response['status']}"
            flag = _check_for_flag_after_login(executor, login_page_url, response.get("cookies") or {})
            if flag:
                evidence_summary += f"; authenticated access revealed flag: {flag}"
            return {"status": "confirmed", "evidence_summary": evidence_summary}

    return {
        "status": "false_positive",
        "evidence_summary": (
            f"tried {len(candidate_pairs)} credential pair(s) against {action_url}; none succeeded"
        ),
    }


def verify_finding(
    finding: dict, executor: ScopedExecutor, extra_credentials: list[tuple[str, str]] | None = None
) -> dict:
    """
    Verify one finding. `finding` is a dict shaped like a core/db.py
    `findings` row (at minimum: finding_type, description,
    evidence_summary). Returns {"status": ..., "evidence_summary": ...}
    — `evidence_summary` is None when the original evidence already
    stands (the auto-confirm path), so callers should pass that through
    to core/db.py's update_finding_status() as-is (it leaves the stored
    evidence_summary untouched when given None).

    `extra_credentials`, when given, is a list of (username, password)
    pairs discovered elsewhere in the SAME run (core/pipeline.py builds
    this from every credential_pair_found finding any stage produced)
    — tried against a default_creds_found candidate before the small
    built-in weak-credential list. Ignored for every other finding_type,
    same as every other verify_finding parameter.
    """
    if finding.get("finding_type") == "default_creds_found":
        return _verify_default_creds_found(finding, executor, extra_credentials)

    return {"status": "confirmed", "evidence_summary": None}
