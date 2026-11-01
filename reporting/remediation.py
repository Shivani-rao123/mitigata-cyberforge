"""
reporting/remediation.py

Bonus B-3 from the PRD ("Suggest a fix for each finding in plain
English"). A plain lookup table, same shape and conventions as
reporting/ptes.py's own _PHASE_BY_FINDING_TYPE — deliberately NOT an
LLM call: remediation advice for a known weakness class ("rotate this
secret", "disable directory listing") is a fixed fact about that class
of weakness, not something that benefits from being regenerated per
finding, and a fixed table is instant, free, and never hallucinates a
wrong fix. This mirrors the project's existing posture (see common/llm.py's
own docstring on preferring deterministic logic for anything that
doesn't genuinely need judgment).

remediation_for() returns None for:
  - a false_positive finding (nothing to fix — verification already
    disproved the claim)
  - an operational note (redirect_followed, crawler_fallback,
    duplicate_binary_skipped — commentary about the scan itself, not
    a weakness on the target)
  - a finding_type this module has no opinion about yet (same
    "visibly missing, not silently wrong" philosophy as
    reporting/ptes.py's own ptes_phase_for())
"""

from __future__ import annotations

# finding_type -> plain-English fix. Written for the person reading
# the report, not a security specialist — concrete and actionable
# ("rotate this credential and store it in a secrets manager, not in
# the binary"), not just naming the weakness class again.
_REMEDIATION_BY_FINDING_TYPE: dict[str, str] = {
    "open_port": (
        "Confirm this service is meant to be reachable from here. If not, close it at the "
        "firewall or stop the service; if it is, make sure it's patched and not running with "
        "default settings."
    ),
    "hardcoded_secret": (
        "Remove the secret from the binary and rotate it immediately (assume it's already "
        "compromised once it ships). Load secrets at runtime from an environment variable or a "
        "secrets manager instead of embedding them in code."
    ),
    "credential_pair_found": (
        "Treat this username/password pair as compromised and rotate it now. Don't ship real "
        "credentials inside a binary at all — use a secrets manager or a runtime config pulled "
        "over an authenticated channel."
    ),
    "unsafe_function_call": (
        "Replace this function with its bounds-checked equivalent (e.g. strcpy -> strncpy/strlcpy, "
        "gets -> fgets, sprintf -> snprintf) and validate input length before copying into a "
        "fixed-size buffer."
    ),
    "default_creds_found": (
        "Change this account's password immediately to something unique and strong, and turn on "
        "multi-factor authentication if the application supports it. Never ship a default "
        "admin/admin-style credential in a production build."
    ),
    "reflected_input": (
        "Encode user input before it's written back into the page (HTML-escape it for HTML "
        "context) instead of reflecting it verbatim, and add a Content-Security-Policy header as "
        "a second layer of defense against script injection."
    ),
    "js_secret_found": (
        "Remove this secret from client-side JavaScript — anything shipped to the browser is "
        "visible to every visitor. Move the logic that needs this secret to a backend endpoint "
        "the browser calls instead."
    ),
    "secret_in_file_found": (
        "Remove this file from anywhere the web server can serve it, and rotate the secret it "
        "contains. Keep config/env files outside the web root and excluded from version control."
    ),
    "sensitive_endpoint_found": (
        "Require authentication for this endpoint, or remove it from the deployed build if it's "
        "left over from development/debugging. Returning a 404 for unauthenticated requests is "
        "safer than a 401/403, which confirms the path exists."
    ),
    "directory_listing_enabled": (
        "Disable directory listing in the web server config (Apache: `Options -Indexes`; Nginx: "
        "`autoindex off;`) so a folder with no index page doesn't expose its full file list."
    ),
    "missing_security_header": (
        "Add the missing header at the web server or application framework level (e.g. "
        "`X-Frame-Options: DENY`, `Content-Security-Policy`, `X-Content-Type-Options: nosniff`) "
        "— most frameworks can set these globally in one place rather than per-route."
    ),
    "js_endpoint_found": (
        "Make sure the backend behind this endpoint enforces its own authentication and rate "
        "limiting — an endpoint only referenced in client-side JS is still just as reachable "
        "as one listed in a public API doc."
    ),
    "header_auth_confirmed": (
        "Rotate this credential/token immediately — it granted access via an Authorization "
        "header using a value discovered elsewhere in this engagement. Store API keys/tokens in "
        "a secrets manager and scope them to the minimum access they actually need."
    ),
    "ctf_flag_found": (
        "This flag is the lab's own success marker, not a weakness by itself — it confirms the "
        "underlying finding that led here is a real, exploitable compromise. Fix that finding "
        "(see its own entry in this report) to close the actual gap."
    ),
}

# Purely operational commentary about the scan itself, not a target
# weakness — same set reporting/ptes.py already treats this way (kept
# as a separate, explicit set here too, same reasoning as that
# module's own docstring: a genuinely new/unmapped finding_type should
# stay visibly missing, not silently fall into this bucket by accident).
_OPERATIONAL_NOTE_TYPES = {"redirect_followed", "crawler_fallback", "duplicate_binary_skipped"}


def remediation_for(finding_type: str, status: str = "flagged") -> str | None:
    """Plain-English fix for one finding, or None when there's nothing
    to suggest — a false_positive (verification disproved the claim),
    an operational note, or a finding_type this module doesn't know
    about yet. Callers (reporting/report_generator.py, webui/app.py)
    should treat None as "don't show a remediation line", not as a
    formatting gap."""
    if status == "false_positive":
        return None
    if finding_type in _OPERATIONAL_NOTE_TYPES:
        return None
    return _REMEDIATION_BY_FINDING_TYPE.get(finding_type)


def known_finding_types() -> frozenset[str]:
    """Every finding_type this module has an opinion about (mapped or
    deliberately no-remediation) — used by tests to catch a newly-added
    finding_type in an agent that nobody taught this module about yet,
    mirroring reporting/ptes.py's own known_finding_types()."""
    return frozenset(_REMEDIATION_BY_FINDING_TYPE) | frozenset(_OPERATIONAL_NOTE_TYPES)
