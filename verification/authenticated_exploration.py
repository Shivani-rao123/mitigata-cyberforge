"""
verification/authenticated_exploration.py

Direct response to a formal requirement spec pasted mid-engagement:
once a discovered credential logs in somewhere, the agent must
"explore the accessible application endpoints and functionality using
the authenticated session" and "identify whether the discovered
endpoint requires authentication" -- not just check one page.

verification/verifier.py's own _check_for_flag_after_login() is
deliberately narrow (its own docstring says so): ONE GET at the site
root, nothing else, because this project's executor has no
session-aware crawl(). That function is left exactly as it is (other
callers/tests depend on its exact one-shot behavior) -- this module is
the wider follow-up, not a replacement.

Given the session cookies a successful login just produced AND the
list of endpoints THIS SAME RUN already discovered (every
sensitive_endpoint_found / directory_listing_enabled finding any stage
produced -- URLs the crawler found but, at the time, had no credential
to try against), re-fetch each one WITH those cookies. Still not a
general-purpose authenticated re-crawl (same underlying limit: no
session-aware crawl() to call), but it covers every endpoint the
engagement already knows about instead of a single guess at the root.

Each endpoint's PRE-login status is carried through and reported as
`required_auth` (401/403 means the endpoint told us outright, before
any login, that it needs a session) -- directly the "identify whether
the discovered endpoint requires authentication" requirement, using
evidence already gathered rather than a fresh probe.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from common.contracts import FindingOut
from common.flag_patterns import FLAG_PATTERNS
from core.scoped_executor import ScopedExecutor

_PROTECTED_STATUSES = (401, 403)

# Matches the EXACT "GET {url} -> {status}[, ...]" prefix every
# http_response-kind Evidence agents/web/agent.py emits starts with
# (_check_sensitive_endpoints(), _check_directory_listing(), and
# _check_login_forms() all share it) -- see each one's own docstring.
_ENDPOINT_STATUS_RE = re.compile(r"GET (?P<url>\S+) -> (?P<status>\d+)")

# Which finding_types name an endpoint worth re-checking once
# authenticated. default_creds_found is deliberately excluded here --
# that's the login form ITSELF, already handled by the login attempt,
# not a destination to explore afterward.
_EXPLORABLE_FINDING_TYPES = ("sensitive_endpoint_found", "directory_listing_enabled")


@dataclass(frozen=True)
class EndpointAccessResult:
    url: str
    pre_auth_status: int | None
    post_auth_status: int
    required_auth: bool
    flag: str | None


def collect_candidate_endpoints(findings: list[FindingOut]) -> list[tuple[str, int | None]]:
    """Pulls every discovered endpoint URL + its pre-login HTTP status
    out of `findings` (any iterable of FindingOut, typically every
    stage's findings pooled together across one whole run -- a
    protected endpoint the web stage found may need a credential a
    LATER binary stage extracts). Deduped by URL, first occurrence
    wins. Returns [] if nothing explorable was found -- a normal
    outcome, not an error."""
    seen: dict[str, int | None] = {}
    for finding in findings:
        if finding.finding_type not in _EXPLORABLE_FINDING_TYPES:
            continue
        summary = finding.evidence.summary if finding.evidence else None
        if not summary:
            continue
        match = _ENDPOINT_STATUS_RE.search(summary)
        if not match:
            continue
        url = match.group("url")
        if url not in seen:
            seen[url] = int(match.group("status"))
    return list(seen.items())


def explore_authenticated_endpoints(
    executor: ScopedExecutor,
    cookies: dict,
    candidate_endpoints: list[tuple[str, int | None]],
) -> list[EndpointAccessResult]:
    """
    `candidate_endpoints` is a list of (url, pre_auth_status) --
    pre_auth_status is whatever the crawler saw BEFORE any login
    happened (pass None for a URL with no prior observation, e.g. a
    site-root fallback a caller adds on its own). Re-fetches each URL
    (deduped) with `cookies` and scans the body for a planted flag
    using the exact same common/flag_patterns.py patterns
    agents/web/agent.py's own flag check uses. Returns [] immediately
    if `cookies` or `candidate_endpoints` is empty/falsy -- nothing to
    explore with, or nothing worth exploring.
    """
    if not cookies or not candidate_endpoints:
        return []

    results: list[EndpointAccessResult] = []
    seen: set[str] = set()
    for url, pre_status in candidate_endpoints:
        if url in seen:
            continue
        seen.add(url)

        response = executor.http_get(url, cookies=cookies)
        post_status = response.get("status", 0)
        body = response.get("body") or ""

        flag = None
        for _flag_type, (pattern, _description) in FLAG_PATTERNS.items():
            match = pattern.search(body)
            if match:
                flag = match.group(0)
                break

        results.append(
            EndpointAccessResult(
                url=url,
                pre_auth_status=pre_status,
                post_auth_status=post_status,
                required_auth=pre_status in _PROTECTED_STATUSES,
                flag=flag,
            )
        )
    return results


def summarize_endpoint_access(results: list[EndpointAccessResult]) -> tuple[str, str | None]:
    """Builds the report text for "record the endpoint, authentication
    method, access results, and any discovered flags" plus the first
    flag found across every endpoint explored (or None if none had
    one). Order follows `results`, so a caller that wants "the most
    likely endpoint wins on a flag tie" should put it first in the
    `candidate_endpoints` it originally built. Returns ("", None) for
    an empty `results` (nothing was explored -- a normal outcome when
    this same run never discovered any extra endpoint, not an error)."""
    if not results:
        return "", None

    lines = []
    first_flag = None
    for r in results:
        line = f"{r.url} -> {r.post_auth_status}"
        if r.required_auth:
            line += " (required authentication)"
        if r.flag:
            line += f"; flag: {r.flag}"
            if first_flag is None:
                first_flag = r.flag
        lines.append(line)
    return "authenticated exploration: " + "; ".join(lines), first_flag
