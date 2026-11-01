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
to try against), re-fetch each one WITH those cookies
(explore_authenticated_endpoints()).

Each endpoint's PRE-login status is carried through and reported as
`required_auth` (401/403 means the endpoint told us outright, before
any login, that it needs a session) -- directly the "identify whether
the discovered endpoint requires authentication" requirement, using
evidence already gathered rather than a fresh probe.

A second round of real-lab feedback went further: a fixed list of
already-known URLs still misses a page only LINKED once logged in (a
post-login dashboard pointing at a "secrets" page nobody could see
before authenticating). core/scoped_executor.py's crawl() now accepts
`cookies`, so authenticated_crawl() below runs an actual, real crawl
WITH the session attached instead of a single re-fetch -- following
exactly that kind of chain automatically. explore_after_login()
combines both: everything this run already knew about PLUS everything
newly reachable once logged in. That's the function
verification/verifier.py and verification/credential_chaining.py call.
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


def authenticated_crawl(executor: ScopedExecutor, cookies: dict, site_root: str) -> list[EndpointAccessResult]:
    """
    Direct response to real-lab feedback: a fixed list of already-known
    URLs misses a page that's only LINKED once you're logged in (a
    "secrets" page reached from a post-login dashboard, say) — the
    pre-login crawler never saw it, so it never became a
    sensitive_endpoint_found/directory_listing_enabled candidate for
    explore_authenticated_endpoints() above to re-check.

    This runs a real CRAWL from `site_root` with `cookies` attached to
    every request (core/scoped_executor.py's crawl() now accepts
    `cookies` for exactly this) — reusing the same same-host, bounded
    depth/page-limit crawl agents/web/agent.py's own pre-login crawl
    uses, so a chain like "login succeeds -> dashboard links to
    /secrets -> /secrets has the flag" gets followed automatically
    instead of needing each hop guessed in advance.

    Every crawled page gets `pre_auth_status=None` here (this module has
    no prior observation of it — it was never reachable without a
    session) and `required_auth=False` (not a claim it DIDN'T need
    auth, just that this function makes no claim either way about its
    pre-login status) — contrast with explore_authenticated_endpoints()
    above, whose candidates carry real pre-login status because the
    crawler actually saw them before login.

    Returns [] immediately if `cookies` is empty — nothing to crawl
    authenticated with.
    """
    if not cookies:
        return []

    pages = executor.crawl(site_root, cookies=cookies)

    results: list[EndpointAccessResult] = []
    for page in pages:
        body = page.get("body") or ""
        flag = None
        for _flag_type, (pattern, _description) in FLAG_PATTERNS.items():
            match = pattern.search(body)
            if match:
                flag = match.group(0)
                break
        results.append(
            EndpointAccessResult(
                url=page.get("url", site_root),
                pre_auth_status=None,
                post_auth_status=page.get("status", 0),
                required_auth=False,
                flag=flag,
            )
        )
    return results


def explore_after_login(
    executor: ScopedExecutor,
    cookies: dict,
    discovered_endpoints: list[tuple[str, int | None]],
    site_root: str,
) -> list[EndpointAccessResult]:
    """
    The full "what can this session reach" answer: combines
    explore_authenticated_endpoints() (every endpoint THIS RUN already
    knew about before logging in — so its `required_auth` tagging is
    real) with authenticated_crawl() (an actual crawl from `site_root`
    WITH the session, following links the pre-login crawler never saw
    because they only exist once authenticated).

    This is the one function verification/verifier.py and
    verification/credential_chaining.py should call after a successful
    login — it replaces calling explore_authenticated_endpoints()
    directly with `discovered_endpoints + [(site_root, None)]` tacked
    on, because that only ever re-fetched the root ONCE and never
    followed any link from it. The explicit site_root re-fetch is kept
    here too (not just left to the crawl) so a flag planted directly at
    the root is still found even in an environment where crawl() can't
    run but a plain GET can.

    Deduped by URL, first occurrence wins — explore_authenticated_
    endpoints()'s results are listed first so a URL this run already
    had a real pre-login status for keeps that `required_auth` tagging
    rather than being silently overwritten by the crawl's own
    less-informed pre_auth_status=None version of the same URL.
    """
    known_results = explore_authenticated_endpoints(
        executor, cookies, list(discovered_endpoints) + [(site_root, None)]
    )
    crawled_results = authenticated_crawl(executor, cookies, site_root)

    seen: set[str] = {r.url for r in known_results}
    combined = list(known_results)
    for result in crawled_results:
        if result.url in seen:
            continue
        seen.add(result.url)
        combined.append(result)
    return combined


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
