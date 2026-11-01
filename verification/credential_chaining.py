"""
verification/credential_chaining.py

Closes a gap a real lab run surfaced directly: a binary's
credential_pair_found finding only ever got tried against a login form
the web agent actually CRAWLED (verification/verifier.py's
extra_credentials path, added earlier). When the lab's login page isn't
linked anywhere the crawler visits — a deliberately "hidden" /lab/login,
reachable only if you already know to look for it — no default_creds_
found finding exists for that credential to attach to at all, so it
never gets tried anywhere, and the chain dead-ends at "here's a
credential" with no attempt to use it.

This module is the fallback for exactly that case: for a host with a
discovered credential_pair_found finding, try it directly against a
short list of conventional login paths — not relying on the crawler
having found the form first. Each attempt reuses verification/
verifier.py's own success heuristic and post-login flag check (literally
the same private helpers, imported directly — this is the same login-
then-check-for-a-flag logic, just reached by a guessed path instead of
a parsed one), so a successful guess here looks and behaves exactly
like a normal confirmed default_creds_found.

Deliberately narrow and clearly logged as a guess (see each finding's
own description) rather than folded silently into verify_finding()'s
normal path — a login that only works at a GUESSED path is weaker,
more surprising evidence than one at a path the crawler actually found
and is worth a reader being able to tell apart.
"""

from __future__ import annotations

from urllib.parse import urlparse

from common.contracts import Evidence, FindingOut
from core.scoped_executor import ScopedExecutor
from verification.authenticated_exploration import explore_after_login, summarize_endpoint_access
from verification.verifier import _build_payload, _looks_like_successful_login

# A short, deliberately small list — this is confirming a specific,
# already-discovered credential actually logs in somewhere, not probing
# for arbitrary login endpoints. Add more here if your lab uses a
# convention not covered (one line, no other code changes needed).
CONVENTIONAL_LOGIN_PATHS = ("/login", "/admin/login", "/lab/login", "/auth/login", "/signin")

# Common field-name guesses, one full set tried per path/credential —
# not every individual field combination, just the handful of
# conventions real login forms actually use. Mirrors the field names
# verification/verifier.py's own PASSWORD_FIELD_NAMES/
# USERNAME_FIELD_NAMES recognize when parsing a REAL crawled form; here
# there's no real form to parse, so these are guessed directly.
_GUESSED_FIELD_SETS: tuple[list[str], ...] = (
    ["username", "password"],
    ["user", "pass"],
    ["email", "password"],
)


def try_credentials_against_conventional_paths(
    executor: ScopedExecutor,
    base_url: str,
    credentials: list[tuple[str, str]],
    discovered_endpoints: list[tuple[str, int | None]] | None = None,
) -> list[FindingOut]:
    """
    Tries every (username, password) in `credentials` against every
    path in CONVENTIONAL_LOGIN_PATHS under `base_url` (e.g.
    "http://10.10.10.5:8085"), stopping at the first path+credential
    that looks like a successful login. Returns a list with that one
    confirmed-style default_creds_found finding (plus a flag, if the
    post-login check turns one up) — empty if nothing worked, or if
    `credentials` is empty (nothing to try).

    `discovered_endpoints`, when given, is the same (url, pre_auth_
    status) list verification/verifier.py's verify_finding() accepts —
    every sensitive_endpoint_found/directory_listing_enabled finding
    the same run produced. Once a login succeeds here, each of these
    is re-fetched with the new session cookies too (see
    verification/authenticated_exploration.py), not just the site
    root — the guessed-path login deserves the same "explore what the
    session can now reach" follow-up a crawled-form login gets.

    Callers (core/pipeline.py, webui/app.py) decide when to call this
    — typically only when a run produced at least one
    credential_pair_found finding but no (or no successfully-verified)
    default_creds_found finding for the same host, so this doesn't
    waste requests re-trying a path the crawler already found and
    verification/verifier.py already confirmed or ruled out.
    """
    if not credentials:
        return []

    host = urlparse(base_url).hostname or base_url

    for path in CONVENTIONAL_LOGIN_PATHS:
        login_url = base_url.rstrip("/") + path
        for username, password in credentials:
            for field_names in _GUESSED_FIELD_SETS:
                payload = _build_payload(field_names, username, password)
                response = executor.http_post(login_url, payload)
                if response.get("status") in (0, 404):
                    # 0 = request itself failed (connection error, etc);
                    # 404 = this guessed path doesn't exist at all —
                    # neither is evidence either way, try the next guess.
                    continue
                if not _looks_like_successful_login(response, login_url):
                    continue

                evidence_summary = (
                    f"POST {login_url} with {username}:{password} -> {response['status']} "
                    "(conventional login path, not discovered by crawling)"
                )
                cookies = response.get("cookies") or {}
                site_root = base_url.rstrip("/") + "/"
                endpoint_results = explore_after_login(
                    executor, cookies, list(discovered_endpoints or []), site_root
                )
                exploration_summary, flag = summarize_endpoint_access(endpoint_results)
                if exploration_summary:
                    evidence_summary += f"; {exploration_summary}"
                if flag:
                    evidence_summary += f"; authenticated access revealed flag: {flag}"

                return [
                    FindingOut(
                        finding_type="default_creds_found",
                        description=(
                            f"Credential pair confirmed against {login_url} — this login path "
                            "wasn't reachable by crawling, so a short list of conventional paths "
                            "was tried directly with the credential found in a binary"
                        ),
                        host=host,
                        evidence=Evidence(kind="conventional_login_probe", summary=evidence_summary),
                    )
                ]

    return []
