"""
agents/basic_auth/agent.py

Tries a discovered credential as an HTTP Authorization header — Basic
("user:pass" base64-encoded) and Bearer (the bare password/token) —
against an endpoint that already told us, before any attempt, that it
needs authentication (a 401/403 response — see verification/
authenticated_exploration.py's collect_candidate_endpoints()).

This covers an auth scheme nothing else in this project can reach:
verification/verifier.py's login-form chain and verification/
credential_chaining.py's conventional-path guesses both POST to an
HTML <form> — there's no form here at all, the credential has to go
directly in a request header. The real review/lab scenario this
answers: a credential_pair_found binary secret that's actually an API
key or a Basic-Auth-protected endpoint's password, not a web login.

Deliberately NOT wired in as an unconditional rule, unlike every other
"try this credential" mechanism in this project (verifier.py's
extra_credentials, credential_chaining.py's conventional paths — both
ALWAYS run once their preconditions are met). Whether this agent ever
runs at all is gated by an explicit LLM decision (see core/pipeline.py
and webui/app.py's own wiring, reusing common/llm.py's
choose_follow_ups()) — direct instruction: this one "shouldn't be
automation". If the LLM is off, unavailable, or its call fails, this
agent simply never runs for that candidate (fails CLOSED) — there is
no pre-existing, tested "always try this" behavior to fall back to,
since this capability didn't exist before the LLM layer did. Contrast
with common/llm.py's own docstring, where the SAME function's None
result means "fall back to the existing rule-based candidates" for
the network/web follow-up planner — the fallback policy is the
caller's choice per use site, not something choose_follow_ups() itself
decides.
"""

from __future__ import annotations

import base64
from urllib.parse import urlparse

from common.contracts import Evidence, FindingOut
from common.flag_patterns import FLAG_PATTERNS
from core.scoped_executor import ScopedExecutor

# Only a real access change counts as evidence here — a 401/403
# endpoint that still returns the same status with credentials
# attached proved nothing either way.
_SUCCESS_STATUS = 200


def _check_flag(body: str) -> str | None:
    for _flag_type, (pattern, _description) in FLAG_PATTERNS.items():
        match = pattern.search(body)
        if match:
            return match.group(0)
    return None


def run(executor: ScopedExecutor, target: str, username: str, password: str) -> list[FindingOut]:
    """
    Tries `target` (a URL that already responded 401/403 before any
    credential was attached) with two header-based auth schemes, in
    order, stopping at the first that returns 200:
      1. Authorization: Basic base64("username:password")
      2. Authorization: Bearer password — covers a bare API-key/token
         credential where "username" is a label rather than a real
         login name (e.g. agents/binary/agent.py's credential_pair_
         found pairing a field literally named "api_key" with "token")

    Returns a list with one confirmed-style header_auth_confirmed
    finding for whichever scheme worked (including a flag in its
    evidence if the response body has one), or an empty list if
    neither got past the original 401/403.
    """
    basic_token = base64.b64encode(f"{username}:{password}".encode()).decode()
    attempts = [
        ("Basic", {"Authorization": f"Basic {basic_token}"}),
        ("Bearer", {"Authorization": f"Bearer {password}"}),
    ]

    host = urlparse(target).hostname

    for scheme, headers in attempts:
        response = executor.http_get(target, headers=headers)
        if response.get("status") != _SUCCESS_STATUS:
            continue

        body = response.get("body") or ""
        flag = _check_flag(body)
        evidence_summary = f"GET {target} with Authorization: {scheme} <redacted> -> 200"
        if flag:
            evidence_summary += f"; revealed flag: {flag}"

        return [
            FindingOut(
                finding_type="header_auth_confirmed",
                description=(
                    f"{target} accepted {scheme} authentication using a credential "
                    "discovered elsewhere in this engagement (no login form involved)"
                ),
                host=host,
                evidence=Evidence(
                    kind="http_response",
                    summary=evidence_summary,
                    raw_ref=f"{username}:{password}",
                ),
            )
        ]

    return []
