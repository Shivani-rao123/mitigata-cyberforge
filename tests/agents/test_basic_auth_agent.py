"""
tests/agents/test_basic_auth_agent.py

Covers agents/basic_auth/agent.py — tries a credential as an
Authorization header (Basic, then Bearer) against an endpoint that
already answered 401/403. No HTML form involved at all, unlike every
other credential-trying mechanism in this project.
"""

from __future__ import annotations

import base64

from agents.basic_auth.agent import run
from tests.mock_executor import MockScopedExecutor


def test_basic_auth_header_confirms_access():
    expected_token = base64.b64encode(b"svc:r3al_pw").decode()

    def _http_get_fn(url, headers=None):
        assert headers == {"Authorization": f"Basic {expected_token}"}
        return {"status": 200, "headers": {}, "body": "welcome, authenticated user"}

    executor = MockScopedExecutor(http_get_fn=_http_get_fn)

    findings = run(executor, "http://10.10.10.5/admin/reports", "svc", "r3al_pw")

    assert len(findings) == 1
    assert findings[0].finding_type == "header_auth_confirmed"
    assert "Basic" in findings[0].evidence.summary
    assert findings[0].evidence.raw_ref == "svc:r3al_pw"
    assert findings[0].host == "10.10.10.5"


def test_falls_back_to_bearer_when_basic_fails():
    def _http_get_fn(url, headers=None):
        if headers.get("Authorization", "").startswith("Bearer"):
            return {"status": 200, "headers": {}, "body": "token accepted"}
        return {"status": 401, "headers": {}, "body": ""}

    executor = MockScopedExecutor(http_get_fn=_http_get_fn)

    findings = run(executor, "http://10.10.10.5/api/data", "api_key", "sk-abc123")

    assert len(findings) == 1
    assert "Bearer" in findings[0].evidence.summary


def test_neither_scheme_working_returns_no_findings():
    def _http_get_fn(url, headers=None):
        return {"status": 403, "headers": {}, "body": ""}

    executor = MockScopedExecutor(http_get_fn=_http_get_fn)

    findings = run(executor, "http://10.10.10.5/admin", "wrong", "creds")

    assert findings == []


def test_flag_in_the_response_body_is_captured():
    def _http_get_fn(url, headers=None):
        return {"status": 200, "headers": {}, "body": "report data: flag{header_auth_flag}"}

    executor = MockScopedExecutor(http_get_fn=_http_get_fn)

    findings = run(executor, "http://10.10.10.5/admin/reports", "svc", "r3al_pw")

    assert "flag{header_auth_flag}" in findings[0].evidence.summary


def test_credential_is_never_exposed_unredacted_in_the_summary_text():
    def _http_get_fn(url, headers=None):
        return {"status": 200, "headers": {}, "body": "ok"}

    executor = MockScopedExecutor(http_get_fn=_http_get_fn)

    findings = run(executor, "http://10.10.10.5/admin", "svc", "sup3r_s3cr3t")

    # The redacted summary never carries the raw password; raw_ref
    # (not meant for display) is where the unredacted pair lives, same
    # convention as every other credential-carrying finding in this project.
    assert "sup3r_s3cr3t" not in findings[0].evidence.summary
    assert findings[0].evidence.raw_ref == "svc:sup3r_s3cr3t"
