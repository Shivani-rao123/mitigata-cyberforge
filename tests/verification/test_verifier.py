"""
tests/verification/test_verifier.py

Unit tests for verification/verifier.py (FR-6).
"""

from __future__ import annotations

from tests.mock_executor import MockScopedExecutor
from verification.verifier import verify_finding

LOGIN_FINDING = {
    "finding_type": "default_creds_found",
    "description": (
        "Login form found at http://10.10.10.5/admin/login.php "
        "(action=/admin/login.php) — candidate for default-credential testing"
    ),
    "evidence_summary": "GET http://10.10.10.5/admin/login.php -> 200, form fields: ['password', 'username']",
}


def test_non_login_finding_auto_confirms_without_any_http_call():
    executor = MockScopedExecutor()
    finding = {
        "finding_type": "open_port",
        "description": "Port 80 open",
        "evidence_summary": "nmap: 80/tcp open http",
    }

    result = verify_finding(finding, executor)

    assert result == {"status": "confirmed", "evidence_summary": None}


def test_login_form_confirmed_when_post_redirects_away_from_login_page():
    def _http_post_fn(url, data):
        assert url == "http://10.10.10.5/admin/login.php"
        if data == {"username": "admin", "password": "admin"}:
            return {"status": 302, "headers": {"Location": "/admin/dashboard"}, "body": ""}
        return {"status": 200, "headers": {}, "body": "invalid credentials"}

    executor = MockScopedExecutor(http_post_fn=_http_post_fn)

    result = verify_finding(LOGIN_FINDING, executor)

    assert result["status"] == "confirmed"
    assert "admin:admin" in result["evidence_summary"]
    assert "302" in result["evidence_summary"]


def test_login_form_false_positive_when_every_weak_pair_fails():
    def _http_post_fn(url, data):
        # Redirects right back to the same login page -- a failure
        # pattern, not a success one.
        return {"status": 302, "headers": {"Location": "/admin/login.php?error=1"}, "body": ""}

    executor = MockScopedExecutor(http_post_fn=_http_post_fn)

    result = verify_finding(LOGIN_FINDING, executor)

    assert result["status"] == "false_positive"
    assert "login.php" in result["evidence_summary"]


def test_login_form_confirmed_on_200_body_with_no_failure_keywords():
    def _http_post_fn(url, data):
        if data == {"username": "admin", "password": "admin"}:
            return {"status": 200, "headers": {}, "body": "<h1>Welcome, admin!</h1>"}
        return {"status": 200, "headers": {}, "body": "invalid credentials, try again"}

    executor = MockScopedExecutor(http_post_fn=_http_post_fn)

    result = verify_finding(LOGIN_FINDING, executor)

    assert result["status"] == "confirmed"


def test_unknown_field_is_left_blank_in_payload():
    captured = {}

    def _http_post_fn(url, data):
        captured.update(data)
        return {"status": 200, "headers": {}, "body": "invalid credentials"}

    finding = dict(LOGIN_FINDING)
    finding["evidence_summary"] = (
        "GET http://10.10.10.5/admin/login.php -> 200, "
        "form fields: ['csrf_token', 'password', 'username']"
    )
    executor = MockScopedExecutor(http_post_fn=_http_post_fn)

    verify_finding(finding, executor)

    assert captured["csrf_token"] == ""


def test_unparsable_description_is_left_flagged_not_guessed():
    executor = MockScopedExecutor()
    finding = {
        "finding_type": "default_creds_found",
        "description": "some format the parser doesn't recognize at all",
        "evidence_summary": "also unrecognized",
    }

    result = verify_finding(finding, executor)

    assert result["status"] == "flagged"
    assert "verification skipped" in result["evidence_summary"]


def test_connection_error_on_every_attempt_is_not_confused_with_confirmed():
    def _http_post_fn(url, data):
        return {"status": 0, "headers": {}, "body": "", "error": "connection refused"}

    executor = MockScopedExecutor(http_post_fn=_http_post_fn)

    result = verify_finding(LOGIN_FINDING, executor)

    assert result["status"] == "false_positive"
