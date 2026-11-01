"""
tests/verification/test_verifier_credential_chaining.py

Covers verification/verifier.py's credential-chaining additions — the
missing link a real review flagged: "binary has hardcoded creds ->
those should get tried against a login form -> a successful login
should lead to a flag" was never demonstrated. Two pieces:
  1. `extra_credentials` (credentials discovered elsewhere in the same
     run, e.g. agents/binary/agent.py's credential_pair_found) are
     tried, and tried BEFORE the generic weak-credential list.
  2. A successful login's session cookies are used for one follow-up
     authenticated GET, scanned for a planted flag.
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


def test_extra_credential_not_in_the_weak_list_is_tried_and_confirms():
    def _http_post_fn(url, data):
        if data == {"username": "svc_account", "password": "r3al_pw"}:
            return {
                "status": 302,
                "headers": {"Location": "/admin/dashboard"},
                "body": "",
                "cookies": {},
            }
        return {"status": 302, "headers": {"Location": "/admin/login.php?error=1"}, "body": ""}

    executor = MockScopedExecutor(http_post_fn=_http_post_fn)

    result = verify_finding(
        LOGIN_FINDING, executor, extra_credentials=[("svc_account", "r3al_pw")]
    )

    assert result["status"] == "confirmed"
    assert "svc_account:r3al_pw" in result["evidence_summary"]


def test_extra_credentials_are_tried_before_the_generic_weak_list():
    attempted_order = []

    def _http_post_fn(url, data):
        attempted_order.append((data.get("username"), data.get("password")))
        return {"status": 302, "headers": {"Location": "/admin/login.php?error=1"}, "body": ""}

    executor = MockScopedExecutor(http_post_fn=_http_post_fn)

    verify_finding(LOGIN_FINDING, executor, extra_credentials=[("svc_account", "r3al_pw")])

    # The discovered credential was tried first, ahead of every entry
    # in verification.verifier.WEAK_CREDENTIAL_PAIRS (admin/admin, ...).
    assert attempted_order[0] == ("svc_account", "r3al_pw")


def test_successful_login_followed_by_flag_on_the_authenticated_page_is_captured():
    def _http_post_fn(url, data):
        if data == {"username": "svc_account", "password": "r3al_pw"}:
            return {
                "status": 302,
                "headers": {"Location": "/admin/dashboard"},
                "body": "",
                "cookies": {"session": "abc123"},
            }
        return {"status": 302, "headers": {"Location": "/admin/login.php?error=1"}, "body": ""}

    def _http_get_fn(url, cookies=None):
        assert url == "http://10.10.10.5/"
        assert cookies == {"session": "abc123"}
        return {"status": 200, "headers": {}, "body": "welcome back! FLAG{post_login_flag}"}

    executor = MockScopedExecutor(http_post_fn=_http_post_fn, http_get_fn=_http_get_fn)

    result = verify_finding(
        LOGIN_FINDING, executor, extra_credentials=[("svc_account", "r3al_pw")]
    )

    assert result["status"] == "confirmed"
    assert "FLAG{post_login_flag}" in result["evidence_summary"]


def test_successful_login_with_no_flag_on_the_authenticated_page_omits_flag_text():
    def _http_post_fn(url, data):
        return {
            "status": 302,
            "headers": {"Location": "/admin/dashboard"},
            "body": "",
            "cookies": {"session": "abc123"},
        }

    def _http_get_fn(url, cookies=None):
        return {"status": 200, "headers": {}, "body": "nothing interesting here"}

    executor = MockScopedExecutor(http_post_fn=_http_post_fn, http_get_fn=_http_get_fn)

    result = verify_finding(LOGIN_FINDING, executor)

    assert result["status"] == "confirmed"
    assert "flag" not in result["evidence_summary"].lower()


def test_successful_login_with_no_cookies_skips_the_flag_check_without_crashing():
    def _http_post_fn(url, data):
        # Confirmed login, but no Set-Cookie at all (e.g. a token-based
        # or cookie-less auth scheme) -- must not crash trying to use it.
        return {"status": 302, "headers": {"Location": "/admin/dashboard"}, "body": ""}

    calls = []

    def _http_get_fn(url, cookies=None):
        calls.append(url)
        return {"status": 200, "headers": {}, "body": ""}

    executor = MockScopedExecutor(http_post_fn=_http_post_fn, http_get_fn=_http_get_fn)

    result = verify_finding(LOGIN_FINDING, executor)

    assert result["status"] == "confirmed"
    assert "flag" not in result["evidence_summary"].lower()
    # No cookies to use -> the authenticated-page check is skipped
    # entirely rather than firing an unauthenticated GET that could
    # never see anything login-gated anyway.
    assert calls == []


def test_extra_credentials_omitted_behaves_exactly_as_before():
    def _http_post_fn(url, data):
        if data == {"username": "admin", "password": "admin"}:
            return {"status": 302, "headers": {"Location": "/admin/dashboard"}, "body": ""}
        return {"status": 302, "headers": {"Location": "/admin/login.php?error=1"}, "body": ""}

    executor = MockScopedExecutor(http_post_fn=_http_post_fn)

    result = verify_finding(LOGIN_FINDING, executor)

    assert result["status"] == "confirmed"
    assert "admin:admin" in result["evidence_summary"]


def test_a_rejected_extra_credential_is_visible_in_the_confirmed_evidence():
    # Direct response to real-lab feedback ("it didn't try executing
    # this creds"): the real, discovered credential IS tried first (see
    # test_extra_credentials_are_tried_before_the_generic_weak_list
    # above) -- what was missing is any trace of that rejection when a
    # LATER weak-list guess is the one that actually confirms. Proves
    # it's provable, not just "trust me, it tried."
    def _http_post_fn(url, data):
        if data == {"username": "admin", "password": "admin"}:
            return {"status": 302, "headers": {"Location": "/admin/dashboard"}, "body": ""}
        # The real discovered credential -- wrong for this particular
        # login form -- gets rejected.
        return {"status": 302, "headers": {"Location": "/admin/login.php?error=1"}, "body": ""}

    executor = MockScopedExecutor(http_post_fn=_http_post_fn)

    result = verify_finding(
        LOGIN_FINDING, executor, extra_credentials=[("cartlab", "B1na_917")]
    )

    assert result["status"] == "confirmed"
    assert "admin:admin" in result["evidence_summary"]
    assert "rejected first" in result["evidence_summary"]
    assert "cartlab:B1na_917" in result["evidence_summary"]


def test_false_positive_lists_every_rejected_credential_pair():
    def _http_post_fn(url, data):
        return {"status": 302, "headers": {"Location": "/admin/login.php?error=1"}, "body": ""}

    executor = MockScopedExecutor(http_post_fn=_http_post_fn)

    result = verify_finding(
        LOGIN_FINDING, executor, extra_credentials=[("cartlab", "B1na_917")]
    )

    assert result["status"] == "false_positive"
    assert "cartlab:B1na_917" in result["evidence_summary"]
    assert "admin:admin" in result["evidence_summary"]
