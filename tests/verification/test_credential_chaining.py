"""
tests/verification/test_credential_chaining.py

Covers verification/credential_chaining.py's
try_credentials_against_conventional_paths() — the fallback for a
credential_pair_found finding whose login page was never discovered by
crawling (so no default_creds_found finding exists for it to attach
to), exactly the gap a real lab run surfaced: a hidden /lab/login the
crawler never visited.
"""

from __future__ import annotations

from tests.mock_executor import MockScopedExecutor
from verification.credential_chaining import try_credentials_against_conventional_paths


def test_no_credentials_returns_empty_without_making_any_requests():
    calls = []

    def _http_post_fn(url, data):
        calls.append(url)
        return {"status": 404, "headers": {}, "body": ""}

    executor = MockScopedExecutor(http_post_fn=_http_post_fn)

    result = try_credentials_against_conventional_paths(executor, "http://10.10.10.5:8085", [])

    assert result == []
    assert calls == []


def test_credential_confirmed_against_a_conventional_path_not_discovered_by_crawling():
    def _http_post_fn(url, data):
        if url == "http://10.10.10.5:8085/lab/login" and data == {
            "username": "cartlab",
            "password": "B1na_917",
        }:
            return {"status": 302, "headers": {"Location": "/lab/dashboard"}, "body": "", "cookies": {}}
        return {"status": 404, "headers": {}, "body": ""}

    executor = MockScopedExecutor(http_post_fn=_http_post_fn)

    result = try_credentials_against_conventional_paths(
        executor, "http://10.10.10.5:8085", [("cartlab", "B1na_917")]
    )

    assert len(result) == 1
    finding = result[0]
    assert finding.finding_type == "default_creds_found"
    assert finding.host == "10.10.10.5"
    assert "lab/login" in finding.evidence.summary
    assert "cartlab:B1na_917" in finding.evidence.summary
    assert "not discovered by crawling" in finding.evidence.summary


def test_a_404_on_a_guessed_path_is_not_evidence_either_way_and_the_next_path_is_tried():
    attempted_urls = []

    def _http_post_fn(url, data):
        attempted_urls.append(url)
        if url.endswith("/lab/login"):
            return {"status": 302, "headers": {"Location": "/lab/dashboard"}, "body": "", "cookies": {}}
        return {"status": 404, "headers": {}, "body": ""}

    executor = MockScopedExecutor(http_post_fn=_http_post_fn)

    result = try_credentials_against_conventional_paths(
        executor, "http://10.10.10.5:8085", [("cartlab", "B1na_917")]
    )

    assert len(result) == 1
    # /login and /admin/login were tried (and 404'd) before /lab/login succeeded.
    assert any(u.endswith("/login") for u in attempted_urls[:-1])


def test_no_path_or_field_set_works_returns_empty():
    def _http_post_fn(url, data):
        return {"status": 404, "headers": {}, "body": ""}

    executor = MockScopedExecutor(http_post_fn=_http_post_fn)

    result = try_credentials_against_conventional_paths(
        executor, "http://10.10.10.5:8085", [("cartlab", "wrong_password")]
    )

    assert result == []


def test_successful_guess_also_captures_a_post_login_flag():
    def _http_post_fn(url, data):
        if url.endswith("/lab/login") and data == {"username": "cartlab", "password": "B1na_917"}:
            return {
                "status": 302,
                "headers": {"Location": "/lab/dashboard"},
                "body": "",
                "cookies": {"session": "xyz"},
            }
        return {"status": 404, "headers": {}, "body": ""}

    def _http_get_fn(url, cookies=None):
        assert cookies == {"session": "xyz"}
        return {"status": 200, "headers": {}, "body": "flag{conventional_path_capture}"}

    executor = MockScopedExecutor(http_post_fn=_http_post_fn, http_get_fn=_http_get_fn)

    result = try_credentials_against_conventional_paths(
        executor, "http://10.10.10.5:8085", [("cartlab", "B1na_917")]
    )

    assert len(result) == 1
    assert "flag{conventional_path_capture}" in result[0].evidence.summary


def test_a_rejected_earlier_credential_is_visible_in_the_confirmed_evidence():
    # Direct response to real-lab feedback ("it didn't try executing
    # this creds") -- the real credential IS tried against every
    # conventional path (/login first, in CONVENTIONAL_LOGIN_PATHS
    # order), it just doesn't work there; only the SECOND credential in
    # the list (a generic guess) confirms at /admin/login. The
    # rejection must still show up in the winning finding's evidence.
    def _http_post_fn(url, data):
        if url == "http://10.10.10.5:8085/admin/login" and data == {
            "username": "admin",
            "password": "admin",
        }:
            return {"status": 302, "headers": {"Location": "/admin/dashboard"}, "body": "", "cookies": {}}
        return {"status": 302, "headers": {"Location": url}, "body": ""}

    executor = MockScopedExecutor(http_post_fn=_http_post_fn)

    result = try_credentials_against_conventional_paths(
        executor, "http://10.10.10.5:8085", [("cartlab", "B1na_917"), ("admin", "admin")]
    )

    assert len(result) == 1
    assert "admin:admin" in result[0].evidence.summary
    assert "rejected first" in result[0].evidence.summary
    assert "cartlab:B1na_917" in result[0].evidence.summary


def test_different_field_name_convention_user_pass_is_also_tried():
    def _http_post_fn(url, data):
        if url.endswith("/login") and data == {"user": "cartlab", "pass": "B1na_917"}:
            return {"status": 302, "headers": {"Location": "/dashboard"}, "body": "", "cookies": {}}
        return {"status": 302, "headers": {"Location": "/login"}, "body": ""}

    executor = MockScopedExecutor(http_post_fn=_http_post_fn)

    result = try_credentials_against_conventional_paths(
        executor, "http://10.10.10.5:8085", [("cartlab", "B1na_917")]
    )

    assert len(result) == 1
