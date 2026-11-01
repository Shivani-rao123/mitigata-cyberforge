"""
tests/verification/test_authenticated_exploration.py

Covers verification/authenticated_exploration.py — the direct response
to a formal requirement spec: once a login succeeds, the agent must
"explore the accessible application endpoints and functionality using
the authenticated session" (not just check the site root) and
"identify whether the discovered endpoint requires authentication".
"""

from __future__ import annotations

from common.contracts import Evidence, FindingOut
from tests.mock_executor import MockScopedExecutor
from verification.authenticated_exploration import (
    collect_candidate_endpoints,
    explore_authenticated_endpoints,
    summarize_endpoint_access,
)


def _finding(finding_type, summary):
    return FindingOut(finding_type=finding_type, description="d", evidence=Evidence(kind="k", summary=summary))


def test_collect_candidate_endpoints_pulls_url_and_status_from_sensitive_and_listing_findings():
    findings = [
        _finding("sensitive_endpoint_found", "GET http://10.10.10.5/admin/backup.zip -> 403"),
        _finding("directory_listing_enabled", "GET http://10.10.10.5/uploads/ -> 200, body matches ..."),
        _finding("missing_security_header", "GET http://10.10.10.5/ -> 200, missing: X-Frame-Options"),
    ]

    result = collect_candidate_endpoints(findings)

    assert ("http://10.10.10.5/admin/backup.zip", 403) in result
    assert ("http://10.10.10.5/uploads/", 200) in result
    # missing_security_header isn't an "explorable endpoint" type -- not collected.
    assert len(result) == 2


def test_collect_candidate_endpoints_dedupes_by_url_keeping_first_status():
    findings = [
        _finding("sensitive_endpoint_found", "GET http://10.10.10.5/admin -> 403"),
        _finding("sensitive_endpoint_found", "GET http://10.10.10.5/admin -> 403"),
    ]

    result = collect_candidate_endpoints(findings)

    assert result == [("http://10.10.10.5/admin", 403)]


def test_collect_candidate_endpoints_returns_empty_for_no_matching_findings():
    findings = [_finding("open_port", "nmap: 80/tcp open")]

    assert collect_candidate_endpoints(findings) == []


def test_explore_returns_empty_without_cookies():
    executor = MockScopedExecutor()
    result = explore_authenticated_endpoints(executor, {}, [("http://10.10.10.5/admin", 403)])
    assert result == []


def test_explore_returns_empty_without_candidate_endpoints():
    executor = MockScopedExecutor()
    result = explore_authenticated_endpoints(executor, {"session": "abc"}, [])
    assert result == []


def test_explore_marks_a_401_or_403_pre_auth_status_as_required_auth():
    def _http_get_fn(url, cookies=None):
        return {"status": 200, "headers": {}, "body": "now visible"}

    executor = MockScopedExecutor(http_get_fn=_http_get_fn)

    result = explore_authenticated_endpoints(
        executor, {"session": "abc"}, [("http://10.10.10.5/admin", 403), ("http://10.10.10.5/public", 200)]
    )

    by_url = {r.url: r for r in result}
    assert by_url["http://10.10.10.5/admin"].required_auth is True
    assert by_url["http://10.10.10.5/public"].required_auth is False
    assert all(r.post_auth_status == 200 for r in result)


def test_explore_captures_a_flag_on_any_explored_endpoint():
    def _http_get_fn(url, cookies=None):
        if url == "http://10.10.10.5/admin/secret":
            return {"status": 200, "headers": {}, "body": "here it is: flag{authenticated_endpoint_flag}"}
        return {"status": 200, "headers": {}, "body": "nothing here"}

    executor = MockScopedExecutor(http_get_fn=_http_get_fn)

    result = explore_authenticated_endpoints(
        executor,
        {"session": "abc"},
        [("http://10.10.10.5/public", 200), ("http://10.10.10.5/admin/secret", 401)],
    )

    by_url = {r.url: r for r in result}
    assert by_url["http://10.10.10.5/admin/secret"].flag == "flag{authenticated_endpoint_flag}"
    assert by_url["http://10.10.10.5/public"].flag is None


def test_explore_dedupes_a_repeated_url():
    calls = []

    def _http_get_fn(url, cookies=None):
        calls.append(url)
        return {"status": 200, "headers": {}, "body": ""}

    executor = MockScopedExecutor(http_get_fn=_http_get_fn)

    result = explore_authenticated_endpoints(
        executor,
        {"session": "abc"},
        [("http://10.10.10.5/admin", 403), ("http://10.10.10.5/admin", 403)],
    )

    assert len(result) == 1
    assert calls == ["http://10.10.10.5/admin"]


def test_summarize_reports_endpoint_auth_method_and_flag():
    def _http_get_fn(url, cookies=None):
        if url == "http://10.10.10.5/admin/secret":
            return {"status": 200, "headers": {}, "body": "flag{summary_test}"}
        return {"status": 200, "headers": {}, "body": "ok"}

    executor = MockScopedExecutor(http_get_fn=_http_get_fn)

    results = explore_authenticated_endpoints(
        executor,
        {"session": "abc"},
        [("http://10.10.10.5/admin/secret", 403), ("http://10.10.10.5/public", 200)],
    )
    summary, flag = summarize_endpoint_access(results)

    assert "http://10.10.10.5/admin/secret -> 200 (required authentication); flag: flag{summary_test}" in summary
    assert "http://10.10.10.5/public -> 200" in summary
    assert flag == "flag{summary_test}"


def test_summarize_returns_empty_for_no_results():
    assert summarize_endpoint_access([]) == ("", None)
