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
    authenticated_crawl,
    collect_candidate_endpoints,
    explore_after_login,
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


def test_authenticated_crawl_returns_empty_without_cookies():
    executor = MockScopedExecutor(crawl_result=[{"url": "http://10.10.10.5/", "status": 200, "body": "flag{x}"}])
    assert authenticated_crawl(executor, {}, "http://10.10.10.5/") == []


def test_authenticated_crawl_follows_a_page_only_linked_once_logged_in():
    # Direct response to real-lab feedback: a login succeeded but the
    # flag was on a page only reachable by following a link FROM the
    # post-login page -- not in any pre-login-discovered endpoint list.
    def _crawl_fn(base_url, cookies=None):
        assert cookies == {"session": "abc"}
        assert base_url == "http://10.10.10.5/"
        return [
            {"url": "http://10.10.10.5/", "status": 200, "body": "welcome, see <a href='/secrets'>secrets</a>"},
            {"url": "http://10.10.10.5/secrets", "status": 200, "body": "flag{crawled_after_login}"},
        ]

    executor = MockScopedExecutor(crawl_fn=_crawl_fn)

    results = authenticated_crawl(executor, {"session": "abc"}, "http://10.10.10.5/")

    by_url = {r.url: r for r in results}
    assert by_url["http://10.10.10.5/secrets"].flag == "flag{crawled_after_login}"
    assert by_url["http://10.10.10.5/"].flag is None
    # Never observed pre-login -- only reachable via the authenticated crawl itself.
    assert all(r.pre_auth_status is None for r in results)


def test_explore_after_login_combines_known_endpoints_with_the_authenticated_crawl():
    def _http_get_fn(url, cookies=None):
        if url == "http://10.10.10.5/admin/backup.zip":
            return {"status": 200, "headers": {}, "body": "flag{known_endpoint_flag}"}
        return {"status": 200, "headers": {}, "body": "ok"}

    def _crawl_fn(base_url, cookies=None):
        return [{"url": "http://10.10.10.5/secrets", "status": 200, "body": "flag{crawled_flag}"}]

    executor = MockScopedExecutor(http_get_fn=_http_get_fn, crawl_fn=_crawl_fn)

    results = explore_after_login(
        executor,
        {"session": "abc"},
        [("http://10.10.10.5/admin/backup.zip", 403)],
        "http://10.10.10.5/",
    )

    by_url = {r.url: r for r in results}
    assert by_url["http://10.10.10.5/admin/backup.zip"].flag == "flag{known_endpoint_flag}"
    assert by_url["http://10.10.10.5/admin/backup.zip"].required_auth is True
    assert by_url["http://10.10.10.5/secrets"].flag == "flag{crawled_flag}"


def test_explore_after_login_dedupes_preferring_the_known_endpoints_required_auth_tag():
    # Same URL appears in both the known-endpoints list (with a real
    # pre-login 403) and the crawl's own results -- the known version's
    # required_auth=True must win, not be silently overwritten.
    def _http_get_fn(url, cookies=None):
        return {"status": 200, "headers": {}, "body": ""}

    def _crawl_fn(base_url, cookies=None):
        return [{"url": "http://10.10.10.5/admin", "status": 200, "body": ""}]

    executor = MockScopedExecutor(http_get_fn=_http_get_fn, crawl_fn=_crawl_fn)

    results = explore_after_login(
        executor, {"session": "abc"}, [("http://10.10.10.5/admin", 403)], "http://10.10.10.5/"
    )

    matching = [r for r in results if r.url == "http://10.10.10.5/admin"]
    assert len(matching) == 1
    assert matching[0].required_auth is True


def test_explore_after_login_still_checks_the_bare_site_root():
    def _http_get_fn(url, cookies=None):
        if url == "http://10.10.10.5/":
            return {"status": 200, "headers": {}, "body": "flag{root_flag}"}
        return {"status": 200, "headers": {}, "body": ""}

    executor = MockScopedExecutor(http_get_fn=_http_get_fn)  # no crawl_fn configured

    results = explore_after_login(executor, {"session": "abc"}, [], "http://10.10.10.5/")

    _, flag = summarize_endpoint_access(results)
    assert flag == "flag{root_flag}"
