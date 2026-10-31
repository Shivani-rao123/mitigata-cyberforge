"""
tests/agents/test_web_agent_katana.py

Integration tests for agents/web/agent.py's katana-backed crawl path:
crawler selection ("auto"/"requests"/"katana"), the js_secret_found /
js_endpoint_found findings pulled from katana's -jsluice output, and the
crawler_fallback behavior when katana is unavailable mid-run. Exercises
the real run() -> _crawl() -> executor.crawl_js() chain through
MockScopedExecutor, not just the pieces in isolation.
"""

import pytest

from agents.web.agent import run
from common.contracts import Job
from core.scoped_executor import ToolNotInstalled
from tests.mock_executor import MockScopedExecutor

ALL_HEADERS = {
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'self'",
}


def _job(target="10.10.10.5:80", crawler=None):
    context = {"crawler": crawler} if crawler else {}
    return Job(job_id="web-katana-job", agent="web", target=target, context=context)


# ---------------------------------------------------------------------------
# An executor that just doesn't offer crawl_js at all (the common case —
# most of the existing test suite's MockScopedExecutor instances look
# like this) must behave exactly like before: no katana attempt, no
# fallback note, "auto" quietly acts like "requests".
# ---------------------------------------------------------------------------


def test_auto_mode_with_no_js_crawl_support_uses_native_crawler_silently():
    executor = MockScopedExecutor(
        crawl_result=[{"url": "http://10.10.10.5:80/", "status": 200, "body": "", "forms": []}],
        http_result={"status": 200, "headers": ALL_HEADERS, "body": ""},
    )
    assert not hasattr(executor, "crawl_js")

    result = run(_job(), executor)

    assert not [f for f in result.findings if f.finding_type == "crawler_fallback"]


# ---------------------------------------------------------------------------
# katana available and working
# ---------------------------------------------------------------------------


def test_auto_mode_uses_katana_pages_when_available():
    katana_result = {
        "pages": [{"url": "http://10.10.10.5:80/admin", "status": 200, "body": "", "forms": []}],
        "js_findings": [],
    }
    executor = MockScopedExecutor(
        crawl_js_result=katana_result,
        http_result={"status": 200, "headers": ALL_HEADERS, "body": ""},
    )
    result = run(_job(), executor)

    sensitive = [f for f in result.findings if f.finding_type == "sensitive_endpoint_found"]
    assert len(sensitive) == 1
    assert not [f for f in result.findings if f.finding_type == "crawler_fallback"]


def test_katana_js_secret_finding_is_surfaced():
    katana_result = {
        "pages": [],
        "js_findings": [
            {
                "finding_kind": "secret",
                "source": "http://10.10.10.5:80/static/bundle.js",
                "rule": "aws-access-token",
                "value": "AKIAFAKEKEY1234567890",
            }
        ],
    }
    executor = MockScopedExecutor(
        crawl_js_result=katana_result,
        http_result={"status": 200, "headers": ALL_HEADERS, "body": ""},
    )
    result = run(_job(), executor)

    secrets = [f for f in result.findings if f.finding_type == "js_secret_found"]
    assert len(secrets) == 1
    assert secrets[0].evidence.kind == "jsluice_secret"
    assert "AKIAFAKEKEY1234567890" not in secrets[0].evidence.summary  # redacted
    assert secrets[0].host == "10.10.10.5"


def test_katana_js_endpoint_finding_is_surfaced():
    katana_result = {
        "pages": [],
        "js_findings": [
            {
                "finding_kind": "endpoint",
                "source": "http://10.10.10.5:80/static/bundle.js",
                "endpoint": "/api/internal/export",
                "method": "POST",
            }
        ],
    }
    executor = MockScopedExecutor(
        crawl_js_result=katana_result,
        http_result={"status": 200, "headers": ALL_HEADERS, "body": ""},
    )
    result = run(_job(), executor)

    endpoints = [f for f in result.findings if f.finding_type == "js_endpoint_found"]
    assert len(endpoints) == 1
    assert "/api/internal/export" in endpoints[0].description
    assert "POST" in endpoints[0].description


def test_js_finding_with_unrecognized_kind_is_ignored_not_crashed():
    katana_result = {"pages": [], "js_findings": [{"finding_kind": "mystery", "source": "http://x/"}]}
    executor = MockScopedExecutor(
        crawl_js_result=katana_result,
        http_result={"status": 200, "headers": ALL_HEADERS, "body": ""},
    )
    result = run(_job(), executor)
    assert result.status == "completed"
    assert not [f for f in result.findings if f.finding_type in ("js_secret_found", "js_endpoint_found")]


def test_js_secret_missing_value_is_skipped_not_crashed():
    katana_result = {
        "pages": [],
        "js_findings": [{"finding_kind": "secret", "source": "http://x/app.js", "rule": "x"}],  # no "value"
    }
    executor = MockScopedExecutor(
        crawl_js_result=katana_result,
        http_result={"status": 200, "headers": ALL_HEADERS, "body": ""},
    )
    result = run(_job(), executor)
    assert not [f for f in result.findings if f.finding_type == "js_secret_found"]


# ---------------------------------------------------------------------------
# katana available but unusable this run -> fallback + visible note
# ---------------------------------------------------------------------------


def test_auto_mode_falls_back_when_katana_raises_tool_not_installed():
    executor = MockScopedExecutor(
        crawl_result=[{"url": "http://10.10.10.5:80/admin", "status": 200, "body": "", "forms": []}],
        raise_on_crawl_js=ToolNotInstalled("katana is not installed on this machine"),
        http_result={"status": 200, "headers": ALL_HEADERS, "body": ""},
    )
    result = run(_job(), executor)

    fallback = [f for f in result.findings if f.finding_type == "crawler_fallback"]
    assert len(fallback) == 1
    assert "ToolNotInstalled" in fallback[0].description

    # the native crawl still ran and was still checked normally
    sensitive = [f for f in result.findings if f.finding_type == "sensitive_endpoint_found"]
    assert len(sensitive) == 1


def test_auto_mode_falls_back_on_subprocess_timeout():
    import subprocess

    executor = MockScopedExecutor(
        crawl_result=[],
        raise_on_crawl_js=subprocess.TimeoutExpired(cmd="katana", timeout=180),
        http_result={"status": 200, "headers": ALL_HEADERS, "body": ""},
    )
    result = run(_job(), executor)
    assert [f for f in result.findings if f.finding_type == "crawler_fallback"]


def test_explicit_katana_mode_propagates_error_instead_of_falling_back():
    """Unlike "auto", an explicit `crawler: "katana"` request should fail
    loudly, not silently degrade — the caller asked for the thorough
    crawl specifically."""
    executor = MockScopedExecutor(
        crawl_result=[{"url": "http://x/", "status": 200, "body": "", "forms": []}],
        raise_on_crawl_js=ToolNotInstalled("katana is not installed"),
    )
    with pytest.raises(ToolNotInstalled):
        run(_job(crawler="katana"), executor)


def test_explicit_katana_mode_on_an_executor_without_js_support_raises():
    executor = MockScopedExecutor(crawl_result=[])
    assert not hasattr(executor, "crawl_js")
    with pytest.raises(ToolNotInstalled):
        run(_job(crawler="katana"), executor)


def test_explicit_requests_mode_never_touches_crawl_js_even_if_available():
    calls = {"crawl_js": 0}

    katana_result = {"pages": [{"url": "http://x/should-not-be-used", "status": 200, "body": "", "forms": []}], "js_findings": []}

    def tracking_crawl_js(base_url):
        calls["crawl_js"] += 1
        return katana_result

    executor = MockScopedExecutor(
        crawl_result=[{"url": "http://10.10.10.5:80/", "status": 200, "body": "", "forms": []}],
        http_result={"status": 200, "headers": ALL_HEADERS, "body": ""},
        crawl_js_result=katana_result,  # attaches crawl_js at all
    )
    # replace with a tracking version to prove it's never called
    executor.crawl_js = tracking_crawl_js

    result = run(_job(crawler="requests"), executor)

    assert calls["crawl_js"] == 0
    urls = {p for f in result.findings for p in [f.description] if "should-not-be-used" in p}
    assert not urls


def test_invalid_crawler_value_raises_clear_error():
    executor = MockScopedExecutor(crawl_result=[])
    with pytest.raises(ValueError, match="crawler"):
        run(_job(crawler="nonsense"), executor)


# ---------------------------------------------------------------------------
# Stress: a large katana capture doesn't blow up the agent's own loops
# ---------------------------------------------------------------------------


def test_large_katana_capture_with_many_pages_and_js_findings():
    pages = [
        {"url": f"http://10.10.10.5:80/page{i}", "status": 200, "body": "<p>x</p>", "forms": []}
        for i in range(500)
    ]
    js_findings = [
        {
            "finding_kind": "secret" if i % 2 == 0 else "endpoint",
            "source": f"http://10.10.10.5:80/app{i}.js",
            "value": f"SECRET{i}",
            "rule": "generic",
            "endpoint": f"/api/x{i}",
            "method": "GET",
        }
        for i in range(500)
    ]
    katana_result = {"pages": pages, "js_findings": js_findings}

    executor = MockScopedExecutor(
        crawl_js_result=katana_result,
        http_result={"status": 200, "headers": ALL_HEADERS, "body": ""},
    )

    import time

    start = time.monotonic()
    result = run(_job(), executor)
    elapsed = time.monotonic() - start

    assert elapsed < 5.0
    assert result.status == "completed"
    secret_findings = [f for f in result.findings if f.finding_type == "js_secret_found"]
    endpoint_findings = [f for f in result.findings if f.finding_type == "js_endpoint_found"]
    assert len(secret_findings) == 250
    assert len(endpoint_findings) == 250
