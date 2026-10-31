"""
tests/core/test_scoped_executor_crawl_js.py

Tests for RealScopedExecutor.crawl_js() — specifically its scope
defense-in-depth (the thing this whole class exists to guarantee), using
a fake ToolEngine injected via the constructor (the same seam
RealScopedExecutor already exposes for scan()). katana itself is not run
here — this only proves the scope-filtering logic around it, mirroring
how test_scoped_executor.py tests the scope guard around scan() without
actually running nmap.
"""

import subprocess

import pytest

from core.scoped_executor import RealScopedExecutor
from core.tool_engine import ToolNotConfigured, ToolNotInstalled


class _FakeKatanaEngine:
    """A minimal fake of core.tool_engine.ToolEngine that only
    understands "katana", for crawl_js()'s own unit tests."""

    def __init__(self, parsed_result: dict | None = None, raise_on_run: Exception | None = None):
        self._parsed_result = parsed_result or {"pages": [], "js_findings": []}
        self._raise_on_run = raise_on_run

    def run(self, tool_name: str, target: str, ports=None) -> str:
        assert tool_name == "katana"
        if self._raise_on_run is not None:
            raise self._raise_on_run
        return ""  # content doesn't matter — parse() below returns the canned dict directly

    def parse(self, tool_name: str, raw_output: str) -> dict:
        assert tool_name == "katana"
        return self._parsed_result


class _RecordingLogger:
    def __init__(self):
        self.calls: list[tuple[str, bool]] = []

    def __call__(self, target: str, in_scope: bool) -> None:
        self.calls.append((target, in_scope))


def _executor(parsed_result=None, raise_on_run=None, is_in_scope=lambda ip: True):
    return RealScopedExecutor(
        is_in_scope=is_in_scope,
        log_scope_check=_RecordingLogger(),
        tool_engine=_FakeKatanaEngine(parsed_result, raise_on_run),
    )


def test_base_url_out_of_scope_is_refused_before_katana_runs():
    from core.scoped_executor import ScopeViolation

    executor = _executor(is_in_scope=lambda ip: False)
    with pytest.raises(ScopeViolation):
        executor.crawl_js("http://10.10.10.5/")


def test_in_scope_pages_pass_through():
    parsed = {
        "pages": [{"url": "http://10.10.10.5/admin", "status": 200, "body": "", "forms": []}],
        "js_findings": [],
    }
    executor = _executor(parsed_result=parsed, is_in_scope=lambda ip: ip == "10.10.10.5")
    result = executor.crawl_js("http://10.10.10.5/")
    assert len(result["pages"]) == 1


def test_page_reported_for_an_out_of_scope_host_is_dropped_not_trusted():
    """The core security property: even if katana itself reports a page
    on a host outside scope (a redirect it followed, a misconfigured
    run, or a compromised/malicious katana), it must not end up in the
    results — same defense-in-depth as scan()'s post-scan
    revalidation."""
    parsed = {
        "pages": [
            {"url": "http://10.10.10.5/safe", "status": 200, "body": "", "forms": []},
            {"url": "http://8.8.8.8/leaked-out-of-scope", "status": 200, "body": "", "forms": []},
        ],
        "js_findings": [],
    }
    executor = _executor(parsed_result=parsed, is_in_scope=lambda ip: ip == "10.10.10.5")
    result = executor.crawl_js("http://10.10.10.5/")

    urls = {p["url"] for p in result["pages"]}
    assert urls == {"http://10.10.10.5/safe"}


def test_js_finding_for_an_out_of_scope_source_is_dropped():
    parsed = {
        "pages": [],
        "js_findings": [
            {"finding_kind": "secret", "source": "http://10.10.10.5/app.js", "value": "x", "rule": "y"},
            {"finding_kind": "secret", "source": "http://8.8.8.8/app.js", "value": "x", "rule": "y"},
        ],
    }
    executor = _executor(parsed_result=parsed, is_in_scope=lambda ip: ip == "10.10.10.5")
    result = executor.crawl_js("http://10.10.10.5/")

    sources = {f["source"] for f in result["js_findings"]}
    assert sources == {"http://10.10.10.5/app.js"}


def test_js_finding_with_missing_source_is_dropped_not_crashed():
    parsed = {"pages": [], "js_findings": [{"finding_kind": "secret", "value": "x"}]}
    executor = _executor(parsed_result=parsed)
    result = executor.crawl_js("http://10.10.10.5/")
    assert result["js_findings"] == []


def test_every_scope_check_is_logged():
    parsed = {
        "pages": [{"url": "http://10.10.10.5/a", "status": 200, "body": "", "forms": []}],
        "js_findings": [],
    }
    logger = _RecordingLogger()
    executor = RealScopedExecutor(
        is_in_scope=lambda ip: True,
        log_scope_check=logger,
        tool_engine=_FakeKatanaEngine(parsed),
    )
    executor.crawl_js("http://10.10.10.5/")
    # base_url guard + the one page's revalidation = at least 2 logged checks
    assert len(logger.calls) >= 2


def test_tool_not_installed_propagates_not_swallowed():
    executor = _executor(raise_on_run=ToolNotInstalled("katana is not installed"))
    with pytest.raises(ToolNotInstalled):
        executor.crawl_js("http://10.10.10.5/")


def test_tool_not_configured_propagates_not_swallowed():
    executor = _executor(raise_on_run=ToolNotConfigured("no 'katana' entry in tools.yaml"))
    with pytest.raises(ToolNotConfigured):
        executor.crawl_js("http://10.10.10.5/")


def test_subprocess_timeout_propagates_not_swallowed():
    executor = _executor(raise_on_run=subprocess.TimeoutExpired(cmd="katana", timeout=180))
    with pytest.raises(subprocess.TimeoutExpired):
        executor.crawl_js("http://10.10.10.5/")


def test_many_out_of_scope_pages_are_filtered_efficiently():
    """Stress-ish: a large katana capture where most results are
    out-of-scope (e.g. katana followed off-host links widely) must still
    filter correctly and quickly — this is a plain list comprehension so
    there's no algorithmic cliff expected, but worth proving directly
    rather than assuming."""
    import time

    pages = [
        {"url": f"http://10.10.10.5/safe{i}", "status": 200, "body": "", "forms": []}
        for i in range(2_000)
    ] + [
        {"url": f"http://1.2.3.{i % 256}/unsafe", "status": 200, "body": "", "forms": []}
        for i in range(2_000)
    ]
    executor = _executor(
        parsed_result={"pages": pages, "js_findings": []},
        is_in_scope=lambda ip: ip == "10.10.10.5",
    )

    start = time.monotonic()
    result = executor.crawl_js("http://10.10.10.5/")
    elapsed = time.monotonic() - start

    assert elapsed < 3.0
    assert len(result["pages"]) == 2_000
    assert all(p["url"].startswith("http://10.10.10.5/") for p in result["pages"])
