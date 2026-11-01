"""
tests/mock_executor.py

A fake ScopedExecutor for agent unit tests. Returns canned data instead of
touching the network, so agent tests run with zero dependencies on the real
executor, the real network, or your partner's core being finished.
"""

from __future__ import annotations

import json
from pathlib import Path

from core.scoped_executor import ScopedExecutor

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"


class MockScopedExecutor(ScopedExecutor):
    """
    Loads canned results from fixtures/ instead of actually scanning or
    crawling anything. Pass a custom `scan_result` / `http_result` /
    `crawl_result` to override the default fixture for a specific test.
    Pass `http_get_fn` instead of `http_result` when a test needs
    `http_get()` to return something different depending on the URL it's
    called with (e.g. the web agent's reflected-input probe vs. its
    header check hitting the same mock in one run).

    `crawl_js` is intentionally NOT defined by default — matching a real
    executor that doesn't offer katana-backed crawling, this instance
    simply has no `crawl_js` attribute at all (hasattr is False), which
    is exactly what agents/web/agent.py's "auto" crawler mode needs to
    see to silently use crawl() with no fallback note. Pass either
    `crawl_js_result` or `raise_on_crawl_js` to opt THIS instance into
    having the method at all, for tests that specifically exercise the
    katana path.
    """

    def __init__(
        self,
        scan_result: dict | None = None,
        http_result: dict | None = None,
        http_get_fn=None,
        http_post_result: dict | None = None,
        http_post_fn=None,
        crawl_result: list[dict] | None = None,
        crawl_fn=None,
        crawl_js_result: dict | None = None,
        raise_on_crawl_js: Exception | None = None,
        download_result: bytes | None = None,
        raise_on_download: Exception | None = None,
    ) -> None:
        self._scan_result = scan_result
        self._http_result = http_result
        self._http_get_fn = http_get_fn
        self._http_post_result = http_post_result
        self._http_post_fn = http_post_fn
        self._crawl_result = crawl_result
        self._crawl_fn = crawl_fn
        self._download_result = download_result
        self._raise_on_download = raise_on_download

        self._crawl_js_result = crawl_js_result
        self._raise_on_crawl_js = raise_on_crawl_js
        if crawl_js_result is not None or raise_on_crawl_js is not None:
            # Attach as an instance attribute only when a test actually
            # configured it — see the class docstring for why this isn't
            # just always-defined.
            self.crawl_js = self._crawl_js_impl

    def _crawl_js_impl(self, base_url: str) -> dict:
        if self._raise_on_crawl_js is not None:
            raise self._raise_on_crawl_js
        return self._crawl_js_result if self._crawl_js_result is not None else {
            "pages": [],
            "js_findings": [],
        }

    def scan(self, target: str, allowed_ports: list[int] | None = None) -> dict:
        if self._scan_result is not None:
            return self._scan_result
        with open(FIXTURES_DIR / "sample_nmap_scan.json") as f:
            return json.load(f)

    def http_get(self, url: str, cookies: dict | None = None, headers: dict | None = None) -> dict:
        if self._http_get_fn is not None:
            # Only pass `cookies`/`headers` through when a caller
            # actually supplied them — keeps every existing single-arg
            # `http_get_fn` (the overwhelming majority of tests) working
            # unchanged; a test that specifically wants to see what a
            # caller sent (e.g. the credential-chaining authenticated
            # re-fetch, or agents/basic_auth/agent.py's header-auth
            # attempt) defines a matching `http_get_fn(url, cookies=...)`
            # / `http_get_fn(url, headers=...)` and opts in via kwargs.
            kwargs = {}
            if cookies is not None:
                kwargs["cookies"] = cookies
            if headers is not None:
                kwargs["headers"] = headers
            if kwargs:
                return self._http_get_fn(url, **kwargs)
            return self._http_get_fn(url)
        if self._http_result is not None:
            return self._http_result
        return {"status": 200, "headers": {}, "body": ""}

    def http_post(self, url: str, data: dict) -> dict:
        if self._http_post_fn is not None:
            return self._http_post_fn(url, data)
        if self._http_post_result is not None:
            return self._http_post_result
        return {"status": 200, "headers": {}, "body": ""}

    def crawl(self, base_url: str, cookies: dict | None = None) -> list[dict]:
        if self._crawl_fn is not None:
            # Same opt-in kwargs pattern as http_get()'s own
            # `_http_get_fn` above — only pass `cookies` through when a
            # caller actually supplied them, so an existing single-arg
            # `crawl_fn(base_url)` test fixture keeps working unchanged.
            if cookies is not None:
                return self._crawl_fn(base_url, cookies=cookies)
            return self._crawl_fn(base_url)
        if self._crawl_result is not None:
            return self._crawl_result
        return []

    def download(self, url: str, max_bytes: int = 20_000_000) -> bytes:
        if self._raise_on_download is not None:
            raise self._raise_on_download
        return self._download_result if self._download_result is not None else b""