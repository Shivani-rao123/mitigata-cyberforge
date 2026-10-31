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
    """

    def __init__(
        self,
        scan_result: dict | None = None,
        http_result: dict | None = None,
        crawl_result: list[dict] | None = None,
        download_result: bytes | None = None,
        raise_on_download: Exception | None = None,
    ) -> None:
        self._scan_result = scan_result
        self._http_result = http_result
        self._crawl_result = crawl_result
        self._download_result = download_result
        self._raise_on_download = raise_on_download

    def scan(self, target: str, allowed_ports: list[int] | None = None) -> dict:
        if self._scan_result is not None:
            return self._scan_result
        with open(FIXTURES_DIR / "sample_nmap_scan.json") as f:
            return json.load(f)

    def http_get(self, url: str) -> dict:
        if self._http_result is not None:
            return self._http_result
        return {"status": 200, "headers": {}, "body": ""}

    def crawl(self, base_url: str) -> list[dict]:
        if self._crawl_result is not None:
            return self._crawl_result
        return []

    def download(self, url: str, max_bytes: int = 20_000_000) -> bytes:
        if self._raise_on_download is not None:
            raise self._raise_on_download
        return self._download_result if self._download_result is not None else b""