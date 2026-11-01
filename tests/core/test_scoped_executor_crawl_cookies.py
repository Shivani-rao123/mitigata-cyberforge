"""
tests/core/test_scoped_executor_crawl_cookies.py

Tests for RealScopedExecutor.crawl()'s new `cookies` parameter — direct
response to real-lab feedback that a confirmed login never actually
discovered anything only reachable once authenticated. crawl() now
attaches `cookies` to every request it makes (including redirect hops),
so verification/authenticated_exploration.py's authenticated_crawl()
can run a real session-aware crawl instead of a single re-fetch.

Mocks requests.get directly, same seam
tests/core/test_scoped_executor_crawl_redirects.py uses.
"""

from __future__ import annotations

import requests

from core.scoped_executor import RealScopedExecutor


class _FakeResponse:
    def __init__(self, status_code: int, body: bytes = b"", headers: dict | None = None):
        self.status_code = status_code
        self._body = body
        self.headers = headers or {}

    def iter_content(self, chunk_size: int = 65_536):
        if self._body:
            yield self._body

    def close(self) -> None:
        pass


class _FakeGet:
    """Maps a URL to a canned _FakeResponse, recording the `cookies`
    kwarg (or its absence) each call was actually made with."""

    def __init__(self, responses: dict[str, _FakeResponse]):
        self._responses = responses
        self.calls: list[tuple[str, object]] = []  # (url, cookies-or-_UNSET)

    def __call__(self, url: str, timeout=None, allow_redirects=None, stream=None, cookies=None, headers=None):
        self.calls.append((url, cookies))
        if url not in self._responses:
            raise requests.RequestException(f"no canned response for {url!r}")
        return self._responses[url]


class _RecordingLogger:
    def __init__(self):
        self.calls: list[tuple[str, bool]] = []

    def __call__(self, target: str, in_scope: bool) -> None:
        self.calls.append((target, in_scope))


def _executor(is_in_scope=lambda ip: True):
    return RealScopedExecutor(
        is_in_scope=is_in_scope,
        log_scope_check=_RecordingLogger(),
        http_timeout_seconds=5,
    )


def _patch_get(monkeypatch, fake_get: _FakeGet) -> None:
    monkeypatch.setattr("core.scoped_executor.requests.get", fake_get)


def _patch_resolve(monkeypatch, host_to_ip: dict[str, str]) -> None:
    def fake_gethostbyname(host):
        if host in host_to_ip:
            return host_to_ip[host]
        raise OSError(f"no fake DNS entry for {host!r}")

    monkeypatch.setattr("core.scoped_executor.socket.gethostbyname", fake_gethostbyname)


def test_crawl_without_cookies_behaves_exactly_as_before(monkeypatch):
    fake_get = _FakeGet({"http://10.10.10.5/": _FakeResponse(200, b"<html>hi</html>")})
    _patch_get(monkeypatch, fake_get)
    _patch_resolve(monkeypatch, {"10.10.10.5": "10.10.10.5"})

    executor = _executor()
    pages = executor.crawl("http://10.10.10.5/")

    assert len(pages) == 1
    assert fake_get.calls == [("http://10.10.10.5/", None)]


def test_crawl_sends_cookies_on_the_initial_request(monkeypatch):
    fake_get = _FakeGet({"http://10.10.10.5/": _FakeResponse(200, b"<html>hi</html>")})
    _patch_get(monkeypatch, fake_get)
    _patch_resolve(monkeypatch, {"10.10.10.5": "10.10.10.5"})

    executor = _executor()
    pages = executor.crawl("http://10.10.10.5/", cookies={"session": "abc123"})

    assert len(pages) == 1
    assert fake_get.calls == [("http://10.10.10.5/", {"session": "abc123"})]


def test_crawl_sends_cookies_on_every_followed_link_too(monkeypatch):
    fake_get = _FakeGet(
        {
            "http://10.10.10.5/": _FakeResponse(200, b'<html><a href="/secrets">secrets</a></html>'),
            "http://10.10.10.5/secrets": _FakeResponse(200, b"flag{crawled_with_cookies}"),
        }
    )
    _patch_get(monkeypatch, fake_get)
    _patch_resolve(monkeypatch, {"10.10.10.5": "10.10.10.5"})

    executor = _executor()
    pages = executor.crawl("http://10.10.10.5/", cookies={"session": "abc123"})

    urls = {p["url"] for p in pages}
    assert "http://10.10.10.5/secrets" in urls
    secrets_page = next(p for p in pages if p["url"] == "http://10.10.10.5/secrets")
    assert "flag{crawled_with_cookies}" in secrets_page["body"]
    # Every single request this crawl made (root + the followed link)
    # carried the session cookie -- not just the first one.
    assert all(cookies == {"session": "abc123"} for _url, cookies in fake_get.calls)


def test_crawl_sends_cookies_on_every_redirect_hop_too(monkeypatch):
    fake_get = _FakeGet(
        {
            "http://10.10.10.5/": _FakeResponse(302, b"", headers={"Location": "/dashboard"}),
            "http://10.10.10.5/dashboard": _FakeResponse(200, b"welcome back"),
        }
    )
    _patch_get(monkeypatch, fake_get)
    _patch_resolve(monkeypatch, {"10.10.10.5": "10.10.10.5"})

    executor = _executor()
    pages = executor.crawl("http://10.10.10.5/", cookies={"session": "abc123"})

    assert len(pages) == 1
    assert pages[0]["url"] == "http://10.10.10.5/dashboard"
    assert fake_get.calls == [
        ("http://10.10.10.5/", {"session": "abc123"}),
        ("http://10.10.10.5/dashboard", {"session": "abc123"}),
    ]
