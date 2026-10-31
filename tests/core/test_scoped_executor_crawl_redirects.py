"""
tests/core/test_scoped_executor_crawl_redirects.py

Tests for RealScopedExecutor.crawl()'s redirect-following behavior
(_fetch_following_redirects). Real targets commonly redirect — a bare IP
to its canonical vhost, http to https, a landing page to a dashboard or
file-manager app behind it — and crawl() used to just record the 3xx
response itself (empty body, nothing to extract links/secrets from) and
never see what was actually being served. Mocks `requests.get` directly
(no real network), the same seam test_scoped_executor_crawl_js.py uses
for katana.
"""

from __future__ import annotations

import pytest
import requests

from core.scoped_executor import RealScopedExecutor, ScopeViolation


class _FakeResponse:
    """Minimal stand-in for requests.Response, just enough for
    _bounded_get()/_decoded_text() to work: iter_content (so
    _read_capped can stream it), status_code, headers, close()."""

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
    """Maps a URL to a canned _FakeResponse, recording every URL it was
    called with (in order) so a test can assert exactly which hops were
    actually fetched."""

    def __init__(self, responses: dict[str, _FakeResponse]):
        self._responses = responses
        self.calls: list[str] = []

    def __call__(self, url: str, timeout=None, allow_redirects=None, stream=None):
        self.calls.append(url)
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
    """crawl()'s scope guard resolves each URL's host via socket —
    stub that out so every test stays fully offline and deterministic."""

    def fake_gethostbyname(host):
        if host in host_to_ip:
            return host_to_ip[host]
        raise OSError(f"no fake DNS entry for {host!r}")

    monkeypatch.setattr("core.scoped_executor.socket.gethostbyname", fake_gethostbyname)


def test_no_redirect_behaves_exactly_as_before(monkeypatch):
    fake_get = _FakeGet(
        {"http://10.10.10.5/": _FakeResponse(200, b"<html>hi</html>")},
    )
    _patch_get(monkeypatch, fake_get)
    _patch_resolve(monkeypatch, {"10.10.10.5": "10.10.10.5"})

    executor = _executor()
    pages = executor.crawl("http://10.10.10.5/")

    assert len(pages) == 1
    assert pages[0]["url"] == "http://10.10.10.5/"
    assert "redirect_chain" not in pages[0]
    assert fake_get.calls == ["http://10.10.10.5/"]


def test_single_redirect_is_followed_and_final_content_captured(monkeypatch):
    fake_get = _FakeGet(
        {
            "http://10.10.10.5/": _FakeResponse(
                302, b"", headers={"Location": "/dashboard"}
            ),
            "http://10.10.10.5/dashboard": _FakeResponse(200, b"<html>Acme Dashboard</html>"),
        }
    )
    _patch_get(monkeypatch, fake_get)
    _patch_resolve(monkeypatch, {"10.10.10.5": "10.10.10.5"})

    executor = _executor()
    pages = executor.crawl("http://10.10.10.5/")

    assert len(pages) == 1
    page = pages[0]
    assert page["url"] == "http://10.10.10.5/dashboard"
    assert page["status"] == 200
    assert "Acme Dashboard" in page["body"]
    assert page["redirect_chain"] == ["http://10.10.10.5/", "http://10.10.10.5/dashboard"]
    assert fake_get.calls == ["http://10.10.10.5/", "http://10.10.10.5/dashboard"]


def test_multi_hop_redirect_chain_is_fully_followed(monkeypatch):
    fake_get = _FakeGet(
        {
            "http://10.10.10.5/": _FakeResponse(301, b"", headers={"Location": "/a"}),
            "http://10.10.10.5/a": _FakeResponse(302, b"", headers={"Location": "/b"}),
            "http://10.10.10.5/b": _FakeResponse(200, b"<html>landed</html>"),
        }
    )
    _patch_get(monkeypatch, fake_get)
    _patch_resolve(monkeypatch, {"10.10.10.5": "10.10.10.5"})

    executor = _executor()
    pages = executor.crawl("http://10.10.10.5/")

    assert len(pages) == 1
    assert pages[0]["url"] == "http://10.10.10.5/b"
    assert "landed" in pages[0]["body"]
    assert pages[0]["redirect_chain"] == [
        "http://10.10.10.5/",
        "http://10.10.10.5/a",
        "http://10.10.10.5/b",
    ]


def test_cross_host_redirect_to_canonical_vhost_is_followed_when_in_scope(monkeypatch):
    # The "bare IP redirects to its canonical hostname" case from the
    # user's own report: hitting 10.10.10.5 directly 302s to
    # files.internal.local, which is a DIFFERENT host but still resolves
    # inside scope, so it should be followed, not treated as off-site.
    fake_get = _FakeGet(
        {
            "http://10.10.10.5/": _FakeResponse(
                302, b"", headers={"Location": "http://files.internal.local/"}
            ),
            "http://files.internal.local/": _FakeResponse(
                200, b'<html><a href="/notes.txt">notes</a></html>'
            ),
        }
    )
    _patch_get(monkeypatch, fake_get)
    _patch_resolve(monkeypatch, {"10.10.10.5": "10.10.10.5", "files.internal.local": "10.10.10.5"})

    executor = _executor()
    pages = executor.crawl("http://10.10.10.5/")

    assert len(pages) == 1
    assert pages[0]["url"] == "http://files.internal.local/"
    # the crawl's notion of "same site" should have widened to the
    # landed host, so a link found on that page would be followed too —
    # proven indirectly: no ScopeViolation, no dropped page.


def test_redirect_to_an_out_of_scope_host_is_not_followed(monkeypatch):
    fake_get = _FakeGet(
        {
            "http://10.10.10.5/": _FakeResponse(
                302, b"", headers={"Location": "http://evil.example.com/"}
            ),
        }
    )
    _patch_get(monkeypatch, fake_get)
    _patch_resolve(monkeypatch, {"10.10.10.5": "10.10.10.5", "evil.example.com": "203.0.113.9"})

    executor = _executor(is_in_scope=lambda ip: ip == "10.10.10.5")
    pages = executor.crawl("http://10.10.10.5/")

    # The redirect response itself (still a 302, no useful body) is what
    # gets recorded — crawl() doesn't raise or silently vanish the page,
    # it just refuses to follow the hop leaving scope.
    assert len(pages) == 1
    assert pages[0]["url"] == "http://10.10.10.5/"
    assert pages[0]["status"] == 302
    assert fake_get.calls == ["http://10.10.10.5/"]  # evil.example.com was never fetched


def test_redirect_missing_location_header_stops_without_crashing(monkeypatch):
    fake_get = _FakeGet({"http://10.10.10.5/": _FakeResponse(302, b"")})  # no Location header
    _patch_get(monkeypatch, fake_get)
    _patch_resolve(monkeypatch, {"10.10.10.5": "10.10.10.5"})

    executor = _executor()
    pages = executor.crawl("http://10.10.10.5/")

    assert len(pages) == 1
    assert pages[0]["status"] == 302
    assert "redirect_chain" not in pages[0]


def test_redirect_loop_is_bounded_not_infinite(monkeypatch):
    fake_get = _FakeGet(
        {
            "http://10.10.10.5/a": _FakeResponse(302, b"", headers={"Location": "/b"}),
            "http://10.10.10.5/b": _FakeResponse(302, b"", headers={"Location": "/a"}),
        }
    )
    _patch_get(monkeypatch, fake_get)
    _patch_resolve(monkeypatch, {"10.10.10.5": "10.10.10.5"})

    executor = _executor()
    pages = executor.crawl("http://10.10.10.5/a")

    # Must terminate (this test itself times out via pytest's default
    # collection if it doesn't) and fall back to recording whatever the
    # last-fetched hop was, rather than hanging or raising.
    assert len(pages) == 1
    assert pages[0]["status"] == 302


def test_links_on_the_redirected_to_page_are_discovered_and_queued(monkeypatch):
    fake_get = _FakeGet(
        {
            "http://10.10.10.5/": _FakeResponse(
                302, b"", headers={"Location": "/files/"}
            ),
            "http://10.10.10.5/files/": _FakeResponse(
                200, b'<html><a href="/files/notes.txt">notes</a></html>'
            ),
            "http://10.10.10.5/files/notes.txt": _FakeResponse(
                200, b"internal memo: rotate the backup key", headers={"Content-Type": "text/plain"}
            ),
        }
    )
    _patch_get(monkeypatch, fake_get)
    _patch_resolve(monkeypatch, {"10.10.10.5": "10.10.10.5"})

    executor = _executor()
    pages = executor.crawl("http://10.10.10.5/")

    urls = {p["url"] for p in pages}
    assert "http://10.10.10.5/files/" in urls
    assert "http://10.10.10.5/files/notes.txt" in urls
    notes_page = next(p for p in pages if p["url"] == "http://10.10.10.5/files/notes.txt")
    assert "rotate the backup key" in notes_page["body"]


def test_base_url_itself_out_of_scope_still_raises_before_any_fetch(monkeypatch):
    fake_get = _FakeGet({})
    _patch_get(monkeypatch, fake_get)
    _patch_resolve(monkeypatch, {"10.10.10.5": "10.10.10.5"})

    executor = _executor(is_in_scope=lambda ip: False)
    with pytest.raises(ScopeViolation):
        executor.crawl("http://10.10.10.5/")
    assert fake_get.calls == []
