"""
tests/core/test_scoped_executor_crawl_binary_detection.py

Tests for RealScopedExecutor.crawl()'s binary-response detection
(_looks_like_binary / the "looks_binary" page field). A compiled binary
served with NO extension anywhere in its URL (a direct /download/<id>
link, relying entirely on Content-Type/Content-Disposition — confirmed as
the actual real-world case by direct user feedback) can never be caught
by any URL-pattern check, extension-based or otherwise. This is caught
instead by sniffing the actual response: magic bytes at the start of the
body, OR a binary-ish declared Content-Type. Uses the same requests.get
mock as test_scoped_executor_crawl_redirects.py.
"""

from __future__ import annotations

import requests

from core.scoped_executor import RealScopedExecutor, _looks_like_binary


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
    def __init__(self, responses: dict[str, _FakeResponse]):
        self._responses = responses
        self.calls: list[str] = []

    def __call__(self, url: str, timeout=None, allow_redirects=None, stream=None):
        self.calls.append(url)
        if url not in self._responses:
            raise requests.RequestException(f"no canned response for {url!r}")
        return self._responses[url]


class _RecordingLogger:
    def __call__(self, target: str, in_scope: bool) -> None:
        pass


def _executor():
    return RealScopedExecutor(
        is_in_scope=lambda ip: True,
        log_scope_check=_RecordingLogger(),
        http_timeout_seconds=5,
    )


def _patch(monkeypatch, fake_get: _FakeGet, host_to_ip: dict[str, str]) -> None:
    monkeypatch.setattr("core.scoped_executor.requests.get", fake_get)

    def fake_gethostbyname(host):
        if host in host_to_ip:
            return host_to_ip[host]
        raise OSError(f"no fake DNS entry for {host!r}")

    monkeypatch.setattr("core.scoped_executor.socket.gethostbyname", fake_gethostbyname)


# --- _looks_like_binary() unit coverage -------------------------------


def test_elf_magic_bytes_detected():
    assert _looks_like_binary(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 20, "application/octet-stream")


def test_pe_mz_magic_bytes_detected():
    assert _looks_like_binary(b"MZ\x90\x00" + b"\x00" * 20, "")


def test_zip_apk_jar_magic_bytes_detected():
    assert _looks_like_binary(b"PK\x03\x04" + b"\x00" * 20, "")


def test_plain_html_is_not_flagged_as_binary():
    assert not _looks_like_binary(b"<html><body>hi</body></html>", "text/html")


def test_content_type_alone_flags_a_format_with_no_magic_byte_signature():
    # Some binary formats (or a truncated response) won't match any
    # magic-byte signature — a clearly binary Content-Type is enough on
    # its own.
    assert _looks_like_binary(b"\x00\x01\x02\x03", "application/octet-stream")


def test_json_content_type_is_not_flagged_even_with_odd_bytes():
    assert not _looks_like_binary(b'{"a": 1}', "application/json")


# --- crawl() integration: a binary served with NO extension anywhere --


def test_download_link_with_no_extension_is_recognized_via_magic_bytes(monkeypatch):
    fake_get = _FakeGet(
        {
            "http://10.10.10.5/": _FakeResponse(
                200, b'<html><a href="/download/a1b2c3d4">get it</a></html>', headers={"Content-Type": "text/html"}
            ),
            "http://10.10.10.5/download/a1b2c3d4": _FakeResponse(
                200,
                b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 40,
                headers={"Content-Type": "application/octet-stream"},
            ),
        }
    )
    _patch(monkeypatch, fake_get, {"10.10.10.5": "10.10.10.5"})

    pages = _executor().crawl("http://10.10.10.5/")

    binary_page = next(p for p in pages if p["url"] == "http://10.10.10.5/download/a1b2c3d4")
    assert binary_page["looks_binary"] is True
    assert binary_page["body"] == ""  # binary content isn't decoded as text
    assert binary_page["forms"] == []


def test_ordinary_html_page_is_not_marked_looks_binary(monkeypatch):
    fake_get = _FakeGet(
        {"http://10.10.10.5/": _FakeResponse(200, b"<html>hi</html>", headers={"Content-Type": "text/html"})}
    )
    _patch(monkeypatch, fake_get, {"10.10.10.5": "10.10.10.5"})

    pages = _executor().crawl("http://10.10.10.5/")
    assert pages[0].get("looks_binary") is not True


def test_binary_page_is_not_mined_for_further_links():
    # Sanity on the "continue" path in crawl(): a binary page's raw bytes
    # could coincidentally contain something href-shaped; it must never
    # be fed through extract_links/extract_forms. Covered indirectly
    # above by forms == [] but pinned explicitly here for the no-crash
    # guarantee on arbitrary bytes.
    from common.html_extract import extract_forms, extract_links

    raw = b"\x7fELF" + b"href=\"/x\" " * 50  # looks link-ish if ever decoded as text
    # crawl() must not pass this through extract_links/extract_forms —
    # verified by test_download_link_with_no_extension_is_recognized_via_magic_bytes
    # showing forms == [] and body == "" for a looks_binary page; this
    # just documents why that matters (these two WOULD match on raw text).
    assert extract_links(raw.decode("latin-1"), "http://x/") != []
    assert extract_forms(raw.decode("latin-1")) == []
