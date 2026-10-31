"""
tests/agents/test_binary_discovery.py

Unit tests for agents/binary/discovery.py — finding downloadable binary
links on a page, so the binary agent can be pointed at a WEBSITE rather
than requiring a pre-known file path or binary URL. Real end-to-end
behavior (does this actually work against a real running site) is
verified separately against fixtures/demo_site/app.py.
"""

from agents.binary.discovery import find_binary_links, looks_like_binary_url
from tests.mock_executor import MockScopedExecutor


def test_finds_a_single_download_link():
    html = """
    <html><body>
      <a href="/about">About</a>
      <a href="/downloads/acme-tool.bin">Download</a>
    </body></html>
    """
    executor = MockScopedExecutor(http_result={"status": 200, "headers": {}, "body": html})

    links = find_binary_links(executor, "http://example.test/")

    assert links == ["http://example.test/downloads/acme-tool.bin"]


def test_page_with_no_binary_links_returns_empty_list():
    html = "<html><body><a href='/about'>About</a><a href='/contact'>Contact</a></body></html>"
    executor = MockScopedExecutor(http_result={"status": 200, "headers": {}, "body": html})

    links = find_binary_links(executor, "http://example.test/")

    assert links == []


def test_empty_page_body_does_not_crash():
    executor = MockScopedExecutor(http_result={"status": 200, "headers": {}, "body": ""})

    links = find_binary_links(executor, "http://example.test/")

    assert links == []


def test_cross_host_binary_links_are_ignored():
    html = '<a href="http://other-site.test/malware.exe">unrelated external link</a>'
    executor = MockScopedExecutor(http_result={"status": 200, "headers": {}, "body": html})

    links = find_binary_links(executor, "http://example.test/")

    assert links == []  # different host — not ours to download


def test_multiple_different_binary_extensions_all_found():
    html = """
    <a href="/app.exe">Windows</a>
    <a href="/app.apk">Android</a>
    <a href="/app.dmg">Mac</a>
    <a href="/app.bin">Linux</a>
    """
    executor = MockScopedExecutor(http_result={"status": 200, "headers": {}, "body": html})

    links = find_binary_links(executor, "http://example.test/")

    assert len(links) == 4


def test_duplicate_links_are_deduplicated():
    html = '<a href="/app.bin">Download</a><a href="/app.bin">Download again</a>'
    executor = MockScopedExecutor(http_result={"status": 200, "headers": {}, "body": html})

    links = find_binary_links(executor, "http://example.test/")

    assert len(links) == 1


def test_relative_links_are_resolved_to_absolute_urls():
    html = '<a href="downloads/tool.bin">Download</a>'
    executor = MockScopedExecutor(http_result={"status": 200, "headers": {}, "body": html})

    links = find_binary_links(executor, "http://example.test/page/")

    assert links == ["http://example.test/page/downloads/tool.bin"]


def test_looks_like_binary_url_true_cases():
    assert looks_like_binary_url("http://x.test/app.exe")
    assert looks_like_binary_url("http://x.test/path/app.APK")  # case-insensitive
    assert looks_like_binary_url("http://x.test/tool.bin")


def test_looks_like_binary_url_false_cases():
    assert not looks_like_binary_url("http://x.test/")
    assert not looks_like_binary_url("http://x.test/page.html")
    assert not looks_like_binary_url("http://x.test/image.png")
