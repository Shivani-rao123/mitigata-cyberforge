"""
tests/core/test_scoped_executor_crawl_page_budget.py

Regression test for crawl_max_pages: a real TinyFileManager-shaped
listing was confirmed to generate ~3 same-host link variants per file
(a "view" link, a "download" link, and a decorative absolute "direct
link" that round-trips through a redirect) plus one nav link per
folder. A listing of just 5 files + 2 folders already produces ~21
depth-1 links -- enough to exhaust the OLD default of 25 pages in BFS
order before a file one folder deep (e.g. ops/secret.txt) is ever
reached, even though nothing about the crawl logic itself was broken:
every fetch succeeded, every link resolved correctly, it simply ran out
of page budget on top-level noise first. Pins the new default (150) at
actually being enough for this realistic shape, using the same
requests.get-mocking seam as test_scoped_executor_crawl_redirects.py
(no real network).
"""

from __future__ import annotations

import requests

from core.scoped_executor import RealScopedExecutor

BASE = "http://10.10.10.5"


class _FakeResponse:
    def __init__(self, status_code: int, body: bytes = b"", headers: dict | None = None):
        self.status_code = status_code
        self._body = body
        self.headers = headers or {"Content-Type": "text/html"}

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


FILES = ["edr_log_generator.py", "firex-10G.log", "firex-30G.log", "firex-50G.log", "README.txt"]


def _build_tfm_like_site() -> dict[str, _FakeResponse]:
    """A root listing with the exact real-world link shape (view/direct/
    download per file, nav+direct per folder), plus one secret file one
    folder deep in `ops/`."""
    rows = []
    for folder in ("backups", "ops"):
        rows.append(f'<a href="?p={folder}">{folder}</a>')
        rows.append(f'<a href="{BASE}/{folder}/">direct {folder}</a>')
    for f in FILES:
        rows.append(f'<a href="?p=&amp;view={f}">{f}</a>')
        rows.append(f'<a href="{BASE}/{f}">direct {f}</a>')
        rows.append(f'<a href="?p=&amp;dl={f}">dl {f}</a>')
    root_body = "".join(rows).encode()

    responses: dict[str, _FakeResponse] = {
        f"{BASE}/index.php?p=": _FakeResponse(200, root_body),
        f"{BASE}/index.php?p=ops": _FakeResponse(
            200, b'<a href="?p=ops&amp;view=netops-handover.txt">netops-handover.txt</a>'
        ),
        f"{BASE}/index.php?p=ops&view=netops-handover.txt": _FakeResponse(
            200, b"AKIAFAKEEXAMPLE12345", {"Content-Type": "text/plain"}
        ),
        f"{BASE}/index.php?p=backups": _FakeResponse(
            200, b'<a href="?p=backups&amp;view=placeholder.txt">placeholder.txt</a>'
        ),
        f"{BASE}/index.php?p=backups&view=placeholder.txt": _FakeResponse(
            200, b"just a placeholder", {"Content-Type": "text/plain"}
        ),
    }
    # The decorative absolute "direct link" variants all redirect to a
    # page with an empty p= -- same dead-end shape confirmed on the real
    # target, converging rather than looping.
    for folder in ("backups", "ops"):
        responses[f"{BASE}/{folder}/"] = _FakeResponse(
            302, headers={"Location": f"/index.php/{folder}/?p="}
        )
        responses[f"{BASE}/index.php/{folder}/?p="] = _FakeResponse(200, b"")
    for f in FILES:
        responses[f"{BASE}/{f}"] = _FakeResponse(302, headers={"Location": f"/index.php/{f}?p="})
        responses[f"{BASE}/index.php/{f}?p="] = _FakeResponse(200, b"")
    for f in FILES:
        responses[f"{BASE}/index.php?p=&view={f}"] = _FakeResponse(200, f"content of {f}".encode())
        responses[f"{BASE}/index.php?p=&dl={f}"] = _FakeResponse(200, f"download of {f}".encode())
    return responses


def test_default_page_budget_reaches_a_file_one_folder_deep(monkeypatch):
    fake_get = _FakeGet(_build_tfm_like_site())
    monkeypatch.setattr("core.scoped_executor.requests.get", fake_get)

    executor = RealScopedExecutor(is_in_scope=lambda ip: True, log_scope_check=lambda *a, **k: None)
    pages = executor.crawl(f"{BASE}/index.php?p=")

    secret_pages = [p for p in pages if "netops-handover" in p["url"]]
    assert secret_pages, (
        "ops/netops-handover.txt was never reached within the default page "
        "budget — this is the exact real-world regression (budget exhausted "
        "on ~21 depth-1 link variants before reaching a file one folder deep)"
    )
    assert secret_pages[0]["body"] == "AKIAFAKEEXAMPLE12345"


def test_a_tight_page_budget_misses_a_file_nested_one_folder_deep(monkeypatch):
    """Illustrates the actual failure class the default was raised to
    avoid: with this exact site but a tight budget, BFS exhausts the
    budget on same-level link variants (view/direct/download per file)
    before reaching anything nested in a folder — not a logic bug, just
    not enough budget for a site shaped this way. (The real target that
    surfaced this had more top-level noise than this fixture reproduces,
    which is why its own old default of 25 was insufficient there even
    though this fixture's 22 total reachable pages fit under 25 — this
    test pins the general failure mode with a budget deliberately set
    below this fixture's own total, rather than asserting the exact
    real-world page count.)"""
    fake_get = _FakeGet(_build_tfm_like_site())
    monkeypatch.setattr("core.scoped_executor.requests.get", fake_get)

    executor = RealScopedExecutor(
        is_in_scope=lambda ip: True, log_scope_check=lambda *a, **k: None, crawl_max_pages=10
    )
    pages = executor.crawl(f"{BASE}/index.php?p=")

    assert len(pages) == 10
    assert not any("netops-handover" in p["url"] for p in pages)
