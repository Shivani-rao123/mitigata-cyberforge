"""
agents/binary/discovery.py

Finds downloadable binary links on a web page, so the binary agent can be
pointed at a WEBSITE — the realistic scenario (a user gives CART a site's
URL) — instead of requiring someone to already know the exact file path
or binary URL.

This is intentionally a thin, standalone piece, not part of the web agent
(agents/web/agent.py), which is being built separately. Once that agent
exists, it can emit the same follow-up job shape
({"agent": "binary", "target": <url>}) from its own crawl, and this
becomes just one of the ways that discovery can happen.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from core.scoped_executor import ScopedExecutor

# Extensions worth downloading and statically analyzing. Anything else
# linked from the page (images, CSS, other HTML pages) is ignored here —
# that's the web agent's job, not the binary agent's.
BINARY_EXTENSIONS = {
    ".exe", ".dll", ".bin", ".so", ".elf", ".apk", ".deb", ".rpm",
    ".dmg", ".pkg", ".msi", ".appimage",
}


def looks_like_binary_url(url: str) -> bool:
    """True if the URL's path ends in a known binary extension."""
    path = urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in BINARY_EXTENSIONS)


def find_binary_links(executor: ScopedExecutor, base_url: str) -> list[str]:
    """
    Fetches `base_url` (scope-checked, via the same executor everything
    else uses) and returns every same-host link whose path ends in a
    known binary extension — e.g. a "Download" button pointing at an
    installer. Single page only (no recursion) — a full multi-page crawl
    belongs to the web agent; this stays fast and simple.
    """
    response = executor.http_get(base_url)
    body = response.get("body", "")
    if not body:
        return []

    base_host = urlparse(base_url).netloc
    hrefs = re.findall(r'href=["\']([^"\']+)["\']', body, re.IGNORECASE)

    found: list[str] = []
    seen: set[str] = set()
    for href in hrefs:
        absolute = urljoin(base_url, href)
        if urlparse(absolute).netloc != base_host:
            continue  # stay on the same host, same principle as crawl()
        if looks_like_binary_url(absolute) and absolute not in seen:
            seen.add(absolute)
            found.append(absolute)

    return found
