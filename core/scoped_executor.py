"""
core/scoped_executor.py

The ONLY door agents use to touch the network. Its ONLY job is scope safety:
check before every probe, log every check, re-validate every resolved IP
after the fact. scan() delegates to ToolEngine (config-driven external
tools); http_get()/crawl() use `requests` directly since they're native
Python, not external binaries.
"""

from __future__ import annotations

import ipaddress
import socket
from abc import ABC, abstractmethod
from typing import Callable
from urllib.parse import urlparse

import requests

from common.html_extract import extract_forms, extract_links

# ToolNotConfigured/ToolNotInstalled aren't used directly in this module
# (crawl_js() lets them propagate rather than catching them — see its
# docstring) but are re-exported here so a caller of crawl_js() can catch
# them via `from core.scoped_executor import ToolNotInstalled` without
# also having to know they actually live in core.tool_engine.
from core.tool_engine import ToolEngine, ToolNotConfigured, ToolNotInstalled  # noqa: F401


class ScopedExecutor(ABC):
    """Interface every real and mock executor must implement."""

    @abstractmethod
    def scan(self, target: str, allowed_ports: list[int] | None = None) -> dict:
        raise NotImplementedError

    @abstractmethod
    def http_get(self, url: str) -> dict:
        """
        Perform a single HTTP(S) GET against `url`, scope-checked (including
        after DNS resolution). Returns {"status": int, "headers": dict,
        "body": str}. Does NOT follow redirects automatically — callers
        decide whether/how to follow, so redirects can't be used to leave
        scope silently.
        """
        raise NotImplementedError

    @abstractmethod
    def crawl(self, base_url: str) -> list[dict]:
        """
        Crawl from `base_url`, staying on the same host, up to a small depth
        and page limit. Every request goes through the same scope checks as
        http_get. Returns a list of {"url": str, "status": int, "body": str,
        "forms": [{"action": str, "method": str, "inputs": [str]}]}.
        """
        raise NotImplementedError

    @abstractmethod
    def download(self, url: str, max_bytes: int = 20_000_000) -> bytes:
        """
        Download a file's raw bytes from `url`, scope-checked the same way
        as http_get (including the resolved-IP recheck). Used when a
        discovered link points at a binary (an installer, firmware, an
        app) that needs to be fetched before the binary agent can analyze
        it — this is the ONLY sanctioned way to pull that file down.
        Raises DownloadError if the response exceeds `max_bytes` or the
        request fails.
        """
        raise NotImplementedError


class ScopeViolation(Exception):
    """Raised when a target/IP is not within the authorized scope."""


class DownloadError(Exception):
    """Raised when download() fails or the remote file exceeds max_bytes."""


# Hard cap on raw response BYTES read off the wire, before any decoding
# or regex work ever happens. Without this, requests.get(...) (non-
# streaming) buffers the entire response into memory regardless of what
# gets sliced off afterward — an in-scope-but-malicious/compromised
# target could serve a multi-GB response and exhaust memory before a
# single byte of truncation logic runs. Streamed + capped here instead,
# the same technique download() already uses for the same reason.
_MAX_RESPONSE_BYTES = 1_000_000  # 1 MB — generous for a real page/form,
# small enough that decoding + regex work on it stays fast regardless of
# content (see common/html_extract.py's own bounds for the regex side of
# this same defense-in-depth).


def _bounded_get(url: str, timeout: int) -> requests.Response:
    """GET `url` with the connection kept streaming, abandoned (closed)
    the moment _MAX_RESPONSE_BYTES is read. Returns a real
    requests.Response whose .raw has been drained up to that cap —
    callers read bytes via _bounded_bytes(), never response.content
    directly (that would try to keep reading the live, possibly-huge
    stream)."""
    response = requests.get(url, timeout=timeout, allow_redirects=False, stream=True)
    response._bounded_bytes = _read_capped(response, _MAX_RESPONSE_BYTES)
    return response


def _read_capped(response: requests.Response, max_bytes: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_content(chunk_size=65_536):
        chunks.append(chunk)
        total += len(chunk)
        if total >= max_bytes:
            break
    response.close()  # stop reading the socket — we may have left data unread on purpose
    return b"".join(chunks)[:max_bytes]


def _decoded_text(response: requests.Response) -> str:
    """
    Decodes the (already byte-capped — see _bounded_get) response body,
    preferring a real charset sniff over requests' own default.

    requests defaults to the HTTP charset-default of ISO-8859-1 for any
    text/* response whose Content-Type header omits a charset= param —
    it does NOT look at a page's <meta charset=...> tag. That's common
    (plenty of real servers, and e.g. Python's own http.server, send
    bare "text/html") and silently mojibakes any non-Latin-1 page (every
    non-English site whose charset is only declared via the meta tag,
    not the header) for every check downstream (form field names,
    reflected-input matching, body content checks).

    charset_normalizer (what modern `requests` uses internally for
    response.apparent_encoding) looks at in-body signals like that and
    gets it right far more often. Used directly here, on the capped raw
    bytes, rather than through response.apparent_encoding/.text —
    accessing either of those on a stream that was deliberately
    abandoned early would try to keep reading past the cap.
    """
    raw = getattr(response, "_bounded_bytes", None)
    if raw is None:
        raw = response.content  # fallback path for a response _bounded_get() didn't build

    try:
        from charset_normalizer import from_bytes

        best = from_bytes(raw).best()
        if best is not None:
            return str(best)
    except ImportError:
        pass  # charset_normalizer not installed — fall through to utf-8

    return raw.decode("utf-8", errors="replace")


class RealScopedExecutor(ScopedExecutor):
    def __init__(
        self,
        is_in_scope: Callable[[str], bool],
        log_scope_check: Callable[[str, bool], None],
        tool_engine: ToolEngine | None = None,
        network_tool: str = "nmap",
        crawl_max_pages: int = 25,
        crawl_max_depth: int = 2,
        http_timeout_seconds: int = 10,
    ) -> None:
        self._is_in_scope = is_in_scope
        self._log_scope_check = log_scope_check
        self._engine = tool_engine or ToolEngine()
        self._network_tool = network_tool
        self._crawl_max_pages = crawl_max_pages
        self._crawl_max_depth = crawl_max_depth
        self._http_timeout = http_timeout_seconds

    # ------------------------------------------------------------------
    # scan() — network discovery (FR-1)
    # ------------------------------------------------------------------

    def scan(self, target: str, allowed_ports: list[int] | None = None) -> dict:
        scan_target = self._resolve_scan_target(target)
        self._guard(scan_target)
        tool_name = self._pick_network_tool(scan_target)
        raw_output = self._engine.run(tool_name, target=scan_target, ports=allowed_ports)
        parsed = self._engine.parse(tool_name, raw_output)
        return self._revalidate_resolved_hosts(parsed)

    def _pick_network_tool(self, scan_target: str) -> str:
        """
        Uses "{network_tool}_subnet" (e.g. "nmap_subnet") instead of the
        plain tool when scanning a multi-address CIDR range — see that
        config/tools.yaml entry's comment for why a subnet scan needs
        different flags (skips -Pn so it doesn't full-scan every empty
        address in the range). A single IP or a /32 uses the normal
        tool unchanged. Falls back to the normal tool name if no
        "_subnet" variant is configured (e.g. a custom network_tool
        that hasn't defined one) rather than failing the whole scan.
        """
        try:
            is_range = ipaddress.ip_network(scan_target, strict=False).num_addresses > 1
        except ValueError:
            is_range = False  # not a plain IP/CIDR (e.g. a bare hostname) — treat as single

        if not is_range:
            return self._network_tool

        subnet_tool = f"{self._network_tool}_subnet"
        return subnet_tool if self._engine.has_tool(subnet_tool) else self._network_tool

    def _resolve_scan_target(self, target: str) -> str:
        """
        Accepts a single IP, a CIDR range (e.g. "192.168.1.0/24" — scan
        every host on a subnet in one run, not just one address you
        already know), or a hostname.

        An IP or CIDR range is passed straight through unchanged — nmap
        natively enumerates every host in a range itself, and
        core/parsers/nmap.py already parses an XML capture with any
        number of <host> elements into "hosts": [...], so a subnet scan
        needs no special handling past this point. A bare "0.0.0.0" is
        NOT a "scan my whole network" wildcard — it's a single address
        (the IPv4 "unspecified" address), and most systems route it back
        to localhost, which is why it only ever finds your own machine.
        To scan everything on your LAN, pass that LAN's actual subnet
        (check `ip addr` / `ifconfig` for your own address and mask,
        e.g. 192.168.1.0/24), not 0.0.0.0 or 0.0.0.0/0 (the entire
        public internet address space, and never in anyone's scope).

        A hostname is resolved to a single IP BEFORE any scope check
        happens — scope.yaml only ever understands IPs/CIDRs, so a bare
        hostname string is never checked or scanned directly.
        """
        try:
            ipaddress.ip_network(target, strict=False)
            return target  # already a valid IP or CIDR range
        except ValueError:
            pass

        try:
            return socket.gethostbyname(target)
        except socket.gaierror:
            raise ScopeViolation(f"{target!r} could not be resolved to an IP")

    def _revalidate_resolved_hosts(self, parsed: dict) -> dict:
        safe_hosts = []
        for host in parsed["hosts"]:
            ip = host["ip"]
            ip_in_scope = self._is_in_scope(ip)
            self._log_scope_check(ip, ip_in_scope)
            if ip_in_scope:
                safe_hosts.append(host)
        return {"hosts": safe_hosts}

    # ------------------------------------------------------------------
    # http_get() / crawl() — web surface (FR-2)
    # ------------------------------------------------------------------

    def http_get(self, url: str) -> dict:
        self._guard_url(url)
        try:
            response = _bounded_get(url, self._http_timeout)
        except requests.RequestException as exc:
            return {"status": 0, "headers": {}, "body": "", "error": str(exc)}

        # Text is already bounded by _MAX_RESPONSE_BYTES on the raw-bytes
        # side; the further [:50_000] char-level cap keeps evidence/report
        # text short even for a dense multi-byte-encoded response that
        # decodes to more characters than its byte count would suggest.
        return {
            "status": response.status_code,
            "headers": dict(response.headers),
            "body": _decoded_text(response)[:50_000],
        }

    def crawl(self, base_url: str) -> list[dict]:
        self._guard_url(base_url)
        base_host = urlparse(base_url).netloc

        visited: set[str] = set()
        to_visit: list[tuple[str, int]] = [(base_url, 0)]
        pages: list[dict] = []

        while to_visit and len(pages) < self._crawl_max_pages:
            url, depth = to_visit.pop(0)
            if url in visited or depth > self._crawl_max_depth:
                continue
            visited.add(url)

            if not self._guard_url(url, raise_on_violation=False):
                continue  # out of scope — skip silently, already logged by _guard_url

            try:
                response = _bounded_get(url, self._http_timeout)
            except requests.RequestException:
                continue

            # One bounded, truncated body feeds BOTH the stored page
            # record and link/form extraction — extraction never sees a
            # larger string than what's actually kept, so the regex
            # bounds in common/html_extract.py and this truncation
            # compose into one consistent size ceiling instead of the
            # extraction step accidentally running on a larger, untruncated
            # copy of the same text.
            body = _decoded_text(response)[:50_000]
            page = {
                "url": url,
                "status": response.status_code,
                "body": body,
                "forms": extract_forms(body),
            }
            pages.append(page)

            if depth < self._crawl_max_depth:
                for link in extract_links(body, url):
                    if urlparse(link).netloc == base_host and link not in visited:
                        to_visit.append((link, depth + 1))

        return pages

    # ------------------------------------------------------------------
    # crawl_js() — katana-backed crawl (FR-2 upgrade over crawl()).
    # Optional: not part of the ScopedExecutor interface, so a caller
    # must check for it (hasattr/getattr) rather than assume every
    # executor has it — the MockScopedExecutor used in tests, and any
    # future alternate executor, aren't required to implement it.
    # ------------------------------------------------------------------

    def crawl_js(self, base_url: str) -> dict:
        """
        Crawl `base_url` through katana instead of the native requests
        crawler — sees links/endpoints/secrets that only exist inside
        JS bundles (a plain requests+regex crawl can't execute or
        statically analyze <script src> content). Returns
        {"pages": [...same shape as crawl()...], "js_findings": [...]}.

        Scope enforcement mirrors scan()'s defense-in-depth exactly:
        `base_url` is guarded before katana ever runs, AND every page
        and js_finding katana reports back is independently re-checked
        against scope afterward (so a misconfigured/compromised katana
        run, or katana itself following an off-host redirect, can't
        smuggle an out-of-scope result into the findings). Anything that
        fails the post-hoc check is dropped and logged, not raised —
        same as _revalidate_resolved_hosts() for scan().

        Raises ToolNotInstalled/ToolNotConfigured if katana isn't
        available — callers (agents/web/agent.py) catch that and fall
        back to crawl(), the always-available native path.
        """
        self._guard_url(base_url)

        raw_output = self._engine.run("katana", target=base_url)
        parsed = self._engine.parse("katana", raw_output)

        safe_pages = [p for p in parsed.get("pages", []) if self._revalidate_url(p.get("url", ""))]
        safe_findings = [
            f for f in parsed.get("js_findings", []) if self._revalidate_url(f.get("source", ""))
        ]

        return {"pages": safe_pages, "js_findings": safe_findings}

    def _revalidate_url(self, url: str) -> bool:
        """Like _guard_url, but never raises — used to filter a tool's
        results after the fact rather than gate a single outgoing
        request. Anything without a resolvable in-scope host is dropped
        silently (and logged) rather than failing the whole batch."""
        if not url:
            self._log_scope_check("<missing url>", False)
            return False
        return self._guard_url(url, raise_on_violation=False)

    def download(self, url: str, max_bytes: int = 20_000_000) -> bytes:
        self._guard_url(url)
        try:
            response = requests.get(
                url, timeout=self._http_timeout, allow_redirects=False, stream=True
            )
        except requests.RequestException as exc:
            raise DownloadError(f"failed to download {url!r}: {exc}") from exc

        chunks: list[bytes] = []
        total = 0
        for chunk in response.iter_content(chunk_size=65_536):
            total += len(chunk)
            if total > max_bytes:
                raise DownloadError(
                    f"{url!r} exceeds the {max_bytes}-byte download cap — refusing to "
                    f"keep downloading (avoids a huge/unbounded file stalling analysis)"
                )
            chunks.append(chunk)

        return b"".join(chunks)

    # ------------------------------------------------------------------
    # internal — scope guards
    # ------------------------------------------------------------------

    def _guard(self, target: str) -> None:
        in_scope = self._is_in_scope(target)
        self._log_scope_check(target, in_scope)
        if not in_scope:
            raise ScopeViolation(f"{target!r} is not within the authorized scope")

    def _guard_url(self, url: str, raise_on_violation: bool = True) -> bool:
        """
        Resolves the URL's host to an IP and checks THAT against scope —
        not just the hostname string — so a DNS record can't be used to
        reach something outside the authorized range. Same defense-in-depth
        pattern as scan()'s post-scan revalidation.
        """
        hostname = urlparse(url).hostname
        if hostname is None:
            self._log_scope_check(url, False)
            if raise_on_violation:
                raise ScopeViolation(f"{url!r} has no resolvable host")
            return False

        try:
            resolved_ip = socket.gethostbyname(hostname)
        except socket.gaierror:
            self._log_scope_check(hostname, False)
            if raise_on_violation:
                raise ScopeViolation(f"{hostname!r} could not be resolved")
            return False

        in_scope = self._is_in_scope(resolved_ip)
        self._log_scope_check(resolved_ip, in_scope)
        if not in_scope and raise_on_violation:
            raise ScopeViolation(f"{url!r} resolves to {resolved_ip}, which is out of scope")
        return in_scope