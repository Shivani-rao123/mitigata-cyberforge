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
from urllib.parse import urljoin, urlparse

import requests

from core.tool_engine import ToolEngine


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
        ip = self._resolve_to_ip(target)
        self._guard(ip)
        raw_output = self._engine.run(self._network_tool, target=ip, ports=allowed_ports)
        parsed = self._engine.parse(self._network_tool, raw_output)
        return self._revalidate_resolved_hosts(parsed)

    def _resolve_to_ip(self, target: str) -> str:
        """
        Accepts either an IP or a hostname. If it's already an IP, returns
        it unchanged. If it's a hostname, resolves it to an IP BEFORE any
        scope check happens — scope.yaml only ever understands IPs/CIDRs,
        so we never check or scan a bare hostname string.
        """
        try:
            ipaddress.ip_address(target)
            return target  # already a valid IP
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
            response = requests.get(
                url, timeout=self._http_timeout, allow_redirects=False
            )
        except requests.RequestException as exc:
            return {"status": 0, "headers": {}, "body": "", "error": str(exc)}

        return {
            "status": response.status_code,
            "headers": dict(response.headers),
            "body": response.text[:50_000],  # cap body size, evidence stays bounded
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
                response = requests.get(url, timeout=self._http_timeout, allow_redirects=False)
            except requests.RequestException:
                continue

            page = {
                "url": url,
                "status": response.status_code,
                "body": response.text[:50_000],
                "forms": self._extract_forms(response.text),
            }
            pages.append(page)

            if depth < self._crawl_max_depth:
                for link in self._extract_links(response.text, url):
                    if urlparse(link).netloc == base_host and link not in visited:
                        to_visit.append((link, depth + 1))

        return pages

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

    @staticmethod
    def _extract_links(html: str, base_url: str) -> list[str]:
        import re
        hrefs = re.findall(r'href=["\']([^"\']+)["\']', html, re.IGNORECASE)
        return [urljoin(base_url, h) for h in hrefs]

    @staticmethod
    def _extract_forms(html: str) -> list[dict]:
        import re
        forms = []
        for form_match in re.finditer(r"<form[^>]*>(.*?)</form>", html, re.IGNORECASE | re.DOTALL):
            form_html = form_match.group(0)
            action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            inputs = re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
            forms.append({
                "action": action_match.group(1) if action_match else "",
                "method": (method_match.group(1) if method_match else "get").lower(),
                "inputs": inputs,
            })
        return forms

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