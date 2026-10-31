"""
core/scoped_executor.py

The ONLY door agents use to touch the network. Its ONLY job is scope safety:
check before every probe, log every check, re-validate every resolved IP
after the fact. It delegates the actual "how do I run this tool" work to
ToolEngine (core/tool_engine.py), which is generic and config-driven.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Callable

from core.tool_engine import ToolEngine


class ScopedExecutor(ABC):
    """Interface every real and mock executor must implement."""

    @abstractmethod
    def scan(self, target: str, allowed_ports: list[int] | None = None) -> dict:
        """
        Run network discovery against `target`, restricted to
        `allowed_ports` if given. Must check scope before sending any probe
        and log the check. Returns:
        {"hosts": [{"ip": str, "hostname": str|None,
                     "services": [{"port": int, "protocol": str,
                                   "service": str, "version": str|None}]}]}
        """
        raise NotImplementedError

    @abstractmethod
    def http_get(self, url: str) -> dict:
        raise NotImplementedError

    @abstractmethod
    def crawl(self, base_url: str) -> list[dict]:
        raise NotImplementedError


class ScopeViolation(Exception):
    """Raised when a target/IP is not within the authorized scope."""


class RealScopedExecutor(ScopedExecutor):
    """
    Production implementation. Owns ONLY scope enforcement — actual tool
    execution is delegated to ToolEngine, which is generic and config-driven
    (config/tools.yaml). Which specific tool scan() uses is itself
    configurable, defaulting to "nmap".
    """

    def __init__(
        self,
        is_in_scope: Callable[[str], bool],
        log_scope_check: Callable[[str, bool], None],
        tool_engine: ToolEngine | None = None,
        network_tool: str = "nmap",
    ) -> None:
        self._is_in_scope = is_in_scope
        self._log_scope_check = log_scope_check
        self._engine = tool_engine or ToolEngine()
        self._network_tool = network_tool

    # ------------------------------------------------------------------
    # scan() — network discovery (FR-1)
    # ------------------------------------------------------------------

    def scan(self, target: str, allowed_ports: list[int] | None = None) -> dict:
        self._guard(target)

        raw_output = self._engine.run(self._network_tool, target=target, ports=allowed_ports)
        parsed = self._engine.parse(self._network_tool, raw_output)

        return self._revalidate_resolved_hosts(parsed)

    def _revalidate_resolved_hosts(self, parsed: dict) -> dict:
        """
        Defense in depth: `target` may have been a hostname, already
        scope-checked as a string by _guard(). The tool itself resolves
        hostnames to IPs, and DNS is not static. Re-check every resolved
        host IP here, drop anything outside scope, and log each check.
        """
        safe_hosts = []
        for host in parsed["hosts"]:
            ip = host["ip"]
            ip_in_scope = self._is_in_scope(ip)
            self._log_scope_check(ip, ip_in_scope)
            if ip_in_scope:
                safe_hosts.append(host)
        return {"hosts": safe_hosts}

    # ------------------------------------------------------------------
    # http_get() / crawl() — web surface (FR-2), filled in alongside the
    # web agent, following the same ToolEngine pattern.
    # ------------------------------------------------------------------

    def http_get(self, url: str) -> dict:
        raise NotImplementedError("fill in alongside the web agent (FR-2)")

    def crawl(self, base_url: str) -> list[dict]:
        raise NotImplementedError("fill in alongside the web agent (FR-2)")

    # ------------------------------------------------------------------
    # internal
    # ------------------------------------------------------------------

    def _guard(self, target: str) -> None:
        in_scope = self._is_in_scope(target)
        self._log_scope_check(target, in_scope)
        if not in_scope:
            raise ScopeViolation(f"{target!r} is not within the authorized scope")