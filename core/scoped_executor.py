"""
core/scoped_executor.py

The ONLY door agents use to touch the network. Scope enforcement, DNS checks,
redirect limits and rate limiting all live here, in one place — agents never
call nmap/requests/sockets directly, so safety can't be forgotten in one
agent and present in another.

Signatures only for now (Phase 0) — logic is filled in once this shape is
agreed. Tests for agents use a mock implementation of this same interface,
so agent development never has to wait on this being finished.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class ScopedExecutor(ABC):
    """Interface every real and mock executor must implement."""

    @abstractmethod
    def scan(self, target: str, allowed_ports: list[int] | None = None) -> dict:
        """
        Run a port/service scan against `target`, restricted to
        `allowed_ports` if given. Must check scope before sending any probe
        and log the check. Returns raw scan output (e.g. parsed nmap result)
        for the calling agent to interpret.
        """
        raise NotImplementedError

    @abstractmethod
    def http_get(self, url: str) -> dict:
        """
        Perform a single HTTP(S) GET against `url`. Must verify the resolved
        host is in scope (including after DNS resolution) and cap redirect
        following before leaving scope. Returns status, headers, and a
        (possibly truncated) body.
        """
        raise NotImplementedError

    @abstractmethod
    def crawl(self, base_url: str) -> list[dict]:
        """
        Crawl from `base_url`, discovering endpoints within the same scope.
        Every request made during the crawl goes through the same scope and
        rate-limit checks as http_get. Returns a list of page/endpoint
        records for the web agent to analyze.
        """
        raise NotImplementedError


class RealScopedExecutor(ScopedExecutor):
    """
    Production implementation — owned by core-platform. Wraps nmap/requests,
    enforces scope.manager.is_in_scope() before every probe (including after
    DNS resolution), and applies rate limits. Implemented after this
    interface is agreed in Phase 0.
    """

    def scan(self, target: str, allowed_ports: list[int] | None = None) -> dict:
        raise NotImplementedError("fill in after Phase 0 sign-off")

    def http_get(self, url: str) -> dict:
        raise NotImplementedError("fill in after Phase 0 sign-off")

    def crawl(self, base_url: str) -> list[dict]:
        raise NotImplementedError("fill in after Phase 0 sign-off")