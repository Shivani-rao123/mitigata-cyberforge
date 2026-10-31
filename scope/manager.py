"""
scope/manager.py

Loads the authorized scope from config/scope.yaml and answers "is this
target in scope?" for both CIDR ranges and single IPs. This is what
core/scoped_executor.py calls before every probe.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path

import yaml


class ScopeManager:
    def __init__(self, scope_file: str = "config/scope.yaml") -> None:
        with open(scope_file) as f:
            config = yaml.safe_load(f)

        self._networks = [ipaddress.ip_network(t, strict=False) for t in config.get("targets", [])]
        self.allowed_ports = config.get("allowed_ports")
        if self.allowed_ports is not None and (
            not isinstance(self.allowed_ports, list) or not self.allowed_ports or
            any(type(port) is not int or not 1 <= port <= 65535 for port in self.allowed_ports)
        ):
            raise ValueError("allowed_ports must be a nonempty list of ports from 1 to 65535")
        self._log_entries: list[tuple[str, bool]] = []

    def is_in_scope(self, target: str) -> bool:
        """
        Checks a single IP (or a hostname already resolved to an IP) against
        every authorized network. A CIDR range passed as `target` (e.g. the
        original scan target) is checked for being contained within, or
        equal to, an authorized network.
        """
        try:
            candidate = ipaddress.ip_network(target, strict=False)
        except ValueError:
            # not a valid IP/CIDR string (e.g. an unresolved hostname) —
            # treat as not-in-scope; callers resolve hostnames before this
            return False

        return any(
            candidate.version == network.version and candidate.subnet_of(network)
            for network in self._networks
        )

    def log_scope_check(self, target: str, in_scope: bool) -> None:
        self._log_entries.append((target, in_scope))
        status = "ALLOWED" if in_scope else "BLOCKED"
        print(f"[scope] {status}: {target}")

    @property
    def log_entries(self) -> list[tuple[str, bool]]:
        return list(self._log_entries)
