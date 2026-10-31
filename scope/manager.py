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
    def __init__(
        self,
        scope_file: str = "config/scope.yaml",
        cidrs: list[str] | None = None,
    ) -> None:
        """
        Scope can come from one of two places:
          - `cidrs`: an explicit list of CIDR/IP strings for THIS run
            (e.g. passed via --scope on the CLI, or a job's scope field
            from the API later). Takes priority when given.
          - `scope_file`: a YAML file with a `targets:` list, used as the
            fallback default (handy for repeated local testing).

        Scope is meant to be per-engagement, not a permanent setting baked
        into a config file — `cidrs` is the primary path; `scope_file` only
        exists so you don't have to pass --scope on every single run.
        """
        if cidrs is not None:
            targets = cidrs
        else:
            with open(scope_file) as f:
                config = yaml.safe_load(f)
            targets = config.get("targets", [])

        self._networks = [ipaddress.ip_network(t, strict=False) for t in targets]
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
            candidate.subnet_of(network) or candidate == network
            for network in self._networks
        )

    def log_scope_check(self, target: str, in_scope: bool) -> None:
        self._log_entries.append((target, in_scope))
        status = "ALLOWED" if in_scope else "BLOCKED"
        print(f"[scope] {status}: {target}")

    @property
    def log_entries(self) -> list[tuple[str, bool]]:
        return list(self._log_entries)

    @property
    def authorized_networks(self) -> list[str]:
        """The CIDR ranges currently in effect, as strings — for display
        (e.g. the web dashboard showing what scope a run used)."""
        return [str(network) for network in self._networks]