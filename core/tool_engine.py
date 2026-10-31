"""
core/tool_engine.py

Generic, config-driven external-tool runner. Knows nothing about nmap,
naabu, or any specific tool — it just reads config/tools.yaml, builds an
argv list safely (never a shell string), runs it with a timeout, and
returns the raw output text for a tool-specific parser to interpret.

Adding a new tool = one entry in tools.yaml + one small parser function.
Nothing in this file or in ScopedExecutor needs to change.
"""

from __future__ import annotations

import importlib
import shutil
import subprocess
from pathlib import Path

import yaml


class ToolNotConfigured(Exception):
    """Raised when a requested tool has no entry in tools.yaml."""


class ToolNotInstalled(Exception):
    """Raised when a tool is configured but its binary isn't on this machine."""


class ToolEngine:
    """
    Usage:
        engine = ToolEngine("config/tools.yaml")
        raw_output = engine.run("nmap", target="10.10.10.5", ports=[80, 443])
        hosts = engine.parse("nmap", raw_output)
    """

    def __init__(self, config_path: str = "config/tools.yaml") -> None:
        with open(config_path) as f:
            self._config = yaml.safe_load(f)["tools"]

    def run(self, tool_name: str, target: str, ports: list[int] | None = None) -> str:
        """
        Run the named tool against `target`. Returns raw stdout for the
        caller (or engine.parse) to interpret. Raises ToolNotConfigured /
        ToolNotInstalled / subprocess.TimeoutExpired on failure — callers
        decide how to handle each.

        Does NOT check scope — that is ScopedExecutor's job, one layer up.
        This function trusts that scope has already been validated.
        """
        tool = self._get_tool_config(tool_name)

        if shutil.which(tool["binary"]) is None:
            raise ToolNotInstalled(
                f"'{tool['binary']}' is not installed on this machine. "
                f"Required for the '{tool_name}' tool."
            )

        cmd = [token.format(target=target) for token in tool["command"]]

        if ports and "ports_flag" in tool:
            ports_str = ",".join(str(p) for p in ports)
            ports_tokens = [token.format(ports=ports_str) for token in tool["ports_flag"]]
            # insert right after the binary name (index 1), before other flags
            cmd[1:1] = ports_tokens

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=tool.get("timeout_seconds", 300),
        )
        return result.stdout

    def has_tool(self, tool_name: str) -> bool:
        """Whether `tool_name` has an entry in tools.yaml — lets a caller
        check for an optional variant (e.g. a "{tool}_subnet" config)
        before using it, without triggering ToolNotConfigured itself."""
        return tool_name in self._config

    def parse(self, tool_name: str, raw_output: str):
        """Look up and call the configured parser for this tool's output."""
        tool = self._get_tool_config(tool_name)
        module_path, func_name = tool["parser"].split(":")
        module = importlib.import_module(module_path)
        parser_func = getattr(module, func_name)
        return parser_func(raw_output)

    def _get_tool_config(self, tool_name: str) -> dict:
        if tool_name not in self._config:
            raise ToolNotConfigured(
                f"No tool named '{tool_name}' in tools.yaml. "
                f"Configured tools: {list(self._config.keys())}"
            )
        return self._config[tool_name]