"""
core/tool_engine.py

Generic, config-driven tool runner. Knows nothing about nmap,
naabu, or any specific tool — it just reads config/tools.yaml, builds an
argv list safely (never a shell string), runs it with a timeout, and
returns the raw output text for a tool-specific parser to interpret.

In-process tools declare a `runner` entry point instead of a binary. Scope
callbacks are supplied by ScopedExecutor, never loaded from target data.

Adding a new tool = one entry in tools.yaml + one small parser function.
Nothing in this file or in ScopedExecutor needs to change.
"""

from __future__ import annotations

import importlib
import os
import re
import signal
import shutil
import subprocess
from pathlib import Path

import yaml


class ToolNotConfigured(Exception):
    """Raised when a requested tool has no entry in tools.yaml."""


class ToolNotInstalled(Exception):
    """Raised when a tool is configured but its binary isn't on this machine."""


class ToolExecutionError(RuntimeError):
    """External tool exited unsuccessfully; callers must not report success."""


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

    def run(self, tool_name: str, target: str, ports: list[int] | None = None, **context) -> str:
        """
        Run the named tool against `target`. Returns raw stdout for the
        caller (or engine.parse) to interpret. Raises ToolNotConfigured /
        ToolNotInstalled / subprocess.TimeoutExpired on failure — callers
        decide how to handle each.

        Does NOT check scope — that is ScopedExecutor's job, one layer up.
        This function trusts that scope has already been validated.
        """
        tool = self._get_tool_config(tool_name)

        if "runner" in tool:
            module_path, func_name = tool["runner"].split(":")
            runner = getattr(importlib.import_module(module_path), func_name)
            return runner(target=target, options=tool.get("options", {}), engine=self, **context)

        binary = shutil.which(tool["binary"])
        local = Path(__file__).resolve().parents[1] / ".tools" / tool["binary"] / (tool["binary"] + (".exe" if os.name == "nt" else ""))
        if (binary is None or tool.get("prefer_local")) and local.is_file():
            binary = str(local)
        if binary is None:
            raise ToolNotInstalled(
                f"'{tool['binary']}' is not installed on this machine. "
                f"Required for the '{tool_name}' tool."
            )

        cmd = [token.format(target=target, **context) for token in tool["command"]]
        # Preserve PATH-based argv for existing integrations, use absolute local fallback.
        if Path(binary).is_file():
            cmd[0] = binary
        if tool.get("required_version"):
            version = subprocess.run([cmd[0], "-version"], capture_output=True, text=True, timeout=10)
            if tool["required_version"] not in version.stdout + version.stderr:
                raise ToolExecutionError(f"{tool_name} requires {tool['required_version']}; install the pinned release")

        if ports and "ports_flag" in tool:
            ports_str = ",".join(str(p) for p in ports)
            ports_tokens = [token.format(ports=ports_str) for token in tool["ports_flag"]]
            # insert right after the binary name (index 1), before other flags
            cmd[1:1] = ports_tokens

        if tool.get("kill_process_tree"):
            result = self._run_process_tree(cmd, tool.get("timeout_seconds", 300))
        else:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=tool.get("timeout_seconds", 300),
            )
        if getattr(result, "returncode", 0):
            raise ToolExecutionError(f"{tool_name} exited with code {result.returncode}; check tool installation and configuration")
        if tool.get("failure_pattern") and re.search(tool["failure_pattern"], result.stdout + result.stderr):
            raise ToolExecutionError(f"{tool_name} reported an initialization or execution error")
        return result.stdout

    @staticmethod
    def _run_process_tree(cmd, timeout):
        """Terminate this invocation's subprocess descendants when its budget expires."""
        kwargs = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {"start_new_session": True}
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, encoding="utf-8", errors="replace", **kwargs)
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except (subprocess.TimeoutExpired, KeyboardInterrupt):
            if os.name == "nt":
                subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                               capture_output=True, timeout=10)
            else:
                os.killpg(process.pid, signal.SIGKILL)
            process.communicate(timeout=10)
            raise
        return subprocess.CompletedProcess(cmd, process.returncode, stdout, stderr)

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
