"""
tests/mock_tool_engine.py

A fake ToolEngine for binary-agent unit tests. Returns canned parsed
results instead of actually running `strings`/`nm` subprocesses, so tests
are fast and deterministic. The real integration (does `strings`/`nm`
actually work against a real binary) is verified separately against
fixtures/vulnerable_binary/vuln.c.
"""

from __future__ import annotations


class MockToolEngine:
    def __init__(
        self,
        strings_result: list[str] | None = None,
        functions_result: list[str] | None = None,
        raise_on_nm: bool = False,
    ) -> None:
        self._strings_result = strings_result or []
        self._functions_result = functions_result or []
        self._raise_on_nm = raise_on_nm

    def run(self, tool_name: str, target: str, ports=None) -> str:
        # Content doesn't matter — parse() below ignores raw_output and
        # returns the canned result directly, keeping the fake simple.
        if tool_name == "nm" and self._raise_on_nm:
            raise RuntimeError("nm failed: not a dynamic executable")
        return ""

    def parse(self, tool_name: str, raw_output: str) -> dict:
        if tool_name == "strings":
            return {"strings": self._strings_result}
        if tool_name == "nm":
            return {"functions": self._functions_result}
        raise ValueError(f"MockToolEngine has no canned result for tool {tool_name!r}")
