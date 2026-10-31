"""
tests/mock_tool_engine.py

A fake ToolEngine for binary-agent unit tests. Returns canned parsed
results instead of actually running `strings`/`nm`/`gitleaks`
subprocesses, so tests are fast and deterministic. The real integration
(does `strings`/`nm` actually work against a real binary) is verified
separately against fixtures/vulnerable_binary/vuln.c; gitleaks has no
such live-binary check in this repo (see core/parsers/gitleaks.py's
caveat note — no network access in the build sandbox to install it).
"""

from __future__ import annotations

from core.tool_engine import ToolNotInstalled


class MockToolEngine:
    def __init__(
        self,
        strings_result: list[str] | None = None,
        functions_result: list[str] | None = None,
        raise_on_nm: bool = False,
        gitleaks_result: list[dict] | None = None,
        gitleaks_unavailable: bool = True,
        raise_on_gitleaks: Exception | None = None,
    ) -> None:
        self._strings_result = strings_result or []
        self._functions_result = functions_result or []
        self._raise_on_nm = raise_on_nm
        self._gitleaks_result = gitleaks_result
        # Defaults to "not installed" so existing tests that never set up
        # gitleaks at all keep exercising the regex fallback path exactly
        # as before — pass gitleaks_result=[...] (or gitleaks_unavailable
        # =False) to opt a test into the gitleaks path instead.
        self._gitleaks_unavailable = gitleaks_unavailable and gitleaks_result is None
        self._raise_on_gitleaks = raise_on_gitleaks

    def run(self, tool_name: str, target: str, ports=None) -> str:
        # Content doesn't matter — parse() below ignores raw_output and
        # returns the canned result directly, keeping the fake simple.
        if tool_name == "nm" and self._raise_on_nm:
            raise RuntimeError("nm failed: not a dynamic executable")
        if tool_name == "gitleaks":
            if self._raise_on_gitleaks is not None:
                raise self._raise_on_gitleaks
            if self._gitleaks_unavailable:
                raise ToolNotInstalled("gitleaks is not installed on this machine")
        return ""

    def parse(self, tool_name: str, raw_output: str) -> dict | list[dict]:
        if tool_name == "strings":
            return {"strings": self._strings_result}
        if tool_name == "nm":
            return {"functions": self._functions_result}
        if tool_name == "gitleaks":
            return self._gitleaks_result if self._gitleaks_result is not None else []
        raise ValueError(f"MockToolEngine has no canned result for tool {tool_name!r}")
