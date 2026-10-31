"""
tests/core/test_tool_engine.py

Minimal unit tests for core/tool_engine.py. Most of its behavior is
already exercised indirectly through tests/core/test_scoped_executor*.py
(which monkeypatch subprocess.run through the real ToolEngine) — this
file covers the bits not already covered there, in particular
has_tool(), added for core/scoped_executor.py's subnet-vs-single-host
tool selection (see test_scoped_executor.py's
test_subnet_scan_uses_nmap_subnet_config_not_the_single_host_one).
"""

from core.tool_engine import ToolEngine, ToolNotConfigured


def test_has_tool_is_true_for_a_configured_tool():
    engine = ToolEngine()
    assert engine.has_tool("nmap") is True


def test_has_tool_is_true_for_the_nmap_subnet_variant():
    engine = ToolEngine()
    assert engine.has_tool("nmap_subnet") is True


def test_has_tool_is_false_for_an_unconfigured_name():
    engine = ToolEngine()
    assert engine.has_tool("totally_made_up_tool_name") is False


def test_has_tool_never_raises_unlike_run_or_parse():
    # The whole point of has_tool() is a check a caller can make BEFORE
    # deciding whether to use an optional tool variant, without having
    # to catch ToolNotConfigured itself.
    engine = ToolEngine()
    try:
        engine.run("totally_made_up_tool_name", target="x")
        assert False, "run() should have raised for an unconfigured tool"
    except ToolNotConfigured:
        pass
    # has_tool() on the same name must not raise at all.
    assert engine.has_tool("totally_made_up_tool_name") is False
