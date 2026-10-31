"""
tests/core/test_tool_engine.py

Tests for the generic, config-driven ToolEngine — independent of any
specific tool (nmap or otherwise).
"""

import subprocess

import pytest

from core.tool_engine import ToolEngine, ToolNotConfigured, ToolNotInstalled


def test_unconfigured_tool_raises_clear_error():
    engine = ToolEngine("config/tools.yaml")
    with pytest.raises(ToolNotConfigured, match="nonexistent-tool"):
        engine.run("nonexistent-tool", target="10.10.10.5")


def test_missing_binary_raises_clear_error(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: None)
    engine = ToolEngine("config/tools.yaml")
    with pytest.raises(ToolNotInstalled, match="nmap"):
        engine.run("nmap", target="10.10.10.5")


def test_builds_correct_command_with_target_substituted(monkeypatch):
    captured_cmd = {}

    def fake_run(cmd, **kwargs):
        captured_cmd["cmd"] = cmd
        class Result:
            stdout = ""
        return Result()

    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/nmap")
    monkeypatch.setattr(subprocess, "run", fake_run)

    engine = ToolEngine("config/tools.yaml")
    engine.run("nmap", target="10.10.10.5")

    assert "10.10.10.5" in captured_cmd["cmd"]
    assert captured_cmd["cmd"][0] == "nmap"


def test_ports_are_inserted_into_the_command_when_given(monkeypatch):
    captured_cmd = {}

    def fake_run(cmd, **kwargs):
        captured_cmd["cmd"] = cmd
        class Result:
            stdout = ""
        return Result()

    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/nmap")
    monkeypatch.setattr(subprocess, "run", fake_run)

    engine = ToolEngine("config/tools.yaml")
    engine.run("nmap", target="10.10.10.5", ports=[80, 443, 8080])

    cmd = captured_cmd["cmd"]
    assert "-p" in cmd
    assert "80,443,8080" in cmd


def test_no_ports_means_no_ports_flag_in_command(monkeypatch):
    captured_cmd = {}

    def fake_run(cmd, **kwargs):
        captured_cmd["cmd"] = cmd
        class Result:
            stdout = ""
        return Result()

    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/nmap")
    monkeypatch.setattr(subprocess, "run", fake_run)

    engine = ToolEngine("config/tools.yaml")
    engine.run("nmap", target="10.10.10.5")

    assert "-p" not in captured_cmd["cmd"]


def test_timeout_propagates_clearly(monkeypatch):
    def fake_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd="nmap", timeout=300)

    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/nmap")
    monkeypatch.setattr(subprocess, "run", fake_run)

    engine = ToolEngine("config/tools.yaml")
    with pytest.raises(subprocess.TimeoutExpired):
        engine.run("nmap", target="10.10.10.5")


def test_parse_dispatches_to_the_configured_parser_module():
    engine = ToolEngine("config/tools.yaml")
    with open("fixtures/sample_nmap_output.xml") as f:
        xml = f.read()

    result = engine.parse("nmap", xml)
    assert "hosts" in result
    assert len(result["hosts"]) == 1  # matches the fixture's one 'up' host