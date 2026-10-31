"""
tests/core/test_scoped_executor_edge_cases.py

Edge cases beyond the happy path already covered in test_scoped_executor.py.
"""

import subprocess

import pytest

from core.scoped_executor import RealScopedExecutor, ScopeViolation


def test_malformed_xml_raises_a_clear_error_not_silently_empty():
    import xml.etree.ElementTree as ET
    with pytest.raises(ET.ParseError):
        RealScopedExecutor._parse_nmap_xml("<nmaprun><host><unterminated")


def test_up_host_missing_address_element_is_skipped_not_crashed():
    xml = """<?xml version="1.0"?>
    <nmaprun>
      <host>
        <status state="up"/>
        <hostnames/>
        <ports/>
      </host>
    </nmaprun>"""
    parsed = RealScopedExecutor._parse_nmap_xml(xml)
    assert parsed["hosts"] == []


def test_open_port_missing_service_element_defaults_to_unknown():
    xml = """<?xml version="1.0"?>
    <nmaprun>
      <host>
        <status state="up"/>
        <address addr="10.10.10.30" addrtype="ipv4"/>
        <hostnames/>
        <ports>
          <port protocol="tcp" portid="31337">
            <state state="open"/>
          </port>
        </ports>
      </host>
    </nmaprun>"""
    parsed = RealScopedExecutor._parse_nmap_xml(xml)
    service = parsed["hosts"][0]["services"][0]
    assert service["service"] == "unknown"
    assert service["version"] is None


def test_udp_protocol_is_captured_correctly():
    xml = """<?xml version="1.0"?>
    <nmaprun>
      <host>
        <status state="up"/>
        <address addr="10.10.10.31" addrtype="ipv4"/>
        <hostnames/>
        <ports>
          <port protocol="udp" portid="53">
            <state state="open"/>
            <service name="domain"/>
          </port>
        </ports>
      </host>
    </nmaprun>"""
    parsed = RealScopedExecutor._parse_nmap_xml(xml)
    service = parsed["hosts"][0]["services"][0]
    assert service["protocol"] == "udp"
    assert service["service"] == "domain"


def test_is_in_scope_callback_raising_propagates_not_swallowed():
    def boom(target):
        raise RuntimeError("scope DB unreachable")

    executor = RealScopedExecutor(is_in_scope=boom, log_scope_check=lambda t, s: None)
    with pytest.raises(RuntimeError, match="scope DB unreachable"):
        executor.scan("10.10.10.5")


def test_nmap_timeout_raises_a_clear_error(monkeypatch):
    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="nmap", timeout=300)

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/nmap")

    executor = RealScopedExecutor(is_in_scope=lambda t: True, log_scope_check=lambda t, s: None)
    with pytest.raises(subprocess.TimeoutExpired):
        executor.scan("10.10.10.5")


def test_resolved_ip_outside_scope_is_filtered_out_even_if_hostname_was_in_scope(monkeypatch):
    """
    DNS-escape case: the target string (a hostname) passes the scope check,
    but nmap resolves it to an IP outside the allowlist. The executor must
    re-validate every resolved host before returning results — this is the
    defense-in-depth requirement from the PRD correction.
    """
    xml_with_out_of_scope_ip = """<?xml version="1.0"?>
    <nmaprun>
      <host>
        <status state="up"/>
        <address addr="8.8.8.8" addrtype="ipv4"/>
        <hostnames/>
        <ports>
          <port protocol="tcp" portid="80">
            <state state="open"/>
            <service name="http"/>
          </port>
        </ports>
      </host>
    </nmaprun>"""

    class FakeCompletedProcess:
        stdout = xml_with_out_of_scope_ip

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: FakeCompletedProcess())
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/nmap")

    calls = []

    def is_in_scope(target):
        # the hostname itself is allowed, but 8.8.8.8 (what it resolves to) is not
        result = target == "lab.internal"
        return result

    def log_scope_check(target, in_scope):
        calls.append((target, in_scope))

    executor = RealScopedExecutor(is_in_scope=is_in_scope, log_scope_check=log_scope_check)
    result = executor.scan("lab.internal")

    assert result["hosts"] == [], "a host resolving outside scope must be filtered out"
    assert ("8.8.8.8", False) in calls, "the resolved IP must be scope-checked and logged too"