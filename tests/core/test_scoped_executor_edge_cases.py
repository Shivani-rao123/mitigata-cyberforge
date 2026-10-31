"""
tests/core/test_scoped_executor_edge_cases.py

Edge cases beyond the happy path already covered in test_scoped_executor.py.
"""

import socket
import subprocess

import pytest

from core.parsers.nmap import parse as parse_nmap_xml
from core.scoped_executor import RealScopedExecutor, ScopeViolation


def test_malformed_xml_raises_a_clear_error_not_silently_empty():
    import xml.etree.ElementTree as ET
    with pytest.raises(ET.ParseError):
        parse_nmap_xml("<nmaprun><host><unterminated")


def test_up_host_missing_address_element_is_skipped_not_crashed():
    xml = """<?xml version="1.0"?>
    <nmaprun>
      <host>
        <status state="up"/>
        <hostnames/>
        <ports/>
      </host>
    </nmaprun>"""
    parsed = parse_nmap_xml(xml)
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
    parsed = parse_nmap_xml(xml)
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
    parsed = parse_nmap_xml(xml)
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


def test_hostname_resolving_outside_scope_is_blocked_before_any_scan_happens(monkeypatch):
    """
    DNS-escape case: an attacker (or just stale DNS) has a hostname that's
    listed in scope resolve to an IP that isn't. core/scoped_executor.py's
    _resolve_scan_target() resolves a hostname to its IP BEFORE the scope
    guard runs — specifically so this is caught immediately: the guard
    checks the RESOLVED IP, not the hostname string, and nmap is never
    even invoked against an out-of-scope address. (An earlier version of
    this test expected nmap to run anyway and the result to be filtered
    afterward — that would mean actually touching an out-of-scope host
    first and only discarding the result after the fact, which is the
    weaker property; blocking before the scan ever happens is what the
    implementation actually does and is the stronger guarantee.)

    _revalidate_resolved_hosts() (covered elsewhere) remains as further
    defense-in-depth for whatever nmap itself reports back.
    """
    nmap_invocations = []
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: nmap_invocations.append((a, k)))
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/nmap")

    # Don't depend on real DNS (unavailable in CI/sandboxed environments).
    def fake_gethostbyname(host):
        if host == "lab.internal":
            return "8.8.8.8"
        raise socket.gaierror(f"unexpected lookup for {host!r} in this test")

    monkeypatch.setattr(socket, "gethostbyname", fake_gethostbyname)

    calls = []

    def is_in_scope(target):
        # the hostname itself is allowed, but 8.8.8.8 (what it resolves to) is not
        return target == "lab.internal"

    def log_scope_check(target, in_scope):
        calls.append((target, in_scope))

    executor = RealScopedExecutor(is_in_scope=is_in_scope, log_scope_check=log_scope_check)

    with pytest.raises(ScopeViolation):
        executor.scan("lab.internal")

    assert ("8.8.8.8", False) in calls, "the resolved IP must be scope-checked and logged"
    assert nmap_invocations == [], "nmap must never run against an out-of-scope resolved IP"