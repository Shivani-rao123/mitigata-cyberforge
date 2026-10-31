"""
tests/core/test_scoped_executor.py

Tests for RealScopedExecutor. nmap itself isn't run here — we test the two
things that can actually go wrong and are fully testable offline:
  1. the XML parser, against a realistic nmap output sample
  2. the scope guard, which must block before any probe and log every check
"""

import pytest

from core.scoped_executor import RealScopedExecutor, ScopeViolation

FIXTURE_PATH = "fixtures/sample_nmap_output.xml"


def _read_fixture() -> str:
    with open(FIXTURE_PATH) as f:
        return f.read()


def _always_in_scope(target: str) -> bool:
    return True


def _never_in_scope(target: str) -> bool:
    return False


class _RecordingLogger:
    def __init__(self) -> None:
        self.calls: list[tuple[str, bool]] = []

    def __call__(self, target: str, in_scope: bool) -> None:
        self.calls.append((target, in_scope))


# ---------------------------------------------------------------------------
# XML parsing
# ---------------------------------------------------------------------------

def test_parses_up_host_with_open_ports_and_service_versions():
    xml = _read_fixture()
    parsed = RealScopedExecutor._parse_nmap_xml(xml)

    assert len(parsed["hosts"]) == 1  # the "down" host must be excluded
    host = parsed["hosts"][0]
    assert host["ip"] == "10.10.10.5"
    assert host["hostname"] == "lab-web01.internal"


def test_only_open_ports_are_included_not_closed_or_filtered():
    xml = _read_fixture()
    parsed = RealScopedExecutor._parse_nmap_xml(xml)

    ports = {s["port"] for s in parsed["hosts"][0]["services"]}
    assert ports == {22, 80}  # 443 (closed) and 8080 (filtered) excluded


def test_service_name_and_version_are_captured():
    xml = _read_fixture()
    parsed = RealScopedExecutor._parse_nmap_xml(xml)

    services = {s["port"]: s for s in parsed["hosts"][0]["services"]}
    assert services[80]["service"] == "http"
    assert services[80]["version"] == "nginx 1.18.0"
    assert services[22]["service"] == "ssh"
    assert "OpenSSH" in services[22]["version"]


def test_down_host_is_excluded_entirely():
    xml = _read_fixture()
    parsed = RealScopedExecutor._parse_nmap_xml(xml)

    ips = {h["ip"] for h in parsed["hosts"]}
    assert "10.10.10.6" not in ips


def test_empty_xml_returns_no_hosts_without_crashing():
    parsed = RealScopedExecutor._parse_nmap_xml("")
    assert parsed == {"hosts": []}


# ---------------------------------------------------------------------------
# Scope guard — must block and log BEFORE any probe
# ---------------------------------------------------------------------------

def test_out_of_scope_target_is_refused_and_logged():
    logger = _RecordingLogger()
    executor = RealScopedExecutor(is_in_scope=_never_in_scope, log_scope_check=logger)

    with pytest.raises(ScopeViolation):
        executor.scan("8.8.8.8")  # deliberately NOT in our lab range

    assert logger.calls == [("8.8.8.8", False)]


def test_in_scope_target_passes_the_guard_and_is_logged():
    logger = _RecordingLogger()
    executor = RealScopedExecutor(is_in_scope=_always_in_scope, log_scope_check=logger)

    # nmap itself may not be installed in CI — we only assert the guard
    # passed (no ScopeViolation) and was logged; a real nmap run is a
    # separate, environment-dependent check.
    try:
        executor.scan("10.10.10.5")
    except RuntimeError as exc:
        assert "nmap is not installed" in str(exc)

    assert logger.calls == [("10.10.10.5", True)]