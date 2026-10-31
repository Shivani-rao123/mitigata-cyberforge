"""
tests/test_main.py

Unit tests for main.py's --ports plumbing (the "single biggest speed
lever for a slow CIDR-range scan" — restricting nmap's own default
~1000-port set down to just the ports a demo actually cares about).
"""

from __future__ import annotations

from main import _parse_ports


def test_parse_ports_returns_none_when_not_given():
    assert _parse_ports(None) is None
    assert _parse_ports("") is None


def test_parse_ports_splits_and_converts_to_ints():
    assert _parse_ports("22,80,443") == [22, 80, 443]


def test_parse_ports_tolerates_whitespace():
    assert _parse_ports(" 22 , 80,  443 ") == [22, 80, 443]
