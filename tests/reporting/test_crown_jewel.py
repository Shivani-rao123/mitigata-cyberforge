"""
tests/reporting/test_crown_jewel.py

Unit tests for reporting/crown_jewel.py (PRD Bonus B-2 -- chain
findings into a full path to a protected "crown jewel" host).
"""

from __future__ import annotations

from reporting.crown_jewel import identify_crown_jewel


def _finding(finding_type, status="confirmed", host_ip="10.10.10.5"):
    return {
        "finding_type": finding_type,
        "status": status,
        "host_ip": host_ip,
        "description": f"desc for {finding_type}",
    }


def test_no_exploitation_finding_means_no_crown_jewel():
    findings = [_finding("open_port"), _finding("missing_security_header")]
    assert identify_crown_jewel(findings) is None


def test_flagged_default_creds_found_does_not_count_as_a_crown_jewel():
    # Only a CONFIRMED default_creds_found is real proof of compromise --
    # a merely-flagged login guess is not a crown jewel.
    findings = [_finding("default_creds_found", status="flagged")]
    assert identify_crown_jewel(findings) is None


def test_confirmed_default_creds_found_is_a_crown_jewel():
    findings = [_finding("open_port"), _finding("default_creds_found", status="confirmed")]
    jewel = identify_crown_jewel(findings)
    assert jewel is not None
    assert jewel["finding_type"] == "default_creds_found"


def test_header_auth_confirmed_counts_without_needing_a_status_check():
    # header_auth_confirmed is only ever emitted once already-true (see
    # agents/basic_auth/agent.py) -- no separate confirmed-status gate.
    findings = [_finding("header_auth_confirmed", status="flagged")]
    jewel = identify_crown_jewel(findings)
    assert jewel is not None
    assert jewel["finding_type"] == "header_auth_confirmed"


def test_ctf_flag_found_outranks_header_auth_confirmed():
    findings = [
        _finding("header_auth_confirmed"),
        _finding("ctf_flag_found"),
    ]
    jewel = identify_crown_jewel(findings)
    assert jewel["finding_type"] == "ctf_flag_found"


def test_header_auth_confirmed_outranks_default_creds_found():
    findings = [
        _finding("default_creds_found", status="confirmed"),
        _finding("header_auth_confirmed"),
    ]
    jewel = identify_crown_jewel(findings)
    assert jewel["finding_type"] == "header_auth_confirmed"


def test_ranking_is_order_independent():
    # Same three findings, reverse input order -- ctf_flag_found still wins.
    findings = [
        _finding("default_creds_found", status="confirmed"),
        _finding("ctf_flag_found"),
        _finding("header_auth_confirmed"),
    ]
    assert identify_crown_jewel(findings)["finding_type"] == "ctf_flag_found"


def test_tie_within_same_finding_type_prefers_the_deepest_one_in_path_order():
    # Two confirmed default_creds_found on different hosts -- the LATER
    # one in path order wins (reached by chaining through more of the
    # path), not the first lucky guess.
    first = _finding("default_creds_found", status="confirmed", host_ip="10.10.10.5")
    second = _finding("default_creds_found", status="confirmed", host_ip="10.10.10.9")
    jewel = identify_crown_jewel([first, second])
    assert jewel is second
    assert jewel["host_ip"] == "10.10.10.9"
