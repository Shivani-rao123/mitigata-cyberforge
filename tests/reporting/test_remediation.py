"""
tests/reporting/test_remediation.py

Unit tests for reporting/remediation.py (PRD Bonus B-3 — plain-English
fix suggestions per finding).
"""

from __future__ import annotations

import re
from pathlib import Path

from reporting.remediation import known_finding_types, remediation_for

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


def test_open_port_has_a_plain_english_fix():
    text = remediation_for("open_port")
    assert text is not None
    assert "firewall" in text.lower() or "close" in text.lower()


def test_hardcoded_secret_mentions_rotating_it():
    text = remediation_for("hardcoded_secret")
    assert text is not None
    assert "rotate" in text.lower()


def test_false_positive_has_no_remediation_regardless_of_type():
    assert remediation_for("default_creds_found", status="false_positive") is None
    assert remediation_for("hardcoded_secret", status="false_positive") is None


def test_operational_notes_have_no_remediation():
    assert remediation_for("redirect_followed") is None
    assert remediation_for("crawler_fallback") is None
    assert remediation_for("duplicate_binary_skipped") is None


def test_unrecognized_finding_type_has_no_remediation():
    assert remediation_for("some_future_finding_type_nobody_mapped_yet") is None


def test_default_creds_found_has_a_fix_regardless_of_status_except_false_positive():
    # Unlike PTES phase tagging, the FIX for "default creds" doesn't
    # depend on whether it's confirmed yet -- "change the password" is
    # the same advice either way.
    assert remediation_for("default_creds_found", status="flagged") is not None
    assert remediation_for("default_creds_found", status="confirmed") is not None


def test_ctf_flag_found_points_back_at_the_root_cause():
    text = remediation_for("ctf_flag_found")
    assert text is not None
    assert "root" in text.lower() or "underlying" in text.lower()


def test_every_finding_type_actually_emitted_by_an_agent_is_known():
    """Regression guard, same pattern as
    tests/reporting/test_ptes.py::test_every_finding_type_actually_emitted_by_an_agent_is_known:
    scans agents/*/agent.py's own source for every finding_type="..."
    literal and asserts reporting/remediation.py has an opinion about
    each one, so a newly-added finding_type doesn't silently ship with
    no fix advice."""
    emitted: set[str] = set()
    for agent_file in (PROJECT_ROOT / "agents").glob("*/agent.py"):
        text = agent_file.read_text()
        emitted.update(re.findall(r'finding_type\s*=\s*"([^"]+)"', text))

    assert emitted, "expected to find at least one finding_type= literal in agents/*/agent.py"
    unknown = emitted - known_finding_types()
    assert not unknown, (
        f"agents emit finding_type(s) {sorted(unknown)} that reporting/remediation.py doesn't "
        "know about yet -- add them to _REMEDIATION_BY_FINDING_TYPE or _OPERATIONAL_NOTE_TYPES"
    )
