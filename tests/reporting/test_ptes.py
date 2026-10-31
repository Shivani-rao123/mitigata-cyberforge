"""
tests/reporting/test_ptes.py

Unit tests for reporting/ptes.py's PTES phase tagging (FR-5).
"""

from __future__ import annotations

import re
from pathlib import Path

from reporting.ptes import known_finding_types, ptes_phase_for

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


def test_open_port_is_intelligence_gathering():
    # Exact example from userflow.md's Step 6 table.
    assert ptes_phase_for("open_port") == "Intelligence Gathering"


def test_flagged_default_creds_found_is_vulnerability_analysis():
    assert ptes_phase_for("default_creds_found", status="flagged") == "Vulnerability Analysis"


def test_confirmed_default_creds_found_is_exploitation():
    # Exact example from userflow.md's Step 6 table.
    assert ptes_phase_for("default_creds_found", status="confirmed") == "Exploitation"


def test_false_positive_default_creds_found_has_no_phase():
    assert ptes_phase_for("default_creds_found", status="false_positive") is None


def test_ctf_flag_found_is_exploitation():
    # Capturing a planted flag IS the proof of compromise, same reasoning
    # as confirmed default_creds_found landing in Exploitation.
    assert ptes_phase_for("ctf_flag_found") == "Exploitation"


def test_operational_notes_have_no_phase():
    assert ptes_phase_for("redirect_followed") is None
    assert ptes_phase_for("crawler_fallback") is None


def test_unrecognized_finding_type_has_no_phase():
    assert ptes_phase_for("some_future_finding_type_nobody_mapped_yet") is None


def test_status_does_not_change_phase_for_types_without_an_override():
    # Only default_creds_found has a status-dependent phase right now —
    # everything else stays in its default phase regardless of status
    # (verification firms up confidence, it doesn't change what KIND of
    # step the finding represents).
    assert ptes_phase_for("missing_security_header", status="flagged") == "Vulnerability Analysis"
    assert ptes_phase_for("missing_security_header", status="confirmed") == "Vulnerability Analysis"


def test_every_finding_type_actually_emitted_by_an_agent_is_known():
    """Regression guard: scans agents/*/agent.py's own source for every
    finding_type="..." literal and asserts reporting/ptes.py has an
    opinion about each one (mapped to a real phase, or deliberately
    no-phase) — so a new finding_type added to an agent later doesn't
    silently fall through PTES tagging with no one noticing."""
    emitted: set[str] = set()
    for agent_file in (PROJECT_ROOT / "agents").glob("*/agent.py"):
        text = agent_file.read_text()
        emitted.update(re.findall(r'finding_type\s*=\s*"([^"]+)"', text))

    assert emitted, "expected to find at least one finding_type= literal in agents/*/agent.py"
    unknown = emitted - known_finding_types()
    assert not unknown, (
        f"agents emit finding_type(s) {sorted(unknown)} that reporting/ptes.py doesn't know "
        "about yet — add them to _PHASE_BY_FINDING_TYPE or _OPERATIONAL_NOTE_TYPES"
    )
