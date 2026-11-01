"""
reporting/ptes.py

FR-5: PTES phase tagging. A small, static lookup table mapping each
finding_type (every string any agent actually emits — see
agents/*/agent.py's finding_type= literals) to the PTES phase it belongs
to, matching userflow.md's Step 6 example exactly (open_port ->
Intelligence Gathering; confirmed default_creds_found -> Exploitation).

PTES ("Penetration Testing Execution Standard") phases used here:
Intelligence Gathering, Vulnerability Analysis, Exploitation. (Pre-
Engagement, Threat Modeling, Post Exploitation, and Reporting are real
PTES phases too, but nothing this project's agents currently emit maps
to them — Threat Modeling and Post Exploitation specifically would need
an agent that reasons about attacker goals or already-gained-access
follow-on actions, neither of which exists yet.)

This module only decides WHICH phase a finding belongs to. It doesn't
touch the DB (core/db.py's set_finding_ptes_phase does that) or decide
confirmed/false_positive (verification/verifier.py does that) — kept
separate so each piece can be tested and reasoned about on its own, the
same split FR-6/FR-5/FR-7 are described as in userflow.md's own steps.
"""

from __future__ import annotations

# Default phase for a finding_type, independent of status — most finding
# types don't change phase once verified; verification only firms up
# confidence (flagged -> confirmed/false_positive), it doesn't change
# what KIND of step in the kill chain the finding represents.
_PHASE_BY_FINDING_TYPE: dict[str, str] = {
    # Intelligence Gathering — mapping the attack surface: what's
    # reachable, not yet a claim that anything is wrong.
    "open_port": "Intelligence Gathering",
    "sensitive_endpoint_found": "Intelligence Gathering",
    "directory_listing_enabled": "Intelligence Gathering",
    "js_endpoint_found": "Intelligence Gathering",
    # Vulnerability Analysis — an actual weakness has been identified
    # (a secret sitting in reachable content, a missing header, unsafe
    # code, a login form that COULD have default creds, reflected input
    # that COULD be XSS) but nothing has been exploited yet.
    "missing_security_header": "Vulnerability Analysis",
    "hardcoded_secret": "Vulnerability Analysis",
    "secret_in_file_found": "Vulnerability Analysis",
    "js_secret_found": "Vulnerability Analysis",
    "unsafe_function_call": "Vulnerability Analysis",
    "reflected_input": "Vulnerability Analysis",
    "default_creds_found": "Vulnerability Analysis",  # see _STATUS_OVERRIDE below
    "credential_pair_found": "Vulnerability Analysis",  # a real username+password pair, but not
    # yet proven to grant access anywhere — stays here even once verification/verifier.py has
    # tried it elsewhere, since THIS finding (the binary where it was found) isn't itself what
    # gets exploited; see default_creds_found's own Exploitation promotion for where a
    # successful login actually lands.
    # Exploitation — capturing a planted flag IS the proof of a
    # successful compromise (same reason confirmed default_creds_found
    # lands here), not merely evidence a weakness exists.
    "ctf_flag_found": "Exploitation",
    # agents/basic_auth/agent.py only ever EMITS this finding_type once
    # a header-auth attempt already got past the original 401/403 (see
    # its own docstring) — unlike default_creds_found, there's no
    # earlier "merely a candidate" state for this one to start in, so
    # it goes straight to Exploitation unconditionally, no
    # _STATUS_OVERRIDE needed.
    "header_auth_confirmed": "Exploitation",
}

# finding_types that are purely operational commentary about how the
# scan itself behaved (a redirect was followed, a preferred tool fell
# back to a narrower one) rather than a fact about the target's attack
# surface — not part of the PTES attack narrative at all, so these get
# no phase (None), same as webui/app.py's own OPERATIONAL_NOTE_TYPES
# split for the dashboard. Kept as a separate set here (not just "not in
# _PHASE_BY_FINDING_TYPE") so a genuinely new/unmapped finding_type is
# still visibly missing — see ptes_phase_for()'s fallback.
_OPERATIONAL_NOTE_TYPES = {"redirect_followed", "crawler_fallback", "duplicate_binary_skipped"}

# Specific (finding_type, status) combinations that move to a LATER
# phase once verification actually confirms them — the only one in this
# project right now is default_creds_found: a flagged login form is
# just a candidate (Vulnerability Analysis); a CONFIRMED one means
# verification/verifier.py actually logged in, which is a real foothold
# (Exploitation). This is exactly userflow.md's Step 5 -> Step 6 example.
_STATUS_OVERRIDE: dict[tuple[str, str], str] = {
    ("default_creds_found", "confirmed"): "Exploitation",
}

# A false_positive finding, whatever its type, isn't part of a real
# attack path — it's a claim verification actively disproved. Tagging
# it with no phase keeps the report generator from listing it as a step
# in an attack chain that never actually happened.
_FALSE_POSITIVE_HAS_NO_PHASE = True


def ptes_phase_for(finding_type: str, status: str = "flagged") -> str | None:
    """The PTES phase for one finding, given its type and verification
    status. Returns None for operational notes, an unrecognized
    finding_type, or a false_positive finding — "no phase" is a
    meaningful answer here, not a bug, so callers (report_generator.py)
    should skip findings this returns None for rather than treating it
    as a formatting gap."""
    if _FALSE_POSITIVE_HAS_NO_PHASE and status == "false_positive":
        return None
    if finding_type in _OPERATIONAL_NOTE_TYPES:
        return None

    override = _STATUS_OVERRIDE.get((finding_type, status))
    if override is not None:
        return override

    return _PHASE_BY_FINDING_TYPE.get(finding_type)


def known_finding_types() -> frozenset[str]:
    """Every finding_type this module has an opinion about (mapped or
    deliberately no-phase) — used by tests to catch a newly-added
    finding_type in an agent that nobody taught this module about yet."""
    return frozenset(_PHASE_BY_FINDING_TYPE) | frozenset(_OPERATIONAL_NOTE_TYPES)
