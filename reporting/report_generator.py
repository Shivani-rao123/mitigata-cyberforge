"""
reporting/report_generator.py

FR-7 (report half): builds the "Attack Path" narrative out of a
target's verified, PTES-tagged findings, matching userflow.md's Step 7
format:

    Attack Path:
    1. [Intelligence Gathering] Port 80/tcp open on 10.10.10.5
    2. [Exploitation] Default credentials (admin/admin) confirmed on
       /admin, granting dashboard access

    Crown Jewel:
    10.10.10.5 -- confirmed compromised at step 2 above (default_creds_found)

    Remediation Recommendations:
    - default_creds_found: Change this account's password immediately...

Also appends two more sections after the Attack Path listing:
  - "Crown Jewel" (PRD Bonus B-2) -- names the single protected host/
    endpoint the chain above actually broke into, via
    reporting/crown_jewel.py. The ordered attack path IS the chain (a
    PTES-phase-ordered walk from discovery through to compromise); this
    section just calls out which step at the end of it is the prize.
  - "Remediation Recommendations" (PRD Bonus B-3) -- one plain-English
    fix per distinct finding_type that appears in the path, via
    reporting/remediation.py.

Split into two layers on purpose:
  - format_attack_path(findings) is pure data-in/string-out — no DB,
    easy to test with plain dicts.
  - build_attack_path(db, target_id) is the thin DB-touching wrapper
    that pulls a target's findings (core/db.py's own CIDR-containment
    resolution already does the "which findings belong to this
    target" work) and resolves each finding's host IP before handing
    off to format_attack_path.

A finding with no ptes_phase (an operational note like
redirect_followed/crawler_fallback, a false_positive, or a finding_type
reporting/ptes.py doesn't know about yet) is NOT part of the attack
path at all — see reporting/ptes.py's own docstring for why "no phase"
is a deliberate, meaningful answer rather than a gap to paper over.
"""

from __future__ import annotations

import re

from reporting.crown_jewel import identify_crown_jewel
from reporting.remediation import remediation_for

# Real PTES phase order (Pre-Engagement and Post Exploitation are part
# of the standard but nothing this project emits maps to them yet — see
# reporting/ptes.py's docstring — kept here anyway so the ordering is
# correct if/when something does).
_PHASE_ORDER: dict[str, int] = {
    "Pre-Engagement": 0,
    "Intelligence Gathering": 1,
    "Threat Modeling": 2,
    "Vulnerability Analysis": 3,
    "Exploitation": 4,
    "Post Exploitation": 5,
    "Reporting": 6,
}

# Parses verification/verifier.py's own evidence_summary format for a
# confirmed default_creds_found finding:
#   f"POST {action_url} with {username}:{password} -> {status}"
_CONFIRMED_CREDS_RE = re.compile(r"with (\S+:\S+) ->")


def _describe(finding: dict) -> str:
    """One finding's attack-path line text (without the leading
    "N. [phase] " prefix — format_attack_path adds that). Falls back to
    the finding's own `description` for any finding_type that doesn't
    have a more narrative-friendly format below."""
    finding_type = finding.get("finding_type")
    host_ip = finding.get("host_ip")

    if finding_type == "open_port":
        base = finding.get("description") or "Port open"
        return f"{base} on {host_ip}" if host_ip else base

    if finding_type == "default_creds_found" and finding.get("status") == "confirmed":
        creds_match = _CONFIRMED_CREDS_RE.search(finding.get("evidence_summary") or "")
        creds = f" ({creds_match.group(1)})" if creds_match else ""
        if host_ip:
            return f"Default credentials{creds} confirmed on {host_ip}, granting access"
        return f"Default credentials{creds} confirmed, granting access"

    return finding.get("description") or f"{finding_type} finding"


def format_attack_path(findings: list[dict]) -> str:
    """
    `findings` is a list of dicts, each at least shaped like a
    core/db.py findings row (finding_type, description, evidence_summary,
    status, ptes_phase) plus an optional `host_ip` key the caller
    resolved separately (core/db.py's findings rows only carry host_id,
    not the host's IP). Findings with no ptes_phase are skipped. Order
    is PTES phase order, then by `id` (insertion order) within a phase,
    so the narrative reads as a plausible kill chain rather than
    whatever order the DB happened to return rows in.
    """
    in_path = [f for f in findings if f.get("ptes_phase")]
    ordered = sorted(
        in_path,
        key=lambda f: (_PHASE_ORDER.get(f["ptes_phase"], len(_PHASE_ORDER)), f.get("id") or 0),
    )

    lines = ["Attack Path:"]
    if not ordered:
        lines.append("(no verified findings yet)")
        return "\n".join(lines)

    for i, finding in enumerate(ordered, start=1):
        lines.append(f"{i}. [{finding['ptes_phase']}] {_describe(finding)}")

    lines.append("")
    lines.extend(_format_crown_jewel_section(ordered))
    lines.append("")
    lines.extend(_format_remediation_section(ordered))
    return "\n".join(lines)


def _format_crown_jewel_section(ordered_findings: list[dict]) -> list[str]:
    """PRD Bonus B-2 -- names the protected host/endpoint the attack
    path above actually broke into, via reporting/crown_jewel.py.
    `ordered_findings` is the SAME PTES-phase-ordered list
    format_attack_path already built, so "step N above" below refers
    to that exact numbering."""
    jewel = identify_crown_jewel(ordered_findings)
    lines = ["Crown Jewel:"]
    if jewel is None:
        lines.append("(no protected host was confirmed compromised this run)")
        return lines

    # Identity, not value, lookup -- two findings can be value-equal
    # dicts (same type/description/etc. on different hosts) and we
    # want THIS exact finding's position, not the first value match.
    step_number = next(i for i, f in enumerate(ordered_findings, start=1) if f is jewel)
    host = jewel.get("host_ip") or "an unresolved host"
    lines.append(f"{host} -- confirmed compromised at step {step_number} above ({jewel['finding_type']})")
    return lines


def _format_remediation_section(ordered_findings: list[dict]) -> list[str]:
    """PRD Bonus B-3 -- plain-English fix per finding, appended after
    the Attack Path listing. Walks the SAME `ordered` findings
    format_attack_path already built (so it's automatically restricted
    to the attack path's own in-scope findings: no false_positive, no
    operational notes, no unknown finding_type), deduped by
    finding_type since the same weakness class often shows up on
    several hosts/endpoints and the fix is identical each time."""
    seen_finding_types: set[str] = set()
    lines = ["Remediation Recommendations:"]
    had_any = False
    for finding in ordered_findings:
        finding_type = finding.get("finding_type")
        if finding_type in seen_finding_types:
            continue
        fix = remediation_for(finding_type, status=finding.get("status", "flagged"))
        if fix is None:
            continue
        seen_finding_types.add(finding_type)
        had_any = True
        lines.append(f"- {finding_type}: {fix}")
    if not had_any:
        lines.append("(nothing to remediate)")
    return lines


def build_attack_path(db, target_id: int) -> str:
    """Thin DB-touching wrapper around format_attack_path — see module
    docstring. `db` is a core/db.py Database instance."""
    findings = db.get_findings_for_target(target_id)

    enriched: list[dict] = []
    for finding in findings:
        host = db.get_host(finding["host_id"]) if finding.get("host_id") is not None else None
        enriched.append({**finding, "host_ip": host["ip"] if host else None})

    return format_attack_path(enriched)
