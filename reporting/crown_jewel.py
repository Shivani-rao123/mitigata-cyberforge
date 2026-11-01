"""
reporting/crown_jewel.py

PRD Bonus B-2: "Chain findings into a full path to a protected 'crown
jewel' host."

The Attack Path report (reporting/report_generator.py) already lists
every verified finding in PTES-phase order -- that ordered list IS the
chain: discovery findings first, then the credentials/weaknesses that
got used, ending with whatever got actually compromised. What's missing
is calling out, explicitly, WHICH host at the end of that chain is the
"crown jewel" -- the protected host/endpoint the whole path was for.

identify_crown_jewel() answers that by picking the single strongest
piece of proof-of-compromise in the ordered findings: a captured flag
beats a confirmed header-auth bypass beats a confirmed default-creds
login, because that's the real strength of the evidence (a flag is
ground truth; a header-auth or default-creds confirmation is "we
proved access," which is also real, just one notch below a flag).
Ties within the same finding_type are broken by picking the LAST one
in path order -- i.e. the one reached by chaining through everything
before it, not the first lucky guess.

A finding with no confirmed compromise anywhere in the run (nothing in
_EXPLOITATION_FINDING_TYPES, or present but not status="confirmed")
means there's no crown jewel yet -- returns None. That's a real,
reportable answer ("we mapped the surface but didn't break into
anything protected this run"), not a bug to hide.
"""

from __future__ import annotations

# Confirmed-compromise finding types, in strength order (strongest
# first) -- same three finding types reporting/ptes.py tags as
# "Exploitation", used here to rank which one is the real crown jewel
# when a run has more than one.
_EXPLOITATION_FINDING_TYPES_BY_STRENGTH: tuple[str, ...] = (
    "ctf_flag_found",  # ground truth: the lab's own planted success marker
    "header_auth_confirmed",  # proved access via a real Authorization header
    "default_creds_found",  # proved access via a real login (only once status="confirmed")
)


def identify_crown_jewel(ordered_findings: list[dict]) -> dict | None:
    """`ordered_findings` is the SAME list reporting/report_generator.py's
    format_attack_path() already built (PTES-phase order, `id` tiebreak
    within a phase) -- so "last in path order" here means "reached by
    chaining through everything listed before it," not just "found
    last by whatever order the DB returned."

    Returns the single finding dict that represents the strongest
    confirmed compromise in the run, or None if nothing in
    `ordered_findings` is a confirmed compromise at all.
    """
    best: dict | None = None
    best_rank: int | None = None

    for finding in ordered_findings:
        finding_type = finding.get("finding_type")
        if finding_type not in _EXPLOITATION_FINDING_TYPES_BY_STRENGTH:
            continue
        # default_creds_found only counts once verification has actually
        # confirmed it -- a merely-flagged login guess is not a crown
        # jewel. ctf_flag_found and header_auth_confirmed are only ever
        # emitted once already-true (see their agents' own docstrings),
        # so there's no equivalent gate needed for those two.
        if finding_type == "default_creds_found" and finding.get("status") != "confirmed":
            continue

        rank = _EXPLOITATION_FINDING_TYPES_BY_STRENGTH.index(finding_type)
        # Strictly stronger wins outright. A tie in strength prefers the
        # LATER finding (reached deeper into the chain) -- since we walk
        # `ordered_findings` in path order, that just means "replace
        # whenever rank <= best_rank", not "<".
        if best_rank is None or rank <= best_rank:
            best = finding
            best_rank = rank

    return best
