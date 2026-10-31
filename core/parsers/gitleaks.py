"""
core/parsers/gitleaks.py

Parses gitleaks's JSON report output (`gitleaks detect --no-git
--report-format json --report-path -`) into a normalized list of secret
findings. Gitleaks's report schema has been stable across versions: a
JSON array, each element describing one leak with (at least) `RuleID`,
`Description`, `Secret` (or `Match`), `File`, and `StartLine`.

Malformed/unparseable output raises ValueError — same philosophy as
core/parsers/nmap.py's XML parsing: a tool that's supposed to have
succeeded but produced garbage is a real error to surface, not something
to silently treat as "zero findings" (which would look identical to a
genuinely clean scan).

A clean scan with nothing found is a valid, syntactically-correct empty
JSON array (`[]`) — that path returns `[]`, not an error.
"""

from __future__ import annotations

import json


def parse(raw_output: str) -> list[dict]:
    """Returns a list of
    {"rule": str, "description": str, "secret": str, "file": str,
     "line": int | None}.
    Raises ValueError if `raw_output` isn't valid JSON, or isn't a JSON
    array/object in the shape gitleaks actually produces.
    """
    stripped = raw_output.strip()
    if not stripped:
        # gitleaks with nothing to report on an empty/trivial target can
        # legitimately produce empty stdout (as opposed to "[]") — treat
        # the same as a clean scan, not an error.
        return []

    try:
        parsed = json.loads(stripped)
    except (json.JSONDecodeError, ValueError) as exc:
        raise ValueError(
            f"gitleaks output isn't valid JSON — can't tell a real scan "
            f"failure from zero findings: {exc}"
        ) from exc

    if isinstance(parsed, dict):
        # gitleaks emits a bare object instead of an array in a couple of
        # known cases: no leaks found (some versions print nothing at all,
        # others an empty structure) or a leak count summary. Neither
        # carries individual findings, so treat it as "no findings" rather
        # than guessing at an undocumented shape.
        return []

    if not isinstance(parsed, list):
        raise ValueError(
            f"gitleaks output parsed as JSON but wasn't a list of findings "
            f"(got {type(parsed).__name__})"
        )

    findings: list[dict] = []
    for i, entry in enumerate(parsed):
        if not isinstance(entry, dict):
            raise ValueError(f"gitleaks finding #{i} wasn't a JSON object (got {entry!r})")
        findings.append(_normalize(entry))
    return findings


def _normalize(entry: dict) -> dict:
    secret = entry.get("Secret") or entry.get("Match") or ""
    line = entry.get("StartLine")
    try:
        line = int(line) if line is not None else None
    except (TypeError, ValueError):
        line = None

    return {
        "rule": str(entry.get("RuleID") or "unknown_rule"),
        "description": str(entry.get("Description") or "Secret detected by gitleaks"),
        "secret": str(secret),
        "file": str(entry.get("File") or ""),
        "line": line,
    }
