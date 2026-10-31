"""
common/redact.py

One redaction rule, shared by every secret-finding path (the regex-based
check in agents/binary/agent.py and the gitleaks-backed one in
core/parsers/gitleaks.py) so a finding's evidence never carries a full
secret value regardless of which method found it.
"""

from __future__ import annotations


def redact(secret: str, keep: int = 4) -> str:
    """Show enough of `secret` to confirm the finding without putting the
    full value in evidence/reports. Degrades gracefully for short/empty
    input instead of producing a negative-length slice or a reveal."""
    if not secret:
        return ""
    if len(secret) <= keep * 2:
        return "*" * len(secret)
    return f"{secret[:keep]}{'*' * (len(secret) - keep * 2)}{secret[-keep:]}"
