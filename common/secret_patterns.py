"""
common/secret_patterns.py

The hand-written regex fallback for hardcoded-secret detection, shared by:
  - agents/binary/agent.py — scans `strings` output from a local/downloaded
    binary when gitleaks isn't installed.
  - core/parsers/katana.py — scans JS response bodies pulled from a crawl
    for secrets, since katana itself has no secret-extraction step.

Narrower than gitleaks's hundreds of vetted rules + entropy detection —
kept intentionally small and easy to read, as the always-available
fallback for environments where gitleaks isn't installed.
"""

from __future__ import annotations

import re

# name -> (compiled regex, human-readable description)
SECRET_PATTERNS: dict[str, tuple[re.Pattern, str]] = {
    "aws_access_key_id": (
        re.compile(r"AKIA[0-9A-Z]{16}"),
        "AWS Access Key ID",
    ),
    "private_key_header": (
        re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        "Private key material",
    ),
    "slack_token": (
        re.compile(r"xox[baprs]-[0-9a-zA-Z-]{10,48}"),
        "Slack token",
    ),
    "stripe_secret_key": (
        re.compile(r"sk_live_[0-9a-zA-Z]{20,}"),
        "Stripe live secret key",
    ),
    "generic_secret_assignment": (
        re.compile(
            r"(?i)(api[_-]?key|secret|token|password)['\"]?\s*[:=]\s*['\"][A-Za-z0-9_\-/+]{8,}['\"]"
        ),
        "Hardcoded secret-like assignment",
    ),
}
