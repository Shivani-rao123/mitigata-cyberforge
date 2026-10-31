"""
common/flag_patterns.py

Detects CTF/lab-style planted flags (e.g. "FLAG{a1b2c3d4}") in crawled
text content. Deliberately separate from common/secret_patterns.py:
a flag isn't a security weakness to redact and warn about — it's the
engagement's own success marker, so unlike every other finding in this
project, a flag's evidence shows the FULL captured value, not a
redacted one (see common/redact.py's docstring — that module is for
credentials/keys, never applied here).

Covers the common naming conventions (flag{...}, CTF{...}, HTB{...},
THM{...}, case-insensitive) rather than one fixed format, since a lab's
exact convention isn't always known ahead of time. If your lab uses a
prefix not listed here, add it to _FLAG_PREFIXES — one line, no other
code needs to change.
"""

from __future__ import annotations

import re

# Prefixes real CTF/lab platforms commonly use before the "{...}" —
# kept as an explicit allowlist rather than a bare r"\w+\{...\}" match,
# which would also match ordinary code/config content that happens to
# have a bare word immediately followed by a brace (e.g. a minified
# CSS/JS rule). Case-insensitive at use time (see FLAG_PATTERNS below).
_FLAG_PREFIXES = ("flag", "ctf", "htb", "thm", "picoctf")

# name -> (compiled regex, human-readable description) — same shape as
# common/secret_patterns.py's SECRET_PATTERNS, so callers that already
# know how to walk that dict (agents/web/agent.py) can treat this one
# identically.
FLAG_PATTERNS: dict[str, tuple[re.Pattern, str]] = {
    "ctf_style_flag": (
        re.compile(r"(?i)\b(?:" + "|".join(_FLAG_PREFIXES) + r")\{[^\s{}]{3,200}\}"),
        "CTF-style planted flag",
    ),
}
