"""
core/parsers/strings_output.py

Parses the raw output of the `strings` tool — one printable string per
line. Nothing fancy: just split into a list, drop empty lines.
"""

from __future__ import annotations


def parse(raw_output: str) -> dict:
    lines = [line for line in raw_output.splitlines() if line.strip()]
    return {"strings": lines}
