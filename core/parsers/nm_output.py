"""
core/parsers/nm_output.py

Parses the raw output of `nm -D --undefined-only <binary>` — the dynamic
symbols a binary imports from shared libraries (libc, etc). Each line
looks like:

                 U strcpy@GLIBC_2.2.5
                 w __gmon_start__

We only care about the symbol name, with any @GLIBC_x.y.z version suffix
stripped off. Non-ELF files, statically-linked binaries, or a missing
binary produce empty/garbage output — this must not crash, just return
an empty list in that case (the agent treats "no functions found" as
"nothing to flag", not an error).
"""

from __future__ import annotations


def parse(raw_output: str) -> dict:
    functions: list[str] = []

    for line in raw_output.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if not parts:
            continue
        symbol = parts[-1]
        symbol = symbol.split("@")[0]  # strip @GLIBC_x.y.z version suffix
        if symbol:
            functions.append(symbol)

    return {"functions": functions}
