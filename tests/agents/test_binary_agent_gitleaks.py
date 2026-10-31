"""
tests/agents/test_binary_agent_gitleaks.py

Integration tests for agents/binary/agent.py's secret check: exercises
the real run() -> _check_secrets() -> engine.run/parse("gitleaks", ...)
chain through MockToolEngine, proving the gitleaks-preferred /
regex-fallback wiring actually works end to end, not just that each
piece works in isolation.
"""

import os
import tempfile
from pathlib import Path

import pytest

from agents.binary.agent import run
from common.contracts import Job
from core.tool_engine import ToolNotConfigured, ToolNotInstalled
from tests.mock_tool_engine import MockToolEngine


@pytest.fixture
def temp_file():
    fd, path = tempfile.mkstemp()
    os.close(fd)
    yield path
    os.remove(path)


def _job(target):
    return Job(job_id="bin-gitleaks-job", agent="binary", target=target)


def test_gitleaks_result_produces_hardcoded_secret_finding(temp_file):
    engine = MockToolEngine(
        gitleaks_result=[
            {
                "rule": "aws-access-token",
                "description": "AWS Access Key",
                "secret": "AKIAABCDEFGHIJKLMNOP",
                "file": "firmware.bin",
                "line": None,
            }
        ],
    )
    result = run(_job(temp_file), engine)

    secrets = [f for f in result.findings if f.finding_type == "hardcoded_secret"]
    assert len(secrets) == 1
    assert secrets[0].evidence.kind == "gitleaks_match"
    assert "AWS Access Key" in secrets[0].description
    # redacted — the full secret never appears in evidence
    assert "AKIAABCDEFGHIJKLMNOP" not in secrets[0].evidence.summary


def test_gitleaks_finding_references_the_original_binary_not_the_strings_extraction(temp_file):
    # gitleaks is run against a `strings` extraction of the binary, not
    # the raw file (see agents/binary/agent.py's _check_secrets_gitleaks
    # docstring — gitleaks silently skips non-UTF8 binary content
    # otherwise). leak['file']/['line'] therefore point at a temp
    # extraction file the user never sees, so the finding deliberately
    # references the real binary's name instead, with no line number.
    engine = MockToolEngine(
        gitleaks_result=[
            {
                "rule": "slack-token",
                "description": "Slack token",
                "secret": "xoxb-fake",
                "file": "/tmp/cart_gitleaks_xyz/binary.strings.txt",
                "line": 42,
            }
        ],
    )
    result = run(_job(temp_file), engine)
    secrets = [f for f in result.findings if f.finding_type == "hardcoded_secret"]
    assert "Slack token found in" in secrets[0].description
    assert Path(temp_file).name in secrets[0].description
    assert "cart_gitleaks" not in secrets[0].description


def test_gitleaks_not_installed_falls_back_to_regex_check(temp_file):
    # gitleaks_result=None + default gitleaks_unavailable=True (the
    # MockToolEngine default) simulates "gitleaks isn't on this machine".
    engine = MockToolEngine(
        strings_result=["some text", "AKIAFAKEKEY1234567890", "more text"],
    )
    result = run(_job(temp_file), engine)

    secrets = [f for f in result.findings if f.finding_type == "hardcoded_secret"]
    assert len(secrets) == 1
    assert secrets[0].evidence.kind == "strings_match"  # fell back, didn't silently drop the finding


def test_gitleaks_not_configured_also_falls_back():
    import tempfile as tf

    fd, path = tf.mkstemp()
    os.close(fd)
    try:
        engine = MockToolEngine(
            raise_on_gitleaks=ToolNotConfigured("no 'gitleaks' entry in tools.yaml"),
            strings_result=["AKIAFAKEKEY1234567890"],
        )
        result = run(_job(path), engine)
        secrets = [f for f in result.findings if f.finding_type == "hardcoded_secret"]
        assert len(secrets) == 1
        assert secrets[0].evidence.kind == "strings_match"
    finally:
        os.remove(path)


def test_gitleaks_crash_for_an_unrelated_reason_is_not_silently_swallowed(temp_file):
    """A gitleaks failure that ISN'T 'not installed/configured' (e.g. it
    ran and produced garbage output — core/parsers/gitleaks.py raises
    ValueError for that) must propagate, not be treated the same as
    'gitleaks missing' and quietly downgraded to the weaker regex check.
    Silently equating 'tool broke' with 'tool absent' would hide a real
    failure behind a false sense of having scanned thoroughly."""
    engine = MockToolEngine(raise_on_gitleaks=ValueError("gitleaks output wasn't valid JSON"))

    with pytest.raises(ValueError, match="gitleaks output wasn't valid JSON"):
        run(_job(temp_file), engine)


def test_gitleaks_and_regex_paths_both_still_find_unsafe_functions(temp_file):
    """Secret-check backend choice must not affect the independent
    unsafe-function-call check."""
    engine = MockToolEngine(
        gitleaks_result=[],
        functions_result=["strcpy"],
    )
    result = run(_job(temp_file), engine)
    unsafe = [f for f in result.findings if f.finding_type == "unsafe_function_call"]
    assert len(unsafe) == 1


def test_no_leaks_from_gitleaks_means_no_secret_findings(temp_file):
    engine = MockToolEngine(gitleaks_result=[])
    result = run(_job(temp_file), engine)
    assert not [f for f in result.findings if f.finding_type == "hardcoded_secret"]


def test_duplicate_leaks_for_the_same_secret_are_deduplicated(temp_file):
    leak = {"rule": "aws-access-token", "description": "AWS Access Key", "secret": "AKIADUPLICATE1234567", "file": "a.py", "line": 1}
    engine = MockToolEngine(gitleaks_result=[leak, dict(leak)])
    result = run(_job(temp_file), engine)
    secrets = [f for f in result.findings if f.finding_type == "hardcoded_secret"]
    assert len(secrets) == 1
