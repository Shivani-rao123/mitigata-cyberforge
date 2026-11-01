"""
tests/agents/test_binary_agent_credential_pairs.py

Unit tests for agents/binary/agent.py's _check_credential_pairs() /
credential_pair_found — the missing link a real review flagged:
"binary has hardcoded creds -> those should get tried against a login
form -> a successful login should lead to a flag" was never
demonstrated. This covers only the EXTRACTION half (a binary's
`strings` output -> a paired username/password finding); the
login-probe half is covered by tests/verification/test_verifier.py and
the end-to-end wiring by tests/core/test_pipeline.py.
"""

import os
import tempfile

import pytest

from agents.binary.agent import run
from common.contracts import Job
from tests.mock_tool_engine import MockToolEngine


@pytest.fixture
def tmp_file():
    fd, path = tempfile.mkstemp()
    os.close(fd)
    with open(path, "wb") as f:
        f.write(b"\x7fELF fake binary content")
    yield path
    os.remove(path)


def _job(target):
    return Job(job_id="cred-pair-job", agent="binary", target=target)


def test_adjacent_username_and_password_strings_are_paired(tmp_file):
    tool_engine = MockToolEngine(strings_result=["username=admin", "password=S3cr3t!"])

    result = run(_job(tmp_file), tool_engine)

    pairs = [f for f in result.findings if f.finding_type == "credential_pair_found"]
    assert len(pairs) == 1
    assert pairs[0].evidence.raw_ref == "admin:S3cr3t!"
    # evidence.summary (human/report-facing) stays redacted — only
    # raw_ref carries the full, unredacted pair.
    assert "S3cr3t!" not in pairs[0].evidence.summary


def test_pairs_within_the_window_but_not_immediately_adjacent_are_still_caught(tmp_file):
    tool_engine = MockToolEngine(
        strings_result=["username=admin", "some_unrelated_string", "password=hunter2"]
    )

    result = run(_job(tmp_file), tool_engine)

    pairs = [f for f in result.findings if f.finding_type == "credential_pair_found"]
    assert len(pairs) == 1
    assert pairs[0].evidence.raw_ref == "admin:hunter2"


def test_username_and_password_too_far_apart_are_not_paired(tmp_file):
    tool_engine = MockToolEngine(
        strings_result=["username=admin", "a", "b", "c", "d", "password=hunter2"]
    )

    result = run(_job(tmp_file), tool_engine)

    assert not [f for f in result.findings if f.finding_type == "credential_pair_found"]


def test_username_assignment_with_no_nearby_password_produces_no_finding(tmp_file):
    tool_engine = MockToolEngine(strings_result=["username=admin", "unrelated text"])

    result = run(_job(tmp_file), tool_engine)

    assert not [f for f in result.findings if f.finding_type == "credential_pair_found"]


def test_recognizes_common_field_name_variants(tmp_file):
    tool_engine = MockToolEngine(strings_result=["login: svc_account", "pwd: letmein123"])

    result = run(_job(tmp_file), tool_engine)

    pairs = [f for f in result.findings if f.finding_type == "credential_pair_found"]
    assert len(pairs) == 1
    assert pairs[0].evidence.raw_ref == "svc_account:letmein123"


def test_duplicate_pairs_are_not_reported_twice(tmp_file):
    tool_engine = MockToolEngine(
        strings_result=[
            "username=admin",
            "password=hunter2",
            "username=admin",
            "password=hunter2",
        ]
    )

    result = run(_job(tmp_file), tool_engine)

    pairs = [f for f in result.findings if f.finding_type == "credential_pair_found"]
    assert len(pairs) == 1


def test_no_username_assignment_at_all_produces_no_findings(tmp_file):
    tool_engine = MockToolEngine(strings_result=["just some unrelated binary strings", "nothing here"])

    result = run(_job(tmp_file), tool_engine)

    assert not [f for f in result.findings if f.finding_type == "credential_pair_found"]
