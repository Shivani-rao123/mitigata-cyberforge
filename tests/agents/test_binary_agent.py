"""
tests/agents/test_binary_agent.py

Unit tests for the binary agent, against a mocked ToolEngine. Real
integration (does `strings`/`nm` actually behave this way against a real
compiled binary) is verified separately against
fixtures/vulnerable_binary/vuln.c — see that file's build instructions.
"""

import os
import tempfile

import pytest

from agents.binary.agent import run
from common.contracts import Job
from tests.mock_tool_engine import MockToolEngine


@pytest.fixture
def temp_file():
    """A real file on disk — _validate_path needs something that exists."""
    fd, path = tempfile.mkstemp()
    os.close(fd)
    yield path
    os.remove(path)


def _job(target):
    return Job(job_id="bin-job", agent="binary", target=target)


def test_aws_key_is_flagged(temp_file):
    engine = MockToolEngine(strings_result=["some text", "AKIAFAKEKEY1234567890", "more text"])
    result = run(_job(temp_file), engine)

    secrets = [f for f in result.findings if f.finding_type == "hardcoded_secret"]
    assert len(secrets) == 1
    assert "AWS Access Key" in secrets[0].description


def test_private_key_header_is_flagged(temp_file):
    engine = MockToolEngine(strings_result=["-----BEGIN RSA PRIVATE KEY-----"])
    result = run(_job(temp_file), engine)

    secrets = [f for f in result.findings if f.finding_type == "hardcoded_secret"]
    assert len(secrets) == 1
    assert "Private key" in secrets[0].description


def test_generic_password_assignment_is_flagged(temp_file):
    engine = MockToolEngine(strings_result=['password="SuperSecretValue123"'])
    result = run(_job(temp_file), engine)

    secrets = [f for f in result.findings if f.finding_type == "hardcoded_secret"]
    assert len(secrets) == 1


def test_clean_strings_produce_no_secret_findings(temp_file):
    engine = MockToolEngine(strings_result=["hello world", "libc.so.6", "GCC: (Ubuntu 12.2.0)"])
    result = run(_job(temp_file), engine)

    secrets = [f for f in result.findings if f.finding_type == "hardcoded_secret"]
    assert secrets == []


def test_duplicate_matches_are_deduplicated(temp_file):
    engine = MockToolEngine(
        strings_result=["AKIAFAKEKEY1234567890", "AKIAFAKEKEY1234567890"]
    )
    result = run(_job(temp_file), engine)

    secrets = [f for f in result.findings if f.finding_type == "hardcoded_secret"]
    assert len(secrets) == 1  # same key appearing twice -> one finding, not two


def test_secret_is_redacted_in_evidence(temp_file):
    engine = MockToolEngine(strings_result=["AKIAFAKEKEY1234567890"])
    result = run(_job(temp_file), engine)

    secrets = [f for f in result.findings if f.finding_type == "hardcoded_secret"]
    assert "AKIAFAKEKEY1234567890" not in secrets[0].evidence.summary
    assert "AKIA" in secrets[0].evidence.summary  # prefix kept for identification


def test_unsafe_function_strcpy_is_flagged(temp_file):
    engine = MockToolEngine(functions_result=["strcpy", "puts", "__libc_start_main"])
    result = run(_job(temp_file), engine)

    unsafe = [f for f in result.findings if f.finding_type == "unsafe_function_call"]
    assert len(unsafe) == 1
    assert "strcpy" in unsafe[0].description


def test_multiple_unsafe_functions_are_all_flagged(temp_file):
    engine = MockToolEngine(functions_result=["strcpy", "system", "gets", "puts"])
    result = run(_job(temp_file), engine)

    unsafe_names = {
        f.description for f in result.findings if f.finding_type == "unsafe_function_call"
    }
    assert len(unsafe_names) == 3


def test_safe_functions_only_produce_no_findings(temp_file):
    engine = MockToolEngine(functions_result=["puts", "printf", "__libc_start_main"])
    result = run(_job(temp_file), engine)

    unsafe = [f for f in result.findings if f.finding_type == "unsafe_function_call"]
    assert unsafe == []


def test_nm_failure_on_non_elf_file_does_not_crash(temp_file):
    engine = MockToolEngine(strings_result=["hello"], raise_on_nm=True)
    result = run(_job(temp_file), engine)

    assert result.status == "completed"
    unsafe = [f for f in result.findings if f.finding_type == "unsafe_function_call"]
    assert unsafe == []  # nm failing is NOT an error, just "nothing to report here"


def test_missing_file_raises_clear_error():
    engine = MockToolEngine()
    job = _job("/this/path/does/not/exist.bin")

    with pytest.raises(FileNotFoundError):
        run(job, engine)


def test_directory_as_target_raises_clear_error():
    engine = MockToolEngine()
    job = _job("/tmp")  # exists, but is a directory, not a file

    with pytest.raises(ValueError):
        run(job, engine)


def test_combined_secret_and_unsafe_function_both_flagged(temp_file):
    engine = MockToolEngine(
        strings_result=["AKIAFAKEKEY1234567890"],
        functions_result=["strcpy"],
    )
    result = run(_job(temp_file), engine)

    types = {f.finding_type for f in result.findings}
    assert types == {"hardcoded_secret", "unsafe_function_call"}
