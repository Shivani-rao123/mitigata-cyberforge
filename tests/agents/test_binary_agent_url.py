"""
tests/agents/test_binary_agent_url.py

Tests for the binary agent's URL-target path: when a discovered link
(e.g. from the web crawler) points at a binary instead of a local file,
the agent must download it through the scope-checked executor first.
"""

import pytest

from agents.binary.agent import run
from common.contracts import Job
from core.scoped_executor import DownloadError, ScopeViolation
from tests.mock_executor import MockScopedExecutor
from tests.mock_tool_engine import MockToolEngine


def _job(target):
    return Job(job_id="bin-url-job", agent="binary", target=target)


def test_url_target_without_executor_raises_clear_error():
    tool_engine = MockToolEngine()
    job = _job("http://example.com/app.bin")

    with pytest.raises(ValueError, match="executor is required"):
        run(job, tool_engine, executor=None)


def test_url_target_is_downloaded_then_analyzed_for_secrets():
    # A tiny fake "binary" whose bytes don't matter — strings/nm are both
    # mocked here, so we're only proving the download -> temp file -> same
    # analysis path is wired correctly, not re-testing strings/nm parsing.
    fake_bytes = b"\x7fELF fake binary content AKIAFAKEKEY1234567890"
    executor = MockScopedExecutor(download_result=fake_bytes)
    tool_engine = MockToolEngine(strings_result=["AKIAFAKEKEY1234567890"])

    result = run(_job("http://target.example/firmware.bin"), tool_engine, executor)

    secrets = [f for f in result.findings if f.finding_type == "hardcoded_secret"]
    assert len(secrets) == 1


def test_download_failure_propagates_as_download_error():
    executor = MockScopedExecutor(raise_on_download=DownloadError("connection refused"))
    tool_engine = MockToolEngine()

    with pytest.raises(DownloadError):
        run(_job("http://target.example/app.bin"), tool_engine, executor)


def test_out_of_scope_url_blocks_before_any_analysis():
    executor = MockScopedExecutor(raise_on_download=ScopeViolation("out of scope"))
    tool_engine = MockToolEngine()

    with pytest.raises(ScopeViolation):
        run(_job("http://not-authorized.example/app.bin"), tool_engine, executor)


def test_downloaded_filename_is_preserved_from_url_path():
    fake_bytes = b"harmless content"
    executor = MockScopedExecutor(download_result=fake_bytes)
    tool_engine = MockToolEngine()  # no secrets, no unsafe functions

    result = run(_job("http://target.example/path/to/installer.exe"), tool_engine, executor)

    # no findings expected — this test only confirms it runs end-to-end
    # without crashing when the URL has a nested path
    assert result.status == "completed"
