"""
tests/agents/test_binary_agent_url.py

Tests for the binary agent's URL-target path: when a discovered link
(e.g. from the web crawler) points at a binary instead of a local file,
the agent must download it through the scope-checked executor first.
"""

import hashlib

import pytest

from agents.binary.agent import SeenBinaryHashes, _filename_from_url, run
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


# --- _filename_from_url (confirmed real-world miss: a file-manager-style
# download link reported the wrong file, e.g. "index.php" instead of the
# actual "agent.bin" it served) ---------------------------------------


def test_filename_prefers_query_string_binary_name_over_path_basename():
    url = "http://target.example/index.php?p=ops%2Fagent.bin&dl=1"
    assert _filename_from_url(url) == "agent.bin"


def test_filename_falls_back_to_path_basename_when_no_query_match():
    url = "http://target.example/downloads/installer.exe"
    assert _filename_from_url(url) == "installer.exe"


def test_filename_falls_back_to_placeholder_when_nothing_matches():
    url = "http://target.example/download?id=42"
    assert _filename_from_url(url) == "download"


# --- seen_hashes dedup (confirmed real-world miss: the same binary
# served via 3 different links produced the same secret/unsafe-function
# findings 3 times over in one report) ---------------------------------


def test_duplicate_content_via_seen_hashes_is_skipped_with_one_note():
    fake_bytes = b"\x7fELF fake binary content AKIAFAKEKEY1234567890"
    tool_engine = MockToolEngine(strings_result=["AKIAFAKEKEY1234567890"])
    tracker = SeenBinaryHashes()

    first = run(
        _job("http://target.example/link-one/agent.bin"),
        tool_engine,
        MockScopedExecutor(download_result=fake_bytes),
        seen_hashes=tracker,
    )
    second = run(
        _job("http://target.example/link-two/agent.bin"),
        tool_engine,
        MockScopedExecutor(download_result=fake_bytes),
        seen_hashes=tracker,
    )

    assert [f.finding_type for f in first.findings] == ["hardcoded_secret"]
    assert [f.finding_type for f in second.findings] == ["duplicate_binary_skipped"]
    digest = hashlib.sha256(fake_bytes).hexdigest()
    assert digest in second.findings[0].evidence.summary


def test_without_seen_hashes_duplicate_content_is_analyzed_every_time():
    # Default (None) behavior is unchanged from before this parameter
    # existed — every existing caller (main.py, run_pipeline.py's direct
    # --agent binary path, every other test in this file) still gets the
    # old no-dedup behavior.
    fake_bytes = b"\x7fELF fake binary content AKIAFAKEKEY1234567890"
    tool_engine = MockToolEngine(strings_result=["AKIAFAKEKEY1234567890"])

    first = run(
        _job("http://target.example/link-one/agent.bin"),
        tool_engine,
        MockScopedExecutor(download_result=fake_bytes),
    )
    second = run(
        _job("http://target.example/link-two/agent.bin"),
        tool_engine,
        MockScopedExecutor(download_result=fake_bytes),
    )

    assert [f.finding_type for f in first.findings] == ["hardcoded_secret"]
    assert [f.finding_type for f in second.findings] == ["hardcoded_secret"]


def test_seen_hashes_add_if_new_returns_true_once_then_false():
    tracker = SeenBinaryHashes()
    assert tracker.add_if_new("abc123") is True
    assert tracker.add_if_new("abc123") is False
    assert tracker.add_if_new("def456") is True
