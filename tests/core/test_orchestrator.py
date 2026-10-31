"""
tests/core/test_orchestrator.py

Unit tests for core/orchestrator.py's run_target(), with the three
agent run() functions mocked out — mirrors tests/webui/test_orchestrate.py's
approach (same dispatch guarantees: a network follow-up feeds the web
stage, a web follow-up feeds the binary stage, one bad stage doesn't
kill the others), but additionally proves the two things this module
adds over webui/orchestrate.py: agent-count-agnostic dispatch (no
hardcoded sequence) with real dedup, and actual concurrent execution of
one wave's independent jobs.
"""

import threading
import time
from unittest.mock import patch

from common.contracts import Evidence, FindingOut, JobResult
from core import orchestrator


def _result(findings=None, follow_up_jobs=None, status="completed"):
    return JobResult(
        job_id="x",
        status=status,
        findings=findings or [],
        follow_up_jobs=follow_up_jobs or [],
    )


def _finding(finding_type="x"):
    return FindingOut(
        finding_type=finding_type,
        description="d",
        evidence=Evidence(kind="k", summary="s"),
    )


@patch("core.orchestrator.run_binary_agent")
@patch("core.orchestrator.run_web_agent")
@patch("core.orchestrator.run_network_agent")
def test_network_follow_up_triggers_web_stage(mock_network, mock_web, mock_binary):
    mock_network.return_value = _result(
        follow_up_jobs=[{"agent": "web", "target": "1.2.3.4:80", "context": {}}]
    )
    mock_web.return_value = _result()

    outcome = orchestrator.run_target("1.2.3.4", executor=object(), scope=["1.2.3.4/32"])

    assert [s.agent for s in outcome.stages] == ["network", "web"]
    mock_web.assert_called_once()


@patch("core.orchestrator.run_binary_agent")
@patch("core.orchestrator.run_web_agent")
@patch("core.orchestrator.run_network_agent")
def test_web_follow_up_triggers_binary_stage(mock_network, mock_web, mock_binary):
    mock_network.return_value = _result(
        follow_up_jobs=[{"agent": "web", "target": "1.2.3.4:80", "context": {}}]
    )
    mock_web.return_value = _result(
        follow_up_jobs=[{"agent": "binary", "target": "http://1.2.3.4/tool.bin", "context": {}}]
    )
    mock_binary.return_value = _result(findings=[_finding("hardcoded_secret")])

    outcome = orchestrator.run_target("1.2.3.4", executor=object(), scope=["1.2.3.4/32"])

    assert [s.agent for s in outcome.stages] == ["network", "web", "binary"]
    assert outcome.total_findings == 1
    # binary agent must get tool_engine/executor as kwargs, not positionally
    _, kwargs = mock_binary.call_args
    assert "tool_engine" in kwargs and "executor" in kwargs


@patch("core.orchestrator.run_network_agent")
def test_no_follow_up_jobs_means_only_network_stage_runs(mock_network):
    mock_network.return_value = _result()

    outcome = orchestrator.run_target("1.2.3.4", executor=object())

    assert [s.agent for s in outcome.stages] == ["network"]


@patch("core.orchestrator.run_network_agent")
def test_network_stage_error_is_captured_not_raised(mock_network):
    mock_network.side_effect = RuntimeError("nmap not installed")

    outcome = orchestrator.run_target("1.2.3.4", executor=object())

    assert len(outcome.stages) == 1
    assert outcome.stages[0].error == "nmap not installed"
    assert outcome.had_any_error is True


@patch("core.orchestrator.run_binary_agent")
@patch("core.orchestrator.run_web_agent")
@patch("core.orchestrator.run_network_agent")
def test_one_bad_web_stage_does_not_block_a_working_one(mock_network, mock_web, mock_binary):
    mock_network.return_value = _result(
        follow_up_jobs=[
            {"agent": "web", "target": "1.2.3.4:80", "context": {}},
            {"agent": "web", "target": "1.2.3.4:8080", "context": {}},
        ]
    )

    def web_side_effect(job, executor):
        if job.target == "1.2.3.4:80":
            raise RuntimeError("connection refused")
        return _result()

    mock_web.side_effect = web_side_effect

    outcome = orchestrator.run_target("1.2.3.4", executor=object())

    web_stages = [s for s in outcome.stages if s.agent == "web"]
    assert len(web_stages) == 2
    errors = sorted(s.error for s in web_stages if s.error)
    assert errors == ["connection refused"]
    assert outcome.had_any_error is True


@patch("core.orchestrator.run_binary_agent")
@patch("core.orchestrator.run_web_agent")
@patch("core.orchestrator.run_network_agent")
def test_multiple_binary_follow_ups_from_same_web_stage_all_run(mock_network, mock_web, mock_binary):
    mock_network.return_value = _result(
        follow_up_jobs=[{"agent": "web", "target": "1.2.3.4:80", "context": {}}]
    )
    mock_web.return_value = _result(
        follow_up_jobs=[
            {"agent": "binary", "target": "http://1.2.3.4/a.bin", "context": {}},
            {"agent": "binary", "target": "http://1.2.3.4/b.exe", "context": {}},
        ]
    )
    mock_binary.return_value = _result()

    outcome = orchestrator.run_target("1.2.3.4", executor=object())

    binary_stages = [s for s in outcome.stages if s.agent == "binary"]
    assert len(binary_stages) == 2


@patch("core.orchestrator.run_network_agent")
def test_scope_display_reflects_scope_passed_in(mock_network):
    mock_network.return_value = _result()

    outcome = orchestrator.run_target("1.2.3.4", executor=object(), scope=["1.2.3.4/32", "127.0.0.1/32"])

    assert outcome.scope == ["1.2.3.4/32", "127.0.0.1/32"]


@patch("core.orchestrator.run_web_agent")
@patch("core.orchestrator.run_network_agent")
def test_duplicate_follow_up_job_from_two_stages_only_runs_once(mock_network, mock_web):
    """Two different web pages both linking the exact same follow-up
    target must still only produce one job — this is core/queue.py's
    dedup, exercised through the real orchestrator path (not called
    directly on JobQueue)."""
    mock_network.return_value = _result(
        follow_up_jobs=[
            {"agent": "web", "target": "1.2.3.4:80", "context": {}},
            {"agent": "web", "target": "1.2.3.4:80", "context": {}},  # exact duplicate
        ]
    )
    mock_web.return_value = _result()

    outcome = orchestrator.run_target("1.2.3.4", executor=object())

    web_stages = [s for s in outcome.stages if s.agent == "web"]
    assert len(web_stages) == 1
    mock_web.assert_called_once()


@patch("core.orchestrator.run_web_agent")
@patch("core.orchestrator.run_network_agent")
def test_independent_jobs_in_one_wave_run_concurrently(mock_network, mock_web):
    """The actual point of FR-4: N independent jobs in the same wave
    must run roughly in parallel, not one after another. Three web
    follow-ups that each sleep 0.3s should finish in well under
    3 * 0.3s wall-clock if they're genuinely concurrent."""
    mock_network.return_value = _result(
        follow_up_jobs=[
            {"agent": "web", "target": f"1.2.3.4:{port}", "context": {}}
            for port in (80, 8080, 8443)
        ]
    )

    def slow_web(job, executor):
        time.sleep(0.3)
        return _result()

    mock_web.side_effect = slow_web

    started = time.monotonic()
    outcome = orchestrator.run_target("1.2.3.4", executor=object(), max_workers=8)
    elapsed = time.monotonic() - started

    assert len([s for s in outcome.stages if s.agent == "web"]) == 3
    # Sequential would be >= 0.9s; concurrent should land close to 0.3s.
    assert elapsed < 0.8


@patch("core.orchestrator.run_network_agent")
def test_one_scoped_executor_instance_is_shared_across_all_stage_calls(mock_network):
    """Proves run_target() passes the SAME executor object through to
    every agent call rather than constructing a new one per stage —
    required for the thread-safety story in this module's docstring."""
    seen_executor_ids: list[int] = []
    lock = threading.Lock()

    def capture(job, executor):
        with lock:
            seen_executor_ids.append(id(executor))
        return _result()

    mock_network.side_effect = capture
    shared_executor = object()

    orchestrator.run_target("1.2.3.4", executor=shared_executor)

    assert seen_executor_ids == [id(shared_executor)]
