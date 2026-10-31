"""
tests/webui/test_orchestrate.py

Unit tests for the dashboard's chaining logic (webui/orchestrate.py),
with the three agent run() functions mocked out — proves the dispatch
logic itself (network's follow-ups feed the web stage, web's follow-ups
feed the binary stage, errors in one stage don't kill the others)
without needing nmap, a real network, or a running Flask server.
"""

from unittest.mock import patch

from common.contracts import Evidence, FindingOut, JobResult
from webui import orchestrate


def _result(findings=None, follow_up_jobs=None):
    return JobResult(
        job_id="x",
        status="completed",
        findings=findings or [],
        follow_up_jobs=follow_up_jobs or [],
    )


def _finding(finding_type="x"):
    return FindingOut(
        finding_type=finding_type,
        description="d",
        evidence=Evidence(kind="k", summary="s"),
    )


@patch("webui.orchestrate.run_binary_agent")
@patch("webui.orchestrate.run_web_agent")
@patch("webui.orchestrate.run_network_agent")
def test_network_follow_up_triggers_web_stage(mock_network, mock_web, mock_binary):
    mock_network.return_value = _result(
        follow_up_jobs=[{"agent": "web", "target": "1.2.3.4:80", "context": {}}]
    )
    mock_web.return_value = _result()

    chain = orchestrate.run_full_chain("1.2.3.4", scope_cidrs=["1.2.3.4/32"])

    agents_run = [s.agent for s in chain.stages]
    assert agents_run == ["network", "web"]
    mock_web.assert_called_once()


@patch("webui.orchestrate.run_binary_agent")
@patch("webui.orchestrate.run_web_agent")
@patch("webui.orchestrate.run_network_agent")
def test_web_follow_up_triggers_binary_stage(mock_network, mock_web, mock_binary):
    mock_network.return_value = _result(
        follow_up_jobs=[{"agent": "web", "target": "1.2.3.4:80", "context": {}}]
    )
    mock_web.return_value = _result(
        follow_up_jobs=[{"agent": "binary", "target": "http://1.2.3.4/tool.bin", "context": {}}]
    )
    mock_binary.return_value = _result(findings=[_finding("hardcoded_secret")])

    chain = orchestrate.run_full_chain("1.2.3.4", scope_cidrs=["1.2.3.4/32"])

    agents_run = [s.agent for s in chain.stages]
    assert agents_run == ["network", "web", "binary"]
    assert chain.total_findings == 1


@patch("webui.orchestrate.run_network_agent")
def test_no_follow_up_jobs_means_only_network_stage_runs(mock_network):
    mock_network.return_value = _result()  # no follow-ups at all

    chain = orchestrate.run_full_chain("1.2.3.4", scope_cidrs=["1.2.3.4/32"])

    assert [s.agent for s in chain.stages] == ["network"]


@patch("webui.orchestrate.run_network_agent")
def test_network_stage_error_is_captured_not_raised(mock_network):
    mock_network.side_effect = RuntimeError("nmap not installed")

    chain = orchestrate.run_full_chain("1.2.3.4", scope_cidrs=["1.2.3.4/32"])

    assert len(chain.stages) == 1
    assert chain.stages[0].error == "nmap not installed"
    assert chain.had_any_error is True


@patch("webui.orchestrate.run_binary_agent")
@patch("webui.orchestrate.run_web_agent")
@patch("webui.orchestrate.run_network_agent")
def test_one_bad_web_stage_does_not_block_a_working_one(mock_network, mock_web, mock_binary):
    mock_network.return_value = _result(
        follow_up_jobs=[
            {"agent": "web", "target": "1.2.3.4:80", "context": {}},
            {"agent": "web", "target": "1.2.3.4:8080", "context": {}},
        ]
    )
    mock_web.side_effect = [RuntimeError("connection refused"), _result()]

    chain = orchestrate.run_full_chain("1.2.3.4", scope_cidrs=["1.2.3.4/32"])

    web_stages = [s for s in chain.stages if s.agent == "web"]
    assert len(web_stages) == 2
    assert web_stages[0].error == "connection refused"
    assert web_stages[1].error is None
    assert chain.had_any_error is True


@patch("webui.orchestrate.run_binary_agent")
@patch("webui.orchestrate.run_web_agent")
@patch("webui.orchestrate.run_network_agent")
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

    chain = orchestrate.run_full_chain("1.2.3.4", scope_cidrs=["1.2.3.4/32"])

    binary_stages = [s for s in chain.stages if s.agent == "binary"]
    assert len(binary_stages) == 2


@patch("webui.orchestrate.run_network_agent")
def test_scope_display_reflects_cidrs_passed_in(mock_network):
    mock_network.return_value = _result()

    chain = orchestrate.run_full_chain("1.2.3.4", scope_cidrs=["1.2.3.4/32", "127.0.0.1/32"])

    assert chain.scope == ["1.2.3.4/32", "127.0.0.1/32"]
