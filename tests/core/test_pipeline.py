"""
tests/core/test_pipeline.py

Unit tests for core/pipeline.py's run_and_persist() -- the end-to-end
wiring (FR-4 orchestration -> FR-7 DB persistence -> FR-6 verification
-> FR-5 PTES tagging -> attack_edges -> FR-7 report). Mocks the three
agent run() functions the same way tests/core/test_orchestrator.py
does, and uses the MockScopedExecutor for http_post (verification)
calls, with a real in-memory Database so persistence is genuinely
exercised, not just mocked away.
"""

from __future__ import annotations

from unittest.mock import patch

from common.contracts import Evidence, FindingOut, HostOut, JobResult, ServiceOut
from core.db import Database
from core.pipeline import run_and_persist
from tests.mock_executor import MockScopedExecutor


def _result(findings=None, follow_up_jobs=None, hosts=None):
    return JobResult(
        job_id="x",
        status="completed",
        hosts=hosts or [],
        findings=findings or [],
        follow_up_jobs=follow_up_jobs or [],
    )


def _finding(finding_type, host="10.10.10.5", description="d"):
    return FindingOut(
        finding_type=finding_type, description=description, host=host, evidence=Evidence(kind="k", summary="s")
    )


@patch("core.orchestrator.run_web_agent")
@patch("core.orchestrator.run_network_agent")
def test_run_and_persist_matches_the_userflow_worked_example(mock_network, mock_web):
    mock_network.return_value = _result(
        hosts=[HostOut(ip="10.10.10.5", services=[ServiceOut(port=80, protocol="tcp", service="http")])],
        findings=[_finding("open_port", description="Port 80/tcp open")],
        follow_up_jobs=[{"agent": "web", "target": "10.10.10.5:80", "context": {}}],
    )

    def _http_post_fn(url, data):
        if data == {"username": "admin", "password": "admin"}:
            return {"status": 302, "headers": {"Location": "/dashboard"}, "body": ""}
        return {"status": 200, "headers": {}, "body": "invalid"}

    mock_web.return_value = _result(
        findings=[
            _finding(
                "default_creds_found",
                description=(
                    "Login form found at http://10.10.10.5/admin "
                    "(action=/admin) — candidate for default-credential testing"
                ),
            )
        ]
    )
    # The web finding's evidence needs the "form fields:" shape the
    # verifier parses -- override it directly on the mocked return.
    mock_web.return_value.findings[0].evidence.summary = (
        "GET http://10.10.10.5/admin -> 200, form fields: ['password', 'username']"
    )

    executor = MockScopedExecutor(http_post_fn=_http_post_fn)

    with Database(":memory:") as db:
        result = run_and_persist(target="10.10.10.5", executor=executor, db=db, scope=["10.10.10.0/24"])

        all_findings = db.list_all_findings()
        assert len(all_findings) == 2

        open_port_row = next(f for f in all_findings if f["finding_type"] == "open_port")
        assert open_port_row["ptes_phase"] == "Intelligence Gathering"
        # open_port has no active re-probe -- verify_finding auto-confirms
        # it immediately, since nmap's own port-state output is already
        # a direct, deterministic observation (see verification/verifier.py).
        assert open_port_row["status"] == "confirmed"

        creds_row = next(f for f in all_findings if f["finding_type"] == "default_creds_found")
        assert creds_row["status"] == "confirmed"
        assert creds_row["ptes_phase"] == "Exploitation"

        edges = db.list_attack_edges()
        assert len(edges) == 1
        assert edges[0]["from_finding_id"] == open_port_row["id"]
        assert edges[0]["to_finding_id"] == creds_row["id"]

    assert "1. [Intelligence Gathering] Port 80/tcp open on 10.10.10.5" in result["attack_path"]
    assert "2. [Exploitation]" in result["attack_path"]
    assert "confirmed on 10.10.10.5" in result["attack_path"]


@patch("core.orchestrator.run_network_agent")
def test_stage_with_no_findings_persists_nothing_but_still_succeeds(mock_network):
    mock_network.return_value = _result(hosts=[HostOut(ip="10.10.10.5")])
    executor = MockScopedExecutor()

    with Database(":memory:") as db:
        result = run_and_persist(target="10.10.10.5", executor=executor, db=db)

        assert db.list_all_findings() == []
        assert db.list_hosts()[0]["ip"] == "10.10.10.5"

    assert result["attack_path"] == "Attack Path:\n(no verified findings yet)"


@patch("core.orchestrator.run_network_agent")
def test_a_failed_stage_does_not_crash_persistence(mock_network):
    mock_network.side_effect = RuntimeError("nmap not installed")
    executor = MockScopedExecutor()

    with Database(":memory:") as db:
        result = run_and_persist(target="10.10.10.5", executor=executor, db=db)

    assert result["outcome"].stages[0].error == "nmap not installed"
    assert result["attack_path"] == "Attack Path:\n(no verified findings yet)"
