"""
tests/core/test_pipeline_header_auth.py

Covers core/pipeline.py's pass 2.6 — HTTP header-auth candidates are
only ever tried when the LLM explicitly approves them. Unlike pass
2.5's rule-based conventional-path fallback, there is no "run it
anyway" default: if the LLM is off (the normal case) or its call
fails, no header-auth attempt happens at all.
"""

from __future__ import annotations

import base64
import sys
import types
from unittest.mock import MagicMock, patch

from common.contracts import Evidence, FindingOut, JobResult
from core.db import Database
from core.pipeline import run_and_persist
from tests.mock_executor import MockScopedExecutor


def _result(findings=None, follow_up_jobs=None):
    return JobResult(job_id="x", status="completed", findings=findings or [], follow_up_jobs=follow_up_jobs or [])


PROTECTED_ENDPOINT_FINDING = FindingOut(
    finding_type="sensitive_endpoint_found",
    description="Sensitive endpoint /api/data responded with HTTP 401",
    host="10.10.10.5",
    evidence=Evidence(kind="http_response", summary="GET http://10.10.10.5/api/data -> 401"),
)

CREDENTIAL_PAIR_FINDING = FindingOut(
    finding_type="credential_pair_found",
    description="Username/password pair found hardcoded together in agent.bin",
    host=None,
    evidence=Evidence(
        kind="strings_credential_pair", summary="username=svc, password=r3**", raw_ref="svc:r3al_pw"
    ),
)


def _fake_openai_module(response_text):
    fake_module = types.ModuleType("openai")

    class _FakeOpenAI:
        def __init__(self, *args, **kwargs):
            self.chat = MagicMock()
            message = MagicMock(content=response_text)
            self.chat.completions.create.return_value = MagicMock(choices=[MagicMock(message=message)])

    fake_module.OpenAI = _FakeOpenAI
    return fake_module


@patch("core.orchestrator.run_binary_agent")
@patch("core.orchestrator.run_web_agent")
@patch("core.orchestrator.run_network_agent")
def test_llm_disabled_means_no_header_auth_attempt_at_all(mock_network, mock_web, mock_binary, monkeypatch):
    import common.llm as llm_module

    monkeypatch.setattr(llm_module, "LLM_ENABLED", False)

    mock_network.return_value = _result(
        follow_up_jobs=[
            {"agent": "web", "target": "10.10.10.5:80", "context": {}},
            {"agent": "binary", "target": "http://10.10.10.5/agent.bin", "context": {}},
        ]
    )
    mock_web.return_value = _result(findings=[PROTECTED_ENDPOINT_FINDING])
    mock_binary.return_value = _result(findings=[CREDENTIAL_PAIR_FINDING])

    get_calls = []

    def _http_get_fn(url, headers=None):
        get_calls.append((url, headers))
        return {"status": 401, "headers": {}, "body": ""}

    executor = MockScopedExecutor(http_get_fn=_http_get_fn)

    with Database(":memory:") as db:
        result = run_and_persist(target="10.10.10.5", executor=executor, db=db)
        findings = db.get_findings_for_target(result["target_id"])

    # No header_auth_confirmed finding at all -- the feature never ran.
    assert not any(f["finding_type"] == "header_auth_confirmed" for f in findings)
    # And no request with an Authorization header was ever made either.
    assert all(headers is None for _url, headers in get_calls)


@patch("core.orchestrator.run_binary_agent")
@patch("core.orchestrator.run_web_agent")
@patch("core.orchestrator.run_network_agent")
def test_llm_call_failure_also_fails_closed_not_open(mock_network, mock_web, mock_binary, monkeypatch):
    import common.llm as llm_module

    monkeypatch.setattr(llm_module, "LLM_ENABLED", True)
    monkeypatch.setattr(llm_module, "_API_KEY", "test-key")
    monkeypatch.setitem(sys.modules, "openai", None)  # simulates package not installed -> call fails

    mock_network.return_value = _result(
        follow_up_jobs=[
            {"agent": "web", "target": "10.10.10.5:80", "context": {}},
            {"agent": "binary", "target": "http://10.10.10.5/agent.bin", "context": {}},
        ]
    )
    mock_web.return_value = _result(findings=[PROTECTED_ENDPOINT_FINDING])
    mock_binary.return_value = _result(findings=[CREDENTIAL_PAIR_FINDING])

    executor = MockScopedExecutor(http_get_fn=lambda url, headers=None: {"status": 401, "headers": {}, "body": ""})

    with Database(":memory:") as db:
        result = run_and_persist(target="10.10.10.5", executor=executor, db=db)
        findings = db.get_findings_for_target(result["target_id"])

    assert not any(f["finding_type"] == "header_auth_confirmed" for f in findings)


@patch("core.orchestrator.run_binary_agent")
@patch("core.orchestrator.run_web_agent")
@patch("core.orchestrator.run_network_agent")
def test_llm_approval_runs_the_attempt_and_persists_a_confirmed_finding(
    mock_network, mock_web, mock_binary, monkeypatch
):
    import common.llm as llm_module

    monkeypatch.setattr(llm_module, "LLM_ENABLED", True)
    monkeypatch.setattr(llm_module, "_API_KEY", "test-key")
    # The planner sees exactly one candidate (one credential x one
    # protected endpoint) -- approve index 0.
    monkeypatch.setitem(sys.modules, "openai", _fake_openai_module("[0]"))

    mock_network.return_value = _result(
        follow_up_jobs=[
            {"agent": "web", "target": "10.10.10.5:80", "context": {}},
            {"agent": "binary", "target": "http://10.10.10.5/agent.bin", "context": {}},
        ]
    )
    mock_web.return_value = _result(findings=[PROTECTED_ENDPOINT_FINDING])
    mock_binary.return_value = _result(findings=[CREDENTIAL_PAIR_FINDING])

    expected_token = base64.b64encode(b"svc:r3al_pw").decode()

    def _http_get_fn(url, headers=None):
        if url == "http://10.10.10.5/api/data" and headers == {"Authorization": f"Basic {expected_token}"}:
            return {"status": 200, "headers": {}, "body": "flag{header_auth_pipeline_flag}"}
        return {"status": 401, "headers": {}, "body": ""}

    executor = MockScopedExecutor(http_get_fn=_http_get_fn)

    with Database(":memory:") as db:
        result = run_and_persist(target="10.10.10.5", executor=executor, db=db)
        findings = db.get_findings_for_target(result["target_id"])

    header_auth_finding = next(f for f in findings if f["finding_type"] == "header_auth_confirmed")
    assert header_auth_finding["status"] == "confirmed"
    assert "flag{header_auth_pipeline_flag}" in header_auth_finding["evidence_summary"]


@patch("core.orchestrator.run_binary_agent")
@patch("core.orchestrator.run_web_agent")
@patch("core.orchestrator.run_network_agent")
def test_llm_rejection_means_no_attempt_runs_even_though_llm_is_on(
    mock_network, mock_web, mock_binary, monkeypatch
):
    import common.llm as llm_module

    monkeypatch.setattr(llm_module, "LLM_ENABLED", True)
    monkeypatch.setattr(llm_module, "_API_KEY", "test-key")
    monkeypatch.setitem(sys.modules, "openai", _fake_openai_module("[]"))  # explicitly rejects everything

    mock_network.return_value = _result(
        follow_up_jobs=[
            {"agent": "web", "target": "10.10.10.5:80", "context": {}},
            {"agent": "binary", "target": "http://10.10.10.5/agent.bin", "context": {}},
        ]
    )
    mock_web.return_value = _result(findings=[PROTECTED_ENDPOINT_FINDING])
    mock_binary.return_value = _result(findings=[CREDENTIAL_PAIR_FINDING])

    get_calls = []

    def _http_get_fn(url, headers=None):
        get_calls.append((url, headers))
        return {"status": 401, "headers": {}, "body": ""}

    executor = MockScopedExecutor(http_get_fn=_http_get_fn)

    with Database(":memory:") as db:
        result = run_and_persist(target="10.10.10.5", executor=executor, db=db)
        findings = db.get_findings_for_target(result["target_id"])

    assert not any(f["finding_type"] == "header_auth_confirmed" for f in findings)
    assert all(headers is None for _url, headers in get_calls)
