"""
tests/core/test_pipeline_credential_chaining.py

End-to-end wiring test for the credential-chaining feature: a
credential_pair_found finding from a binary stage (anywhere in the
run) must reach verification/verifier.py's login-probe step for a
default_creds_found finding from a DIFFERENT (web) stage — the exact
chain a real review flagged as missing: "binary has hardcoded creds ->
those should get tried against a login form -> a successful login
should lead to a flag".
"""

from __future__ import annotations

from unittest.mock import patch

from common.contracts import Evidence, FindingOut, JobResult
from core.db import Database
from core.pipeline import run_and_persist
from tests.mock_executor import MockScopedExecutor


def _result(findings=None, follow_up_jobs=None):
    return JobResult(job_id="x", status="completed", findings=findings or [], follow_up_jobs=follow_up_jobs or [])


LOGIN_FINDING = FindingOut(
    finding_type="default_creds_found",
    description=(
        "Login form found at http://10.10.10.5/admin/login.php "
        "(action=/admin/login.php) — candidate for default-credential testing"
    ),
    host="10.10.10.5",
    evidence=Evidence(
        kind="http_response",
        summary="GET http://10.10.10.5/admin/login.php -> 200, form fields: ['password', 'username']",
    ),
)

CREDENTIAL_PAIR_FINDING = FindingOut(
    finding_type="credential_pair_found",
    description="Username/password pair found hardcoded together in agent.bin",
    host=None,
    evidence=Evidence(
        kind="strings_credential_pair",
        summary="username=svc_account, password=r3**",
        raw_ref="svc_account:r3al_pw",
    ),
)


@patch("core.orchestrator.run_binary_agent")
@patch("core.orchestrator.run_web_agent")
@patch("core.orchestrator.run_network_agent")
def test_binary_derived_credential_confirms_a_login_form_from_a_different_stage(
    mock_network, mock_web, mock_binary
):
    mock_network.return_value = _result(
        follow_up_jobs=[
            {"agent": "web", "target": "10.10.10.5:80", "context": {}},
            {"agent": "binary", "target": "http://10.10.10.5/agent.bin", "context": {}},
        ]
    )
    mock_web.return_value = _result(findings=[LOGIN_FINDING])
    mock_binary.return_value = _result(findings=[CREDENTIAL_PAIR_FINDING])

    def _http_post_fn(url, data):
        if data == {"username": "svc_account", "password": "r3al_pw"}:
            return {"status": 302, "headers": {"Location": "/admin/dashboard"}, "body": "", "cookies": {}}
        return {"status": 302, "headers": {"Location": "/admin/login.php?error=1"}, "body": ""}

    executor = MockScopedExecutor(http_post_fn=_http_post_fn)

    with Database(":memory:") as db:
        result = run_and_persist(target="10.10.10.5", executor=executor, db=db)

        findings = db.get_findings_for_target(result["target_id"])
        login_finding = next(f for f in findings if f["finding_type"] == "default_creds_found")

        assert login_finding["status"] == "confirmed"
        assert "svc_account:r3al_pw" in login_finding["evidence_summary"]


@patch("core.orchestrator.run_binary_agent")
@patch("core.orchestrator.run_web_agent")
@patch("core.orchestrator.run_network_agent")
def test_no_credential_pair_findings_leaves_the_weak_list_as_the_only_option(
    mock_network, mock_web, mock_binary
):
    # Regression: a run with no credential_pair_found anywhere must not
    # crash building an empty extra_credentials list, and must still
    # fall back to the generic weak-credential list exactly as before
    # this feature existed.
    mock_network.return_value = _result(follow_up_jobs=[{"agent": "web", "target": "10.10.10.5:80", "context": {}}])
    mock_web.return_value = _result(findings=[LOGIN_FINDING])
    mock_binary.return_value = _result()

    def _http_post_fn(url, data):
        if data == {"username": "admin", "password": "admin"}:
            return {"status": 302, "headers": {"Location": "/admin/dashboard"}, "body": ""}
        return {"status": 302, "headers": {"Location": "/admin/login.php?error=1"}, "body": ""}

    executor = MockScopedExecutor(http_post_fn=_http_post_fn)

    with Database(":memory:") as db:
        result = run_and_persist(target="10.10.10.5", executor=executor, db=db)

        findings = db.get_findings_for_target(result["target_id"])
        login_finding = next(f for f in findings if f["finding_type"] == "default_creds_found")

        assert login_finding["status"] == "confirmed"
        assert "admin:admin" in login_finding["evidence_summary"]
