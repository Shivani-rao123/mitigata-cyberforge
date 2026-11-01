"""
tests/core/test_pipeline_authenticated_exploration.py

End-to-end test for the full chain the formal requirement spec
describes: a sensitive_endpoint_found finding (401 -- requires auth)
discovered by the web stage, a credential_pair_found finding from a
different (binary) stage, a successful login using it, and a flag that
only lives on that SPECIFIC endpoint -- not the site root -- captured
once the authenticated session re-visits it.
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
    description="Login form found at http://10.10.10.5/admin/login.php (action=/admin/login.php)",
    host="10.10.10.5",
    evidence=Evidence(
        kind="http_response",
        summary="GET http://10.10.10.5/admin/login.php -> 200, form fields: ['password', 'username']",
    ),
)

PROTECTED_ENDPOINT_FINDING = FindingOut(
    finding_type="sensitive_endpoint_found",
    description="Sensitive endpoint /admin/reports responded with HTTP 401",
    host="10.10.10.5",
    evidence=Evidence(kind="http_response", summary="GET http://10.10.10.5/admin/reports -> 401"),
)

CREDENTIAL_PAIR_FINDING = FindingOut(
    finding_type="credential_pair_found",
    description="Username/password pair found hardcoded together in agent.bin",
    host=None,
    evidence=Evidence(kind="strings_credential_pair", summary="username=svc, password=r3**", raw_ref="svc:r3al_pw"),
)


@patch("core.orchestrator.run_binary_agent")
@patch("core.orchestrator.run_web_agent")
@patch("core.orchestrator.run_network_agent")
def test_flag_only_on_a_discovered_endpoint_is_found_via_authenticated_exploration(
    mock_network, mock_web, mock_binary
):
    mock_network.return_value = _result(
        follow_up_jobs=[
            {"agent": "web", "target": "10.10.10.5:80", "context": {}},
            {"agent": "binary", "target": "http://10.10.10.5/agent.bin", "context": {}},
        ]
    )
    mock_web.return_value = _result(findings=[LOGIN_FINDING, PROTECTED_ENDPOINT_FINDING])
    mock_binary.return_value = _result(findings=[CREDENTIAL_PAIR_FINDING])

    def _http_post_fn(url, data):
        if data == {"username": "svc", "password": "r3al_pw"}:
            return {"status": 302, "headers": {"Location": "/admin/dashboard"}, "body": "", "cookies": {"s": "1"}}
        return {"status": 302, "headers": {"Location": "/admin/login.php?error=1"}, "body": ""}

    def _http_get_fn(url, cookies=None):
        if url == "http://10.10.10.5/admin/reports":
            assert cookies == {"s": "1"}
            return {"status": 200, "headers": {}, "body": "quarterly report: flag{endpoint_only_flag}"}
        return {"status": 200, "headers": {}, "body": "nothing here"}

    executor = MockScopedExecutor(http_post_fn=_http_post_fn, http_get_fn=_http_get_fn)

    with Database(":memory:") as db:
        result = run_and_persist(target="10.10.10.5", executor=executor, db=db)

        findings = db.get_findings_for_target(result["target_id"])
        login_finding = next(f for f in findings if f["finding_type"] == "default_creds_found")

        assert login_finding["status"] == "confirmed"
        assert "flag{endpoint_only_flag}" in login_finding["evidence_summary"]
        assert "/admin/reports" in login_finding["evidence_summary"]
        assert "required authentication" in login_finding["evidence_summary"]
