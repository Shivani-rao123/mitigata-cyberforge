"""
tests/core/test_pipeline_conventional_login_fallback.py

Covers core/pipeline.py's pass 2.5 — the fallback that fires when a
credential_pair_found finding exists but no default_creds_found
finding from a CRAWLED login form ever confirmed it (pass 2). This is
exactly the real lab-run gap: the web agent crawled /admin and
/controls/login (so a default_creds_found finding exists and gets
tried, but with the WRONG credentials attached to it, or it simply
fails), while the lab's real endpoint, /lab/login, was never crawled
at all. Pass 2.5 tries the binary-derived credential directly against
a short list of conventional paths on the web stage's own host.
"""

from __future__ import annotations

from unittest.mock import patch

from common.contracts import Evidence, FindingOut, JobResult
from core.db import Database
from core.pipeline import run_and_persist
from tests.mock_executor import MockScopedExecutor


def _result(findings=None, follow_up_jobs=None):
    return JobResult(job_id="x", status="completed", findings=findings or [], follow_up_jobs=follow_up_jobs or [])


# A login form the crawler DID find, but the binary's credential doesn't
# work against it -- forces pass 2 to leave any_default_creds_confirmed
# False, so pass 2.5 has to do the real work.
UNRELATED_LOGIN_FINDING = FindingOut(
    finding_type="default_creds_found",
    description="Login form found at http://10.152.241.236:8085/admin (action=/admin)",
    host="10.152.241.236",
    evidence=Evidence(
        kind="http_response",
        summary="GET http://10.152.241.236:8085/admin -> 200, form fields: ['password', 'username']",
    ),
)

CREDENTIAL_PAIR_FINDING = FindingOut(
    finding_type="credential_pair_found",
    description="Username/password pair found hardcoded together in agent.bin",
    host=None,
    evidence=Evidence(
        kind="strings_credential_pair",
        summary="username=cartlab, password=B1**",
        raw_ref="cartlab:B1na_917",
    ),
)


@patch("core.orchestrator.run_binary_agent")
@patch("core.orchestrator.run_web_agent")
@patch("core.orchestrator.run_network_agent")
def test_uncrawled_lab_login_is_still_confirmed_via_conventional_path_fallback(
    mock_network, mock_web, mock_binary
):
    mock_network.return_value = _result(
        follow_up_jobs=[
            {"agent": "web", "target": "10.152.241.236:8085", "context": {}},
            {"agent": "binary", "target": "http://10.152.241.236:8085/agent.bin", "context": {}},
        ]
    )
    mock_web.return_value = _result(findings=[UNRELATED_LOGIN_FINDING])
    mock_binary.return_value = _result(findings=[CREDENTIAL_PAIR_FINDING])

    def _http_post_fn(url, data):
        # The crawled /admin form rejects the credential outright...
        if url == "http://10.152.241.236:8085/admin":
            return {"status": 302, "headers": {"Location": "/admin?error=1"}, "body": ""}
        # ...but the uncrawled, conventional /lab/login path accepts it.
        if url == "http://10.152.241.236:8085/lab/login" and data == {
            "username": "cartlab",
            "password": "B1na_917",
        }:
            return {"status": 302, "headers": {"Location": "/lab/dashboard"}, "body": "", "cookies": {}}
        return {"status": 404, "headers": {}, "body": ""}

    executor = MockScopedExecutor(http_post_fn=_http_post_fn)

    with Database(":memory:") as db:
        result = run_and_persist(target="10.152.241.236", executor=executor, db=db)

        findings = db.get_findings_for_target(result["target_id"])
        confirmed = [f for f in findings if f["finding_type"] == "default_creds_found" and f["status"] == "confirmed"]

        assert len(confirmed) == 1
        assert "lab/login" in confirmed[0]["evidence_summary"]
        assert "not discovered by crawling" in confirmed[0]["evidence_summary"]


@patch("core.orchestrator.run_binary_agent")
@patch("core.orchestrator.run_web_agent")
@patch("core.orchestrator.run_network_agent")
def test_fallback_is_skipped_once_a_crawled_form_already_confirmed_the_credential(
    mock_network, mock_web, mock_binary
):
    # Regression: when the crawled form itself confirms the credential
    # (pass 2), pass 2.5 must not fire at all -- no extra requests to a
    # path that was never crawled, since the real one already worked.
    mock_network.return_value = _result(
        follow_up_jobs=[
            {"agent": "web", "target": "10.152.241.236:8085", "context": {}},
            {"agent": "binary", "target": "http://10.152.241.236:8085/agent.bin", "context": {}},
        ]
    )
    mock_web.return_value = _result(findings=[UNRELATED_LOGIN_FINDING])
    mock_binary.return_value = _result(findings=[CREDENTIAL_PAIR_FINDING])

    attempted_urls = []

    def _http_post_fn(url, data):
        attempted_urls.append(url)
        if url == "http://10.152.241.236:8085/admin" and data == {
            "username": "cartlab",
            "password": "B1na_917",
        }:
            return {"status": 302, "headers": {"Location": "/admin/dashboard"}, "body": ""}
        return {"status": 302, "headers": {"Location": "/admin?error=1"}, "body": ""}

    executor = MockScopedExecutor(http_post_fn=_http_post_fn)

    with Database(":memory:") as db:
        run_and_persist(target="10.152.241.236", executor=executor, db=db)

    conventional_paths = ("/login", "/admin/login", "/lab/login", "/auth/login", "/signin")
    assert not any(url.endswith(path) for url in attempted_urls for path in conventional_paths)
