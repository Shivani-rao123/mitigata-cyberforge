"""
tests/webui/test_app.py

Unit tests for webui/app.py's Flask routes.

The crawler dropdown (and all its katana-availability wording) was
removed from the dashboard per direct user feedback ("remove that
katana part in ui let it work in background") — crawler mode is no
longer a user-facing choice at all; the form always implicitly asks
for "auto" and the web agent decides for itself whether katana is
usable this run, falling back silently (surfaced as a crawler_fallback
finding, not UI chrome) if not. VALID_CRAWLER_MODES / the crawler
param itself are UNCHANGED in app.py — only the dashboard stopped
exposing them — so main.py/run_pipeline.py callers passing an explicit
crawler mode are unaffected.
"""

from unittest.mock import patch

from common.contracts import Evidence, FindingOut, HostOut, JobResult, ServiceOut
from webui.app import app


def _get_index():
    with app.test_client() as c:
        return c.get("/").data.decode()


def test_index_page_has_no_crawler_selector_or_katana_wording():
    html = _get_index()
    assert "katana" not in html.lower()
    assert 'name="crawler"' not in html


def test_scan_error_path_also_has_no_crawler_or_katana_wording():
    with app.test_client() as c:
        html = c.post("/scan", data={"target": ""}).data.decode()
    assert "Target is required." in html
    assert "katana" not in html.lower()
    assert 'name="crawler"' not in html


@patch("webui.app.run_target")
def test_scan_without_a_crawler_field_still_defaults_to_auto_mode(mock_run_target):
    """The dashboard form no longer sends a crawler field at all (the
    dropdown is gone) — /scan's own request.form.get("crawler", "auto")
    default must still carry the run, so the web agent's crawl
    behavior doesn't silently change just because the UI stopped
    asking the user to pick."""
    from core.orchestrator import OrchestrationResult

    mock_run_target.return_value = OrchestrationResult(target="127.0.0.1")

    with app.test_client() as c:
        c.post("/scan", data={"target": "127.0.0.1", "scope": "127.0.0.1/32"})

    mock_run_target.assert_called_once()
    _, kwargs = mock_run_target.call_args
    assert kwargs["crawler"] == "auto"


def test_scan_route_uses_the_fr4_concurrent_orchestrator_not_the_old_sequential_chain():
    """
    Regression guard for the FR-4 wiring: /scan must call
    core.orchestrator.run_target (new, concurrent, agent-count-agnostic)
    and render its OrchestrationResult, not webui.orchestrate.run_full_chain
    (the old synchronous chain this dashboard used before). All three
    agents are mocked here so this test needs no real network/nmap and
    runs the same whether or not the machine has katana.
    """

    def _result(findings=None, follow_up_jobs=None):
        return JobResult(
            job_id="x", status="completed", findings=findings or [], follow_up_jobs=follow_up_jobs or []
        )

    def _finding(finding_type="open_port"):
        return FindingOut(
            finding_type=finding_type, description="d", evidence=Evidence(kind="k", summary="s")
        )

    with (
        patch("core.orchestrator.run_network_agent") as mock_network,
        patch("core.orchestrator.run_web_agent") as mock_web,
        patch("core.orchestrator.run_binary_agent") as mock_binary,
        # webui.app's own module-level import of run_full_chain is gone;
        # if something reintroduced it, this guard would fail the
        # assertion below rather than silently passing either way.
    ):
        mock_network.return_value = _result(
            findings=[_finding("open_port")],
            follow_up_jobs=[{"agent": "web", "target": "127.0.0.1:80", "context": {}}],
        )
        mock_web.return_value = _result(findings=[_finding("missing_security_header")])

        with app.test_client() as c:
            resp = c.post(
                "/scan", data={"target": "127.0.0.1", "scope": "127.0.0.1/32", "crawler": "requests"}
            )

    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "open_port" in html
    assert "missing_security_header" in html
    mock_network.assert_called_once()
    mock_web.assert_called_once()
    mock_binary.assert_not_called()


def test_results_page_keeps_real_findings_out_of_the_operational_notes_pane():
    """UI-only regression: a real scan against a file-manager-style
    target produces a dozen redirect_followed notes for every finding
    that actually matters. categorize_chain()/results.html must keep
    the genuine finding (missing_security_header, in the "Issues" tab
    pane) structurally separate from the operational noise
    (redirect_followed, crawler_fallback, in the "Operational notes"
    tab pane) — each its own <section>, with the sidebar's count badge
    telling the reader how much noise is in the latter without having
    to open it — rather than interleaving them in whatever order the
    agent happened to produce them."""

    def _finding(finding_type):
        return FindingOut(
            finding_type=finding_type, description=f"desc for {finding_type}", evidence=Evidence(kind="k", summary="s")
        )

    network_result = JobResult(
        job_id="x",
        status="completed",
        findings=[],
        follow_up_jobs=[{"agent": "web", "target": "1.2.3.4:80", "context": {}}],
    )
    web_result = JobResult(
        job_id="x",
        status="completed",
        findings=[
            _finding("crawler_fallback"),
            _finding("missing_security_header"),
            *[_finding("redirect_followed") for _ in range(11)],
        ],
    )

    with (
        patch("core.orchestrator.run_network_agent", return_value=network_result),
        patch("core.orchestrator.run_web_agent", return_value=web_result),
    ):
        with app.test_client() as c:
            resp = c.post("/scan", data={"target": "1.2.3.4", "scope": "1.2.3.4/32"})

    html = resp.get_data(as_text=True)
    assert resp.status_code == 200
    # Sidebar badge shows the operational count (crawler_fallback + 11
    # redirect_followed) without needing to open that tab.
    assert '>12</span>' in html
    # Structurally separate panes: the Issues section (with the real
    # finding) is written before the Operational notes section.
    assert html.index('id="issues"') < html.index('id="operational"')
    issues_section = html[html.index('id="issues"') : html.index('id="operational"')]
    assert "missing_security_header" in issues_section
    assert "redirect_followed" not in issues_section


def test_results_page_splits_findings_into_separate_category_cards():
    """UI regression for the follow-up feedback: "web part network open
    port live hosts and services in scope endpoint flag common issue is
    messed into one place" — open_port goes in the Hosts & Open Ports
    card (with the live host/service list), sensitive_endpoint_found in
    Endpoints, missing_security_header in Issues, and crawler_fallback/
    redirect_followed stay collapsed in Operational notes — four
    distinct cards, not one flat pile."""

    def _finding(finding_type):
        return FindingOut(
            finding_type=finding_type, description=f"desc for {finding_type}", evidence=Evidence(kind="k", summary="s")
        )

    network_result = JobResult(
        job_id="x",
        status="completed",
        hosts=[HostOut(ip="10.10.10.5", services=[ServiceOut(port=80, protocol="tcp", service="http")])],
        findings=[_finding("open_port")],
        follow_up_jobs=[{"agent": "web", "target": "10.10.10.5:80", "context": {}}],
    )
    web_result = JobResult(
        job_id="x",
        status="completed",
        findings=[
            _finding("sensitive_endpoint_found"),
            _finding("missing_security_header"),
            _finding("crawler_fallback"),
            _finding("redirect_followed"),
        ],
    )

    with (
        patch("core.orchestrator.run_network_agent", return_value=network_result),
        patch("core.orchestrator.run_web_agent", return_value=web_result),
    ):
        with app.test_client() as c:
            resp = c.post("/scan", data={"target": "10.10.10.5", "scope": "10.10.10.0/24"})

    html = resp.get_data(as_text=True)
    assert resp.status_code == 200
    assert 'id="hosts"' in html and 'id="endpoints"' in html and 'id="issues"' in html and 'id="operational"' in html

    hosts_card = html[html.index('id="hosts"') : html.index('id="endpoints"')]
    endpoints_card = html[html.index('id="endpoints"') : html.index('id="issues"')]
    issues_card = html[html.index('id="issues"') : html.index('id="operational"')]
    operational_card = html[html.index('id="operational"') :]

    assert "10.10.10.5" in hosts_card and "open_port" in hosts_card
    assert "sensitive_endpoint_found" in endpoints_card
    assert "missing_security_header" in issues_card
    assert "crawler_fallback" in operational_card and "redirect_followed" in operational_card
    # none of the other three cards leak findings that belong elsewhere
    assert "sensitive_endpoint_found" not in hosts_card and "missing_security_header" not in hosts_card
    assert "open_port" not in issues_card and "missing_security_header" not in endpoints_card


def test_categorize_chain_buckets_findings_by_category_not_by_stage():
    from webui.app import categorize_chain

    def _finding(finding_type):
        return FindingOut(
            finding_type=finding_type, description="d", evidence=Evidence(kind="k", summary="s")
        )

    class _Stage:
        def __init__(self, agent, target, result):
            self.agent = agent
            self.target = target
            self.result = result
            self.error = None

    class _Chain:
        def __init__(self, stages):
            self.stages = stages

    stages = [
        _Stage(
            "network",
            "10.10.10.5",
            JobResult(
                job_id="x",
                status="completed",
                hosts=[HostOut(ip="10.10.10.5")],
                findings=[_finding("open_port")],
            ),
        ),
        _Stage(
            "web",
            "10.10.10.5:80",
            JobResult(
                job_id="x",
                status="completed",
                findings=[
                    _finding("js_endpoint_found"),
                    _finding("hardcoded_secret"),
                    _finding("redirect_followed"),
                ],
            ),
        ),
    ]

    categories = categorize_chain(_Chain(stages))

    assert [e["finding"].finding_type for e in categories["hosts"]] == ["open_port"]
    assert [e["finding"].finding_type for e in categories["endpoints"]] == ["js_endpoint_found"]
    assert [e["finding"].finding_type for e in categories["issues"]] == ["hardcoded_secret"]
    assert [e["finding"].finding_type for e in categories["operational"]] == ["redirect_followed"]
    assert [h.ip for h in categories["live_hosts"]] == ["10.10.10.5"]


def test_scan_route_chains_a_binary_credential_into_an_uncrawled_conventional_login_path():
    """Direct regression for the real lab-run failure report: a scan
    run through THIS route (the dashboard) produced a correctly
    extracted credential_pair_found finding but no login attempt and
    no flag, because this route has no verification step at all by
    design. webui.app._apply_credential_chaining() is the fix -- it
    must fire here even though /scan never touches core/pipeline.py or
    a database."""

    def _finding(finding_type, **kwargs):
        return FindingOut(
            finding_type=finding_type, description=kwargs.get("description", "d"),
            host=kwargs.get("host"),
            evidence=Evidence(
                kind="k", summary=kwargs.get("summary", "s"), raw_ref=kwargs.get("raw_ref")
            ),
        )

    network_result = JobResult(
        job_id="x",
        status="completed",
        findings=[],
        follow_up_jobs=[
            {"agent": "web", "target": "10.152.241.236:8085", "context": {}},
            {"agent": "binary", "target": "http://10.152.241.236:8085/agent.bin", "context": {}},
        ],
    )
    # A login form the crawler DID find, unrelated to the real creds --
    # forces _apply_credential_chaining to fall through to the
    # conventional-path guesswork, same as the real failed scan.
    web_result = JobResult(
        job_id="x",
        status="completed",
        findings=[
            _finding(
                "default_creds_found",
                description="Login form found at http://10.152.241.236:8085/admin (action=/admin)",
                host="10.152.241.236",
                summary="GET http://10.152.241.236:8085/admin -> 200, form fields: ['password', 'username']",
            )
        ],
    )
    binary_result = JobResult(
        job_id="x",
        status="completed",
        findings=[
            _finding(
                "credential_pair_found",
                description="Username/password pair found hardcoded together in agent.bin",
                summary="username=cartlab, password=B1**",
                raw_ref="cartlab:B1na_917",
            )
        ],
    )

    def _http_post_fn(url, data):
        if url == "http://10.152.241.236:8085/admin":
            return {"status": 302, "headers": {"Location": "/admin?error=1"}, "body": ""}
        if url == "http://10.152.241.236:8085/lab/login" and data == {
            "username": "cartlab",
            "password": "B1na_917",
        }:
            return {"status": 302, "headers": {"Location": "/lab/dashboard"}, "body": "", "cookies": {}}
        return {"status": 404, "headers": {}, "body": ""}

    with (
        patch("core.orchestrator.run_network_agent", return_value=network_result),
        patch("core.orchestrator.run_web_agent", return_value=web_result),
        patch("core.orchestrator.run_binary_agent", return_value=binary_result),
        patch("webui.app.RealScopedExecutor") as mock_executor_cls,
    ):
        from tests.mock_executor import MockScopedExecutor

        mock_executor_cls.return_value = MockScopedExecutor(http_post_fn=_http_post_fn)

        with app.test_client() as c:
            resp = c.post(
                "/scan", data={"target": "10.152.241.236", "scope": "10.152.241.236/32"}
            )

    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "lab/login" in html
    assert "not discovered by crawling" in html
    assert "cartlab:B1na_917" in html


def test_header_auth_does_not_run_through_the_dashboard_when_llm_is_off(monkeypatch):
    """webui.app._apply_credential_chaining()'s header-auth pass is
    fail-CLOSED, same as core/pipeline.py's: with LLM_ENABLED False
    (the default), no Authorization-header attempt happens at all,
    even with a real credential_pair_found and a 401 endpoint present."""
    import common.llm as llm_module

    monkeypatch.setattr(llm_module, "LLM_ENABLED", False)

    def _finding(finding_type, **kwargs):
        return FindingOut(
            finding_type=finding_type,
            description=kwargs.get("description", "d"),
            host=kwargs.get("host"),
            evidence=Evidence(kind="k", summary=kwargs.get("summary", "s"), raw_ref=kwargs.get("raw_ref")),
        )

    network_result = JobResult(
        job_id="x",
        status="completed",
        findings=[],
        follow_up_jobs=[
            {"agent": "web", "target": "10.10.10.5:8085", "context": {}},
            {"agent": "binary", "target": "http://10.10.10.5:8085/agent.bin", "context": {}},
        ],
    )
    web_result = JobResult(
        job_id="x",
        status="completed",
        findings=[
            _finding(
                "sensitive_endpoint_found",
                description="Sensitive endpoint /api/data responded with HTTP 401",
                host="10.10.10.5",
                summary="GET http://10.10.10.5:8085/api/data -> 401",
            )
        ],
    )
    binary_result = JobResult(
        job_id="x",
        status="completed",
        findings=[
            _finding(
                "credential_pair_found",
                description="Username/password pair found hardcoded together in agent.bin",
                summary="username=svc, password=r3**",
                raw_ref="svc:r3al_pw",
            )
        ],
    )

    get_calls = []

    def _http_get_fn(url, headers=None):
        get_calls.append((url, headers))
        return {"status": 401, "headers": {}, "body": ""}

    with (
        patch("core.orchestrator.run_network_agent", return_value=network_result),
        patch("core.orchestrator.run_web_agent", return_value=web_result),
        patch("core.orchestrator.run_binary_agent", return_value=binary_result),
        patch("webui.app.RealScopedExecutor") as mock_executor_cls,
    ):
        from tests.mock_executor import MockScopedExecutor

        mock_executor_cls.return_value = MockScopedExecutor(http_get_fn=_http_get_fn)

        with app.test_client() as c:
            resp = c.post("/scan", data={"target": "10.10.10.5", "scope": "10.10.10.5/32"})

    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "header_auth_confirmed" not in html
    assert all(headers is None for _url, headers in get_calls)


def test_webui_app_module_does_not_import_the_old_sequential_chain():
    """run_full_chain (webui/orchestrate.py) was the pre-FR-4 dashboard
    path. It must stay importable (its own tests still cover it) but
    webui/app.py itself must no longer reference it, or a scan would be
    silently back on the slow sequential path this work replaced."""
    import webui.app as app_module

    assert not hasattr(app_module, "run_full_chain")
    assert hasattr(app_module, "run_target")


def test_remediation_filter_returns_plain_english_fix_text():
    from webui.app import remediation_filter

    text = remediation_filter("hardcoded_secret")
    assert text is not None
    assert "rotate" in text.lower()


def test_remediation_filter_returns_none_for_operational_notes():
    from webui.app import remediation_filter

    assert remediation_filter("redirect_followed") is None


def test_results_page_shows_how_to_fix_text_for_a_real_finding():
    """PRD Bonus B-3 end-to-end: a real finding on the results page
    carries its plain-English fix right next to it, not just the raw
    finding_type/description."""

    def _finding(finding_type):
        return FindingOut(
            finding_type=finding_type, description=f"desc for {finding_type}", evidence=Evidence(kind="k", summary="s")
        )

    network_result = JobResult(
        job_id="x",
        status="completed",
        findings=[],
        follow_up_jobs=[{"agent": "web", "target": "1.2.3.4:80", "context": {}}],
    )
    web_result = JobResult(job_id="x", status="completed", findings=[_finding("missing_security_header")])

    with patch("core.orchestrator.run_network_agent", return_value=network_result):
        with patch("core.orchestrator.run_web_agent", return_value=web_result):
            with app.test_client() as c:
                resp = c.post("/scan", data={"target": "1.2.3.4", "scope": "1.2.3.4/32"})

    html = resp.get_data(as_text=True)
    assert resp.status_code == 200
    assert "How to fix:" in html
    assert "X-Frame-Options" in html or "header" in html.lower()
