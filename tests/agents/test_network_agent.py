"""
tests/agents/test_network_agent.py

Unit tests for the network agent. Uses MockScopedExecutor — no real network,
no dependency on core being finished.
"""

from agents.network.agent import run
from common.contracts import Job
from tests.mock_executor import MockScopedExecutor


def _make_job() -> Job:
    return Job(
        job_id="job-001",
        agent="network",
        target="10.10.10.0/24",
        allowed_ports=[22, 80, 443, 9999],
    )


def test_parses_hosts_and_services_from_fixture():
    executor = MockScopedExecutor()  # loads fixtures/sample_nmap_scan.json
    result = run(_make_job(), executor)

    assert result.status == "completed"
    assert result.job_id == "job-001"

    ips = {h.ip for h in result.hosts}
    assert ips == {"10.10.10.5", "10.10.10.9"}

    host_5 = next(h for h in result.hosts if h.ip == "10.10.10.5")
    ports = {s.port for s in host_5.services}
    assert ports == {80, 22}


def test_emits_open_port_finding_per_service():
    executor = MockScopedExecutor()
    result = run(_make_job(), executor)

    # 3 services total across both hosts in the fixture -> 3 open_port findings
    open_port_findings = [f for f in result.findings if f.finding_type == "open_port"]
    assert len(open_port_findings) == 3
    assert all(f.evidence.kind == "nmap_output" for f in open_port_findings)


def test_http_service_triggers_exactly_one_web_follow_up_job():
    executor = MockScopedExecutor()
    result = run(_make_job(), executor)

    web_jobs = [j for j in result.follow_up_jobs if j["agent"] == "web"]
    assert len(web_jobs) == 1
    assert web_jobs[0]["target"] == "10.10.10.5:80"


def test_non_web_service_does_not_trigger_a_web_job():
    executor = MockScopedExecutor()
    result = run(_make_job(), executor)

    # port 22 (ssh) and port 9999 (unknown) must not produce web follow-ups
    web_targets = {j["target"] for j in result.follow_up_jobs if j["agent"] == "web"}
    assert "10.10.10.5:22" not in web_targets
    assert "10.10.10.9:9999" not in web_targets


def test_empty_scan_result_produces_no_hosts_or_findings():
    executor = MockScopedExecutor(scan_result={"hosts": []})
    result = run(_make_job(), executor)

    assert result.status == "completed"
    assert result.hosts == []
    assert result.findings == []
    assert result.follow_up_jobs == []


def test_llm_disabled_by_default_leaves_the_rule_based_follow_up_jobs_untouched(monkeypatch):
    """common/llm.py's choose_follow_ups() is off by default
    (CART_LLM_FOLLOWUPS unset) — confirms wiring it into this agent
    didn't change its own default, already-tested behavior at all."""
    import common.llm as llm_module

    monkeypatch.setattr(llm_module, "LLM_ENABLED", False)
    executor = MockScopedExecutor()

    result = run(_make_job(), executor)

    web_jobs = [j for j in result.follow_up_jobs if j["agent"] == "web"]
    assert len(web_jobs) == 1
    assert web_jobs[0]["target"] == "10.10.10.5:80"


def test_llm_enabled_can_filter_down_the_rule_based_candidates(monkeypatch):
    """When explicitly turned on and the model rejects every candidate
    (an empty [] response), the agent's own follow_up_jobs reflects
    that -- proving the LLM layer actually reaches this agent's return
    value, not just common/llm.py in isolation."""
    import sys
    import types
    from unittest.mock import MagicMock

    import common.llm as llm_module

    monkeypatch.setattr(llm_module, "LLM_ENABLED", True)

    fake_module = types.ModuleType("openai")

    class _FakeOpenAI:
        def __init__(self, *args, **kwargs):
            self.chat = MagicMock()
            message = MagicMock(content="[]")
            self.chat.completions.create.return_value = MagicMock(choices=[MagicMock(message=message)])

    fake_module.OpenAI = _FakeOpenAI
    monkeypatch.setitem(sys.modules, "openai", fake_module)

    executor = MockScopedExecutor()
    result = run(_make_job(), executor)

    assert result.follow_up_jobs == []