"""
tests/agents/test_network_agent_edge_cases.py

Edge cases beyond the happy path already covered in test_network_agent.py.
"""

from agents.network.agent import run
from common.contracts import Job
from tests.mock_executor import MockScopedExecutor


def _job(target="10.10.10.0/24"):
    return Job(job_id="job-edge", agent="network", target=target, allowed_ports=[22, 80, 443])


def test_host_with_zero_open_services_is_recorded_with_no_findings():
    executor = MockScopedExecutor(scan_result={
        "hosts": [{"ip": "10.10.10.20", "hostname": None, "services": []}]
    })
    result = run(_job(), executor)

    assert len(result.hosts) == 1
    assert result.hosts[0].services == []
    assert result.findings == []
    assert result.follow_up_jobs == []


def test_empty_service_name_does_not_crash_and_is_not_treated_as_web():
    executor = MockScopedExecutor(scan_result={
        "hosts": [{"ip": "10.10.10.21", "hostname": None,
                    "services": [{"port": 3000, "protocol": "tcp", "service": "", "version": None}]}]
    })
    result = run(_job(), executor)

    assert len(result.findings) == 1  # still an open_port finding
    assert result.follow_up_jobs == []  # but no web job for an unnamed service


def test_https_service_also_triggers_a_web_follow_up_job():
    executor = MockScopedExecutor(scan_result={
        "hosts": [{"ip": "10.10.10.22", "hostname": None,
                    "services": [{"port": 443, "protocol": "tcp", "service": "https", "version": None}]}]
    })
    result = run(_job(), executor)

    assert len(result.follow_up_jobs) == 1
    assert result.follow_up_jobs[0]["target"] == "10.10.10.22:443"


def test_service_name_matching_is_case_insensitive():
    executor = MockScopedExecutor(scan_result={
        "hosts": [{"ip": "10.10.10.23", "hostname": None,
                    "services": [{"port": 80, "protocol": "tcp", "service": "HTTP", "version": None}]}]
    })
    result = run(_job(), executor)

    assert len(result.follow_up_jobs) == 1


def test_two_web_services_on_same_host_produce_two_separate_follow_up_jobs():
    executor = MockScopedExecutor(scan_result={
        "hosts": [{"ip": "10.10.10.24", "hostname": None, "services": [
            {"port": 80, "protocol": "tcp", "service": "http", "version": None},
            {"port": 443, "protocol": "tcp", "service": "https", "version": None},
        ]}]
    })
    result = run(_job(), executor)

    targets = {j["target"] for j in result.follow_up_jobs}
    assert targets == {"10.10.10.24:80", "10.10.10.24:443"}


def test_large_number_of_hosts_does_not_crash_and_counts_correctly():
    hosts = [
        {"ip": f"10.10.10.{i}", "hostname": None,
         "services": [{"port": 80, "protocol": "tcp", "service": "http", "version": None}]}
        for i in range(2, 102)  # 100 hosts
    ]
    executor = MockScopedExecutor(scan_result={"hosts": hosts})
    result = run(_job(), executor)

    assert len(result.hosts) == 100
    assert len(result.findings) == 100
    assert len(result.follow_up_jobs) == 100


def test_missing_version_key_entirely_does_not_crash():
    # version omitted entirely, not just None
    executor = MockScopedExecutor(scan_result={
        "hosts": [{"ip": "10.10.10.25", "hostname": None,
                    "services": [{"port": 22, "protocol": "tcp", "service": "ssh"}]}]
    })
    result = run(_job(), executor)
    assert result.hosts[0].services[0].version is None