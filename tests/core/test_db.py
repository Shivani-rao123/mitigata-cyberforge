"""
tests/core/test_db.py

Unit tests for core/db.py's Database wrapper — uses an in-memory SQLite
DB (":memory:") so every test starts from a clean, schema-applied slate
with zero file I/O.
"""

from __future__ import annotations

import pytest

from common.contracts import Job
from core.db import Database


@pytest.fixture
def db():
    with Database(":memory:") as d:
        yield d


def test_schema_applies_without_error(db):
    # If __init__ didn't raise, the schema applied. Sanity-check a table
    # that schema.sql defines actually exists and starts empty.
    assert db.list_hosts() == []
    assert db.list_targets() == []


def test_insert_and_list_target(db):
    target_id = db.insert_target("10.10.10.0/24")
    targets = db.list_targets()
    assert len(targets) == 1
    assert targets[0]["id"] == target_id
    assert targets[0]["cidr_or_host"] == "10.10.10.0/24"


def test_get_or_create_host_dedupes_by_ip(db):
    id1 = db.get_or_create_host("10.10.10.5")
    id2 = db.get_or_create_host("10.10.10.5")
    assert id1 == id2
    assert len(db.list_hosts()) == 1


def test_get_or_create_host_fills_in_hostname_later(db):
    host_id = db.get_or_create_host("10.10.10.5")
    db.get_or_create_host("10.10.10.5", hostname="box.local")
    host = db.get_host(host_id)
    assert host["hostname"] == "box.local"


def test_get_or_create_service_dedupes_by_host_port_protocol(db):
    host_id = db.get_or_create_host("10.10.10.5")
    svc1 = db.get_or_create_service(host_id, 80, "tcp", "http")
    svc2 = db.get_or_create_service(host_id, 80, "tcp", "http", version="Werkzeug 3.1")
    assert svc1 == svc2
    services = db.list_services_for_host(host_id)
    assert len(services) == 1
    assert services[0]["version"] == "Werkzeug 3.1"


def test_insert_finding_and_update_status(db):
    host_id = db.get_or_create_host("10.10.10.5")
    finding_id = db.insert_finding(
        host_id=host_id,
        agent="web",
        finding_type="default_creds_found",
        description="Login form found",
        evidence_summary="GET /admin -> 200",
    )
    finding = db.get_finding(finding_id)
    assert finding["status"] == "flagged"

    db.update_finding_status(finding_id, "confirmed", evidence_summary="POST admin:admin -> 302")
    finding = db.get_finding(finding_id)
    assert finding["status"] == "confirmed"
    assert finding["evidence_summary"] == "POST admin:admin -> 302"


def test_set_finding_ptes_phase(db):
    host_id = db.get_or_create_host("10.10.10.5")
    finding_id = db.insert_finding(
        host_id=host_id, agent="network", finding_type="open_port", description="Port 80 open"
    )
    db.set_finding_ptes_phase(finding_id, "Intelligence Gathering")
    assert db.get_finding(finding_id)["ptes_phase"] == "Intelligence Gathering"


def test_attack_edge_links_two_findings(db):
    host_id = db.get_or_create_host("10.10.10.5")
    f1 = db.insert_finding(host_id=host_id, agent="network", finding_type="open_port", description="d1")
    f2 = db.insert_finding(
        host_id=host_id, agent="web", finding_type="default_creds_found", description="d2"
    )
    edge_id = db.insert_attack_edge(f1, f2, note="port led to web login")
    edges = db.list_attack_edges()
    assert len(edges) == 1
    assert edges[0]["from_finding_id"] == f1
    assert edges[0]["to_finding_id"] == f2


def test_pending_job_round_trip(db):
    job = Job(job_id="job-001", agent="web", target="10.10.10.5:80", context={"host_id": 1})
    db.insert_pending_job(job)
    stored = db.get_job("job-001")
    assert stored["status"] == "pending"
    assert stored["agent"] == "web"

    db.update_job_status("job-001", "done")
    assert db.get_job("job-001")["status"] == "done"


def test_scope_log_round_trip(db):
    db.insert_scope_log("10.10.10.5", True)
    db.insert_scope_log("8.8.8.8", False)
    entries = db.list_scope_log()
    assert len(entries) == 2
    assert entries[0]["in_scope"] == 1  # sqlite stores bool as 0/1
    assert entries[1]["in_scope"] == 0


def test_get_findings_for_target_resolves_cidr_containment(db):
    target_id = db.insert_target("10.10.10.0/24")
    host_in = db.get_or_create_host("10.10.10.5")
    host_out = db.get_or_create_host("192.168.1.1")
    f_in = db.insert_finding(host_id=host_in, agent="network", finding_type="open_port", description="d")
    db.insert_finding(host_id=host_out, agent="network", finding_type="open_port", description="d")

    findings = db.get_findings_for_target(target_id)
    assert [f["id"] for f in findings] == [f_in]


def test_get_findings_for_target_falls_back_to_hostname_match(db):
    target_id = db.insert_target("example.internal")
    host_id = db.get_or_create_host("10.10.10.5", hostname="example.internal")
    f_id = db.insert_finding(host_id=host_id, agent="network", finding_type="open_port", description="d")

    findings = db.get_findings_for_target(target_id)
    assert [f["id"] for f in findings] == [f_id]


def test_get_findings_for_unknown_target_returns_empty(db):
    assert db.get_findings_for_target(999) == []


def test_two_databases_do_not_share_state(db):
    db.insert_target("1.2.3.4")
    with Database(":memory:") as other:
        assert other.list_targets() == []
