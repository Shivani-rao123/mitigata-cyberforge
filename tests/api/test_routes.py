"""
tests/api/test_routes.py

Unit tests for api/routes.py's REST API (FR-7, API half). Uses a fresh
in-memory Database per test via api.app.create_app(db=...), so nothing
here touches the real store/cart.db file.
"""

from __future__ import annotations

from unittest.mock import patch

from api.app import create_app
from core.db import Database


def _client_with_db(db):
    app = create_app(db=db)
    return app.test_client()


def test_list_targets_returns_inserted_targets():
    with Database(":memory:") as db:
        db.insert_target("10.10.10.0/24")
        client = _client_with_db(db)

        resp = client.get("/targets")

    assert resp.status_code == 200
    body = resp.get_json()
    assert len(body) == 1
    assert body[0]["cidr_or_host"] == "10.10.10.0/24"


def test_get_target_findings_matches_userflow_step_8_shape():
    with Database(":memory:") as db:
        target_id = db.insert_target("10.10.10.0/24")
        host_id = db.get_or_create_host("10.10.10.5")
        finding_id = db.insert_finding(
            host_id=host_id,
            agent="web",
            finding_type="default_creds_found",
            description="/admin login form, no rate limiting",
            evidence_summary="POST /admin/login with admin:admin -> 302 redirect to /dashboard",
        )
        db.update_finding_status(finding_id, "confirmed")
        db.set_finding_ptes_phase(finding_id, "Exploitation")
        client = _client_with_db(db)

        resp = client.get(f"/targets/{target_id}/findings")

    assert resp.status_code == 200
    body = resp.get_json()
    assert body == [
        {
            "finding_type": "default_creds_found",
            "status": "confirmed",
            "ptes_phase": "Exploitation",
            "evidence": "POST /admin/login with admin:admin -> 302 redirect to /dashboard",
        }
    ]


def test_get_target_findings_for_unknown_target_is_an_empty_list():
    with Database(":memory:") as db:
        client = _client_with_db(db)

        resp = client.get("/targets/999/findings")

    assert resp.status_code == 200
    assert resp.get_json() == []


def test_get_target_report_returns_the_attack_path_as_plain_text():
    with Database(":memory:") as db:
        target_id = db.insert_target("10.10.10.0/24")
        host_id = db.get_or_create_host("10.10.10.5")
        finding_id = db.insert_finding(
            host_id=host_id,
            agent="network",
            finding_type="open_port",
            description="Port 80/tcp open",
            evidence_summary="80/tcp open http",
        )
        db.set_finding_ptes_phase(finding_id, "Intelligence Gathering")
        client = _client_with_db(db)

        resp = client.get(f"/targets/{target_id}/report")

    assert resp.status_code == 200
    assert resp.content_type.startswith("text/plain")
    text = resp.get_data(as_text=True)
    assert "Attack Path:" in text
    assert "1. [Intelligence Gathering] Port 80/tcp open on 10.10.10.5" in text


def test_create_app_constructs_its_own_database_when_none_given():
    # Patches api.app's own Database name rather than touching the real
    # store/cart.db -- this only checks create_app()'s wiring (it
    # builds and stores *something* when no db is passed), not
    # core/db.py's own file-opening behavior, which test_db.py covers.
    sentinel_db = Database(":memory:")

    with patch("api.app.Database", return_value=sentinel_db) as mock_database:
        app = create_app()

    mock_database.assert_called_once_with()
    assert app.config["CART_DB"] is sentinel_db
    sentinel_db.close()
