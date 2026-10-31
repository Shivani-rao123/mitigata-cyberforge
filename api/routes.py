"""
api/routes.py

FR-7 (REST API half): a small, read-only Flask Blueprint over whatever
core/db.py has already persisted. Matches userflow.md's Step 8 example
exactly:

    GET /targets/1/findings
    -> [
        {
          "finding_type": "default_creds_found",
          "status": "confirmed",
          "ptes_phase": "Exploitation",
          "evidence": "POST /admin/login with admin:admin -> 302 redirect to /dashboard"
        }
      ]

This blueprint doesn't open or own a Database itself — api/app.py wires
one in via app.config["CART_DB"] — so it has no opinion about where
the DB file lives or how the app is started, and stays easy to test
with a throwaway in-memory Database.
"""

from __future__ import annotations

from flask import Blueprint, current_app, jsonify

from reporting.report_generator import build_attack_path

bp = Blueprint("api", __name__)


def _db():
    return current_app.config["CART_DB"]


def _serialize_finding(finding: dict) -> dict:
    """Matches userflow.md's Step 8 field names exactly: finding_type,
    status, ptes_phase, evidence (the finding's evidence_summary,
    renamed on the way out since the DB column name is an
    implementation detail the API shouldn't leak)."""
    return {
        "finding_type": finding["finding_type"],
        "status": finding["status"],
        "ptes_phase": finding.get("ptes_phase"),
        "evidence": finding.get("evidence_summary"),
    }


@bp.route("/targets", methods=["GET"])
def list_targets():
    return jsonify(_db().list_targets())


@bp.route("/targets/<int:target_id>/findings", methods=["GET"])
def get_target_findings(target_id: int):
    findings = _db().get_findings_for_target(target_id)
    return jsonify([_serialize_finding(f) for f in findings])


@bp.route("/targets/<int:target_id>/report", methods=["GET"])
def get_target_report(target_id: int):
    """The same Attack Path narrative reporting/report_generator.py
    builds, as plain text — a judge/demo-friendly way to see the
    end-to-end result without parsing JSON by hand."""
    report = build_attack_path(_db(), target_id)
    return current_app.response_class(report, mimetype="text/plain")
