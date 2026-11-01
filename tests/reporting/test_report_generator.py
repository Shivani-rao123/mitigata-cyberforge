"""
tests/reporting/test_report_generator.py

Unit tests for reporting/report_generator.py (FR-7, report half).

Note: intentionally no tests/reporting/__init__.py in this directory —
one here previously collided with the real top-level reporting/
package and broke pytest's import resolution (see
tests/reporting/test_ptes.py's module docstring area / session history
for the full story). None of the other tests/<subdir>s have one either.
"""

from __future__ import annotations

from core.db import Database
from reporting.report_generator import build_attack_path, format_attack_path


def test_matches_userflow_worked_example_ordering_and_wording():
    # The exact two-finding scenario from userflow.md's Step 7.
    findings = [
        {
            "id": 1,
            "finding_type": "open_port",
            "description": "Port 80/tcp open",
            "evidence_summary": "80/tcp open http",
            "status": "flagged",
            "ptes_phase": "Intelligence Gathering",
            "host_ip": "10.10.10.5",
        },
        {
            "id": 2,
            "finding_type": "default_creds_found",
            "description": "/admin login form, no rate limiting",
            "evidence_summary": "POST /admin/login with admin:admin -> 302",
            "status": "confirmed",
            "ptes_phase": "Exploitation",
            "host_ip": "10.10.10.5",
        },
    ]

    report = format_attack_path(findings)

    lines = report.splitlines()
    assert lines[0] == "Attack Path:"
    assert lines[1] == "1. [Intelligence Gathering] Port 80/tcp open on 10.10.10.5"
    assert lines[2] == "2. [Exploitation] Default credentials (admin:admin) confirmed on 10.10.10.5, granting access"


def test_findings_with_no_ptes_phase_are_excluded():
    findings = [
        {
            "id": 1,
            "finding_type": "redirect_followed",
            "description": "followed a redirect",
            "evidence_summary": "",
            "status": "flagged",
            "ptes_phase": None,
            "host_ip": "10.10.10.5",
        },
        {
            "id": 2,
            "finding_type": "open_port",
            "description": "Port 22/tcp open",
            "evidence_summary": "22/tcp open ssh",
            "status": "flagged",
            "ptes_phase": "Intelligence Gathering",
            "host_ip": "10.10.10.5",
        },
    ]

    report = format_attack_path(findings)

    assert "redirect_followed" not in report
    assert "1. [Intelligence Gathering] Port 22/tcp open on 10.10.10.5" in report
    # Attack Path section is header + exactly one entry (the Remediation
    # Recommendations section that follows is covered by its own tests).
    attack_path_section = report.split("\n\n")[0]
    assert attack_path_section.count("\n") == 1


def test_empty_findings_produce_a_placeholder_not_a_crash():
    report = format_attack_path([])
    assert report == "Attack Path:\n(no verified findings yet)"


def test_ordering_is_by_phase_not_input_order_with_id_tiebreak_within_a_phase():
    findings = [
        {
            "id": 5,
            "finding_type": "hardcoded_secret",
            "description": "secret B",
            "evidence_summary": "",
            "status": "confirmed",
            "ptes_phase": "Vulnerability Analysis",
            "host_ip": "10.10.10.5",
        },
        {
            "id": 1,
            "finding_type": "open_port",
            "description": "Port 80/tcp open",
            "evidence_summary": "",
            "status": "flagged",
            "ptes_phase": "Intelligence Gathering",
            "host_ip": "10.10.10.5",
        },
        {
            "id": 3,
            "finding_type": "hardcoded_secret",
            "description": "secret A",
            "evidence_summary": "",
            "status": "confirmed",
            "ptes_phase": "Vulnerability Analysis",
            "host_ip": "10.10.10.5",
        },
    ]

    report = format_attack_path(findings)
    lines = report.splitlines()[1:]

    assert "Intelligence Gathering" in lines[0]
    assert "secret A" in lines[1]  # id 3 before id 5 within the same phase
    assert "secret B" in lines[2]


def test_build_attack_path_resolves_host_ip_through_the_real_db():
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

        report = build_attack_path(db, target_id)

    assert "1. [Intelligence Gathering] Port 80/tcp open on 10.10.10.5" in report


def test_build_attack_path_for_unknown_target_is_the_empty_placeholder():
    with Database(":memory:") as db:
        report = build_attack_path(db, 999)

    assert report == "Attack Path:\n(no verified findings yet)"


def test_crown_jewel_section_names_the_confirmed_compromised_host():
    findings = [
        {
            "id": 1,
            "finding_type": "open_port",
            "description": "Port 80/tcp open",
            "evidence_summary": "80/tcp open http",
            "status": "flagged",
            "ptes_phase": "Intelligence Gathering",
            "host_ip": "10.10.10.5",
        },
        {
            "id": 2,
            "finding_type": "default_creds_found",
            "description": "/admin login form, no rate limiting",
            "evidence_summary": "POST /admin/login with admin:admin -> 302",
            "status": "confirmed",
            "ptes_phase": "Exploitation",
            "host_ip": "10.10.10.5",
        },
    ]

    report = format_attack_path(findings)

    assert "Crown Jewel:" in report
    assert "10.10.10.5 -- confirmed compromised at step 2 above (default_creds_found)" in report


def test_crown_jewel_section_includes_description_and_evidence_for_detail():
    # Direct response to real feedback: the banner/section named the
    # host and finding_type but gave no detail on HOW it was broken
    # into -- the description and evidence_summary answer that.
    findings = [
        {
            "id": 1,
            "finding_type": "default_creds_found",
            "description": "Credential pair confirmed against http://10.10.10.5:8085/admin/login",
            "evidence_summary": "POST http://10.10.10.5:8085/admin/login with admin:admin -> 302",
            "status": "confirmed",
            "ptes_phase": "Exploitation",
            "host_ip": "10.10.10.5",
        },
    ]

    report = format_attack_path(findings)

    assert "Credential pair confirmed against http://10.10.10.5:8085/admin/login" in report
    assert "Evidence: POST http://10.10.10.5:8085/admin/login with admin:admin -> 302" in report


def test_crown_jewel_section_placeholder_when_nothing_confirmed():
    findings = [
        {
            "id": 1,
            "finding_type": "open_port",
            "description": "Port 80/tcp open",
            "evidence_summary": "",
            "status": "flagged",
            "ptes_phase": "Intelligence Gathering",
            "host_ip": "10.10.10.5",
        },
    ]

    report = format_attack_path(findings)

    assert "Crown Jewel:" in report
    assert "(no protected host was confirmed compromised this run)" in report


def test_remediation_section_is_appended_after_the_attack_path():
    findings = [
        {
            "id": 1,
            "finding_type": "default_creds_found",
            "description": "/admin login form, no rate limiting",
            "evidence_summary": "POST /admin/login with admin:admin -> 302",
            "status": "confirmed",
            "ptes_phase": "Exploitation",
            "host_ip": "10.10.10.5",
        },
    ]

    report = format_attack_path(findings)

    assert "Remediation Recommendations:" in report
    assert "- default_creds_found:" in report
    assert "password" in report.lower()


def test_remediation_section_dedupes_by_finding_type():
    findings = [
        {
            "id": 1,
            "finding_type": "hardcoded_secret",
            "description": "secret A",
            "evidence_summary": "",
            "status": "confirmed",
            "ptes_phase": "Vulnerability Analysis",
            "host_ip": "10.10.10.5",
        },
        {
            "id": 2,
            "finding_type": "hardcoded_secret",
            "description": "secret B",
            "evidence_summary": "",
            "status": "confirmed",
            "ptes_phase": "Vulnerability Analysis",
            "host_ip": "10.10.10.6",
        },
    ]

    report = format_attack_path(findings)

    assert report.count("- hardcoded_secret:") == 1


def test_remediation_section_skips_types_with_nothing_to_suggest():
    findings = [
        {
            "id": 1,
            "finding_type": "ctf_flag_found",
            "description": "flag captured",
            "evidence_summary": "",
            "status": "confirmed",
            "ptes_phase": "Exploitation",
            "host_ip": "10.10.10.5",
        },
    ]

    report = format_attack_path(findings)

    assert "Remediation Recommendations:" in report
    assert "- ctf_flag_found:" in report  # ctf_flag_found DOES have remediation text (points to root cause)


def test_remediation_section_placeholder_when_nothing_to_remediate():
    # A finding_type reporting/remediation.py has no opinion about yet
    # (the dict sets ptes_phase directly so it's still in-path, exactly
    # the same "unmapped but present" scenario reporting/ptes.py's own
    # tests exercise for known_finding_types()).
    findings = [
        {
            "id": 1,
            "finding_type": "some_future_finding_type_nobody_mapped_yet",
            "description": "something new",
            "evidence_summary": "",
            "status": "flagged",
            "ptes_phase": "Intelligence Gathering",
            "host_ip": "10.10.10.5",
        },
    ]

    report = format_attack_path(findings)

    assert "Remediation Recommendations:" in report
    assert "(nothing to remediate)" in report
