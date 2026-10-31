"""
core/pipeline.py

The full end-to-end wiring for a single run, matching userflow.md's
worked example start to finish: run_target() (FR-4's concurrent
orchestrator) -> persist hosts/services/findings (FR-7's core/db.py) ->
verify each finding (FR-6's verification/verifier.py) -> tag its PTES
phase (FR-5's reporting/ptes.py) -> link attack_edges between a stage's
findings and whatever follow-up stage they led to -> build the Attack
Path narrative (FR-7's reporting/report_generator.py).

Deliberately a NEW module, not a change to core/orchestrator.py (which
stays DB-agnostic and keeps working exactly as webui/app.py's dashboard
already relies on it) or to main.py's existing per-agent commands.
run_pipeline.py (project root) is the CLI entrypoint that calls this.
"""

from __future__ import annotations

from urllib.parse import urlparse

from common.contracts import FindingOut
from core.db import Database
from core.orchestrator import OrchestrationResult, StageResult, run_target
from core.scoped_executor import ScopedExecutor
from reporting.ptes import ptes_phase_for
from reporting.report_generator import build_attack_path
from verification.verifier import verify_finding


def _host_key_for_finding(finding: FindingOut, stage: StageResult) -> str:
    """A finding's own `host` field is the right key when the agent set
    it (every current finding_type sets it — see agents/*/agent.py).
    Falls back to the stage's own target string (stripping a port or a
    URL scheme/path) only for a finding that somehow didn't set `host`,
    so nothing gets silently dropped."""
    if finding.host:
        return finding.host
    target = stage.target
    if "://" in target:
        return urlparse(target).hostname or target
    return target.split(":", 1)[0]


def run_and_persist(
    target: str,
    executor: ScopedExecutor,
    db: Database,
    scope: list[str] | None = None,
    crawler: str = "auto",
    allowed_ports: list[int] | None = None,
) -> dict:
    """
    Runs `target` through the full agent chain via core.orchestrator.
    run_target(), then persists everything to `db`, verifies and
    PTES-tags each finding, links attack_edges along the same
    follow-up-job chains the orchestrator already used to decide what
    ran next, and returns:

        {"target_id": int, "outcome": OrchestrationResult, "attack_path": str}

    `allowed_ports` is passed straight through to run_target()'s own
    initial network job — see its docstring; it's the main lever for a
    slow CIDR-range scan, not anything about how stages are dispatched.
    """
    target_id = db.insert_target(target)
    outcome: OrchestrationResult = run_target(
        target, executor, scope=scope, crawler=crawler, allowed_ports=allowed_ports
    )

    # Pass 1: persist every discovered host + its services (only the
    # network agent's stages populate JobResult.hosts; web/binary
    # stages report findings against a host they didn't "discover").
    host_ip_to_id: dict[str, int] = {}
    for stage in outcome.stages:
        if stage.result is None:
            continue
        for host in stage.result.hosts:
            host_id = db.get_or_create_host(host.ip, hostname=host.hostname)
            host_ip_to_id[host.ip] = host_id
            for svc in host.services:
                db.get_or_create_service(host_id, svc.port, svc.protocol, svc.service, version=svc.version)

    # Pass 2: persist every finding (against whichever host it names,
    # creating that host row on the fly if pass 1 didn't already),
    # then verify + PTES-tag it. stage_finding_ids tracks, per stage
    # index, the finding ids just inserted for it -- used by pass 3 to
    # link attack_edges along the same chains the orchestrator followed.
    stage_finding_ids: dict[int, list[int]] = {}
    for stage_index, stage in enumerate(outcome.stages):
        if stage.result is None:
            continue
        finding_ids: list[int] = []
        for finding in stage.result.findings:
            host_key = _host_key_for_finding(finding, stage)
            host_id = host_ip_to_id.get(host_key)
            if host_id is None:
                host_id = db.get_or_create_host(host_key)
                host_ip_to_id[host_key] = host_id

            finding_id = db.insert_finding(
                host_id=host_id,
                agent=stage.agent,
                finding_type=finding.finding_type,
                description=finding.description,
                evidence_summary=finding.evidence.summary,
                evidence_raw_ref=finding.evidence.raw_ref,
            )

            verdict = verify_finding(
                {
                    "finding_type": finding.finding_type,
                    "description": finding.description,
                    "evidence_summary": finding.evidence.summary,
                },
                executor,
            )
            final_status = verdict["status"]
            if final_status != "flagged":
                db.update_finding_status(finding_id, final_status, evidence_summary=verdict["evidence_summary"])

            phase = ptes_phase_for(finding.finding_type, status=final_status)
            db.set_finding_ptes_phase(finding_id, phase)

            finding_ids.append(finding_id)
        stage_finding_ids[stage_index] = finding_ids

    # Pass 3: attack_edges along the same follow_up_jobs chains
    # core.orchestrator.run_target() already used to decide what ran
    # next -- every finding in a stage that produced a follow-up is
    # linked to every finding the follow-up's own stage produced. This
    # over-links when a stage has several findings and several
    # follow-ups (a full cross-product, not "which specific finding
    # caused which specific follow-up" -- the agents don't record that
    # finer-grained link today), which is fine for a report meant to
    # show plausible chains, not a precise causal graph.
    for stage_index, stage in enumerate(outcome.stages):
        if stage.result is None or not stage_finding_ids.get(stage_index):
            continue
        for follow_up in stage.result.follow_up_jobs:
            for other_index, other_stage in enumerate(outcome.stages):
                if other_stage.agent == follow_up["agent"] and other_stage.target == follow_up["target"]:
                    for from_id in stage_finding_ids[stage_index]:
                        for to_id in stage_finding_ids.get(other_index, []):
                            db.insert_attack_edge(
                                from_id, to_id, note=f"{stage.agent} stage led to {other_stage.agent} job"
                            )
                    break

    return {
        "target_id": target_id,
        "outcome": outcome,
        "attack_path": build_attack_path(db, target_id),
    }
