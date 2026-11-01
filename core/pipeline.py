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

from agents.basic_auth.agent import run as run_basic_auth_agent
from agents.web.agent import _to_base_url
from common.contracts import FindingOut, Job
from common.llm import choose_follow_ups
from core.db import Database
from core.orchestrator import OrchestrationResult, StageResult, run_target
from core.scoped_executor import ScopedExecutor
from reporting.ptes import ptes_phase_for
from reporting.report_generator import build_attack_path
from verification.authenticated_exploration import collect_candidate_endpoints
from verification.credential_chaining import try_credentials_against_conventional_paths
from verification.verifier import verify_finding

# 401/403 statuses mean the endpoint told us, before any credential
# was ever attached, that it needs some kind of authentication — these
# are the only candidates worth proposing to agents/basic_auth/agent.py
# below. A 200 endpoint is already accessible; trying header-auth
# against it would prove nothing either way.
_PROTECTED_STATUSES = (401, 403)


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

    # Credential-chaining (direct response to a real review flag: "binary
    # has hardcoded creds -> those should get tried against a login form
    # -> a successful login should lead to a flag" was never
    # demonstrated). Collected ONCE, across every stage in this whole
    # run, before verification starts — a credential_pair_found finding
    # from a binary stage that ran AFTER the web stage that found the
    # login form (the common order: network -> web finds both the login
    # form and a binary link -> binary analyzes it) still needs to be
    # available when that earlier web stage's default_creds_found
    # finding gets verified below, since verification is this whole
    # separate pass over ALL stages' findings, not interleaved with
    # orchestration. See verification/verifier.py's own docstring for
    # how these get used (tried before the generic weak-credential
    # list).
    extra_credentials: list[tuple[str, str]] = []
    all_findings: list[FindingOut] = []
    for stage in outcome.stages:
        if stage.result is None:
            continue
        all_findings.extend(stage.result.findings)
        for finding in stage.result.findings:
            if finding.finding_type != "credential_pair_found" or not finding.evidence.raw_ref:
                continue
            username, _, password = finding.evidence.raw_ref.partition(":")
            if username and password:
                extra_credentials.append((username, password))

    # Every endpoint this whole run discovered (sensitive_endpoint_found /
    # directory_listing_enabled, pooled across every stage the same way
    # extra_credentials is above) — passed into verify_finding() and the
    # pass-2.5 fallback below so a successful login explores everything
    # already known about this target, not just its own site root. See
    # verification/authenticated_exploration.py's own docstring.
    discovered_endpoints = collect_candidate_endpoints(all_findings)

    # Pass 2: persist every finding (against whichever host it names,
    # creating that host row on the fly if pass 1 didn't already),
    # then verify + PTES-tag it. stage_finding_ids tracks, per stage
    # index, the finding ids just inserted for it -- used by pass 3 to
    # link attack_edges along the same chains the orchestrator followed.
    stage_finding_ids: dict[int, list[int]] = {}
    # Tracked so pass 2.5 below only kicks in when nothing already
    # confirmed a login with these credentials via a crawled form —
    # no point guessing conventional paths once the real one worked.
    any_default_creds_confirmed = False
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
                extra_credentials=extra_credentials,
                discovered_endpoints=discovered_endpoints,
            )
            final_status = verdict["status"]
            if final_status != "flagged":
                db.update_finding_status(finding_id, final_status, evidence_summary=verdict["evidence_summary"])
            if finding.finding_type == "default_creds_found" and final_status == "confirmed":
                any_default_creds_confirmed = True

            phase = ptes_phase_for(finding.finding_type, status=final_status)
            db.set_finding_ptes_phase(finding_id, phase)

            finding_ids.append(finding_id)
        stage_finding_ids[stage_index] = finding_ids

    # Pass 2.5: a binary-derived credential that never got confirmed
    # against any CRAWLED login form (pass 2 above) — e.g. the login
    # page isn't linked anywhere the crawler visits, a real case a lab
    # run surfaced directly — gets one more shot: tried against a short
    # list of conventional login paths on each host a web stage ran
    # against. See verification/credential_chaining.py's own docstring.
    # Each hit becomes a new, already-confirmed default_creds_found
    # finding (and a flag in its evidence, if the post-login check
    # found one) — persisted the same way pass 2's own confirmed
    # findings are, just without a verify_finding() round-trip since
    # try_credentials_against_conventional_paths() already did the
    # proving itself.
    if extra_credentials and not any_default_creds_confirmed:
        for stage in outcome.stages:
            if stage.agent != "web" or stage.result is None:
                continue
            base_url = _to_base_url(stage.target)
            new_findings = try_credentials_against_conventional_paths(
                executor, base_url, extra_credentials, discovered_endpoints=discovered_endpoints
            )
            for finding in new_findings:
                host_key = finding.host or _host_key_for_finding(finding, stage)
                host_id = host_ip_to_id.get(host_key)
                if host_id is None:
                    host_id = db.get_or_create_host(host_key)
                    host_ip_to_id[host_key] = host_id

                finding_id = db.insert_finding(
                    host_id=host_id,
                    agent="web",
                    finding_type=finding.finding_type,
                    description=finding.description,
                    evidence_summary=finding.evidence.summary,
                    evidence_raw_ref=finding.evidence.raw_ref,
                )
                db.update_finding_status(finding_id, "confirmed", evidence_summary=None)
                db.set_finding_ptes_phase(
                    finding_id, ptes_phase_for(finding.finding_type, status="confirmed")
                )
            if new_findings:
                any_default_creds_confirmed = True
                break  # one confirmed login across every host checked is enough

    # Pass 2.6: HTTP header-based auth (Basic/Bearer) against any
    # endpoint that answered 401/403 before any credential was tried —
    # the one auth scheme nothing above can reach, since there's no
    # HTML <form> to POST to at all (see agents/basic_auth/agent.py's
    # own docstring). Deliberately NOT an unconditional rule like pass
    # 2.5 above: whether this runs AT ALL for a given candidate is an
    # explicit LLM decision (reusing common/llm.py's choose_follow_ups()
    # — same mechanism as the network/web follow-up planner, different
    # fallback policy). If the LLM is off, unavailable, or its call
    # fails (None), this fails CLOSED -- no header-auth attempts happen
    # at all, unlike pass 2.5's rule-based fallback, because there is
    # no pre-existing "always try this" behavior to fall back to here.
    protected_endpoints = [(url, status) for url, status in discovered_endpoints if status in _PROTECTED_STATUSES]
    if extra_credentials and protected_endpoints:
        candidates = [
            {"agent": "basic_auth", "target": url, "context": {"username": username, "password": password}}
            for url, _status in protected_endpoints
            for username, password in extra_credentials
        ]
        planning_job = Job(job_id="basic-auth-planner", agent="web", target=target)
        approved = choose_follow_ups(planning_job, all_findings, candidates)
        if approved is None:
            approved = []  # fail CLOSED -- see this pass's own comment above

        for candidate in approved:
            new_findings = run_basic_auth_agent(
                executor,
                candidate["target"],
                candidate["context"]["username"],
                candidate["context"]["password"],
            )
            for finding in new_findings:
                host_key = finding.host or candidate["target"]
                host_id = host_ip_to_id.get(host_key)
                if host_id is None:
                    host_id = db.get_or_create_host(host_key)
                    host_ip_to_id[host_key] = host_id

                finding_id = db.insert_finding(
                    host_id=host_id,
                    agent="basic_auth",
                    finding_type=finding.finding_type,
                    description=finding.description,
                    evidence_summary=finding.evidence.summary,
                    evidence_raw_ref=finding.evidence.raw_ref,
                )
                db.update_finding_status(finding_id, "confirmed", evidence_summary=None)
                db.set_finding_ptes_phase(
                    finding_id, ptes_phase_for(finding.finding_type, status="confirmed")
                )

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
