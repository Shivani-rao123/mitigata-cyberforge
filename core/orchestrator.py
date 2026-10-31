"""
core/orchestrator.py

FR-4: multi-agent coordination. Runs a target through however many agent
stages its own discoveries call for — the network agent finds a web
port and hands it to the web agent; the web agent finds a downloadable
binary and hands it to the binary agent — automatically, driven entirely
by each agent's own `follow_up_jobs` (see common/contracts.py's
JobResult). There is NO hardcoded "network, then web, then binary"
sequence anywhere in this file: it starts one network job, and keeps
running whatever follow-up jobs show up until none are left. Adding a
fourth agent that hands off to a fifth would need zero changes here.

The actual fix for "it's slow": every job in one "wave" (e.g. three web
follow-ups from a single network scan, or five binary follow-ups from
three different web crawls) is independent of the others in that same
wave — nothing about running them one after another was ever necessary.
run_target() runs each wave through a ThreadPoolExecutor instead of a
plain for loop (every agent here is I/O-bound: HTTP requests, subprocess
calls to nmap/katana/gitleaks/strings/nm — none of it holds Python's
GIL), while still collecting each wave's results in the ORIGINAL
dispatch order (via Executor.map, which returns results in call order
regardless of completion order) — so a run's output is deterministic
and reads top-to-bottom the same way every time, concurrency or not.

One ScopedExecutor instance is shared across every worker thread. That's
safe: RealScopedExecutor holds no mutable state that a scan/crawl/
http_get/download call writes to — every one of those just makes its own
independent requests.get()/subprocess.run() call. The only shared thing
is the log_scope_check callback, where concurrent calls can interleave
their output, which is a cosmetic ordering question, not a correctness
one.

Not DB-backed / not persistent across process restarts — see
core/queue.py's own docstring for the same caveat. This file only talks
to JobQueue through enqueue()/dequeue_all(), so swapping that module's
internals later needs no change here.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from agents.binary.agent import run as run_binary_agent
from agents.network.agent import run as run_network_agent
from agents.web.agent import run as run_web_agent
from common.contracts import Job, JobResult
from core.queue import JobQueue
from core.scoped_executor import ScopedExecutor

# Imported as plain module-level names (not frozen into a dict at import
# time) so that tests can @patch("core.orchestrator.run_network_agent")
# etc. the same way tests/webui/test_orchestrate.py already does for
# webui/orchestrate.py's own run_network_agent/run_web_agent/
# run_binary_agent names — _run_one() below references these names at
# CALL time, so a patch takes effect on every call, including from
# worker threads.
DEFAULT_MAX_WORKERS = 8


@dataclass
class StageResult:
    """One agent job's outcome within a run — same shape
    webui/orchestrate.py's StageResult already used, so a caller (e.g.
    the dashboard) can render either one identically."""

    agent: str
    target: str
    result: JobResult | None = None
    error: str | None = None


@dataclass
class OrchestrationResult:
    """Everything produced by running run_target() to completion."""

    target: str
    scope: list[str] = field(default_factory=list)
    stages: list[StageResult] = field(default_factory=list)

    @property
    def all_findings(self) -> list[tuple[str, str, object]]:
        """(agent_name, target, finding) for every finding across every stage."""
        out = []
        for stage in self.stages:
            if stage.result:
                for finding in stage.result.findings:
                    out.append((stage.agent, stage.target, finding))
        return out

    @property
    def total_findings(self) -> int:
        return len(self.all_findings)

    @property
    def had_any_error(self) -> bool:
        return any(stage.error for stage in self.stages)


def _run_one(job: Job, executor: ScopedExecutor) -> tuple[Job, StageResult]:
    """Runs a single job, catching any exception as a per-stage error —
    one broken job (nmap not installed, a dead target) must never take
    down the rest of a wave running alongside it in the same
    ThreadPoolExecutor.map() call."""
    stage = StageResult(agent=job.agent, target=job.target)

    try:
        # Looked up by name from this module's globals at call time
        # (not a dict built once at import) so @patch on the module-
        # level run_*_agent names takes effect — see the comment by
        # the imports above.
        if job.agent == "network":
            result = run_network_agent(job, executor)
        elif job.agent == "web":
            result = run_web_agent(job, executor)
        elif job.agent == "binary":
            # The binary agent's run() takes tool_engine/executor as
            # separate optional kwargs rather than just `executor` —
            # see agents/binary/agent.py's signature.
            result = run_binary_agent(job, tool_engine=None, executor=executor)
        else:
            stage.error = f"no agent runner registered for agent {job.agent!r}"
            return job, stage
        stage.result = result
    except Exception as exc:  # noqa: BLE001 — surfaced on the stage, not fatal to the run
        stage.error = str(exc)

    return job, stage


def _build_follow_up_job(job_id: str, follow_up: dict, crawler: str) -> Job:
    """Turns one of a stage's follow_up_jobs dicts into a real Job.
    A web follow-up gets the run's `crawler` preference merged in
    (the originating agent doesn't know about it — only the orchestrator
    does), on top of whatever context that agent already set (e.g. the
    network agent's host_ip/service_port), not instead of it."""
    context = dict(follow_up.get("context") or {})
    if follow_up["agent"] == "web":
        context.setdefault("crawler", crawler)
    return Job(job_id=job_id, agent=follow_up["agent"], target=follow_up["target"], context=context)


def run_target(
    target: str,
    executor: ScopedExecutor,
    scope: list[str] | None = None,
    crawler: str = "auto",
    max_workers: int = DEFAULT_MAX_WORKERS,
    allowed_ports: list[int] | None = None,
) -> OrchestrationResult:
    """
    Runs `target` through the full agent chain, starting from one
    network job and letting each stage's own follow_up_jobs decide what
    runs next. Jobs that become ready in the same wave run concurrently,
    up to `max_workers` at once; the queue naturally drains in "network
    -> every web follow-up -> every binary follow-up (-> ...)" waves
    without that sequence being hardcoded anywhere.

    `scope` is display-only here (the authoritative scope check already
    happened when `executor` was built — see core/scoped_executor.py) —
    carried through to OrchestrationResult so a caller can show it
    without having to track it separately.

    `allowed_ports` restricts ONLY the initial network scan (nmap's own
    "-p" flag, plumbed through core/tool_engine.py) — the single biggest
    speed lever for a CIDR-range target: nmap's own default ~1000-port
    set run with -sV against every live host in e.g. a /24 is what makes
    a subnet scan slow, far more than anything about how this orchestrator
    dispatches jobs. None (the default) leaves nmap's own default port
    set in effect, same as before this parameter existed.
    """
    queue = JobQueue()
    queue.enqueue(
        Job(job_id="orch-network-0", agent="network", target=target, allowed_ports=allowed_ports)
    )

    outcome = OrchestrationResult(target=target, scope=scope or [])

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        wave_num = 0
        wave = queue.dequeue_all()
        while wave:
            wave_num += 1
            for i, (job, stage) in enumerate(pool.map(lambda j: _run_one(j, executor), wave)):
                outcome.stages.append(stage)
                if stage.result is None:
                    continue
                for j, follow_up in enumerate(stage.result.follow_up_jobs):
                    queue.enqueue(
                        _build_follow_up_job(
                            job_id=f"orch-{follow_up['agent']}-{wave_num}-{i}-{j}",
                            follow_up=follow_up,
                            crawler=crawler,
                        )
                    )
            wave = queue.dequeue_all()

    return outcome
