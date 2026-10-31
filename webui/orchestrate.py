"""
webui/orchestrate.py

Runs the full agent chain for one target: network -> (any web follow-up
jobs) -> (any binary follow-up jobs from those), exactly what you'd
otherwise do by hand with three separate `main.py` commands, copying each
step's follow-up job target into the next command yourself.

This is a dashboard convenience, NOT the real orchestrator (FR-4) — that
is core/orchestrator.py + core/queue.py, which handle a persistent job
queue, dedup, and a DB-backed pipeline. This just runs the three agents
in one request, synchronously, so the GUI has something to show. Once
the real orchestrator/API exist, the GUI's "Run Scan" button can call
that instead of this module with no change to the templates.

Kept deliberately separate from webui/app.py (the Flask routes) so the
chaining logic itself can be unit-tested with mocked agents/executor,
without needing nmap, a real network, or a running Flask server.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from agents.binary.agent import run as run_binary_agent
from agents.network.agent import run as run_network_agent
from agents.web.agent import run as run_web_agent
from common.contracts import Job, JobResult
from core.scoped_executor import RealScopedExecutor
from scope.manager import ScopeManager


@dataclass
class StageResult:
    """One agent's run within the chain, plus any error it hit."""

    agent: str
    target: str
    result: JobResult | None = None
    error: str | None = None


@dataclass
class ChainResult:
    """Everything produced by running the full network -> web -> binary chain."""

    target: str
    scope: list[str]
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


def run_full_chain(
    target: str,
    scope_cidrs: list[str] | None = None,
    scope_file: str = "config/scope.yaml",
) -> ChainResult:
    """
    Runs network agent against `target`, then the web agent against every
    web follow-up job it produces, then the binary agent against every
    binary follow-up job THOSE produce. Each stage's failure is captured
    on that stage (error message) rather than raising — one broken stage
    (e.g. nmap not installed) shouldn't prevent showing the stages that
    did work.
    """
    if scope_cidrs:
        scope_manager = ScopeManager(cidrs=scope_cidrs)
    else:
        scope_manager = ScopeManager(scope_file)
    scope_display = scope_manager.authorized_networks

    executor = RealScopedExecutor(
        is_in_scope=scope_manager.is_in_scope,
        log_scope_check=scope_manager.log_scope_check,
    )

    chain = ChainResult(target=target, scope=scope_display)

    # --- Stage 1: network ---------------------------------------------
    network_job = Job(job_id="ui-network-1", agent="network", target=target)
    network_stage = StageResult(agent="network", target=target)
    chain.stages.append(network_stage)

    try:
        network_result = run_network_agent(network_job, executor)
        network_stage.result = network_result
    except Exception as exc:  # noqa: BLE001 — surfaced to the UI, not swallowed
        network_stage.error = str(exc)
        return chain  # nothing to chain into without a network result

    # --- Stage 2: web, once per follow-up job the network agent made ---
    web_follow_ups = [fj for fj in network_result.follow_up_jobs if fj["agent"] == "web"]
    web_results: list[JobResult] = []

    for i, fj in enumerate(web_follow_ups):
        web_job = Job(job_id=f"ui-web-{i}", agent="web", target=fj["target"])
        web_stage = StageResult(agent="web", target=fj["target"])
        chain.stages.append(web_stage)
        try:
            web_result = run_web_agent(web_job, executor)
            web_stage.result = web_result
            web_results.append(web_result)
        except Exception as exc:  # noqa: BLE001
            web_stage.error = str(exc)

    # --- Stage 3: binary, once per follow-up job any web stage made ---
    for i, web_result in enumerate(web_results):
        binary_follow_ups = [fj for fj in web_result.follow_up_jobs if fj["agent"] == "binary"]
        for j, fj in enumerate(binary_follow_ups):
            binary_job = Job(job_id=f"ui-binary-{i}-{j}", agent="binary", target=fj["target"])
            binary_stage = StageResult(agent="binary", target=fj["target"])
            chain.stages.append(binary_stage)
            try:
                binary_result = run_binary_agent(binary_job, tool_engine=None, executor=executor)
                binary_stage.result = binary_result
            except Exception as exc:  # noqa: BLE001
                binary_stage.error = str(exc)

    return chain
