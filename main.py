"""
main.py

Single entrypoint. Right now this wires up only what's been built so far
(scope manager, scoped executor, network agent) — your partner's core
(DB, orchestrator, job queue, verification, report) plugs in here later,
replacing the plain print() calls below with real persistence and the
auto-created follow-up jobs actually being picked up.

Run: python main.py --scope config/scope.yaml --target 127.0.0.1
"""

from __future__ import annotations

import argparse

from agents.network.agent import run as run_network_agent
from common.contracts import Job
from core.scoped_executor import RealScopedExecutor
from scope.manager import ScopeManager


def main() -> None:
    parser = argparse.ArgumentParser(description="CART — run one network discovery pass")
    parser.add_argument("--scope", default="config/scope.yaml", help="Path to scope config")
    parser.add_argument("--target", default="127.0.0.1", help="Target to scan")
    args = parser.parse_args()

    print(f"=== CART — loading scope from {args.scope} ===")
    scope_manager = ScopeManager(args.scope)

    executor = RealScopedExecutor(
        is_in_scope=scope_manager.is_in_scope,
        log_scope_check=scope_manager.log_scope_check,
    )

    job = Job(job_id="run-001", agent="network", target=args.target)

    print(f"\n=== Running network discovery against {args.target} ===")
    result = run_network_agent(job, executor)

    print(f"\n=== Result: {result.status} ===")
    print(f"Hosts found: {len(result.hosts)}")
    for host in result.hosts:
        print(f"  {host.ip} ({host.hostname or 'no hostname'})")
        for svc in host.services:
            print(f"    - {svc.port}/{svc.protocol}  {svc.service}  {svc.version or ''}")

    print(f"\nFindings: {len(result.findings)}")
    for finding in result.findings:
        print(f"  [{finding.finding_type}] {finding.description}")

    print(f"\nFollow-up jobs core would auto-create: {len(result.follow_up_jobs)}")
    for fj in result.follow_up_jobs:
        print(f"  -> agent={fj['agent']}  target={fj['target']}")

    print("\n(No DB yet — nothing persisted. Core will plug in here next.)")


if __name__ == "__main__":
    main()