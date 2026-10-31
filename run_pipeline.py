"""
run_pipeline.py

The full end-to-end CLI entrypoint: discover -> persist -> verify ->
PTES-tag -> link attack edges -> print the Attack Path, matching
userflow.md's worked example start to finish with ONE command and no
further human input, e.g.:

    python run_pipeline.py --target 10.10.10.5 --scope 10.10.10.0/24

A NEW entrypoint, deliberately separate from main.py (which still runs
exactly one agent at a time, unpersisted — useful for debugging a
single agent in isolation) and from webui/app.py's dashboard route
(which calls core.orchestrator.run_target() directly, with no DB). This
is the only place core/pipeline.py's run_and_persist() gets called from
the command line.
"""

from __future__ import annotations

import argparse

from core.db import Database
from core.pipeline import run_and_persist
from core.scoped_executor import RealScopedExecutor
from scope.manager import ScopeManager


def _build_scoped_executor(args: argparse.Namespace) -> RealScopedExecutor:
    """Same pattern as main.py's own _build_scoped_executor — kept as
    its own small copy here rather than importing main.py's private
    helper, so this entrypoint has no dependency on main.py's internals
    (or its argparse side effects) at all."""
    if args.scope:
        cidrs = [c.strip() for c in args.scope.split(",") if c.strip()]
        print(f"=== CART — scope for this run: {cidrs} ===")
        scope_manager = ScopeManager(cidrs=cidrs)
    else:
        print(f"=== CART — loading scope from {args.scope_file} ===")
        scope_manager = ScopeManager(args.scope_file)

    return RealScopedExecutor(
        is_in_scope=scope_manager.is_in_scope,
        log_scope_check=scope_manager.log_scope_check,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="CART — run the full discover/persist/verify/report pipeline against one target"
    )
    parser.add_argument("--target", required=True, help="An IP, hostname, or CIDR range to run against.")
    parser.add_argument(
        "--scope",
        default=None,
        help=(
            "One or more authorized CIDR/IP ranges for THIS run, comma-separated. "
            "If omitted, falls back to --scope-file."
        ),
    )
    parser.add_argument(
        "--scope-file",
        default="config/scope.yaml",
        help="Path to the fallback scope config, used when --scope isn't given.",
    )
    parser.add_argument(
        "--crawler",
        choices=["auto", "requests", "katana"],
        default="auto",
        help="Which crawler the web agent should use (see agents/web/agent.py).",
    )
    parser.add_argument(
        "--db-path",
        default=None,
        help="SQLite file to persist into. Defaults to store/cart.db (core/db.py's own default).",
    )
    parser.add_argument(
        "--ports",
        default=None,
        help=(
            "Comma-separated TCP ports to restrict the initial network scan to "
            "(e.g. --ports 22,80,443,8080). Omit to use nmap's own default port set. "
            "Restricting this is the main lever for a slow CIDR-range (e.g. /24) scan."
        ),
    )
    args = parser.parse_args()

    executor = _build_scoped_executor(args)
    db = Database(args.db_path) if args.db_path else Database()
    allowed_ports = [int(p.strip()) for p in args.ports.split(",") if p.strip()] if args.ports else None

    try:
        print(f"\n=== Running full pipeline against {args.target} ===")
        if allowed_ports:
            print(f"(network scan restricted to ports: {allowed_ports})")
        print(
            "(this runs every stage the target's own discoveries call for — "
            "network scan, then whatever web/binary follow-ups it produces — "
            "concurrently within each wave. A real remote host can take a "
            "while with no visible progress in the meantime; that's normal.)"
        )
        outcome_data = run_and_persist(
            target=args.target,
            executor=executor,
            db=db,
            scope=[args.scope] if args.scope else None,
            crawler=args.crawler,
            allowed_ports=allowed_ports,
        )

        outcome = outcome_data["outcome"]
        print(f"\n=== Ran {len(outcome.stages)} stage(s), {outcome.total_findings} finding(s) total ===")
        for stage in outcome.stages:
            if stage.error:
                print(f"  [{stage.agent} -> {stage.target}] ERROR: {stage.error}")
            elif stage.result:
                print(f"  [{stage.agent} -> {stage.target}] {len(stage.result.findings)} finding(s)")

        print(f"\nPersisted as target id {outcome_data['target_id']}.")
        print(f"\n{outcome_data['attack_path']}")
    finally:
        db.close()


if __name__ == "__main__":
    main()
