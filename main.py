"""
main.py

Single entrypoint for running one agent at a time. Your partner's core
(DB, orchestrator, job queue, verification, report) plugs in here later,
replacing the plain print() calls below with real persistence and the
auto-created follow-up jobs actually being picked up and dispatched
automatically.

Run network discovery:
    python main.py --agent network --target 127.0.0.1

Run network discovery with a per-run scope (no need to hand-edit
config/scope.yaml for a one-off target):
    python main.py --agent network --target krcbc.in --scope 31.97.62.119/32

Run binary analysis on a local file (no network, no scope check):
    python main.py --agent binary --target fixtures/vulnerable_binary/vuln

Run the web surface agent against a discovered HTTP(S) service:
    python main.py --agent web --target 10.10.10.5:80 --scope 10.10.10.0/24
"""

from __future__ import annotations

import argparse

from agents.network.agent import run as run_network_agent
from common.contracts import Job
from core.scoped_executor import RealScopedExecutor
from scope.manager import ScopeManager


def main() -> None:
    parser = argparse.ArgumentParser(description="CART — run one agent pass")
    parser.add_argument(
        "--agent",
        choices=["network", "binary", "web"],
        default="network",
        help="Which agent to run.",
    )
    parser.add_argument(
        "--target",
        default="127.0.0.1",
        help=(
            "For --agent network: an IP or hostname. For --agent binary: a local "
            "file path (or an http(s) URL). For --agent web: a host:port pair "
            "(scheme inferred from the port) or a full http(s) URL."
        ),
    )
    parser.add_argument(
        "--scope",
        default=None,
        help=(
            "One or more authorized CIDR/IP ranges for THIS run, comma-separated "
            "(e.g. --scope 31.97.62.119/32,127.0.0.1/32). Used by --agent network "
            "and --agent web (both touch the network, so both need scope). "
            "If omitted, falls back to config/scope.yaml."
        ),
    )
    parser.add_argument(
        "--scope-file",
        default="config/scope.yaml",
        help="Path to the fallback scope config, used when --scope isn't given.",
    )
    args = parser.parse_args()

    if args.agent == "network":
        _run_network(args)
    elif args.agent == "binary":
        _run_binary(args)
    elif args.agent == "web":
        _run_web(args)


def _build_scoped_executor(args: argparse.Namespace) -> RealScopedExecutor:
    """Shared by every agent that touches the network (network, web, and
    binary-with-a-URL-target): builds the scope manager from --scope or
    --scope-file, then the executor that enforces it on every probe."""
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


def _run_network(args: argparse.Namespace) -> None:
    executor = _build_scoped_executor(args)

    job = Job(job_id="run-001", agent="network", target=args.target)

    print(f"\n=== Running network discovery against {args.target} ===")
    print(
        "(nmap's output is captured and only shown once the scan finishes — "
        "a real remote host can take 1-3+ minutes with no visible progress "
        "in the meantime, especially if some ports are firewalled rather "
        "than closed outright. This is normal, not a hang.)"
    )
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


def _run_binary(args: argparse.Namespace) -> None:
    from agents.binary.agent import run as run_binary_agent
    from agents.binary.discovery import find_binary_links, looks_like_binary_url

    is_url = args.target.startswith("http://") or args.target.startswith("https://")

    executor = None
    if is_url:
        # A URL target has to be fetched, which touches the network — so
        # it needs the same scope-checked executor the network agent
        # uses, built from --scope / --scope-file exactly the same way.
        executor = _build_scoped_executor(args)

    if is_url and not looks_like_binary_url(args.target):
        # Target looks like a WEBSITE, not a direct binary link — the
        # realistic case: a user gives CART a site, not a file. Discover
        # downloadable binaries on that page first, then analyze each one.
        print(f"\n=== Looking for downloadable binaries on {args.target} ===")
        links = find_binary_links(executor, args.target)

        if not links:
            print("  No downloadable binaries found on this page.")
            print("\n(No DB yet — nothing persisted. Core will plug in here next.)")
            return

        print(f"  Found {len(links)} downloadable binary link(s):")
        for link in links:
            print(f"    - {link}")

        for link in links:
            job = Job(job_id=f"run-{link}", agent="binary", target=link)
            print(f"\n=== Running binary analysis against {link} ===")
            result = run_binary_agent(job, executor=executor)
            _print_binary_result(result)

        print("\n(No DB yet — nothing persisted. Core will plug in here next.)")
        return

    # Direct target: either a local file path, or a URL that already
    # points straight at a binary (e.g. found by the web agent's own
    # crawl and handed over as a follow-up job).
    job = Job(job_id="run-001", agent="binary", target=args.target)
    print(f"\n=== Running binary analysis against {args.target} ===")
    result = run_binary_agent(job, executor=executor)
    _print_binary_result(result)
    print("\n(No DB yet — nothing persisted. Core will plug in here next.)")


def _print_binary_result(result) -> None:
    print(f"=== Result: {result.status} ===")
    print(f"Findings: {len(result.findings)}")
    for finding in result.findings:
        print(f"  [{finding.finding_type}] {finding.description}")
        print(f"      evidence: {finding.evidence.summary}")
    if not result.findings:
        print("  (none found)")


def _run_web(args: argparse.Namespace) -> None:
    from agents.web.agent import run as run_web_agent

    executor = _build_scoped_executor(args)

    job = Job(job_id="run-001", agent="web", target=args.target)

    print(f"\n=== Running web surface agent against {args.target} ===")
    result = run_web_agent(job, executor)

    print(f"\n=== Result: {result.status} ===")
    print(f"Findings: {len(result.findings)}")
    for finding in result.findings:
        print(f"  [{finding.finding_type}] {finding.description}")
        print(f"      evidence: {finding.evidence.summary}")

    if not result.findings:
        print("  (none found)")

    print(f"\nFollow-up jobs core would auto-create: {len(result.follow_up_jobs)}")
    for fj in result.follow_up_jobs:
        print(f"  -> agent={fj['agent']}  target={fj['target']}")

    print("\n(No DB yet — nothing persisted. Core will plug in here next.)")


if __name__ == "__main__":
    main()
