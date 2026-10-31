"""
main.py

Run network discovery, then standard Katana for each discovered web service.
Uses the scoped executor throughout. DB/verification/reporting are not wired yet.

Run: python main.py --scope config/scope.yaml --target 127.0.0.1
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
from urllib.parse import urlsplit

from core.katana import normalize

from agents.network.agent import run as run_network_agent
from agents.web.agent import run as run_web_agent
from common.contracts import Job
from core.scoped_executor import RealScopedExecutor, ScopeViolation
from core.tool_engine import ToolNotInstalled, ToolExecutionError
from scope.manager import ScopeManager


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="CART — network discovery followed by standard Katana web discovery")
    parser.add_argument("--scope", default="config/scope.yaml", help="Path to scope config")
    parser.add_argument("--target", default="127.0.0.1", help="Target to scan")
    parser.add_argument("--agent", choices=("network", "web", "all"), default="all",
                        help="network: Nmap only; web: standard Katana only (target must be a URL); all: network then web (default)")
    parser.add_argument("--ports", help="Comma-separated Nmap ports, restricted to scope allowed_ports")
    for flag, maximum, help_text in (
        ("depth", 10, "Katana crawl depth (default 3)"),
        ("rate-limit", 100, "Katana requests per second (default 5)"),
        ("concurrency", 10, "Katana concurrent fetchers (default 2)"),
        ("crawl-duration", 30, "Katana crawl seconds per target (default 30, process cap 60 per batch)"),
        ("request-timeout", 30, "Katana request timeout in seconds (default 8)"),
        ("max-endpoints", 10000, "Maximum retained web endpoints (default 500)"),
    ):
        parser.add_argument("--" + flag, type=_bounded_int(maximum), help=help_text)
    parser.add_argument("--output", help="Save network results, web results and endpoint/form inventory as JSON")
    args = parser.parse_args(argv)
    web_options = {key: getattr(args, key) for key in ("depth", "rate_limit", "concurrency", "crawl_duration", "request_timeout", "max_endpoints") if getattr(args, key) is not None}
    if args.agent == "network" and web_options:
        parser.error("Katana crawl options require --agent web or --agent all")
    if args.agent == "web" and args.ports:
        parser.error("--ports is for Nmap; put the web port in --target http://host:port")
    if args.agent == "web":
        try:
            args.target = normalize(args.target)
        except ValueError as exc:
            parser.error(str(exc))
    elif "://" in args.target:
        parser.error("Nmap target must be an IP/CIDR; use --agent web for a URL")

    print(f"=== CART — loading scope from {args.scope} ===")
    try:
        scope_manager = ScopeManager(args.scope)
    except (OSError, ValueError) as exc:
        print(f"Scope configuration failed: {exc}")
        return 1

    executor = RealScopedExecutor(
        is_in_scope=scope_manager.is_in_scope,
        log_scope_check=scope_manager.log_scope_check,
        web_options=web_options,
    )

    if args.agent == "web":
        target_url = urlsplit(args.target)
        port = target_url.port or (443 if target_url.scheme == "https" else 80)
        if scope_manager.allowed_ports is not None and port not in scope_manager.allowed_ports:
            print(f"Web port {port} is not in scope allowed_ports")
            return 1
        web_result = _run_web(Job(job_id="run-web-001", agent="web", target=args.target), executor)
        return _save_and_exit(args.output, None, [web_result])

    ports = scope_manager.allowed_ports
    if args.ports:
        try:
            ports = list(dict.fromkeys(int(value.strip()) for value in args.ports.split(",")))
            if not ports or any(not 1 <= port <= 65535 for port in ports):
                raise ValueError("Ports must be from 1 to 65535")
            if scope_manager.allowed_ports is not None and not set(ports) <= set(scope_manager.allowed_ports):
                raise ValueError("Requested ports must be in scope allowed_ports")
        except ValueError as exc:
            parser.error(str(exc))

    job = Job(job_id="run-001", agent="network", target=args.target, allowed_ports=ports)

    print(f"\n=== Running network discovery against {args.target} ===")
    try:
        result = run_network_agent(job, executor)
    except (ToolNotInstalled, ToolExecutionError, ScopeViolation, subprocess.TimeoutExpired, OSError, ValueError) as exc:
        print(f"Network discovery failed: {exc}")
        return 1

    print(f"\n=== Result: {result.status} ===")
    print(f"Hosts found: {len(result.hosts)}")
    for host in result.hosts:
        print(f"  {host.ip} ({host.hostname or 'no hostname'})")
        for svc in host.services:
            print(f"    - {svc.port}/{svc.protocol}  {svc.service}  {svc.version or ''}")

    print(f"\nFindings: {len(result.findings)}")
    for finding in result.findings:
        print(f"  [{finding.finding_type}] {finding.description}")

    web_results = []
    seen = set()
    for index, follow_up in enumerate(result.follow_up_jobs, start=1):
        if follow_up.get("agent") != "web":
            continue
        key = (follow_up["target"], follow_up.get("context", {}).get("scheme"))
        if key in seen:
            continue
        seen.add(key)
        web_job = Job(job_id=f"run-web-{index:03d}", **follow_up)
        scheme = web_job.context.get("scheme", "http")
        url = web_job.target if "://" in web_job.target else f"{scheme}://{web_job.target}"
        # JSON quoting works for these literal URLs in both PowerShell and POSIX shells.
        print(f"\nSuggested separate web scan: python main.py --agent web --scope {json.dumps(args.scope)} --target {json.dumps(url)} --depth 3 --rate-limit 5 --output web-results.json")
        if args.agent != "network":
            web_results.append(_run_web(web_job, executor))

    if args.agent == "network":
        print("\nNmap-only mode: Katana was not started. Run a suggested command above when ready.")
    elif not web_results:
        print("\nNo HTTP/HTTPS services detected; Katana was not needed.")
    return _save_and_exit(args.output, result, web_results)


def _bounded_int(maximum):
    def convert(value):
        try:
            number = int(value)
        except ValueError:
            raise argparse.ArgumentTypeError("Expected an integer")
        if not 1 <= number <= maximum:
            raise argparse.ArgumentTypeError(f"Expected a value from 1 to {maximum}")
        return number
    return convert


def _run_web(job, executor):
    print(f"\n=== Running standard Katana against {job.target} ===", flush=True)
    pages = []
    result = run_web_agent(job, executor, inventory=pages)
    forms = [form for page in pages for form in page.get("forms", [])]
    technologies = sorted({tech for page in pages for tech in page.get("technologies", [])})
    print(f"Web result: {result.status}; endpoints: {len(pages)}; forms: {len(forms)}")
    print(f"Technologies: {', '.join(technologies) or 'none detected'}")
    for page in pages:
        print(f"  {page.get('method', 'GET')} {page['url']} -> {page.get('status')} ({page.get('classification', 'endpoint')})")
    for form in forms:
        names = ", ".join(dict.fromkeys(field.get("name") or "unnamed" for field in form.get("fields", [])))
        print(f"  Form {form.get('method', 'GET')} {form.get('action')}: {names}")
    if result.status != "completed":
        print("Web discovery incomplete; inspect scope, Katana installation and crawl limits.")
    return {"job": job.model_dump(), "result": result.model_dump(), "endpoints": pages}


def _save_and_exit(output_path, network_result, web_results):
    if output_path:
        output = Path(output_path)
        try:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps({"network": network_result.model_dump() if network_result else None, "web": web_results}, indent=2), encoding="utf-8")
        except OSError as exc:
            print(f"Could not save results: {exc}")
            return 1
        print(f"\nResults saved to {output.resolve()}")
    else:
        print("\nResults printed only; use --output results.json to save them.")
    return 0 if (network_result is None or network_result.status == "completed") and all(item["result"]["status"] == "completed" for item in web_results) else 2


if __name__ == "__main__":
    raise SystemExit(main())
