"""
agents/network/agent.py

Network discovery agent. Scans the job's target through the ScopedExecutor,
turns raw scan output into HostOut/ServiceOut/FindingOut, and requests a
follow-up web-agent job for every HTTP-like service it finds.

Never calls nmap, sockets, or requests directly — all network access goes
through the injected `executor` (core.scoped_executor.ScopedExecutor),
which enforces scope. See core/scoped_executor.py.
"""

from __future__ import annotations

from common.contracts import (
    Evidence,
    FindingOut,
    HostOut,
    Job,
    JobResult,
    ServiceOut,
)
from common.llm import choose_follow_ups
from core.scoped_executor import ScopedExecutor

# Service names treated as web surfaces worth a follow-up web-agent job.
WEB_SERVICE_NAMES = {"http", "https", "http-proxy", "http-alt"}


def run(job: Job, executor: ScopedExecutor) -> JobResult:
    """
    Execute a network-discovery job.

    Assumes `job.agent == "network"` and that scope has already been
    validated by whoever enqueued this job — this function additionally
    relies on `executor.scan` to enforce scope itself before any probe.
    """
    raw = executor.scan(job.target, job.allowed_ports)

    hosts: list[HostOut] = []
    findings: list[FindingOut] = []
    follow_up_jobs: list[dict] = []

    for raw_host in raw.get("hosts", []):
        ip = raw_host["ip"]
        services = [
            ServiceOut(
                port=s["port"],
                protocol=s["protocol"],
                service=s["service"],
                version=s.get("version"),
            )
            for s in raw_host.get("services", [])
        ]
        hosts.append(HostOut(ip=ip, hostname=raw_host.get("hostname"), services=services))

        for service in services:
            findings.append(
                FindingOut(
                    finding_type="open_port",
                    description=f"Port {service.port}/{service.protocol} open ({service.service})",
                    host=ip,
                    service_port=service.port,
                    evidence=Evidence(
                        kind="nmap_output",
                        summary=f"{service.port}/{service.protocol} open {service.service}"
                        + (f" {service.version}" if service.version else ""),
                    ),
                )
            )

            if service.service.lower() in WEB_SERVICE_NAMES:
                follow_up_jobs.append(
                    {
                        "agent": "web",
                        "target": f"{ip}:{service.port}",
                        "context": {"host_ip": ip, "service_port": service.port},
                    }
                )

    # Optional LLM-in-the-loop pass (off by default — see
    # common/llm.py's own docstring). The rule-based list above is
    # built exactly as before either way; this can only trim/reorder
    # it, never add to it. choose_follow_ups() returns None on any
    # failure (including the feature being off), in which case the
    # rule-based list is used completely unchanged.
    chosen_follow_ups = choose_follow_ups(job, findings, follow_up_jobs)
    if chosen_follow_ups is not None:
        follow_up_jobs = chosen_follow_ups

    return JobResult(
        job_id=job.job_id,
        status="completed",
        hosts=hosts,
        findings=findings,
        follow_up_jobs=follow_up_jobs,
    )