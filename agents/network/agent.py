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
from core.scoped_executor import ScopedExecutor

# Service names treated as web surfaces worth a follow-up web-agent job.
WEB_SERVICE_NAMES = {"http", "https", "http-proxy", "http-alt", "https-alt", "ssl/http", "ssl/https"}


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

            name = service.service.lower()
            if service.protocol == "tcp" and name in WEB_SERVICE_NAMES:
                authority = f"[{ip}]" if ":" in ip else ip
                scheme = "https" if name in {"https", "https-alt", "ssl/http", "ssl/https"} else "http"
                follow_up_jobs.append(
                    {
                        "agent": "web",
                        "target": f"{authority}:{service.port}",
                        "context": {"host_ip": ip, "service_port": service.port, "scheme": scheme},
                    }
                )

    return JobResult(
        job_id=job.job_id,
        status="completed",
        hosts=hosts,
        findings=findings,
        follow_up_jobs=follow_up_jobs,
    )
