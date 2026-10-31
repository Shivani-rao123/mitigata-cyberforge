"""Inventory findings only; discovery is not proof of a vulnerability."""
from urllib.parse import urlsplit
import subprocess

from common.contracts import Evidence, FindingOut, JobResult
from core.scoped_executor import ScopeViolation
from core.tool_engine import ToolExecutionError, ToolNotInstalled


def run(job, executor, *, inventory=None):
    target = job.target
    if "://" not in target:
        scheme = job.context.get("scheme", "https" if target.endswith(":443") else "http")
        target = f"{scheme}://{target}"
    try:
        pages = executor.crawl(target)
    except (ToolNotInstalled, ToolExecutionError, ScopeViolation, OSError, ValueError, subprocess.TimeoutExpired):
        return JobResult(job_id=job.job_id, status="failed")
    if inventory is not None:
        inventory.extend(pages)
    findings = []
    for page in pages:
        if page.get("classification") in {"missing", "error", "rate_limited"} or page.get("error"):
            continue
        url = urlsplit(page["url"])
        findings.append(FindingOut(
            finding_type="web_surface", host=job.context.get("host_ip", url.hostname),
            service_port=url.port or (443 if url.scheme == "https" else 80),
            description=f"{page.get('classification', 'endpoint')}: {url.path}",
            evidence=Evidence(kind="http_response", summary=(
                f"{page.get('method', 'GET')} {url.path[:160]} -> {page.get('status', 'unverified')}; "
                f"forms={len(page.get('forms', []))}; inputs={len(page.get('inputs', []))}; technologies={','.join(page.get('technologies', []))}"
            )[:400]),
        ))
    partial = any(p.get("error") or p.get("truncated") or (p.get("status") or 0) >= 429 for p in pages) or bool(pages and pages[0].get("crawl", {}).get("limited"))
    return JobResult(job_id=job.job_id, status="failed" if not findings and partial else "partial" if partial else "completed", findings=findings)
