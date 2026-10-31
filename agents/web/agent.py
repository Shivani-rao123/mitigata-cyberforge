"""
agents/web/agent.py

Web surface agent (FR-2). Crawls a discovered HTTP(S) service, lists the
endpoints and forms it finds, and flags common issues:

  - sensitive_endpoint_found   — a path matching a list of commonly
    sensitive locations (admin panels, login pages, config/backup files,
    VCS metadata, etc.) that actually responded.
  - default_creds_found        — a login-looking form (one with a
    password-type field) found on the site. Flagged only here — actually
    proving a default/weak credential works is the verification engine's
    job (FR-6), not this agent's. Matches the exact flow traced in
    userflow.md (step 4 flags it, step 5 confirms it).
  - reflected_input             — a GET-method form whose input is echoed
    back, unescaped, in the response when probed with a unique marker
    string (the classic reflected-XSS smell test).
  - missing_security_header     — the site is missing one or more of a
    small set of security-relevant response headers.
  - directory_listing_enabled   — a response that looks like an
    autoindex / directory-listing page.

Never calls `requests` directly — all HTTP access goes through the
injected `executor` (core.scoped_executor.ScopedExecutor), which enforces
scope on every request. See core/scoped_executor.py.

Also closes the coordination loop described in agents/binary/agent.py's
docstring (FR-4): if crawling turns up a link that looks like a
downloadable binary, this agent hands it off as a follow-up binary-agent
job instead of trying to analyze it itself.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from common.contracts import Evidence, FindingOut, Job, JobResult
from core.scoped_executor import ScopedExecutor

# Paths worth a dedicated look even if nothing else about them is odd.
# Matched against both the exact path and as a parent of deeper paths
# (e.g. "/admin" also matches "/admin/dashboard").
SENSITIVE_PATHS = (
    "/admin",
    "/login",
    "/wp-admin",
    "/wp-login.php",
    "/phpmyadmin",
    "/.git/config",
    "/.env",
    "/config",
    "/backup",
    "/console",
    "/manager/html",
    "/.svn/entries",
)

# Form input names that suggest "this form logs someone in".
PASSWORD_FIELD_NAMES = {"password", "passwd", "pwd", "pass"}

# Response headers worth having; missing any of these is worth a finding.
# Keys are lower-cased header names, matched case-insensitively.
SECURITY_HEADERS = {
    "x-frame-options": "clickjacking protection — without it, the page can be framed and used to trick users into clicking hidden UI",
    "x-content-type-options": "MIME-sniffing protection — without it, browsers may render served content as a different, exploitable type",
    "content-security-policy": "restricts which scripts/resources a page may load — a key defense against XSS",
}

DIRECTORY_LISTING_MARKERS = ("Index of /", "<title>Index of")

# Extensions that suggest a link points at a downloadable binary worth
# handing to the binary agent (FR-3) instead of this agent analyzing it.
BINARY_EXTENSIONS = (
    ".exe",
    ".dll",
    ".bin",
    ".so",
    ".apk",
    ".deb",
    ".rpm",
    ".msi",
    ".dmg",
    ".sh",
)

HREF_RE = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)

# Unique enough that it won't collide with real page content.
REFLECTED_PROBE_MARKER = "CARTPROBE_6f1e9c"


def run(job: Job, executor: ScopedExecutor) -> JobResult:
    """
    Execute a web-surface job.

    `job.target` is either a full URL ("http://host:port/path") or the
    bare "host:port" shape the network agent's follow-up jobs use (scheme
    is inferred from the port when one isn't given). Scope is enforced by
    `executor` on every request it makes — this function never touches
    the network directly.
    """
    base_url = _to_base_url(job.target)

    pages = executor.crawl(base_url)
    header_response = executor.http_get(base_url)

    findings: list[FindingOut] = []
    findings.extend(_check_missing_headers(base_url, header_response))

    follow_up_jobs: list[dict] = []
    seen_binary_links: set[str] = set()

    for page in pages:
        findings.extend(_check_sensitive_path(page))
        findings.extend(_check_login_forms(page))
        findings.extend(_check_directory_listing(page))
        findings.extend(_check_reflected_input(page, executor))

        for link in _extract_binary_links(page):
            if link in seen_binary_links:
                continue
            seen_binary_links.add(link)
            follow_up_jobs.append(
                {
                    "agent": "binary",
                    "target": link,
                    "context": dict(job.context),
                }
            )

    return JobResult(
        job_id=job.job_id,
        status="completed",
        findings=findings,
        follow_up_jobs=follow_up_jobs,
    )


def _to_base_url(target: str) -> str:
    if target.startswith("http://") or target.startswith("https://"):
        return target
    if ":" in target:
        host, _, port_str = target.rpartition(":")
        port = int(port_str)
    else:
        host, port = target, 80
    scheme = "https" if port in (443, 8443) else "http"
    return f"{scheme}://{host}:{port}"


def _host(url: str) -> str | None:
    return urlparse(url).hostname


def _port(url: str) -> int | None:
    return urlparse(url).port


def _matches_sensitive_path(path: str, sensitive: str) -> bool:
    p = path.rstrip("/")
    s = sensitive.rstrip("/")
    return p == s or p.startswith(s + "/")


def _check_sensitive_path(page: dict) -> list[FindingOut]:
    if page.get("status", 0) not in (200, 401, 403):
        return []  # doesn't actually exist (404 etc) — nothing to flag

    path = urlparse(page["url"]).path or "/"
    for sensitive in SENSITIVE_PATHS:
        if _matches_sensitive_path(path, sensitive):
            return [
                FindingOut(
                    finding_type="sensitive_endpoint_found",
                    description=f"Sensitive endpoint {path} responded with HTTP {page['status']}",
                    host=_host(page["url"]),
                    service_port=_port(page["url"]),
                    evidence=Evidence(
                        kind="http_response",
                        summary=f"GET {page['url']} -> {page['status']}",
                    ),
                )
            ]
    return []


def _check_login_forms(page: dict) -> list[FindingOut]:
    findings: list[FindingOut] = []
    for form in page.get("forms", []):
        inputs_lower = {i.lower() for i in form.get("inputs", [])}
        if inputs_lower & PASSWORD_FIELD_NAMES:
            findings.append(
                FindingOut(
                    finding_type="default_creds_found",
                    description=(
                        f"Login form found at {page['url']} "
                        f"(action={form.get('action') or page['url']}) — "
                        f"candidate for default-credential testing"
                    ),
                    host=_host(page["url"]),
                    service_port=_port(page["url"]),
                    evidence=Evidence(
                        kind="http_response",
                        summary=(
                            f"GET {page['url']} -> {page.get('status')}, "
                            f"form fields: {sorted(form.get('inputs', []))}"
                        ),
                    ),
                )
            )
    return findings


def _check_directory_listing(page: dict) -> list[FindingOut]:
    body = page.get("body", "")
    if any(marker in body for marker in DIRECTORY_LISTING_MARKERS):
        return [
            FindingOut(
                finding_type="directory_listing_enabled",
                description=f"Directory listing appears to be enabled at {page['url']}",
                host=_host(page["url"]),
                service_port=_port(page["url"]),
                evidence=Evidence(
                    kind="http_response",
                    summary=(
                        f"GET {page['url']} -> {page.get('status')}, "
                        f"body matches a directory-index pattern"
                    ),
                ),
            )
        ]
    return []


def _check_reflected_input(page: dict, executor: ScopedExecutor) -> list[FindingOut]:
    findings: list[FindingOut] = []
    for form in page.get("forms", []):
        if form.get("method", "get").lower() != "get":
            # The executor only offers GET (http_get/crawl) — no POST
            # primitive — so POST forms aren't probed here. Reflected
            # input via GET parameters is the common, cheap case anyway.
            continue

        inputs = form.get("inputs", [])
        if not inputs:
            continue

        action_url = urljoin(page["url"], form.get("action") or page["url"])
        query = "&".join(f"{name}={REFLECTED_PROBE_MARKER}" for name in inputs)
        separator = "&" if "?" in action_url else "?"
        probe_url = f"{action_url}{separator}{query}"

        response = executor.http_get(probe_url)
        if REFLECTED_PROBE_MARKER in response.get("body", ""):
            findings.append(
                FindingOut(
                    finding_type="reflected_input",
                    description=(
                        f"Form at {page['url']} (action={form.get('action')}) "
                        f"echoes unescaped input back in the response"
                    ),
                    host=_host(page["url"]),
                    service_port=_port(page["url"]),
                    evidence=Evidence(
                        kind="http_response",
                        summary=(
                            f"GET {probe_url} -> {response.get('status')}, "
                            f"marker '{REFLECTED_PROBE_MARKER}' reflected in body"
                        ),
                    ),
                )
            )
    return findings


def _check_missing_headers(base_url: str, response: dict) -> list[FindingOut]:
    headers_lower = {k.lower() for k in response.get("headers", {})}
    missing = [name for name in SECURITY_HEADERS if name not in headers_lower]
    if not missing:
        return []

    return [
        FindingOut(
            finding_type="missing_security_header",
            description=f"{base_url} is missing security header(s): {', '.join(missing)}",
            host=_host(base_url),
            service_port=_port(base_url),
            evidence=Evidence(
                kind="http_response",
                summary=(
                    f"GET {base_url} -> {response.get('status')}, "
                    f"headers present: {sorted(headers_lower)}"
                ),
            ),
        )
    ]


def _extract_binary_links(page: dict) -> list[str]:
    body = page.get("body", "")
    links: list[str] = []
    for href in HREF_RE.findall(body):
        resolved = urljoin(page["url"], href)
        path = urlparse(resolved).path.lower()
        if path.endswith(BINARY_EXTENSIONS):
            links.append(resolved)
    return links
