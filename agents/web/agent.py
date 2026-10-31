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
  - js_secret_found             — a hardcoded secret pulled directly out
    of a JS bundle's source (katana's -jsluice mode only — the native
    requests+regex crawl can never see this, since it never fetches
    <script src> as code).
  - js_endpoint_found           — an API endpoint referenced only inside
    JS source, not in any server-rendered HTML — exactly the "attack
    surface a plain crawler can't see on a JS/React/TS SPA" gap (katana
    -jsluice only).
  - crawler_fallback            — informational: the preferred JS-aware
    crawler (katana) wasn't available/usable, so this run fell back to
    the native crawler. Surfaced as a (non-security) finding rather than
    a silent downgrade, so a report reader can tell "found nothing" apart
    from "couldn't look as thoroughly as it could have."

Never calls `requests` directly — all HTTP access goes through the
injected `executor` (core.scoped_executor.ScopedExecutor), which enforces
scope on every request. See core/scoped_executor.py.

Also closes the coordination loop described in agents/binary/agent.py's
docstring (FR-4): if crawling turns up a link that looks like a
downloadable binary, this agent hands it off as a follow-up binary-agent
job instead of trying to analyze it itself.

Crawler selection: `job.context.get("crawler")` controls which backend is
used —
  - "auto" (default): try executor.crawl_js() (katana) if the executor
    exposes it; on ToolNotInstalled/ToolNotConfigured/a subprocess
    timeout, silently fall back to executor.crawl() (the native,
    always-available path) and record a `crawler_fallback` finding.
  - "requests": always use executor.crawl() — skips katana entirely,
    even if available (useful for a fast/offline run).
  - "katana": always use executor.crawl_js() — if it's unavailable, the
    error propagates instead of silently falling back (an explicit
    request for the JS-aware crawl should fail loudly, not degrade
    quietly).
"""

from __future__ import annotations

import subprocess
from urllib.parse import urljoin, urlparse

from common.contracts import Evidence, FindingOut, Job, JobResult
from common.html_extract import extract_links
from common.redact import redact
from core.scoped_executor import ScopedExecutor, ToolNotConfigured, ToolNotInstalled

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

# Unique enough that it won't collide with real page content.
REFLECTED_PROBE_MARKER = "CARTPROBE_6f1e9c"

# Errors that mean "katana isn't usable right now" — in "auto" mode these
# trigger a fallback to the native crawler instead of failing the job.
_KATANA_UNAVAILABLE_ERRORS = (ToolNotInstalled, ToolNotConfigured, subprocess.TimeoutExpired)


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
    crawler_mode = job.context.get("crawler", "auto")

    pages, js_findings, findings = _crawl(executor, base_url, crawler_mode)

    header_response = executor.http_get(base_url)
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

    for js_finding in js_findings:
        findings.extend(_check_js_finding(js_finding, base_url))

    return JobResult(
        job_id=job.job_id,
        status="completed",
        findings=findings,
        follow_up_jobs=follow_up_jobs,
    )


def _crawl(
    executor: ScopedExecutor, base_url: str, crawler_mode: str
) -> tuple[list[dict], list[dict], list[FindingOut]]:
    """Returns (pages, js_findings, findings) — `findings` only ever
    carries the crawler_fallback note (or is empty), kept separate from
    the per-page checks below for clarity.

    `crawl_js` is deliberately NOT part of the ScopedExecutor interface
    (see core/scoped_executor.py) — an executor either has it or doesn't,
    checked here with hasattr rather than assumed. That distinction
    matters for the crawler_fallback finding below: an executor that
    structurally doesn't offer JS-aware crawling at all (hasattr False)
    is a normal, expected shape, not worth a note every single run; an
    executor that DOES offer it but couldn't use it THIS run (katana
    missing/misconfigured/timed out) is the case worth flagging.
    """
    if crawler_mode not in ("auto", "requests", "katana"):
        raise ValueError(
            f"job.context['crawler'] must be 'auto', 'requests', or 'katana', "
            f"got {crawler_mode!r}"
        )

    if crawler_mode == "requests":
        return executor.crawl(base_url), [], []

    has_js_crawl = hasattr(executor, "crawl_js")

    if crawler_mode == "katana":
        if not has_js_crawl:
            raise ToolNotInstalled(
                "crawler='katana' was explicitly requested but this executor "
                "doesn't implement crawl_js()"
            )
        result = executor.crawl_js(base_url)
        return result["pages"], result["js_findings"], []

    # "auto": prefer katana when the executor offers it at all, falling
    # back to the native crawler on anything that means "katana isn't
    # usable right now" rather than failing the whole job over a
    # missing/misbehaving optional tool. An executor that doesn't offer
    # crawl_js at all just quietly uses the native crawler — no note.
    if not has_js_crawl:
        return executor.crawl(base_url), [], []

    try:
        result = executor.crawl_js(base_url)
        return result["pages"], result["js_findings"], []
    except _KATANA_UNAVAILABLE_ERRORS as exc:
        fallback_note = FindingOut(
            finding_type="crawler_fallback",
            description=(
                "The JS-aware crawler (katana) wasn't usable for this run "
                f"({type(exc).__name__}: {exc}) — fell back to the native "
                "crawler. Endpoints/secrets that only exist inside JS "
                "bundles may have been missed."
            ),
            host=_host(base_url),
            service_port=_port(base_url),
            evidence=Evidence(kind="tool_unavailable", summary=str(exc)),
        )
        return executor.crawl(base_url), [], [fallback_note]


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


def _check_js_finding(js_finding: dict, base_url: str) -> list[FindingOut]:
    """Turns one katana -jsluice record (see core/parsers/katana.py) into
    a FindingOut. Defensive against missing/malformed fields — a
    half-populated record is skipped, not a crash."""
    kind = js_finding.get("finding_kind")
    source = js_finding.get("source") or base_url

    if kind == "secret":
        value = js_finding.get("value")
        if not value:
            return []
        rule = js_finding.get("rule", "unknown")
        return [
            FindingOut(
                finding_type="js_secret_found",
                description=(
                    f"Hardcoded secret ({rule}) found in client-side JS "
                    f"served from {source}"
                ),
                host=_host(source),
                service_port=_port(source),
                evidence=Evidence(
                    kind="jsluice_secret",
                    summary=f"{rule}: {redact(value)}",
                ),
            )
        ]

    if kind == "endpoint":
        endpoint = js_finding.get("endpoint")
        if not endpoint:
            return []
        method = js_finding.get("method", "GET")
        return [
            FindingOut(
                finding_type="js_endpoint_found",
                description=(
                    f"API endpoint {method} {endpoint} referenced only in "
                    f"client-side JS from {source} — not reachable via a "
                    f"server-rendered crawl"
                ),
                host=_host(source),
                service_port=_port(source),
                evidence=Evidence(
                    kind="jsluice_endpoint",
                    summary=f"{method} {endpoint} (source: {source})",
                ),
            )
        ]

    return []  # unrecognized finding_kind — defensive no-op, not a crash


def _extract_binary_links(page: dict) -> list[str]:
    links: list[str] = []
    for resolved in extract_links(page.get("body", ""), page["url"]):
        if urlparse(resolved).path.lower().endswith(BINARY_EXTENSIONS):
            links.append(resolved)
    return links
