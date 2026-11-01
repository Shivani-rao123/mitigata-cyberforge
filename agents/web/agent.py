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
  - js_secret_found             — a hardcoded secret pulled out of a JS
    bundle's source. Found via katana's -jsluice mode when available, or
    (when it isn't — see common/js_extract.py) via this agent's own
    fetch-and-regex-scan fallback: fetch every <script src=...> the
    crawl found and scan its body against common/secret_patterns.py.
    Narrower than katana (a real JS parser), but needs no external
    binary — works on any machine with just this project's existing
    Python deps.
  - js_endpoint_found           — an API endpoint referenced only inside
    JS source, not in any server-rendered HTML — exactly the "attack
    surface a plain crawler can't see on a JS/React/TS SPA" gap. Same
    katana-or-fallback split as js_secret_found; the fallback uses
    common/js_extract.py's regex matching for fetch/axios/jQuery.ajax/
    XMLHttpRequest call shapes — the common cases, not a full JS parser.
  - crawler_fallback            — informational: the preferred JS-aware
    crawler (katana) wasn't available/usable, so this run fell back to
    the native crawler (with its own JS-bundle regex scan — see above,
    not a silent "give up"). Surfaced as a (non-security) finding rather
    than a silent downgrade, so a report reader can tell "found nothing"
    apart from "couldn't look as thoroughly as it could have."
  - secret_in_file_found        — a hardcoded secret found in a crawled
    plain-text/data file that ISN'T JS (a .txt handover note, a .env, a
    .bak config, a .log, ...) — e.g. a file-manager-style directory
    listing someone can download from. Regex-scanned against the same
    common/secret_patterns.py patterns js_secret_found uses, kept as a
    separate finding_type since the discovery path differs (see
    TEXT_SECRET_SCAN_EXTENSIONS). Deliberately does NOT scan ordinary
    HTML page bodies — see that constant's comment.
  - redirect_followed            — informational: a crawled page was only
    reached after following one or more redirects (http->https, a bare
    IP landing on its canonical vhost, a gate page in front of a
    dashboard/file-manager app, ...). core/scoped_executor.py's crawl()
    follows these itself now (bounded hops, each hop scope-checked) —
    this just makes that fact visible in the report instead of the final
    content silently showing up with no explanation of how it was reached.

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

import re
import subprocess
from urllib.parse import quote, unquote, urljoin, urlparse

from common.contracts import Evidence, FindingOut, Job, JobResult
from common.flag_patterns import FLAG_PATTERNS
from common.html_extract import extract_links, extract_script_srcs
from common.js_extract import extract_js_endpoints
from common.llm import choose_follow_ups
from common.redact import redact
from common.secret_patterns import SECRET_PATTERNS
from core.scoped_executor import ScopedExecutor, ScopeViolation, ToolNotConfigured, ToolNotInstalled

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

# Extensions that suggest a crawled link is a plain-text/data file worth
# regex-scanning for hardcoded secrets — the thing a file-manager-style
# listing (a dynamic directory of downloadable files, e.g. a "File
# Manager" app) commonly exposes: handover notes, exported configs,
# backups, logs, structured data dumps. Deliberately disjoint from
# BINARY_EXTENSIONS above (those go to the binary agent instead) and
# deliberately NOT including .html/.htm — scanning a normal HTML page's
# full body for SECRET_PATTERNS is noisy (marketing/example copy, embedded
# sample code) and is not done here; js_secret_found already covers the
# one HTML-adjacent case that matters (JS bundles — see _scan_js_bundles).
TEXT_SECRET_SCAN_EXTENSIONS = (
    ".txt",
    ".log",
    ".conf",
    ".cfg",
    ".ini",
    ".env",
    ".yaml",
    ".yml",
    ".json",
    ".xml",
    ".csv",
    ".md",
    ".properties",
    ".bak",
    ".sql",
)

def _extension_match_re(extensions: tuple[str, ...]) -> re.Pattern:
    """
    Builds a regex that matches any of `extensions` as a filename-ending
    token ANYWHERE in a URL — not just urlparse(url).path, which a
    file-manager-style app routinely bypasses by passing the filename as
    a query-string VALUE instead of putting it in the path at all (e.g.
    index.php?p=ops%2Fnetops-handover.txt&dl has no extension anywhere
    in its path, "/index.php" — only inside the URL-encoded query).
    Callers match this against the full, URL-decoded url (unquote(url)),
    not just its path.

    Bounded so e.g. ".txt" has to actually END a filename-looking token
    (next char is '/', '?', '&', '#', or end-of-string) rather than
    matching some unrelated substring like "textile", or a longer,
    different extension like ".txtfile".
    """
    return re.compile(
        r"\.(" + "|".join(ext.lstrip(".") for ext in extensions) + r")(?:[/?&#]|$)",
        re.IGNORECASE,
    )


# See _check_file_secrets() below.
_SCANNABLE_FILE_EXT_RE = _extension_match_re(TEXT_SECRET_SCAN_EXTENSIONS)

# See _extract_binary_links() below — the exact same query-string-filename
# gap applies to binary downloads (an .exe/.apk/... served via a
# file-manager's "?p=...&dl"-style link) as it does to text-file secrets;
# this was a real, live-confirmed miss (a query-string binary link
# produced no binary follow-up job at all, so the binary agent never ran
# — observed directly: only a path-based .exe link was ever picked up).
_BINARY_EXT_RE = _extension_match_re(BINARY_EXTENSIONS)

# Unique enough that it won't collide with real page content. Includes
# an HTML-special character ("<...>") on purpose — a prior all-alphanumeric
# marker ("CARTPROBE_6f1e9c") could never actually distinguish a page that
# safely HTML-escapes reflected input (which would re-render it as
# "&lt;CARTPROBE_6f1e9c&gt;") from one that doesn't: the marker text
# itself showed up in the body either way, so every GET form with any
# input at all was flagged, escaped or not — a confirmed false-positive
# source (e.g. a "/controls/escaped"-style endpoint that correctly
# escapes). Checking for this exact RAW form in the response (see
# _check_reflected_input below) only matches when the `<`/`>` survived
# un-escaped, which is the actual signal that matters here.
REFLECTED_PROBE_MARKER = "<CARTPROBE_6f1e9c>"

# Errors that mean "katana isn't usable right now" — in "auto" mode these
# trigger a fallback to the native crawler instead of failing the job.
_KATANA_UNAVAILABLE_ERRORS = (ToolNotInstalled, ToolNotConfigured, subprocess.TimeoutExpired)

# Hard cap on how many <script src=...> files one crawl will fetch and
# scan — a page can reference a lot of third-party JS (analytics, ad
# tech, UI framework chunks); bounding this keeps a crawl's time budget
# predictable regardless of how many scripts a page happens to load.
MAX_JS_FILES_PER_CRAWL = 15


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
        findings.extend(_check_redirect_followed(page))
        findings.extend(_check_sensitive_path(page))
        findings.extend(_check_login_forms(page))
        findings.extend(_check_directory_listing(page))
        findings.extend(_check_reflected_input(page, executor))
        findings.extend(_check_file_secrets(page))
        findings.extend(_check_planted_flags(page))

        binary_links = _extract_binary_links(page)
        if page.get("looks_binary"):
            # A link reached ONLY via Content-Type/magic-byte sniffing
            # (core/scoped_executor.py's crawl()) — no extension anywhere
            # in its URL at all (a direct /download/<id>-style link), so
            # _extract_binary_links()'s extension matching can never find
            # it. The crawl already fetched and classified it; this is
            # just the page itself being a binary, not a link ON it.
            binary_links.append(page["url"])

        for link in binary_links:
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

    # Optional LLM-in-the-loop pass (off by default — see
    # common/llm.py's own docstring). Same pattern as
    # agents/network/agent.py: the rule-based binary-link candidates
    # above are built exactly as before either way; this can only
    # trim/reorder that list, never add a target that wasn't already
    # found by crawling.
    chosen_follow_ups = choose_follow_ups(job, findings, follow_up_jobs)
    if chosen_follow_ups is not None:
        follow_up_jobs = chosen_follow_ups

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
        pages = executor.crawl(base_url)
        return pages, _scan_js_bundles(executor, pages, base_url), []

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
    # back to the native crawler (plus its own JS-bundle regex scan —
    # see _scan_js_bundles) on anything that means "katana isn't usable
    # right now" rather than failing the whole job over a missing/
    # misbehaving optional tool. An executor that doesn't offer
    # crawl_js at all just quietly uses the native crawler — no note.
    if not has_js_crawl:
        pages = executor.crawl(base_url)
        return pages, _scan_js_bundles(executor, pages, base_url), []

    try:
        result = executor.crawl_js(base_url)
        return result["pages"], result["js_findings"], []
    except _KATANA_UNAVAILABLE_ERRORS as exc:
        fallback_note = FindingOut(
            finding_type="crawler_fallback",
            description=(
                "The JS-aware crawler (katana) wasn't usable for this run "
                f"({type(exc).__name__}: {exc}) — fell back to the native "
                "crawler's own (narrower, regex-based) JS-bundle scan. "
                "Endpoints/secrets built dynamically (string concatenation, "
                "a wrapper function) rather than as a plain string literal "
                "may have been missed."
            ),
            host=_host(base_url),
            service_port=_port(base_url),
            evidence=Evidence(kind="tool_unavailable", summary=str(exc)),
        )
        pages = executor.crawl(base_url)
        return pages, _scan_js_bundles(executor, pages, base_url), [fallback_note]


def _scan_js_bundles(executor: ScopedExecutor, pages: list[dict], base_url: str) -> list[dict]:
    """
    The no-external-binary alternative to katana's -jsluice: fetches every
    SAME-HOST <script src=...> referenced by the crawled pages and
    regex-scans each one for secrets (common/secret_patterns.py — the
    same patterns the binary agent and katana parser use) and API-call
    endpoints (common/js_extract.py). Narrower than a real JS parser, but
    needs nothing beyond this project's existing Python dependencies.

    Third-party scripts (a CDN-hosted library like code.jquery.com — the
    overwhelmingly common case for <script src>) are skipped BEFORE
    fetching, not just left to fail: they're out of scope by definition
    (this agent only has authorization for the target's own host), not
    useful for finding the target's own secrets/endpoints, and fetching
    one used to crash the entire web stage with an unhandled
    ScopeViolation the moment a page referenced one — wiping out every
    finding the rest of the crawl had already produced. The per-URL
    try/except below is defense in depth on top of that filter (e.g. a
    same-host script whose DNS resolves somewhere unexpected), so a
    single bad script still can't take down the whole stage.

    Returns js_findings in the same {"finding_kind": "secret"|"endpoint",
    "source": ..., ...} shape core/parsers/katana.py produces, so
    _check_js_finding() below handles either source identically.
    """
    base_host = urlparse(base_url).netloc

    script_urls: list[str] = []
    seen_scripts: set[str] = set()
    for page in pages:
        for src in extract_script_srcs(page.get("body", ""), page.get("url", base_url)):
            if src in seen_scripts:
                continue
            seen_scripts.add(src)
            if urlparse(src).netloc != base_host:
                continue  # third-party script (CDN, analytics, ...) — out of scope, skip
            script_urls.append(src)
            if len(script_urls) >= MAX_JS_FILES_PER_CRAWL:
                break
        if len(script_urls) >= MAX_JS_FILES_PER_CRAWL:
            break

    js_findings: list[dict] = []
    seen_secrets: set[tuple[str, str]] = set()

    for script_url in script_urls:
        try:
            response = executor.http_get(script_url)
        except ScopeViolation:
            continue  # e.g. DNS resolved this same-host-looking URL out of scope — skip, don't crash
        body = response.get("body", "")
        if not body:
            continue

        for secret_type, (pattern, description) in SECRET_PATTERNS.items():
            match = pattern.search(body)
            if not match:
                continue
            dedup_key = (script_url, secret_type)
            if dedup_key in seen_secrets:
                continue
            seen_secrets.add(dedup_key)
            js_findings.append(
                {
                    "finding_kind": "secret",
                    "source": script_url,
                    "rule": description,
                    "value": match.group(0),
                }
            )

        for endpoint_match in extract_js_endpoints(body):
            if endpoint_match["endpoint"].startswith(("http://", "https://")):
                resolved = endpoint_match["endpoint"]
            else:
                resolved = urljoin(script_url, endpoint_match["endpoint"])
            js_findings.append(
                {
                    "finding_kind": "endpoint",
                    "source": script_url,
                    "endpoint": resolved,
                    "method": endpoint_match["method"],
                }
            )

    return js_findings


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


def _check_redirect_followed(page: dict) -> list[FindingOut]:
    """Informational note when a crawled page was only reached by
    following a redirect (see core/scoped_executor.py's crawl()) — a
    report reader should know this content came from a different URL
    than the one actually requested (a bare IP landing on a vhost, a
    dashboard/file-manager app sitting behind a redirect, etc.), not
    just see it show up under the final URL with no explanation."""
    chain = page.get("redirect_chain")
    if not chain or len(chain) < 2:
        return []
    requested, final = chain[0], chain[-1]
    return [
        FindingOut(
            finding_type="redirect_followed",
            description=(
                f"{requested} redirected to {final}"
                + (f" ({len(chain) - 1} hop(s))" if len(chain) > 2 else "")
                + " — crawled content reflects the final destination"
            ),
            host=_host(final),
            service_port=_port(final),
            evidence=Evidence(kind="redirect_chain", summary=" -> ".join(chain)),
        )
    ]


def _check_file_secrets(page: dict) -> list[FindingOut]:
    """
    Regex-scans a crawled plain-text/data file's body (see
    TEXT_SECRET_SCAN_EXTENSIONS — a .txt handover note, a .env, a .bak
    config, a .log, ...) against common/secret_patterns.py's SECRET_PATTERNS
    — the same patterns js_secret_found and the binary agent's gitleaks
    fallback already use. Distinct finding_type from js_secret_found
    (secret_in_file_found) since this comes from a different discovery
    path (any linked file the native crawler fetched, not specifically a
    JS bundle) and a report reader should be able to tell them apart.

    Deliberately restricted to TEXT_SECRET_SCAN_EXTENSIONS — an ordinary
    crawled HTML page's body is NOT scanned here (see that constant's
    comment for why). Matched against the full URL (path AND query,
    decoded) via _SCANNABLE_FILE_EXT_RE, not just the path — a file
    manager that passes the filename as a query value (e.g.
    index.php?p=ops%2Fnetops-handover.txt) has no extension in its path
    at all, and a path-only check misses it entirely even though the
    actual served content is exactly a plain-text file.
    """
    if page.get("status", 0) != 200:
        return []  # nothing was actually served (404/403/etc) — no body worth scanning
    if not _SCANNABLE_FILE_EXT_RE.search(unquote(page["url"])):
        return []

    body = page.get("body", "")
    if not body:
        return []

    findings: list[FindingOut] = []
    for secret_type, (pattern, description) in SECRET_PATTERNS.items():
        match = pattern.search(body)
        if not match:
            continue
        findings.append(
            FindingOut(
                finding_type="secret_in_file_found",
                description=(
                    f"Hardcoded secret ({description}) found in a plain-text "
                    f"file served at {page['url']}"
                ),
                host=_host(page["url"]),
                service_port=_port(page["url"]),
                evidence=Evidence(
                    kind="file_secret",
                    summary=f"{description}: {redact(match.group(0))}",
                ),
            )
        )
    return findings


def _check_planted_flags(page: dict) -> list[FindingOut]:
    """
    Regex-scans a crawled plain-text/data file's body (same
    TEXT_SECRET_SCAN_EXTENSIONS restriction _check_file_secrets uses,
    for the same reason — see that function's docstring) for a
    CTF/lab-style planted flag (common/flag_patterns.py's FLAG_PATTERNS).

    Deliberately NOT merged into _check_file_secrets's loop even though
    the scanning logic is nearly identical: a flag is a different KIND
    of thing than a secret (it's the engagement's own success marker,
    not a weakness), gets its own finding_type (ctf_flag_found) so a
    report/dashboard can show it distinctly, and — unlike every other
    finding in this project — its evidence shows the FULL captured
    value, never redact()ed. redact() exists to keep a real credential
    out of a report; a flag is the opposite: the thing you're trying to
    prove you found.
    """
    if page.get("status", 0) != 200:
        return []
    if not _SCANNABLE_FILE_EXT_RE.search(unquote(page["url"])):
        return []

    body = page.get("body", "")
    if not body:
        return []

    findings: list[FindingOut] = []
    for flag_type, (pattern, description) in FLAG_PATTERNS.items():
        for match in pattern.finditer(body):
            findings.append(
                FindingOut(
                    finding_type="ctf_flag_found",
                    description=f"{description} captured in a file served at {page['url']}",
                    host=_host(page["url"]),
                    service_port=_port(page["url"]),
                    evidence=Evidence(
                        kind="ctf_flag",
                        summary=f"{description}: {match.group(0)}",
                    ),
                )
            )
    return findings


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
        # The marker itself now contains "<"/">" (see REFLECTED_PROBE_MARKER's
        # own comment) so it must be percent-encoded to go in a query
        # string at all — the server then decides whether to re-render it
        # raw (unsafe) or HTML-escaped (safe), which is exactly what this
        # check needs to tell apart.
        encoded_marker = quote(REFLECTED_PROBE_MARKER, safe="")
        query = "&".join(f"{name}={encoded_marker}" for name in inputs)
        separator = "&" if "?" in action_url else "?"
        probe_url = f"{action_url}{separator}{query}"

        response = executor.http_get(probe_url)
        # Only the RAW, unescaped marker counts as a real finding — a page
        # that HTML-escapes the input re-renders "&lt;CARTPROBE_6f1e9c&gt;"
        # instead, which does not contain this literal substring, so a
        # properly-escaping endpoint correctly produces no finding here.
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
    """
    Links worth handing to the binary agent (FR-3) as a follow-up job.
    Matched via _BINARY_EXT_RE against the full, decoded URL (path AND
    query) — NOT just urlparse(url).path — since a file-manager-style
    download link commonly passes the filename as a query-string value
    (e.g. index.php?p=tools%2Fagent.exe&dl), which has no extension in
    its path at all. A path-only check silently drops exactly this kind
    of link; see _extension_match_re()'s docstring for the same gap
    already fixed on the secret-file-scanning side.
    """
    links: list[str] = []
    for resolved in extract_links(page.get("body", ""), page["url"]):
        if _BINARY_EXT_RE.search(unquote(resolved)):
            links.append(resolved)
    return links
