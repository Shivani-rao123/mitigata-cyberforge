"""
core/parsers/katana.py

Parses katana's JSON-Lines output (`-jsonl`, optionally with `-headless`
for JS-rendered SPAs and `-jsluice` for pulling endpoints out of JS
bundles) into two things:

  - "pages": the same {"url", "status", "body", "forms"} shape
    core/scoped_executor.py's native crawl() already returns, so
    agents/web/agent.py's checks (sensitive path, login form, reflected
    input, headers, directory listing) run unchanged regardless of which
    crawler produced the page.
  - "js_findings": endpoints/secrets pulled out of JS, surfaced as
    agents/web/agent.py's js_endpoint_found / js_secret_found findings.

VERIFIED against a real `katana -jsonl -silent -d 2 -jsluice -timeout 10`
capture (v1.1.2) — the schema caveat that used to be here is resolved.
Two real-world facts that shaped this file:

  1. Katana does NOT emit a distinct `"type": "secret"`/`"type":
     "endpoint"` record type (an earlier version of this parser assumed
     it did, going only off documentation with no binary to test
     against). What -jsluice actually does is make katana CRAWL the
     endpoints it finds referenced inside JS source as ordinary further
     requests — each one comes back as a normal page record, but tagged
     `request.tag == "js"` (vs "script" for a plain `<script src=...>`
     reference, or no tag at all for a server-rendered link). That tag
     is how a JS-only endpoint is told apart from one also reachable via
     server-rendered HTML — exactly the distinction js_endpoint_found is
     supposed to capture.
  2. Katana has no secret-extraction step at all (confirmed against
     `katana -h`: -jsluice is documented as "enable jsluice parsing in
     javascript file" for endpoint discovery only). So secrets embedded
     in a JS bundle are found here instead, by regex-scanning the body
     of any page record that looks like a JS file (by URL extension or
     Content-Type) against the same pattern set the binary agent uses —
     see common/secret_patterns.py.

The old `"type": "secret"`/`"type": "endpoint"` record shape is still
accepted (harmless, and some katana configurations/versions may emit it,
per the original docs) — it just isn't the only source of js_findings
anymore.
"""

from __future__ import annotations

import json

from common.html_extract import extract_forms
from common.secret_patterns import SECRET_PATTERNS

# Each entry: the keys (in priority order) to look for at increasing
# nesting depth. A JSON Lines record from katana is usually either flat
# or nested under "request"/"response" — we check both shapes.
_URL_KEYS = ("endpoint", "url", "request_url")
_STATUS_KEYS = ("status_code", "status")
_BODY_KEYS = ("body", "response_body", "raw")
_HEADERS_KEYS = ("headers", "response_headers")

# jsluice-style records are distinguished by a "type" field. Everything
# else is treated as a normal crawl record. See module docstring — this
# shape was never actually observed from a real katana run, but is kept
# as a tolerated alternate input.
_JS_FINDING_TYPES = {"endpoint", "secret"}

# request.tag values that mean "this request exists only because katana
# parsed it out of JS source" (jsluice), as opposed to "script" (a plain
# <script src=...> reference) or no tag (a server-rendered link/page).
_JS_DISCOVERED_TAGS = {"js", "xhr"}

# How a page is recognized as "this response is JS source, worth
# scanning for secrets" when nothing else says so explicitly.
_JS_FILE_EXTENSIONS = (".js", ".mjs", ".cjs")


def parse(raw_output: str) -> dict:
    """Returns {"pages": [...], "js_findings": [...], "skipped_lines": int}.
    `skipped_lines` counts lines that were present but unparseable/didn't
    match any recognized shape — surfaced so a caller can log it instead
    of the failure being invisible, without it being fatal."""
    pages: list[dict] = []
    js_findings: list[dict] = []
    skipped_lines = 0

    for line in raw_output.splitlines():
        line = line.strip()
        if not line:
            continue

        try:
            record = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            skipped_lines += 1
            continue

        if not isinstance(record, dict):
            skipped_lines += 1
            continue

        record_type = record.get("type")
        if record_type in _JS_FINDING_TYPES:
            finding = _parse_js_finding(record, record_type)
            if finding is not None:
                js_findings.append(finding)
            else:
                skipped_lines += 1
            continue

        page = _parse_page_record(record)
        if page is not None:
            pages.append(page)
        else:
            skipped_lines += 1

    # Derive additional js_findings from the real-world katana shape:
    # endpoints discovered via JS (by request tag) and secrets embedded
    # in JS response bodies (by regex), neither of which arrive as a
    # "type": "..." record in practice. See module docstring.
    js_findings.extend(_derive_endpoint_findings(pages))
    js_findings.extend(_derive_secret_findings(pages))

    return {"pages": pages, "js_findings": js_findings, "skipped_lines": skipped_lines}


def _first_present(record: dict, keys: tuple[str, ...]):
    for key in keys:
        if key in record and record[key] is not None:
            return record[key]
    return None


def _parse_page_record(record: dict) -> dict | None:
    # katana nests the actual response under "response" (and the request
    # under "request") in its default -jsonl shape; fall back to flat
    # top-level keys for older/alternate output modes.
    response = record.get("response") if isinstance(record.get("response"), dict) else record
    request = record.get("request") if isinstance(record.get("request"), dict) else record

    url = _first_present(record, _URL_KEYS) or _first_present(request, _URL_KEYS)
    if not url or not isinstance(url, str):
        return None  # no usable URL — can't build a page record from this line

    status = _first_present(response, _STATUS_KEYS)
    try:
        status = int(status) if status is not None else 0
    except (TypeError, ValueError):
        status = 0

    body = _first_present(response, _BODY_KEYS)
    body = body if isinstance(body, str) else ""

    headers = _first_present(response, _HEADERS_KEYS)
    headers = headers if isinstance(headers, dict) else {}

    # Request metadata used only by the js_findings derivation below —
    # harmless extra keys for any caller that only reads
    # url/status/body/headers/forms (agents/web/agent.py does).
    tag = request.get("tag") if isinstance(request, dict) else None
    source = request.get("source") if isinstance(request, dict) else None

    return {
        "url": url,
        "status": status,
        "body": body,
        "headers": headers,
        "forms": extract_forms(body),
        "request_tag": tag,
        "request_source": source,
    }


def _parse_js_finding(record: dict, record_type: str) -> dict | None:
    # jsluice-style payloads nest the actual match under "data"; be
    # tolerant of it being flat on the record instead.
    data = record.get("data") if isinstance(record.get("data"), dict) else record

    source = record.get("source") or record.get("url") or data.get("source")
    if not source:
        return None

    if record_type == "secret":
        value = data.get("value") or data.get("match") or data.get("secret")
        kind = data.get("kind") or data.get("rule") or data.get("name") or "unknown"
        if not value:
            return None
        return {
            "finding_kind": "secret",
            "source": source,
            "rule": str(kind),
            "value": str(value),
        }

    # record_type == "endpoint"
    endpoint = data.get("url") or data.get("endpoint") or data.get("path")
    if not endpoint:
        return None
    return {
        "finding_kind": "endpoint",
        "source": source,
        "endpoint": str(endpoint),
        "method": str(data.get("method") or "GET"),
    }


def _looks_like_js_file(page: dict) -> bool:
    url = page["url"].split("?", 1)[0].split("#", 1)[0]
    if url.lower().endswith(_JS_FILE_EXTENSIONS):
        return True
    content_type = ""
    for key, value in page.get("headers", {}).items():
        if key.lower() == "content-type" and isinstance(value, str):
            content_type = value.lower()
            break
    return "javascript" in content_type


def _derive_endpoint_findings(pages: list[dict]) -> list[dict]:
    """An endpoint katana only reached because it was referenced inside
    JS source (not server-rendered HTML) — real attack surface a plain
    crawler can't see. request_source is the JS file it came from."""
    findings: list[dict] = []
    for page in pages:
        if page.get("request_tag") not in _JS_DISCOVERED_TAGS:
            continue
        source = page.get("request_source")
        if not source:
            continue
        findings.append(
            {
                "finding_kind": "endpoint",
                "source": source,
                "endpoint": page["url"],
                "method": "GET",
            }
        )
    return findings


def _derive_secret_findings(pages: list[dict]) -> list[dict]:
    """Regex-scans every response that looks like JS source for the same
    hardcoded-secret shapes the binary agent looks for — katana itself
    has no secret-extraction step (see module docstring)."""
    findings: list[dict] = []
    seen: set[tuple[str, str]] = set()

    for page in pages:
        if not _looks_like_js_file(page):
            continue
        body = page.get("body", "")
        if not body:
            continue

        for secret_type, (pattern, description) in SECRET_PATTERNS.items():
            match = pattern.search(body)
            if not match:
                continue
            dedup_key = (page["url"], secret_type)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            findings.append(
                {
                    "finding_kind": "secret",
                    "source": page["url"],
                    "rule": description,
                    "value": match.group(0),
                }
            )

    return findings
