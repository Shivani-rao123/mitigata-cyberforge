"""
core/parsers/katana.py

Parses katana's JSON-Lines output (`-jsonl`, optionally with `-headless`
for JS-rendered SPAs and `-jsluice` for pulling endpoints/secrets out of
JS bundles) into two things:

  - "pages": the same {"url", "status", "body", "forms"} shape
    core/scoped_executor.py's native crawl() already returns, so
    agents/web/agent.py's checks (sensitive path, login form, reflected
    input, headers, directory listing) run unchanged regardless of which
    crawler produced the page.
  - "js_findings": endpoints/secrets katana's jsluice mode pulled directly
    out of JS source (things a non-JS-executing crawler can never see,
    since they only exist inside a bundle, not in any rendered HTML).

IMPORTANT — schema caveat: katana's exact JSON field names have changed
across versions and this was written without a live katana binary to
verify against (see the conversation this was built from — no network
access in the build sandbox to install/run it). This parser is
deliberately defensive: it accepts several plausible field-name variants
for the same piece of data and skips anything it doesn't recognize rather
than crashing on it. Before relying on this in a real run, feed one real
`katana -jsonl -silent -u <target>` capture through `parse()` and confirm
the page/js_findings counts look right — adjust the `_FIELD_CANDIDATES`
tables below if your katana version's field names differ.
"""

from __future__ import annotations

import json

from common.html_extract import extract_forms

# Each entry: the keys (in priority order) to look for at increasing
# nesting depth. A JSON Lines record from katana is usually either flat
# or nested under "request"/"response" — we check both shapes.
_URL_KEYS = ("endpoint", "url", "request_url")
_STATUS_KEYS = ("status_code", "status")
_BODY_KEYS = ("body", "response_body", "raw")
_HEADERS_KEYS = ("headers", "response_headers")

# jsluice-style records are distinguished by a "type" field. Everything
# else is treated as a normal crawl record.
_JS_FINDING_TYPES = {"endpoint", "secret"}


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

    return {
        "url": url,
        "status": status,
        "body": body,
        "headers": headers,
        "forms": extract_forms(body),
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
