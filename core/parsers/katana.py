"""Normalize Katana JSONL, retaining input names but never request/cookie values."""
import json
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit


def _url(value, base=""):
    try:
        p = urlsplit(urljoin(base, value))
        if p.scheme not in {"http", "https"} or not p.hostname or p.username or p.password:
            return None
        p.port  # validate malformed ports
        return urlunsplit((p.scheme, p.netloc, p.path or "/", p.query, ""))
    except (ValueError, TypeError):
        return None


def parse(raw_output):
    meta, target, limit, mode = {}, None, 500, "crawl"
    try:
        wrapper = json.loads(raw_output)
    except (ValueError, TypeError):
        wrapper = None
    if isinstance(wrapper, dict) and "events" in wrapper:
        meta, target, limit, mode = wrapper.get("meta", {}), wrapper.get("target"), wrapper.get("max_endpoints", 500), wrapper.get("mode", "crawl")
        raw_output = wrapper["events"]
    rows = {}
    malformed = 0

    def add(request, response=None, source="katana"):
        if not isinstance(request, dict):
            return
        url = _url(request.get("endpoint", request.get("url", "")))
        if not url:
            return
        if target:
            dest, allowed = urlsplit(url), urlsplit(target)
            if (dest.scheme, dest.hostname, dest.port or (443 if dest.scheme == "https" else 80)) != (allowed.scheme, allowed.hostname, allowed.port or (443 if allowed.scheme == "https" else 80)):
                return
        method = str(request.get("method", "GET")).upper()
        key = (method, url)
        if key not in rows and len(rows) >= limit:
            meta["limited"] = True
            return
        response = response if isinstance(response, dict) else {}
        status = response.get("status_code")
        status = status if isinstance(status, int) else None
        row = rows.setdefault(key, {"url": url, "method": method, "source": source,
                                  "status": None, "technologies": [], "forms": [],
                                  "inputs": [], "classification": "endpoint"})
        if status is not None:
            row["status"] = status
            row["classification"] = "protected" if status in {401, 403} else "rate_limited" if status == 429 else "missing" if status in {404, 410} else "error" if status >= 500 else "endpoint"
        techs = response.get("technologies", [])
        if isinstance(techs, list):
            row["technologies"] = sorted(set(row["technologies"]) | {t for t in techs if isinstance(t, str)})
        for form in response.get("forms", []) or []:
            if not isinstance(form, dict):
                continue
            action = _url(form.get("action", ""), url)
            names = [n for n in form.get("parameters", []) if isinstance(n, str)]
            clean = {"action": action, "method": str(form.get("method", "GET")).upper(),
                     "enctype": form.get("enctype", ""), "fields": [{"name": n} for n in names]}
            if clean not in row["forms"]:
                row["forms"].append(clean)
            if row["classification"] == "endpoint":
                row["classification"] = "form"
        for name, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True):
            item = {"name": name, "location": "query"}
            if item not in row["inputs"]:
                row["inputs"].append(item)
        body = request.get("body")
        if isinstance(body, str) and body:
            try:
                data = json.loads(body)
                names = list(data) if isinstance(data, dict) else []
                location = "json"
            except ValueError:
                names = [n for n, _ in parse_qsl(body, keep_blank_values=True)]
                location = "body"
            for name in names:
                item = {"name": name, "location": location}
                if item not in row["inputs"]:
                    row["inputs"].append(item)
        for xhr in response.get("xhr_requests", []) or []:
            add(xhr, source="xhr")

    for line in raw_output.splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
            if not isinstance(event, dict) or not isinstance(event.get("request"), dict):
                raise ValueError("not a Katana result")
            add(event["request"], event.get("response"))
            if event.get("error"):
                meta.update(limited=True, error="katana_request_error")
        except (ValueError, TypeError, AttributeError):
            malformed += 1
    if malformed:
        meta.update(limited=True, malformed_lines=malformed)
    result = list(rows.values())
    if mode == "get" and target:
        result = [row for row in result if row["url"] == target and row["method"] == "GET"][:1]
    if not result and target:
        result = [{"url": target, "method": "GET", "status": None, "source": "katana", "forms": [], "inputs": [], "technologies": [], "classification": "error", "error": meta.get("error", "katana_no_results")}]
    if result:
        result[0]["crawl"] = meta
    return result
