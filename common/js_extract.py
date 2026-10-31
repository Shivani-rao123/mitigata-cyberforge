"""
common/js_extract.py

Regex-based extraction of API-call endpoints out of raw JS source text —
the piece that lets agents/web/agent.py produce real js_endpoint_found /
js_secret_found findings WITHOUT katana installed. (Secret scanning
reuses common/secret_patterns.py directly; this module is the endpoint
half of the same idea.)

Why this exists: katana is the better tool for this (a real JS parser,
not regex), but it's an external Go binary that has to be installed
separately and isn't available on every machine a demo/grader runs on.
This gives every machine that already has Python working (which this
project already requires) a real, if narrower, version of the same
capability — no extra install, matching the project's existing
"stdlib only, no exotic deps" style (see common/html_extract.py).

Deliberately narrower than a real JS parser: it pattern-matches the
handful of call shapes that cover the overwhelming majority of real
client-side API calls (fetch, XMLHttpRequest, axios, jQuery.ajax) rather
than actually parsing JS syntax, so it won't catch a URL built up via
string concatenation/template interpolation or hidden behind a wrapper
function. Still matches a plain, unconcatenated string literal URL,
which is what the common cases (and everything katana's own -jsluice
mode is documented to look for) look like in practice.
"""

from __future__ import annotations

import re

# A string literal URL/path argument: '"...\'" or '\'...\''. Bounded —
# no real endpoint path is thousands of characters long, and bounding it
# avoids any pathological-input slowdown on an adversarial JS body.
_STR = r'["\']([^"\']{1,500})["\']'

# fetch("...") / fetch('...', {method: "POST"}) — the method, if present
# in a following options object literal, is picked up by a second,
# narrower regex below rather than embedded here (keeps this pattern
# simple and avoids matching deep into unrelated object literals).
_FETCH_RE = re.compile(r"\bfetch\s*\(\s*" + _STR, re.IGNORECASE)

# axios.get("..."), axios.post("...", ...), axios({url: "...", ...})
_AXIOS_METHOD_RE = re.compile(
    r"\baxios\s*\.\s*(get|post|put|patch|delete|head)\s*\(\s*" + _STR, re.IGNORECASE
)
_AXIOS_CONFIG_RE = re.compile(r"\baxios\s*\(\s*\{[^{}]{0,500}?\burl\s*:\s*" + _STR, re.IGNORECASE | re.DOTALL)

# $.ajax({url: "...", ...}) / jQuery.ajax({...})
_JQUERY_AJAX_RE = re.compile(
    r"(?:\$|jQuery)\s*\.\s*ajax\s*\(\s*\{[^{}]{0,500}?\burl\s*:\s*" + _STR, re.IGNORECASE | re.DOTALL
)

# xhr.open("METHOD", "...") / request.open("get", "...")
_XHR_OPEN_RE = re.compile(
    r'\.open\s*\(\s*["\'](GET|POST|PUT|PATCH|DELETE|HEAD)["\']\s*,\s*' + _STR,
    re.IGNORECASE,
)

# A method: "POST" key appearing shortly after a fetch(...) call's URL
# argument, within the same options-object-ish chunk of source — best
# effort, not a real parser; defaults to GET when nothing matches.
_METHOD_HINT_RE = re.compile(r'\bmethod\s*:\s*["\'](\w+)["\']', re.IGNORECASE)

# Window to look for a trailing {method: "..."} after a fetch(url, ...
# call — generous enough for a real options object, bounded against a
# pathological body.
_METHOD_HINT_WINDOW = 200

# Paths that are just decoration, not real API surface — skip these so
# they don't crowd out genuine endpoints with noise.
_SKIP_PREFIXES = ("data:", "blob:", "#")


def extract_js_endpoints(js_source: str) -> list[dict]:
    """Returns [{"endpoint": str, "method": str}, ...] for every API-call
    URL this regex set recognizes in `js_source`. Does not resolve
    relative paths to absolute URLs — callers do that (they know which
    JS file's URL to resolve against). Does not dedupe."""
    if not js_source:
        return []

    endpoints: list[dict] = []

    for match in _FETCH_RE.finditer(js_source):
        endpoint = match.group(1)
        if endpoint.startswith(_SKIP_PREFIXES):
            continue
        window_end = min(len(js_source), match.end() + _METHOD_HINT_WINDOW)
        hint = _METHOD_HINT_RE.search(js_source, match.end(), window_end)
        method = hint.group(1).upper() if hint else "GET"
        endpoints.append({"endpoint": endpoint, "method": method})

    for match in _AXIOS_METHOD_RE.finditer(js_source):
        endpoint = match.group(2)
        if endpoint.startswith(_SKIP_PREFIXES):
            continue
        endpoints.append({"endpoint": endpoint, "method": match.group(1).upper()})

    for match in _AXIOS_CONFIG_RE.finditer(js_source):
        endpoint = match.group(1)
        if endpoint.startswith(_SKIP_PREFIXES):
            continue
        endpoints.append({"endpoint": endpoint, "method": "GET"})

    for match in _JQUERY_AJAX_RE.finditer(js_source):
        endpoint = match.group(1)
        if endpoint.startswith(_SKIP_PREFIXES):
            continue
        endpoints.append({"endpoint": endpoint, "method": "GET"})

    for match in _XHR_OPEN_RE.finditer(js_source):
        endpoint = match.group(2)
        if endpoint.startswith(_SKIP_PREFIXES):
            continue
        endpoints.append({"endpoint": endpoint, "method": match.group(1).upper()})

    return endpoints
