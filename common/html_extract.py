"""
common/html_extract.py

Tiny, dependency-free HTML scraping helpers shared by anything that needs
to pull links/forms out of a page body: core/scoped_executor.py's native
crawler, core/parsers/katana.py (katana returns raw response bodies too,
not just pre-parsed forms), and agents/web/agent.py's binary-link
detection. Kept in one place instead of three copies so a fix (or a
ReDoS-safety tweak) only has to happen once.

Regex-based on purpose — no HTML parser dependency, matching the rest of
this project's "stdlib only, no exotic deps" style. The patterns here are
deliberately simple (no nested quantifiers, bounded alternation) so they
can't catastrophic-backtrack on adversarial input; see
tests/common/test_html_extract.py's stress cases for proof. This is a
light scrape, not a full HTML parser: edge cases like unclosed tags,
duplicate attributes, or non-standard quoting are handled by "don't
crash, extract what's unambiguous" rather than "match a real browser's
DOM" — good enough for finding candidate links/forms to probe, not for
rendering.
"""

from __future__ import annotations

import html
import re
from urllib.parse import urljoin

# Matches href="..." or href='...' (double or single quotes only — bare,
# unquoted hrefs are non-conformant HTML and rare enough to skip rather
# than risk a looser, slower pattern).
_HREF_RE = re.compile(r'href\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)

# <script src="..."> / <script src='...'> only — not inline <script>...
# </script> bodies, which extract_links-style regex can't safely isolate
# anyway (nested quotes/braces make a tight bound impractical). Bounded
# like _HREF_RE for the same reason.
_SCRIPT_SRC_RE = re.compile(r'<script\b[^>]{0,2048}\bsrc\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)

# Both quantifiers are explicitly bounded, not just lazy. A lazy `.*?`
# alone is NOT enough to avoid a real performance cliff here: with no
# cap, many "<form " occurrences that never see a closing '>' (or many
# "<form ...>" openers that never see a closing "</form>") each force an
# O(remaining-input-length) scan before failing/retrying, and that
# repeats once per occurrence — O(n^2) on crawled, attacker-influenced
# page bodies. Measured directly against an earlier unbounded version of
# this pattern: 20,000 unclosed "<form " tags took ~14s; even bounded to
# a generous 32KB body cap, ~2,800 unclosed-body "<form...>" openers
# packed into the 50,000-char page-body ceiling this is always called
# with (core/scoped_executor.py truncates before extraction, not after)
# still took ~1.4s. The 8KB cap below keeps the same adversarial case
# under half a second while costing nothing on a real form — no
# legitimate form has an 8KB+ body or a 2KB+ attribute list.
_FORM_RE = re.compile(r"<form([^>]{0,2048})>(.{0,8192}?)</form>", re.IGNORECASE | re.DOTALL)
_ACTION_RE = re.compile(r'action\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)
_METHOD_RE = re.compile(r'method\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)
_INPUT_NAME_RE = re.compile(r'<input[^>]*\bname\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)

# Hard caps so a single pathological page (huge body, thousands of forms)
# can't turn a crawl into a memory/CPU sink. Silently truncating is the
# right call here — "found the first N forms/links" beats "hung" or
# "crashed" for an autonomous run with a time budget (see PRD's Run Time
# scoring target).
MAX_LINKS_PER_PAGE = 500
MAX_FORMS_PER_PAGE = 100
MAX_INPUTS_PER_FORM = 200
MAX_SCRIPTS_PER_PAGE = 50


def extract_links(html_text: str, base_url: str) -> list[str]:
    """Absolute URLs for every href in `html_text`, resolved against
    `base_url`. Does not dedupe or filter by host — callers decide that.
    Bounded by MAX_LINKS_PER_PAGE regardless of how many hrefs actually
    appear.

    Every href is HTML-unescaped (html.unescape) before resolving. A
    multi-param query string link is correctly written in HTML with its
    "&" entity-escaped — e.g. href="?p=&amp;view=file.txt" — and without
    unescaping, urljoin keeps that "&amp;" literal, so the resolved URL's
    query string becomes "p=&amp;view=file.txt". A server parses that by
    splitting on the real "&" between "amp;" and "view", producing an
    "amp;view" parameter instead of "view" — the destination app never
    sees the parameter it actually needs and silently serves something
    else (its default page, usually), with no exception anywhere to
    signal that anything went wrong. Confirmed against a real
    TinyFileManager target: its own file/download links are written
    exactly this way (?p=&amp;view=<file>), which is why a crawl could
    discover a file's directory entry but never actually reach that
    file's content."""
    if not html_text:
        return []

    links: list[str] = []
    for href in _HREF_RE.findall(html_text):
        if len(links) >= MAX_LINKS_PER_PAGE:
            break
        href = html.unescape(href.strip())
        if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue
        try:
            links.append(urljoin(base_url, href))
        except ValueError:
            continue  # malformed href (e.g. control chars) — skip, don't crash
    return links


def extract_script_srcs(html_text: str, base_url: str) -> list[str]:
    """Absolute URLs for every <script src=...> in `html_text`, resolved
    against `base_url` — used to find JS bundles worth fetching and
    scanning for secrets/endpoints without a JS-aware crawler (see
    common/js_extract.py). Does not dedupe — callers decide that.
    Bounded by MAX_SCRIPTS_PER_PAGE regardless of how many appear.

    Each src is HTML-unescaped before resolving — same reasoning as
    extract_links() above (a multi-param script src is rarer than a
    multi-param href, but no less broken by skipping this)."""
    if not html_text:
        return []

    srcs: list[str] = []
    for src in _SCRIPT_SRC_RE.findall(html_text):
        if len(srcs) >= MAX_SCRIPTS_PER_PAGE:
            break
        src = html.unescape(src.strip())
        if not src:
            continue
        try:
            srcs.append(urljoin(base_url, src))
        except ValueError:
            continue  # malformed src (e.g. control chars) — skip, don't crash
    return srcs


def extract_forms(html_text: str) -> list[dict]:
    """[{"action": str, "method": "get"|"post", "inputs": [str, ...]}, ...]
    for every <form> in `html_text`. Missing action defaults to ""
    (caller resolves against the page URL); missing/invalid method
    defaults to "get" (the HTML spec's own default).

    `action` is HTML-unescaped before being returned — same reasoning
    as extract_links()'s own unescaping: a form with a multi-param
    action (action="submit.php?step=1&amp;mode=x") would otherwise reach
    the caller's urljoin() with the "&amp;" still literal, mangling the
    query string the same way an un-unescaped href does."""
    if not html_text:
        return []

    forms: list[dict] = []
    for open_tag, body in _FORM_RE.findall(html_text):
        if len(forms) >= MAX_FORMS_PER_PAGE:
            break

        action_match = _ACTION_RE.search(open_tag)
        method_match = _METHOD_RE.search(open_tag)
        method = (method_match.group(1).strip().lower() if method_match else "get") or "get"
        if method not in ("get", "post"):
            method = "get"  # unrecognized method attribute — treat as the default

        inputs = _INPUT_NAME_RE.findall(body)[:MAX_INPUTS_PER_FORM]

        forms.append(
            {
                "action": html.unescape(action_match.group(1).strip()) if action_match else "",
                "method": method,
                "inputs": inputs,
            }
        )
    return forms
