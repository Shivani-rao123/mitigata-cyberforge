"""
tests/common/test_html_extract.py

Unit tests for common/html_extract.py — the link/form scraping shared by
core/scoped_executor.py's native crawl(), core/parsers/katana.py, and
agents/web/agent.py's binary-link detection.
"""

import time

from common.html_extract import (
    MAX_FORMS_PER_PAGE,
    MAX_INPUTS_PER_FORM,
    MAX_LINKS_PER_PAGE,
    MAX_SCRIPTS_PER_PAGE,
    extract_forms,
    extract_links,
    extract_script_srcs,
)

# ---------------------------------------------------------------------------
# extract_links
# ---------------------------------------------------------------------------


def test_relative_link_resolved_against_base_url():
    html = '<a href="/admin">Admin</a>'
    links = extract_links(html, "http://10.10.10.5:80/page")
    assert links == ["http://10.10.10.5:80/admin"]


def test_absolute_link_passed_through():
    html = '<a href="http://other.example/x">X</a>'
    links = extract_links(html, "http://10.10.10.5:80/")
    assert links == ["http://other.example/x"]


def test_html_escaped_ampersand_in_multi_param_href_is_decoded_before_joining():
    """Real-world regression, confirmed against an actual TinyFileManager
    target: a correctly-escaped multi-param href like
    href="?p=&amp;view=secret.txt" must resolve to a query string of
    "p=&view=secret.txt" (two params: p, view) — NOT
    "p=&amp;view=secret.txt" (one garbled param named "amp;view"), which
    is what a downstream app actually receives if the literal "&amp;"
    is left in the URL. Confirmed server-side: parse_qs on an
    un-unescaped join yields {"amp;view": [...]}, not {"p": [...],
    "view": [...]} — the app never sees the "view" parameter it needs
    and silently serves something else instead, with no error anywhere
    to signal it."""
    html = '<a href="?p=&amp;view=secret.txt">secret.txt</a>'
    links = extract_links(html, "http://192.168.60.139/index.php?p=")
    assert links == ["http://192.168.60.139/index.php?p=&view=secret.txt"]

    from urllib.parse import parse_qs, urlparse

    assert parse_qs(urlparse(links[0]).query) == {"view": ["secret.txt"]}


def test_other_common_html_entities_in_hrefs_are_also_decoded():
    html = '<a href="/search?q=a&amp;b=c&quot;&apos;&lt;&gt;">x</a>'
    links = extract_links(html, "http://10.10.10.5/")
    assert links == ['http://10.10.10.5/search?q=a&b=c"\'<>']


def test_single_and_double_quoted_hrefs_both_match():
    html = "<a href='/a'>a</a><a href=\"/b\">b</a>"
    links = extract_links(html, "http://10.10.10.5/")
    assert set(links) == {"http://10.10.10.5/a", "http://10.10.10.5/b"}


def test_fragment_js_mailto_and_tel_links_are_skipped():
    html = """
    <a href="#top">top</a>
    <a href="javascript:void(0)">js</a>
    <a href="mailto:a@b.com">mail</a>
    <a href="tel:+1234567890">tel</a>
    <a href="/real">real</a>
    """
    links = extract_links(html, "http://10.10.10.5/")
    assert links == ["http://10.10.10.5/real"]


def test_empty_href_is_skipped():
    html = '<a href="">empty</a><a href="/ok">ok</a>'
    links = extract_links(html, "http://10.10.10.5/")
    assert links == ["http://10.10.10.5/ok"]


def test_no_html_returns_empty_list():
    assert extract_links("", "http://10.10.10.5/") == []
    assert extract_links("<p>no links here</p>", "http://10.10.10.5/") == []


def test_link_count_is_capped():
    html = "".join(f'<a href="/page{i}">x</a>' for i in range(MAX_LINKS_PER_PAGE + 50))
    links = extract_links(html, "http://10.10.10.5/")
    assert len(links) == MAX_LINKS_PER_PAGE


def test_malformed_href_does_not_crash():
    # A control character inside a URL can make urljoin/urlsplit raise
    # ValueError on some inputs — must be skipped, not propagate.
    html = '<a href="/ok\x00bad">bad</a><a href="/fine">fine</a>'
    links = extract_links(html, "http://10.10.10.5/")
    assert "http://10.10.10.5/fine" in links


# ---------------------------------------------------------------------------
# extract_script_srcs
# ---------------------------------------------------------------------------


def test_relative_script_src_resolved_against_base_url():
    html = '<script src="/static/app.js"></script>'
    srcs = extract_script_srcs(html, "http://10.10.10.5/")
    assert srcs == ["http://10.10.10.5/static/app.js"]


def test_absolute_script_src_passed_through():
    html = '<script src="https://cdn.example.com/lib.js"></script>'
    srcs = extract_script_srcs(html, "http://10.10.10.5/")
    assert srcs == ["https://cdn.example.com/lib.js"]


def test_inline_script_with_no_src_is_ignored():
    html = "<script>console.log('hi');</script>"
    assert extract_script_srcs(html, "http://10.10.10.5/") == []


def test_script_tag_with_extra_attributes_still_matches_src():
    html = '<script type="text/javascript" src="/a.js" defer></script>'
    srcs = extract_script_srcs(html, "http://10.10.10.5/")
    assert srcs == ["http://10.10.10.5/a.js"]


def test_multiple_script_tags_all_found_in_order():
    html = '<script src="/a.js"></script><script src="/b.js"></script>'
    srcs = extract_script_srcs(html, "http://10.10.10.5/")
    assert srcs == ["http://10.10.10.5/a.js", "http://10.10.10.5/b.js"]


def test_empty_src_is_skipped():
    html = '<script src=""></script><script src="/real.js"></script>'
    srcs = extract_script_srcs(html, "http://10.10.10.5/")
    assert srcs == ["http://10.10.10.5/real.js"]


def test_html_escaped_ampersand_in_script_src_is_decoded():
    html = '<script src="/bundle.js?v=1&amp;cb=2"></script>'
    srcs = extract_script_srcs(html, "http://10.10.10.5/")
    assert srcs == ["http://10.10.10.5/bundle.js?v=1&cb=2"]


def test_no_html_returns_empty_list_for_scripts():
    assert extract_script_srcs("", "http://10.10.10.5/") == []


def test_script_count_is_capped():
    html = "".join(f'<script src="/s{i}.js"></script>' for i in range(MAX_SCRIPTS_PER_PAGE + 20))
    srcs = extract_script_srcs(html, "http://10.10.10.5/")
    assert len(srcs) == MAX_SCRIPTS_PER_PAGE


def test_malformed_script_src_does_not_crash():
    html = '<script src="/ok\x00bad.js"></script><script src="/fine.js"></script>'
    srcs = extract_script_srcs(html, "http://10.10.10.5/")
    assert "http://10.10.10.5/fine.js" in srcs


# ---------------------------------------------------------------------------
# extract_forms
# ---------------------------------------------------------------------------


def test_basic_form_with_action_method_and_inputs():
    html = '<form action="/login" method="post"><input name="user"><input name="pass"></form>'
    forms = extract_forms(html)
    assert forms == [{"action": "/login", "method": "post", "inputs": ["user", "pass"]}]


def test_missing_action_defaults_to_empty_string():
    html = '<form method="get"><input name="q"></form>'
    forms = extract_forms(html)
    assert forms[0]["action"] == ""


def test_html_escaped_ampersand_in_form_action_is_decoded():
    html = '<form action="submit.php?step=1&amp;mode=x" method="post"></form>'
    forms = extract_forms(html)
    assert forms[0]["action"] == "submit.php?step=1&mode=x"


def test_missing_method_defaults_to_get():
    html = '<form action="/search"><input name="q"></form>'
    forms = extract_forms(html)
    assert forms[0]["method"] == "get"


def test_unrecognized_method_defaults_to_get():
    html = '<form action="/x" method="PATCH"><input name="a"></form>'
    forms = extract_forms(html)
    assert forms[0]["method"] == "get"


def test_method_is_case_insensitive_and_lowercased():
    html = '<form action="/x" method="POST"><input name="a"></form>'
    forms = extract_forms(html)
    assert forms[0]["method"] == "post"


def test_form_with_no_inputs_has_empty_input_list():
    html = '<form action="/x" method="get"></form>'
    forms = extract_forms(html)
    assert forms[0]["inputs"] == []


def test_multiple_forms_on_one_page():
    html = """
    <form action="/login" method="post"><input name="password"></form>
    <form action="/search" method="get"><input name="q"></form>
    """
    forms = extract_forms(html)
    assert len(forms) == 2
    assert {f["action"] for f in forms} == {"/login", "/search"}


def test_inputs_without_name_attribute_are_ignored():
    html = '<form action="/x"><input type="submit"><input name="real"></form>'
    forms = extract_forms(html)
    assert forms[0]["inputs"] == ["real"]


def test_no_form_tags_returns_empty_list():
    assert extract_forms("") == []
    assert extract_forms("<p>nothing here</p>") == []


def test_form_count_is_capped():
    html = "".join(f'<form action="/f{i}"></form>' for i in range(MAX_FORMS_PER_PAGE + 20))
    forms = extract_forms(html)
    assert len(forms) == MAX_FORMS_PER_PAGE


def test_input_count_per_form_is_capped():
    inputs = "".join(f'<input name="f{i}">' for i in range(MAX_INPUTS_PER_FORM + 20))
    html = f'<form action="/x">{inputs}</form>'
    forms = extract_forms(html)
    assert len(forms[0]["inputs"]) == MAX_INPUTS_PER_FORM


# ---------------------------------------------------------------------------
# ReDoS-safety: these regexes run on attacker-influenced content (crawled
# page bodies), so pathological input must not cause catastrophic
# backtracking. Each assertion is really "this returns at all, quickly" —
# a vulnerable pattern would hang rather than fail an assertion.
# ---------------------------------------------------------------------------


def test_many_unclosed_opening_tags_do_not_hang():
    """No '>' anywhere at all — forces a full backtrack scan per
    occurrence unless the opening-tag attribute group is bounded. Earlier
    measured at ~14s against an unbounded `[^>]*`; bounded, this is
    comfortably sub-second."""
    html = "<form " * 20_000
    start = time.monotonic()
    forms = extract_forms(html)
    elapsed = time.monotonic() - start
    assert elapsed < 3.0
    assert forms == []


def test_many_unclosed_form_bodies_at_realistic_page_size_do_not_hang():
    """A separate adversarial shape from the above: valid '<form ...>'
    openers (so the first group succeeds immediately) but no '</form>'
    anywhere, at the actual size core/scoped_executor.py now caps a page
    body to (50,000 chars) before this function ever sees it. This is
    the realistic worst case, not a hypothetical unbounded one."""
    opener = '<form action="/x">'
    html = (opener * (50_000 // len(opener) + 1))[:50_000]
    start = time.monotonic()
    forms = extract_forms(html)
    elapsed = time.monotonic() - start
    assert elapsed < 3.0
    assert forms == []


def test_very_long_single_line_body_does_not_hang():
    html = "<a href=\"/x\">" + ("a" * 2_000_000) + "</a>"
    start = time.monotonic()
    links = extract_links(html, "http://10.10.10.5/")
    elapsed = time.monotonic() - start
    assert elapsed < 2.0
    assert links == ["http://10.10.10.5/x"]


def test_form_body_over_the_cap_is_not_matched_not_hung():
    """A long run of "<<<<..." inside a form body could pathologically
    interact with a naive "match up to the next '>'" pattern — confirming
    it doesn't hang is the main point of this test. The documented
    tradeoff that makes that possible: a body bigger than the 8KB cap
    (_FORM_RE's second group) is a real, if rare, shape a legitimate form
    could have, and it silently fails to match rather than being found —
    same "truncate rather than hang" choice as MAX_LINKS_PER_PAGE etc.
    This asserts that documented behavior, not just the timing."""
    html = '<form action="/x">' + ("<" * 50_000) + "</form>"
    start = time.monotonic()
    forms = extract_forms(html)
    elapsed = time.monotonic() - start
    assert elapsed < 2.0
    assert forms == []  # body (50,000 chars) exceeds the 8KB cap — not a bug, see docstring above


def test_form_body_within_the_cap_is_matched():
    """The companion case to the one above: the same shape, but under
    the cap, is matched normally — the cap doesn't just make everything
    fail."""
    html = '<form action="/x">' + ("<" * 100) + "</form>"
    forms = extract_forms(html)
    assert len(forms) == 1
