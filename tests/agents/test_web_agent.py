"""
tests/agents/test_web_agent.py

Unit tests for the web agent (FR-2). Uses MockScopedExecutor — no real
network, no dependency on core being finished.
"""

from html import escape as html_escape
from urllib.parse import parse_qs, urlparse

from agents.web.agent import run
from common.contracts import Job
from tests.mock_executor import MockScopedExecutor

ALL_HEADERS = {
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'self'",
}


def _job(target: str = "10.10.10.5:80", context: dict | None = None) -> Job:
    return Job(job_id="web-job", agent="web", target=target, context=context or {})


def test_infers_http_scheme_from_bare_host_port():
    seen = {}

    def http_get_fn(url):
        seen["url"] = url
        return {"status": 200, "headers": ALL_HEADERS, "body": ""}

    executor = MockScopedExecutor(crawl_result=[], http_get_fn=http_get_fn)
    run(_job("10.10.10.5:80"), executor)

    assert seen["url"] == "http://10.10.10.5:80"


def test_infers_https_scheme_for_port_443():
    seen = {}

    def http_get_fn(url):
        seen["url"] = url
        return {"status": 200, "headers": ALL_HEADERS, "body": ""}

    executor = MockScopedExecutor(crawl_result=[], http_get_fn=http_get_fn)
    run(_job("10.10.10.5:443"), executor)

    assert seen["url"] == "https://10.10.10.5:443"


def test_full_url_target_is_used_unchanged():
    seen = {}

    def http_get_fn(url):
        seen["url"] = url
        return {"status": 200, "headers": ALL_HEADERS, "body": ""}

    executor = MockScopedExecutor(crawl_result=[], http_get_fn=http_get_fn)
    run(_job("https://10.10.10.5:8443/app"), executor)

    assert seen["url"] == "https://10.10.10.5:8443/app"


def test_sensitive_endpoint_is_flagged():
    pages = [
        {"url": "http://10.10.10.5:80/admin", "status": 200, "body": "<html></html>", "forms": []},
        {"url": "http://10.10.10.5:80/about", "status": 200, "body": "<html></html>", "forms": []},
    ]
    executor = MockScopedExecutor(
        crawl_result=pages, http_result={"status": 200, "headers": ALL_HEADERS, "body": ""}
    )
    result = run(_job(), executor)

    sensitive = [f for f in result.findings if f.finding_type == "sensitive_endpoint_found"]
    assert len(sensitive) == 1
    assert "/admin" in sensitive[0].description


def test_sensitive_subpath_also_matches():
    pages = [
        {"url": "http://10.10.10.5:80/admin/dashboard", "status": 200, "body": "", "forms": []},
    ]
    executor = MockScopedExecutor(
        crawl_result=pages, http_result={"status": 200, "headers": ALL_HEADERS, "body": ""}
    )
    result = run(_job(), executor)

    sensitive = [f for f in result.findings if f.finding_type == "sensitive_endpoint_found"]
    assert len(sensitive) == 1


def test_404_sensitive_path_is_not_flagged():
    pages = [
        {"url": "http://10.10.10.5:80/admin", "status": 404, "body": "not found", "forms": []},
    ]
    executor = MockScopedExecutor(
        crawl_result=pages, http_result={"status": 200, "headers": ALL_HEADERS, "body": ""}
    )
    result = run(_job(), executor)

    assert not [f for f in result.findings if f.finding_type == "sensitive_endpoint_found"]


def test_login_form_flagged_as_default_creds_candidate():
    pages = [
        {
            "url": "http://10.10.10.5:80/admin",
            "status": 200,
            "body": "",
            "forms": [{"action": "/admin/login", "method": "post", "inputs": ["username", "password"]}],
        }
    ]
    executor = MockScopedExecutor(
        crawl_result=pages, http_result={"status": 200, "headers": ALL_HEADERS, "body": ""}
    )
    result = run(_job(), executor)

    creds = [f for f in result.findings if f.finding_type == "default_creds_found"]
    assert len(creds) == 1
    assert creds[0].host == "10.10.10.5"
    assert creds[0].service_port == 80


def test_form_without_password_field_is_not_flagged_as_login():
    pages = [
        {
            "url": "http://10.10.10.5:80/search",
            "status": 200,
            "body": "",
            "forms": [{"action": "/search", "method": "get", "inputs": ["q"]}],
        }
    ]
    executor = MockScopedExecutor(
        crawl_result=pages, http_result={"status": 200, "headers": ALL_HEADERS, "body": ""}
    )
    result = run(_job(), executor)

    assert not [f for f in result.findings if f.finding_type == "default_creds_found"]


def test_reflected_input_is_detected_on_get_forms():
    pages = [
        {
            "url": "http://10.10.10.5:80/search",
            "status": 200,
            "body": "",
            "forms": [{"action": "/search", "method": "get", "inputs": ["q"]}],
        }
    ]

    def http_get_fn(url):
        # Realistic vulnerable behavior: the app decodes the "q" query
        # param and echoes it straight into the HTML, unescaped — this
        # is what actually makes the probe marker's "<"/">" survive
        # into the response raw (see REFLECTED_PROBE_MARKER's own
        # comment on why the marker now contains them).
        query = parse_qs(urlparse(url).query)
        if "q" in query:
            return {"status": 200, "headers": {}, "body": f"<p>results for {query['q'][0]}</p>"}
        return {"status": 200, "headers": ALL_HEADERS, "body": ""}

    executor = MockScopedExecutor(crawl_result=pages, http_get_fn=http_get_fn)
    result = run(_job(), executor)

    reflected = [f for f in result.findings if f.finding_type == "reflected_input"]
    assert len(reflected) == 1


def test_html_escaped_input_is_not_flagged_as_reflected():
    # Direct regression test for a real false-positive: a page that
    # correctly HTML-escapes the reflected value (so "<" becomes
    # "&lt;" etc.) must NOT be flagged — the old all-alphanumeric probe
    # marker could never tell this apart from a genuinely unescaped
    # reflection, since the marker text itself showed up in the body
    # either way.
    pages = [
        {
            "url": "http://10.10.10.5:80/controls/escaped",
            "status": 200,
            "body": "",
            "forms": [{"action": "/controls/escaped", "method": "get", "inputs": ["q"]}],
        }
    ]

    def http_get_fn(url):
        query = parse_qs(urlparse(url).query)
        if "q" in query:
            # Properly escaping app: html.escape() on the decoded value
            # before rendering it back.
            return {"status": 200, "headers": {}, "body": f"<p>{html_escape(query['q'][0])}</p>"}
        return {"status": 200, "headers": ALL_HEADERS, "body": ""}

    executor = MockScopedExecutor(crawl_result=pages, http_get_fn=http_get_fn)
    result = run(_job(), executor)

    assert not [f for f in result.findings if f.finding_type == "reflected_input"]


def test_unreflected_input_is_not_flagged():
    pages = [
        {
            "url": "http://10.10.10.5:80/search",
            "status": 200,
            "body": "",
            "forms": [{"action": "/search", "method": "get", "inputs": ["q"]}],
        }
    ]

    def http_get_fn(url):
        return {"status": 200, "headers": ALL_HEADERS, "body": "<p>no results</p>"}

    executor = MockScopedExecutor(crawl_result=pages, http_get_fn=http_get_fn)
    result = run(_job(), executor)

    assert not [f for f in result.findings if f.finding_type == "reflected_input"]


def test_post_forms_are_not_probed_for_reflection():
    pages = [
        {
            "url": "http://10.10.10.5:80/contact",
            "status": 200,
            "body": "",
            "forms": [{"action": "/contact", "method": "post", "inputs": ["message"]}],
        }
    ]
    calls = []

    def http_get_fn(url):
        calls.append(url)
        return {"status": 200, "headers": ALL_HEADERS, "body": ""}

    executor = MockScopedExecutor(crawl_result=pages, http_get_fn=http_get_fn)
    run(_job(), executor)

    # only the one header-check call against the base URL — no probe for the POST form
    assert calls == ["http://10.10.10.5:80"]


def test_missing_security_headers_is_flagged():
    executor = MockScopedExecutor(
        crawl_result=[], http_result={"status": 200, "headers": {}, "body": ""}
    )
    result = run(_job(), executor)

    missing = [f for f in result.findings if f.finding_type == "missing_security_header"]
    assert len(missing) == 1
    assert "x-frame-options" in missing[0].description.lower()


def test_complete_headers_produce_no_finding():
    executor = MockScopedExecutor(
        crawl_result=[], http_result={"status": 200, "headers": ALL_HEADERS, "body": ""}
    )
    result = run(_job(), executor)

    assert not [f for f in result.findings if f.finding_type == "missing_security_header"]


def test_directory_listing_is_flagged():
    pages = [
        {
            "url": "http://10.10.10.5:80/uploads/",
            "status": 200,
            "body": "<title>Index of /uploads</title>",
            "forms": [],
        }
    ]
    executor = MockScopedExecutor(
        crawl_result=pages, http_result={"status": 200, "headers": ALL_HEADERS, "body": ""}
    )
    result = run(_job(), executor)

    listings = [f for f in result.findings if f.finding_type == "directory_listing_enabled"]
    assert len(listings) == 1


def test_downloadable_binary_link_triggers_binary_follow_up_job():
    pages = [
        {
            "url": "http://10.10.10.5:80/downloads",
            "status": 200,
            "body": '<a href="/files/agent_setup.exe">Download</a>',
            "forms": [],
        }
    ]
    executor = MockScopedExecutor(
        crawl_result=pages, http_result={"status": 200, "headers": ALL_HEADERS, "body": ""}
    )
    result = run(_job(), executor)

    binary_jobs = [j for j in result.follow_up_jobs if j["agent"] == "binary"]
    assert len(binary_jobs) == 1
    assert binary_jobs[0]["target"] == "http://10.10.10.5:80/files/agent_setup.exe"


def test_duplicate_binary_links_across_pages_dedupe():
    pages = [
        {
            "url": "http://10.10.10.5:80/a",
            "status": 200,
            "body": '<a href="/files/app.bin">a</a>',
            "forms": [],
        },
        {
            "url": "http://10.10.10.5:80/b",
            "status": 200,
            "body": '<a href="/files/app.bin">b</a>',
            "forms": [],
        },
    ]
    executor = MockScopedExecutor(
        crawl_result=pages, http_result={"status": 200, "headers": ALL_HEADERS, "body": ""}
    )
    result = run(_job(), executor)

    binary_jobs = [j for j in result.follow_up_jobs if j["agent"] == "binary"]
    assert len(binary_jobs) == 1


def test_binary_link_passed_as_a_query_string_value_still_triggers_follow_up():
    # Regression test: a file-manager-style download link
    # (index.php?p=<urlencoded path>&dl) with NO extension anywhere in
    # the URL path — only inside the query value — used to be silently
    # dropped by _extract_binary_links()'s path-only extension check, so
    # the binary agent never ran at all for exactly this (very common)
    # link shape. Same root cause as the secret-in-file query-string
    # fix, confirmed live against a real file-manager-style target.
    pages = [
        {
            "url": "http://10.10.10.5:80/",
            "status": 200,
            "body": '<a href="/index.php?p=tools%2Fagent.exe&dl">Download agent</a>',
            "forms": [],
        }
    ]
    executor = MockScopedExecutor(
        crawl_result=pages, http_result={"status": 200, "headers": ALL_HEADERS, "body": ""}
    )
    result = run(_job(), executor)

    binary_jobs = [j for j in result.follow_up_jobs if j["agent"] == "binary"]
    assert len(binary_jobs) == 1
    assert binary_jobs[0]["target"] == "http://10.10.10.5:80/index.php?p=tools%2Fagent.exe&dl"


def test_non_binary_links_do_not_trigger_follow_up_jobs():
    pages = [
        {
            "url": "http://10.10.10.5:80/",
            "status": 200,
            "body": '<a href="/about.html">About</a>',
            "forms": [],
        }
    ]
    executor = MockScopedExecutor(
        crawl_result=pages, http_result={"status": 200, "headers": ALL_HEADERS, "body": ""}
    )
    result = run(_job(), executor)

    assert result.follow_up_jobs == []


def test_binary_response_with_no_extension_in_url_still_triggers_follow_up():
    # core/scoped_executor.py's crawl() sets looks_binary=True on a page
    # whose content sniffs as a real binary (magic bytes / Content-Type)
    # regardless of its URL — e.g. a direct /download/<id> link with no
    # extension anywhere. _extract_binary_links() can't catch this (no
    # extension to match), so run() checks page["looks_binary"] directly.
    pages = [
        {
            "url": "http://10.10.10.5:80/download/a1b2c3d4",
            "status": 200,
            "body": "",
            "forms": [],
            "looks_binary": True,
        }
    ]
    executor = MockScopedExecutor(
        crawl_result=pages, http_result={"status": 200, "headers": ALL_HEADERS, "body": ""}
    )
    result = run(_job(), executor)

    binary_jobs = [j for j in result.follow_up_jobs if j["agent"] == "binary"]
    assert len(binary_jobs) == 1
    assert binary_jobs[0]["target"] == "http://10.10.10.5:80/download/a1b2c3d4"


def test_looks_binary_and_href_binary_link_on_same_page_both_fire_once_each():
    pages = [
        {
            "url": "http://10.10.10.5:80/download/a1b2c3d4",  # the page itself is a binary
            "status": 200,
            "body": "",
            "forms": [],
            "looks_binary": True,
        },
        {
            "url": "http://10.10.10.5:80/",
            "status": 200,
            "body": '<a href="/files/tool.exe">tool</a>',  # an extension-based link too
            "forms": [],
        },
    ]
    executor = MockScopedExecutor(
        crawl_result=pages, http_result={"status": 200, "headers": ALL_HEADERS, "body": ""}
    )
    result = run(_job(), executor)

    targets = {j["target"] for j in result.follow_up_jobs if j["agent"] == "binary"}
    assert targets == {
        "http://10.10.10.5:80/download/a1b2c3d4",
        "http://10.10.10.5:80/files/tool.exe",
    }


def test_empty_crawl_still_runs_header_check_only():
    executor = MockScopedExecutor(
        crawl_result=[], http_result={"status": 200, "headers": ALL_HEADERS, "body": ""}
    )
    result = run(_job(), executor)

    assert result.status == "completed"
    assert result.findings == []
    assert result.follow_up_jobs == []


def test_llm_disabled_by_default_leaves_rule_based_binary_follow_ups_untouched(monkeypatch):
    """common/llm.py's choose_follow_ups() is off by default — confirms
    wiring it into this agent didn't change its own default,
    already-tested binary-follow-up behavior at all."""
    import common.llm as llm_module

    monkeypatch.setattr(llm_module, "LLM_ENABLED", False)

    pages = [
        {
            "url": "http://10.10.10.5:80/downloads",
            "status": 200,
            "body": '<a href="/files/agent_setup.exe">Download</a>',
            "forms": [],
        }
    ]
    executor = MockScopedExecutor(
        crawl_result=pages, http_result={"status": 200, "headers": ALL_HEADERS, "body": ""}
    )
    result = run(_job(), executor)

    binary_jobs = [j for j in result.follow_up_jobs if j["agent"] == "binary"]
    assert len(binary_jobs) == 1
    assert binary_jobs[0]["target"] == "http://10.10.10.5:80/files/agent_setup.exe"


def test_llm_enabled_can_filter_down_binary_follow_up_candidates(monkeypatch):
    """When explicitly turned on and the model rejects the only
    candidate (an empty [] response), the agent's own follow_up_jobs
    reflects that -- proving the LLM layer actually reaches this
    agent's return value, not just common/llm.py in isolation."""
    import sys
    import types
    from unittest.mock import MagicMock

    import common.llm as llm_module

    monkeypatch.setattr(llm_module, "LLM_ENABLED", True)

    fake_module = types.ModuleType("openai")

    class _FakeOpenAI:
        def __init__(self, *args, **kwargs):
            self.chat = MagicMock()
            message = MagicMock(content="[]")
            self.chat.completions.create.return_value = MagicMock(choices=[MagicMock(message=message)])

    fake_module.OpenAI = _FakeOpenAI
    monkeypatch.setitem(sys.modules, "openai", fake_module)

    pages = [
        {
            "url": "http://10.10.10.5:80/downloads",
            "status": 200,
            "body": '<a href="/files/agent_setup.exe">Download</a>',
            "forms": [],
        }
    ]
    executor = MockScopedExecutor(
        crawl_result=pages, http_result={"status": 200, "headers": ALL_HEADERS, "body": ""}
    )
    result = run(_job(), executor)

    assert [j for j in result.follow_up_jobs if j["agent"] == "binary"] == []
