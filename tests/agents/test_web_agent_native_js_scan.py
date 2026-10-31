"""
tests/agents/test_web_agent_native_js_scan.py

Unit tests for agents/web/agent.py's _scan_js_bundles() and its wiring
into _crawl()'s three native-crawler branches ("requests" mode, "auto"
mode with no crawl_js support, and "auto" mode's katana-unavailable
fallback). This is the zero-extra-install alternative to katana's
-jsluice: it fetches <script src=...> files found by the native crawler
and regex-scans them for secrets (common/secret_patterns.py) and API
endpoints (common/js_extract.py), so js_secret_found / js_endpoint_found
can fire without katana installed at all.
"""

from agents.web.agent import run
from common.contracts import Job
from core.scoped_executor import ScopeViolation, ToolNotInstalled
from tests.mock_executor import MockScopedExecutor

ALL_HEADERS = {
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'self'",
}

# A fake Stripe secret key, built via concatenation (not a contiguous
# literal) so this test file itself doesn't trip GitHub's push-protection
# secret scanner — mirrors the same pattern used by
# fixtures/js_demo_site/app.py and tests/common/test_secret_patterns.py.
_FAKE_STRIPE_KEY = "sk_live_51H8xyzFAKEKEY" + "abcdefghijklmnopqrstuvwxyzABCD12"

_JS_BUNDLE_BODY = f"""
const STRIPE_KEY = "{_FAKE_STRIPE_KEY}";
function loadData() {{
  fetch("/api/internal/users/export", {{method: "GET"}});
}}
loadData();
"""

_HOMEPAGE_WITH_SCRIPT = (
    '<html><body><h1>Acme Dashboard</h1>'
    '<script src="/static/app.js"></script></body></html>'
)


def _job(target="10.10.10.5:80", crawler=None):
    context = {"crawler": crawler} if crawler else {}
    return Job(job_id="web-native-js-job", agent="web", target=target, context=context)


def _http_get_fn(js_url):
    def fn(url):
        if url == js_url:
            return {
                "status": 200,
                "headers": {"Content-Type": "application/javascript"},
                "body": _JS_BUNDLE_BODY,
            }
        return {"status": 200, "headers": ALL_HEADERS, "body": ""}

    return fn


def test_explicit_requests_mode_finds_secret_and_endpoint_in_js_bundle():
    executor = MockScopedExecutor(
        crawl_result=[
            {
                "url": "http://10.10.10.5:80/",
                "status": 200,
                "body": _HOMEPAGE_WITH_SCRIPT,
                "forms": [],
            }
        ],
        http_get_fn=_http_get_fn("http://10.10.10.5:80/static/app.js"),
    )
    result = run(_job(crawler="requests"), executor)

    secrets = [f for f in result.findings if f.finding_type == "js_secret_found"]
    endpoints = [f for f in result.findings if f.finding_type == "js_endpoint_found"]

    assert len(secrets) == 1
    assert _FAKE_STRIPE_KEY not in secrets[0].evidence.summary  # redacted

    assert len(endpoints) == 1
    assert "/api/internal/users/export" in endpoints[0].description
    assert "GET" in endpoints[0].description


def test_auto_mode_with_no_js_crawl_support_also_scans_js_bundles():
    executor = MockScopedExecutor(
        crawl_result=[
            {
                "url": "http://10.10.10.5:80/",
                "status": 200,
                "body": _HOMEPAGE_WITH_SCRIPT,
                "forms": [],
            }
        ],
        http_get_fn=_http_get_fn("http://10.10.10.5:80/static/app.js"),
    )
    assert not hasattr(executor, "crawl_js")

    result = run(_job(), executor)

    assert [f for f in result.findings if f.finding_type == "js_secret_found"]
    assert [f for f in result.findings if f.finding_type == "js_endpoint_found"]


def test_auto_mode_katana_fallback_also_scans_js_bundles():
    executor = MockScopedExecutor(
        crawl_result=[
            {
                "url": "http://10.10.10.5:80/",
                "status": 200,
                "body": _HOMEPAGE_WITH_SCRIPT,
                "forms": [],
            }
        ],
        raise_on_crawl_js=ToolNotInstalled("katana is not installed on this machine"),
        http_get_fn=_http_get_fn("http://10.10.10.5:80/static/app.js"),
    )
    result = run(_job(), executor)

    assert [f for f in result.findings if f.finding_type == "crawler_fallback"]
    assert [f for f in result.findings if f.finding_type == "js_secret_found"]
    assert [f for f in result.findings if f.finding_type == "js_endpoint_found"]


def test_explicit_katana_mode_does_not_also_run_the_native_js_scan():
    # Explicit "katana" mode fully commits to the katana path — if it
    # succeeds, the native js-bundle scan should not ALSO run (it would
    # just duplicate findings katana's own -jsluice output already
    # covers, against pages katana never even fetched via requests).
    katana_result = {
        "pages": [{"url": "http://10.10.10.5:80/", "status": 200, "body": "", "forms": []}],
        "js_findings": [],
    }
    executor = MockScopedExecutor(
        crawl_js_result=katana_result,
        http_get_fn=_http_get_fn("http://10.10.10.5:80/static/app.js"),
    )
    result = run(_job(crawler="katana"), executor)

    assert not [f for f in result.findings if f.finding_type in ("js_secret_found", "js_endpoint_found")]


def test_page_with_no_script_tags_yields_no_js_findings():
    executor = MockScopedExecutor(
        crawl_result=[
            {"url": "http://10.10.10.5:80/", "status": 200, "body": "<html></html>", "forms": []}
        ],
        http_result={"status": 200, "headers": ALL_HEADERS, "body": ""},
    )
    result = run(_job(crawler="requests"), executor)
    assert not [f for f in result.findings if f.finding_type in ("js_secret_found", "js_endpoint_found")]


def test_script_fetch_failure_does_not_crash_the_run():
    executor = MockScopedExecutor(
        crawl_result=[
            {
                "url": "http://10.10.10.5:80/",
                "status": 200,
                "body": _HOMEPAGE_WITH_SCRIPT,
                "forms": [],
            }
        ],
        # http_get returns an empty-body error shape for every URL,
        # including the script — must be skipped, not crash the agent.
        http_get_fn=lambda url: {"status": 0, "headers": {}, "body": "", "error": "boom"},
    )
    result = run(_job(crawler="requests"), executor)
    assert result.status == "completed"
    assert not [f for f in result.findings if f.finding_type in ("js_secret_found", "js_endpoint_found")]


def test_same_script_src_on_multiple_pages_is_only_fetched_once():
    calls = {"count": 0}

    def http_get_fn(url):
        if url == "http://10.10.10.5:80/static/app.js":
            calls["count"] += 1
            return {"status": 200, "headers": {}, "body": _JS_BUNDLE_BODY}
        return {"status": 200, "headers": ALL_HEADERS, "body": ""}

    executor = MockScopedExecutor(
        crawl_result=[
            {
                "url": "http://10.10.10.5:80/",
                "status": 200,
                "body": _HOMEPAGE_WITH_SCRIPT,
                "forms": [],
            },
            {
                "url": "http://10.10.10.5:80/about",
                "status": 200,
                "body": _HOMEPAGE_WITH_SCRIPT,
                "forms": [],
            },
        ],
        http_get_fn=http_get_fn,
    )
    run(_job(crawler="requests"), executor)

    assert calls["count"] == 1


def test_third_party_cdn_script_does_not_crash_the_whole_web_stage():
    """Regression test for a real crash: a page referencing a
    third-party CDN script (e.g. code.jquery.com) used to make
    _scan_js_bundles() call executor.http_get() on an out-of-scope URL,
    raising an unhandled ScopeViolation that wiped out EVERY finding the
    rest of the crawl had already produced (observed live — the web
    stage reported 0 findings and 1 stage error reading exactly
    "'https://code.jquery.com/jquery-3.6.1.min.js' resolves to
    151.101.129.155, which is out of scope"). Must now just skip the
    third-party script and keep every other finding."""
    calls = {"cdn": 0}

    def http_get_fn(url):
        if "code.jquery.com" in url:
            calls["cdn"] += 1
            raise ScopeViolation(
                "'https://code.jquery.com/jquery-3.6.1.min.js' resolves to "
                "151.101.129.155, which is out of scope"
            )
        return {"status": 200, "headers": ALL_HEADERS, "body": ""}

    homepage = {
        "url": "http://10.10.10.5:80/",
        "status": 200,
        "body": (
            '<html><body>'
            '<script src="https://code.jquery.com/jquery-3.6.1.min.js"></script>'
            '<a href="/admin">admin</a>'
            "</body></html>"
        ),
        "forms": [],
    }
    admin_page = {
        "url": "http://10.10.10.5:80/admin",
        "status": 200,
        "body": "<html><body>admin panel</body></html>",
        "forms": [],
    }
    executor = MockScopedExecutor(crawl_result=[homepage, admin_page], http_get_fn=http_get_fn)

    result = run(_job(crawler="requests"), executor)

    # the run completed and the unrelated, perfectly findable finding
    # on the same page survived — nothing was wiped out
    assert result.status == "completed"
    assert [f for f in result.findings if f.finding_type == "sensitive_endpoint_found"]
    # the third-party script was never even fetched — filtered out by
    # same-host matching before http_get() was called at all
    assert calls["cdn"] == 0


def test_same_host_script_that_resolves_out_of_scope_is_skipped_not_fatal():
    """Defense in depth: even a script whose URL LOOKS same-host (so the
    cheap netloc filter lets it through) can still raise ScopeViolation
    at fetch time (e.g. DNS resolves it somewhere unexpected) — that must
    be caught and skipped too, not just the pre-filtered third-party
    case above."""

    def http_get_fn(url):
        if url.endswith("app.js"):
            raise ScopeViolation(f"{url!r} resolves outside scope")
        return {"status": 200, "headers": ALL_HEADERS, "body": ""}

    page = {
        "url": "http://10.10.10.5:80/",
        "status": 200,
        "body": '<html><body><script src="/static/app.js"></script></body></html>',
        "forms": [],
    }
    executor = MockScopedExecutor(crawl_result=[page], http_get_fn=http_get_fn)

    result = run(_job(crawler="requests"), executor)

    assert result.status == "completed"
    assert not [f for f in result.findings if f.finding_type in ("js_secret_found", "js_endpoint_found")]
