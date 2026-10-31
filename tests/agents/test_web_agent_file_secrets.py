"""
tests/agents/test_web_agent_file_secrets.py

User story: "As a pentester running CART against a target, when the
target's bare IP redirects to an internal app with a dynamic file
listing (a 'File Manager'-style page), and one of the listed files is a
plain-text note containing an internal secret (not a JS bundle, not a
compiled binary — just a .txt a sysadmin left exposed), CART's web agent
should follow the redirect, discover the file, fetch it, and report the
secret — without needing katana, gitleaks, or any extra install, and
without flooding the report with false positives from ordinary HTML
page content."

Covers agents/web/agent.py's new _check_redirect_followed() and
_check_file_secrets(), using MockScopedExecutor (crawl_result lets a
test hand the agent pre-built pages exactly as core/scoped_executor.py's
real crawl() would produce them, redirect_chain included, without
needing a real redirect or a real network).
"""

from agents.web.agent import run
from common.contracts import Job
from tests.mock_executor import MockScopedExecutor

ALL_HEADERS = {
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'self'",
}

# A fake AWS access key, 20 chars (AKIA + 16), matching the exact shape
# gitleaks'/SECRET_PATTERNS' aws_access_key_id rule requires — the same
# fake value already used in fixtures/vulnerable_binary/vuln.c.
_FAKE_AWS_KEY = "AKIAFAKEEXAMPLE12345"

_HANDOVER_BODY = f"""NetOps handover notes
----------------------
- internal AWS key for the backup bucket: {_FAKE_AWS_KEY}
- rotate this after onboarding is done.
"""


def _job(target="10.10.10.5:80", crawler="requests"):
    return Job(job_id="web-file-secrets-job", agent="web", target=target, context={"crawler": crawler})


def test_user_story_secret_in_a_file_behind_a_redirect_is_found_and_reported():
    """The core user story end to end: a redirected-to file-manager
    listing, a .txt file in it with a real secret, discovered via the
    native (no-katana) path."""
    listing_page = {
        "url": "http://10.10.10.5:80/filemanager/",
        "status": 200,
        "body": (
            '<html><body><h1>File Manager</h1>'
            '<a href="/filemanager/README.txt">README.txt</a>'
            '<a href="/filemanager/ops/netops-handover.txt">netops-handover.txt</a>'
            "</body></html>"
        ),
        "forms": [],
        "redirect_chain": ["http://10.10.10.5:80/", "http://10.10.10.5:80/filemanager/"],
    }
    readme_page = {
        "url": "http://10.10.10.5:80/filemanager/README.txt",
        "status": 200,
        "body": "Just a readme, nothing sensitive here.",
        "forms": [],
    }
    handover_page = {
        "url": "http://10.10.10.5:80/filemanager/ops/netops-handover.txt",
        "status": 200,
        "body": _HANDOVER_BODY,
        "forms": [],
    }

    executor = MockScopedExecutor(
        crawl_result=[listing_page, readme_page, handover_page],
        http_result={"status": 200, "headers": ALL_HEADERS, "body": ""},
    )
    result = run(_job(), executor)

    redirects = [f for f in result.findings if f.finding_type == "redirect_followed"]
    assert len(redirects) == 1
    assert "10.10.10.5" in redirects[0].description
    assert "filemanager" in redirects[0].description

    secrets = [f for f in result.findings if f.finding_type == "secret_in_file_found"]
    assert len(secrets) == 1
    assert "netops-handover.txt" in secrets[0].description
    assert _FAKE_AWS_KEY not in secrets[0].evidence.summary  # redacted
    assert "AWS Access Key ID" in secrets[0].evidence.summary

    # the clean file right next to it produced no secret finding
    assert not any("README.txt" in f.description for f in secrets)


def test_html_page_body_is_not_scanned_for_secrets_even_if_it_contains_one():
    # Deliberate: an ordinary HTML page isn't secret-scanned by this
    # check (that would be noisy — marketing copy, embedded sample code).
    # Only js_secret_found (JS bundles) and secret_in_file_found (listed
    # text-file extensions) cover secret discovery.
    page = {
        "url": "http://10.10.10.5:80/about.html",
        "status": 200,
        "body": f"<html><body>Our key is {_FAKE_AWS_KEY} (don't tell anyone)</body></html>",
        "forms": [],
    }
    executor = MockScopedExecutor(
        crawl_result=[page],
        http_result={"status": 200, "headers": ALL_HEADERS, "body": ""},
    )
    result = run(_job(), executor)
    assert not [f for f in result.findings if f.finding_type == "secret_in_file_found"]


def test_404_text_file_is_not_scanned():
    page = {
        "url": "http://10.10.10.5:80/old-backup.env",
        "status": 404,
        "body": f"ignored even though it mentions {_FAKE_AWS_KEY}",
        "forms": [],
    }
    executor = MockScopedExecutor(
        crawl_result=[page],
        http_result={"status": 200, "headers": ALL_HEADERS, "body": ""},
    )
    result = run(_job(), executor)
    assert not [f for f in result.findings if f.finding_type == "secret_in_file_found"]


def test_text_file_with_no_secret_pattern_produces_no_finding():
    page = {
        "url": "http://10.10.10.5:80/changelog.txt",
        "status": 200,
        "body": "v1.2.0 - fixed a typo\nv1.1.0 - initial release",
        "forms": [],
    }
    executor = MockScopedExecutor(
        crawl_result=[page],
        http_result={"status": 200, "headers": ALL_HEADERS, "body": ""},
    )
    result = run(_job(), executor)
    assert not [f for f in result.findings if f.finding_type == "secret_in_file_found"]


def test_each_supported_text_extension_is_scanned():
    for ext in (".txt", ".log", ".conf", ".cfg", ".ini", ".env", ".yaml", ".yml", ".json", ".xml", ".csv", ".md", ".bak", ".sql"):
        page = {
            "url": f"http://10.10.10.5:80/leak{ext}",
            "status": 200,
            "body": f"key={_FAKE_AWS_KEY}",
            "forms": [],
        }
        executor = MockScopedExecutor(
            crawl_result=[page],
            http_result={"status": 200, "headers": ALL_HEADERS, "body": ""},
        )
        result = run(_job(), executor)
        found = [f for f in result.findings if f.finding_type == "secret_in_file_found"]
        assert len(found) == 1, f"expected a finding for {ext}, got {found}"


def test_page_with_no_redirect_chain_produces_no_redirect_finding():
    page = {
        "url": "http://10.10.10.5:80/",
        "status": 200,
        "body": "<html></html>",
        "forms": [],
    }
    executor = MockScopedExecutor(
        crawl_result=[page],
        http_result={"status": 200, "headers": ALL_HEADERS, "body": ""},
    )
    result = run(_job(), executor)
    assert not [f for f in result.findings if f.finding_type == "redirect_followed"]


def test_multi_hop_redirect_finding_mentions_hop_count():
    page = {
        "url": "http://10.10.10.5:80/final",
        "status": 200,
        "body": "<html></html>",
        "forms": [],
        "redirect_chain": [
            "http://10.10.10.5:80/",
            "http://10.10.10.5:80/a",
            "http://10.10.10.5:80/final",
        ],
    }
    executor = MockScopedExecutor(
        crawl_result=[page],
        http_result={"status": 200, "headers": ALL_HEADERS, "body": ""},
    )
    result = run(_job(), executor)
    redirects = [f for f in result.findings if f.finding_type == "redirect_followed"]
    assert len(redirects) == 1
    assert "2 hop" in redirects[0].description
