"""
tests/agents/test_web_agent_flags.py

Covers agents/web/agent.py's _check_planted_flags() (common/flag_patterns.py)
— capturing CTF/lab-style planted flags found in a crawled plain-text
file, direct follow-up to a user request: "capture the planted flags on
the lab network". Mirrors tests/agents/test_web_agent_file_secrets.py's
MockScopedExecutor pattern.
"""

from agents.web.agent import run
from common.contracts import Job
from tests.mock_executor import MockScopedExecutor

ALL_HEADERS = {
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'self'",
}


def _job(target="10.10.10.5:80", crawler="requests"):
    return Job(job_id="web-flags-job", agent="web", target=target, context={"crawler": crawler})


def _executor(pages):
    return MockScopedExecutor(
        crawl_result=pages, http_result={"status": 200, "headers": ALL_HEADERS, "body": ""}
    )


def test_flag_in_a_crawled_text_file_is_captured_unredacted():
    page = {
        "url": "http://10.10.10.5:80/notes.txt",
        "status": 200,
        "body": "Internal notes.\nCongrats, here's your proof: FLAG{a1b2c3d4e5f6}\n",
        "forms": [],
    }
    result = run(_job(), _executor([page]))

    flags = [f for f in result.findings if f.finding_type == "ctf_flag_found"]
    assert len(flags) == 1
    assert "FLAG{a1b2c3d4e5f6}" in flags[0].evidence.summary  # NOT redacted, unlike secrets
    assert "notes.txt" in flags[0].description


def test_flag_detection_is_case_insensitive_and_covers_common_prefixes():
    for text, expected in [
        ("flag{lowercase_ok}", "flag{lowercase_ok}"),
        ("Flag{Mixed_Case}", "Flag{Mixed_Case}"),
        ("CTF{alt_prefix}", "CTF{alt_prefix}"),
        ("HTB{hackthebox_style}", "HTB{hackthebox_style}"),
        ("THM{tryhackme_style}", "THM{tryhackme_style}"),
    ]:
        page = {"url": "http://10.10.10.5:80/a.txt", "status": 200, "body": text, "forms": []}
        result = run(_job(), _executor([page]))
        flags = [f for f in result.findings if f.finding_type == "ctf_flag_found"]
        assert len(flags) == 1, f"expected a flag finding for {text!r}"
        assert expected in flags[0].evidence.summary


def test_multiple_distinct_flags_in_one_file_are_all_captured():
    page = {
        "url": "http://10.10.10.5:80/multi.txt",
        "status": 200,
        "body": "first: FLAG{one_down} second: FLAG{two_down}",
        "forms": [],
    }
    result = run(_job(), _executor([page]))

    flags = [f for f in result.findings if f.finding_type == "ctf_flag_found"]
    captured = {f.evidence.summary for f in flags}
    assert len(flags) == 2
    assert any("FLAG{one_down}" in s for s in captured)
    assert any("FLAG{two_down}" in s for s in captured)


def test_html_page_body_is_not_scanned_for_flags():
    # Same restriction _check_file_secrets uses — an ordinary HTML
    # page's body isn't scanned, only TEXT_SECRET_SCAN_EXTENSIONS files.
    page = {
        "url": "http://10.10.10.5:80/",
        "status": 200,
        "body": "<html><body>FLAG{should_not_be_found_here}</body></html>",
        "forms": [],
    }
    result = run(_job(), _executor([page]))
    assert not [f for f in result.findings if f.finding_type == "ctf_flag_found"]


def test_text_with_no_flag_produces_no_finding():
    page = {
        "url": "http://10.10.10.5:80/plain.txt",
        "status": 200,
        "body": "Nothing interesting here, just notes.",
        "forms": [],
    }
    result = run(_job(), _executor([page]))
    assert not [f for f in result.findings if f.finding_type == "ctf_flag_found"]


def test_a_404_page_is_not_scanned_even_if_body_contains_flag_text():
    page = {
        "url": "http://10.10.10.5:80/gone.txt",
        "status": 404,
        "body": "FLAG{should_not_count_on_a_404}",
        "forms": [],
    }
    result = run(_job(), _executor([page]))
    assert not [f for f in result.findings if f.finding_type == "ctf_flag_found"]
