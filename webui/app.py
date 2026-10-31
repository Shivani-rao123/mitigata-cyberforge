"""
webui/app.py

A small dashboard for CART — lets you type in a target and scope, click
Run, and see the full network -> web -> binary chain's results in a
browser instead of three separate CLI commands.

This is a convenience layer on top of what's already built (the same
agents, the same ScopedExecutor, the same scope enforcement as main.py
uses) — see webui/orchestrate.py for the actual chaining logic. It is
NOT the real API (FR-7) or orchestrator (FR-4core/orchestrator.py,
core/queue.py) — those are a persistent, DB-backed job queue your
partner is building. Swap this dashboard to call that API once it
exists; the templates don't need to change, only where the data comes
from.

Run:
    python3 webui/app.py
Then open http://127.0.0.1:5500 in a browser.
"""

from __future__ import annotations

from flask import Flask, render_template, request

from core.tool_engine import ToolEngine
from webui.orchestrate import run_full_chain

app = Flask(__name__)

# How seriously each finding type should read in the UI. Anything not
# listed here defaults to "medium" — see the `severity` Jinja filter below.
FINDING_SEVERITY = {
    "hardcoded_secret": "high",
    "unsafe_function_call": "high",
    "default_creds_found": "high",
    "reflected_input": "high",
    "js_secret_found": "high",  # a secret hardcoded in a JS bundle is just as real as one in a binary
    "secret_in_file_found": "high",  # a secret in a crawled plain-text/config/log file (not JS) —
    # e.g. an exposed handover note, .env, or backup config found via a crawled link
    "sensitive_endpoint_found": "medium",
    "directory_listing_enabled": "medium",
    "redirect_followed": "info",  # operational note: the crawl followed a redirect to a new host/path
    "missing_security_header": "low",
    "js_endpoint_found": "low",  # attack-surface disclosure, not itself a proven weakness
    "open_port": "info",
    "crawler_fallback": "info",  # operational note (katana unavailable this run), not a finding
}


@app.template_filter("severity")
def severity_filter(finding_type: str) -> str:
    return FINDING_SEVERITY.get(finding_type, "medium")


@app.route("/", methods=["GET"])
def index():
    # Whether katana is ACTUALLY installed on this machine right now —
    # not just configured in tools.yaml (every machine has that entry;
    # far fewer have the binary). The form offers "katana only" as a
    # crawler mode, and presenting that as a normal, always-available
    # choice is misleading on a machine that doesn't have it installed —
    # see ToolEngine.is_installed()'s docstring for the has_tool() vs
    # is_installed() distinction this relies on.
    katana_installed = ToolEngine().is_installed("katana")
    return render_template("index.html", katana_installed=katana_installed)


VALID_CRAWLER_MODES = ("auto", "requests", "katana")


@app.route("/scan", methods=["POST"])
def scan():
    target = request.form.get("target", "").strip()
    scope_raw = request.form.get("scope", "").strip()
    crawler = request.form.get("crawler", "auto").strip() or "auto"
    katana_installed = ToolEngine().is_installed("katana")

    if not target:
        return render_template("index.html", error="Target is required.", katana_installed=katana_installed)

    if crawler not in VALID_CRAWLER_MODES:
        return render_template(
            "index.html", error=f"Unknown crawler mode: {crawler!r}", katana_installed=katana_installed
        )

    scope_cidrs = [c.strip() for c in scope_raw.split(",") if c.strip()] or None

    try:
        chain = run_full_chain(target, scope_cidrs=scope_cidrs, crawler=crawler)
    except Exception as exc:  # noqa: BLE001 — show it in the UI, not a stack trace
        return render_template(
            "index.html", error=f"Could not start scan: {exc}", katana_installed=katana_installed
        )

    return render_template("results.html", chain=chain, target=target)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5500, debug=True)
