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

from webui.orchestrate import run_full_chain

app = Flask(__name__)

# How seriously each finding type should read in the UI. Anything not
# listed here defaults to "medium" — see the `severity` Jinja filter below.
FINDING_SEVERITY = {
    "hardcoded_secret": "high",
    "unsafe_function_call": "high",
    "default_creds_found": "high",
    "reflected_input": "high",
    "sensitive_endpoint_found": "medium",
    "directory_listing_enabled": "medium",
    "missing_security_header": "low",
    "open_port": "info",
}


@app.template_filter("severity")
def severity_filter(finding_type: str) -> str:
    return FINDING_SEVERITY.get(finding_type, "medium")


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    target = request.form.get("target", "").strip()
    scope_raw = request.form.get("scope", "").strip()

    if not target:
        return render_template("index.html", error="Target is required.")

    scope_cidrs = [c.strip() for c in scope_raw.split(",") if c.strip()] or None

    try:
        chain = run_full_chain(target, scope_cidrs=scope_cidrs)
    except Exception as exc:  # noqa: BLE001 — show it in the UI, not a stack trace
        return render_template("index.html", error=f"Could not start scan: {exc}")

    return render_template("results.html", chain=chain, target=target)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5500, debug=True)
