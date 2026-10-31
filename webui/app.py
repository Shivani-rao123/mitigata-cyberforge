"""
webui/app.py

A small dashboard for CART — lets you type in a target and scope, click
Run, and see the full network -> web -> binary chain's results in a
browser instead of three separate CLI commands.

This is a convenience layer on top of what's already built (the same
agents, the same ScopedExecutor, the same scope enforcement as main.py
uses). It now calls core/orchestrator.py's run_target() (FR-4) — the
concurrent, agent-count-agnostic dispatcher — instead of
webui/orchestrate.py's older synchronous run_full_chain(), which is the
reason a scan used to take as long as every stage added up end to end.
core/orchestrator.py's OrchestrationResult/StageResult were built to
carry the exact same field names webui/orchestrate.py's ChainResult/
StageResult did (scope, stages, total_findings, and per-stage agent/
target/result/error), so results.html needed no changes at all.
webui/orchestrate.py itself is left in place, untouched, with its own
test suite still green — nothing else in the project still imports it.

It is NOT the real API (FR-7) — that's a persistent, DB-backed job
queue your partner is building on top of this. Swap this dashboard to
call that API once it exists; the templates still won't need to
change, only where the data comes from.

Run:
    python3 webui/app.py
Then open http://127.0.0.1:5500 in a browser.
"""

from __future__ import annotations

from flask import Flask, render_template, request

from core.orchestrator import run_target
from core.scoped_executor import RealScopedExecutor
from core.tool_engine import ToolEngine
from scope.manager import ScopeManager

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


# Display-only ordering — doesn't change what's found or how, just the
# order a stage's findings render in: real weaknesses first, operational
# notes ("redirect_followed", "crawler_fallback", "open_port" — things
# that describe what the crawl/scan did rather than something wrong)
# last, instead of interleaved with whatever order the agent happened
# to produce them in. A real TinyFileManager-style target can produce a
# dozen redirect_followed notes for every one finding that actually
# matters; without this, those notes bury the real findings.
_SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2, "info": 3}

# "info"-severity findings that are purely operational commentary, not a
# weakness of any kind — collapsed into their own closed-by-default
# section in results.html (sort_findings still needs this split, so it
# lives here rather than duplicated in the template).
OPERATIONAL_NOTE_TYPES = {"redirect_followed", "crawler_fallback", "open_port"}


@app.template_filter("sort_findings")
def sort_findings_filter(findings):
    """Findings for one stage, split into (notable, operational) —
    `notable` sorted high->low->info by severity (stable: same-severity
    findings keep their original relative order), `operational` left in
    original order since there's no severity signal worth sorting by
    within a pile of redirect_followed notes."""
    notable = [f for f in findings if f.finding_type not in OPERATIONAL_NOTE_TYPES]
    operational = [f for f in findings if f.finding_type in OPERATIONAL_NOTE_TYPES]
    notable.sort(key=lambda f: _SEVERITY_RANK.get(FINDING_SEVERITY.get(f.finding_type, "medium"), 1))
    return notable, operational


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
        # Same scope-resolution webui/orchestrate.py's run_full_chain()
        # used internally (explicit CIDRs from the form take priority,
        # falling back to config/scope.yaml) — now built here since
        # run_target() takes an already-built executor rather than
        # constructing its own, so it isn't tied to one particular
        # scope-loading convention.
        if scope_cidrs:
            scope_manager = ScopeManager(cidrs=scope_cidrs)
        else:
            scope_manager = ScopeManager("config/scope.yaml")
        executor = RealScopedExecutor(
            is_in_scope=scope_manager.is_in_scope,
            log_scope_check=scope_manager.log_scope_check,
        )
        chain = run_target(
            target,
            executor=executor,
            scope=scope_manager.authorized_networks,
            crawler=crawler,
        )
    except Exception as exc:  # noqa: BLE001 — show it in the UI, not a stack trace
        return render_template(
            "index.html", error=f"Could not start scan: {exc}", katana_installed=katana_installed
        )

    return render_template("results.html", chain=chain, target=target)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5500, debug=True)
