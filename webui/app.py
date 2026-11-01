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

from agents.web.agent import _to_base_url
from core.orchestrator import run_target
from core.scoped_executor import RealScopedExecutor
from scope.manager import ScopeManager
from verification.authenticated_exploration import collect_candidate_endpoints
from verification.credential_chaining import try_credentials_against_conventional_paths
from verification.verifier import verify_finding

app = Flask(__name__)

# How seriously each finding type should read in the UI. Anything not
# listed here defaults to "medium" — see the `severity` Jinja filter below.
FINDING_SEVERITY = {
    "hardcoded_secret": "high",
    "unsafe_function_call": "high",
    "default_creds_found": "high",
    "credential_pair_found": "high",  # a real username+password pair found hardcoded in a binary
    "reflected_input": "high",
    "js_secret_found": "high",  # a secret hardcoded in a JS bundle is just as real as one in a binary
    "secret_in_file_found": "high",  # a secret in a crawled plain-text/config/log file (not JS) —
    # e.g. an exposed handover note, .env, or backup config found via a crawled link
    "ctf_flag_found": "high",  # the engagement's own success marker — always worth top billing
    "sensitive_endpoint_found": "medium",
    "directory_listing_enabled": "medium",
    "redirect_followed": "info",  # operational note: the crawl followed a redirect to a new host/path
    "missing_security_header": "low",
    "js_endpoint_found": "low",  # attack-surface disclosure, not itself a proven weakness
    "open_port": "info",
    "crawler_fallback": "info",  # operational note (katana unavailable this run), not a finding
    "duplicate_binary_skipped": "info",  # operational note — same binary already analyzed this run
}


@app.template_filter("severity")
def severity_filter(finding_type: str) -> str:
    return FINDING_SEVERITY.get(finding_type, "medium")


# Display-only ordering — doesn't change what's found or how, just how
# findings are sorted within the "Issues" card: real weaknesses first,
# high->low->info by severity (stable: same-severity findings keep
# their original relative order).
_SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2, "info": 3}

# categorize_chain() below buckets every finding, across every stage,
# into one of four cards instead of the old per-stage flat list —
# direct response to live feedback that "web part network open port
# live hosts and services in scope endpoint flag common issue is
# messed into one place": each of those is now its own sidebar entry
# in results.html, built from these three buckets (anything not in
# HOST_FINDING_TYPES/ENDPOINT_FINDING_TYPES/OPERATIONAL_NOTE_TYPES
# falls into "issues", the catch-all for "common issue").

# Discovered-port/host information — shown in the "Hosts & Open Ports"
# card together with the raw host/service list from stage.result.hosts,
# not buried in a collapsed operational-notes section like before.
HOST_FINDING_TYPES = {"open_port"}

# Attack-surface disclosure — things the web agent found exist, which
# aren't themselves a proven weakness (that's what "Issues" is for) but
# are exactly the "endpoint flag" category asked for separately.
ENDPOINT_FINDING_TYPES = {"sensitive_endpoint_found", "js_endpoint_found", "directory_listing_enabled"}

# Purely operational commentary about how the scan/crawl itself
# behaved (a redirect was followed, a preferred tool fell back to a
# narrower one) rather than a fact about the target's attack surface —
# collapsed into its own closed-by-default card. A real TinyFileManager
# -style target can produce a dozen redirect_followed notes for every
# one finding that actually matters; without this split, those notes
# bury everything else.
OPERATIONAL_NOTE_TYPES = {"redirect_followed", "crawler_fallback", "duplicate_binary_skipped"}


def _apply_credential_chaining(chain, executor) -> None:
    """Dashboard-only counterpart to core/pipeline.py's own pass 2 /
    pass 2.5 (see that module's docstring for the full rationale) —
    this is the SAME gap a real lab run surfaced: a scan run through
    this dashboard has no verification step at all by design (see this
    module's own docstring), so a binary's credential_pair_found
    finding never got tried against anything here, even after
    core/pipeline.py learned to do it. Rather than bolting a full
    verification pass onto every finding type (a much bigger behavior
    change to a route that intentionally stays a thin, DB-less demo
    layer), this only does the one thing the user is actually asking
    for: take whatever credential(s) a binary stage found and try
    them, in place, against (a) any default_creds_found login form the
    web agent already crawled, then (b) if that didn't confirm
    anything, a short list of conventional login paths. Mutates
    `chain.stages[*].result.findings` in place — FindingOut/Evidence
    are plain pydantic models, not frozen, so updating evidence.summary
    or appending a new FindingOut is safe and categorize_chain() below
    picks either up exactly like any other finding."""
    extra_credentials: list[tuple[str, str]] = []
    all_findings = []
    for stage in chain.stages:
        if stage.result is None:
            continue
        all_findings.extend(stage.result.findings)
        for finding in stage.result.findings:
            if finding.finding_type != "credential_pair_found" or not finding.evidence.raw_ref:
                continue
            username, _, password = finding.evidence.raw_ref.partition(":")
            if username and password:
                extra_credentials.append((username, password))

    if not extra_credentials:
        return

    # Every endpoint this scan discovered (sensitive_endpoint_found /
    # directory_listing_enabled) — once a login confirms below, each of
    # these gets re-fetched with the new session cookies too, not just
    # the site root. See verification/authenticated_exploration.py.
    discovered_endpoints = collect_candidate_endpoints(all_findings)

    any_default_creds_confirmed = False
    for stage in chain.stages:
        if stage.result is None:
            continue
        for finding in stage.result.findings:
            if finding.finding_type != "default_creds_found":
                continue
            verdict = verify_finding(
                {
                    "finding_type": finding.finding_type,
                    "description": finding.description,
                    "evidence_summary": finding.evidence.summary,
                },
                executor,
                extra_credentials=extra_credentials,
                discovered_endpoints=discovered_endpoints,
            )
            if verdict["status"] == "confirmed":
                any_default_creds_confirmed = True
                finding.evidence.summary = verdict["evidence_summary"]

    if any_default_creds_confirmed:
        return

    for stage in chain.stages:
        if stage.agent != "web" or stage.result is None:
            continue
        base_url = _to_base_url(stage.target)
        new_findings = try_credentials_against_conventional_paths(
            executor, base_url, extra_credentials, discovered_endpoints=discovered_endpoints
        )
        if new_findings:
            stage.result.findings.extend(new_findings)
            break  # one confirmed login across every host checked is enough


def categorize_chain(chain) -> dict:
    """Buckets every finding across every stage of `chain` into the
    four results.html cards, plus the raw discovered host/service list
    (only network stages populate JobResult.hosts). Each bucketed entry
    is {"finding": ..., "agent": ..., "target": ...} — the agent/target
    are kept per-finding (not per-card) since a card now mixes findings
    from however many stages contributed to it."""
    live_hosts = []
    buckets: dict[str, list[dict]] = {"hosts": [], "endpoints": [], "issues": [], "operational": []}

    for stage in chain.stages:
        if not stage.result:
            continue
        live_hosts.extend(stage.result.hosts)
        for finding in stage.result.findings:
            entry = {"finding": finding, "agent": stage.agent, "target": stage.target}
            if finding.finding_type in OPERATIONAL_NOTE_TYPES:
                buckets["operational"].append(entry)
            elif finding.finding_type in HOST_FINDING_TYPES:
                buckets["hosts"].append(entry)
            elif finding.finding_type in ENDPOINT_FINDING_TYPES:
                buckets["endpoints"].append(entry)
            else:
                buckets["issues"].append(entry)

    buckets["issues"].sort(
        key=lambda e: _SEVERITY_RANK.get(FINDING_SEVERITY.get(e["finding"].finding_type, "medium"), 1)
    )

    return {"live_hosts": live_hosts, **buckets}


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


# Crawler mode is no longer a user-facing choice (see scan() below) — per
# direct user feedback ("remove that katana part in ui let it work in
# background"), the dashboard just always requests "auto" and the web
# agent decides for itself whether katana is actually usable this run
# (ToolEngine.is_installed() under the hood), falling back to the native
# crawler silently if not — you'll see that as a crawler_fallback finding
# if/when it happens, not as UI chrome about whether a binary is on PATH.
# VALID_CRAWLER_MODES / the crawler param itself are kept (not removed)
# so main.py, run_pipeline.py, and any future API caller can still pick
# "requests" or "katana" explicitly — only the dashboard form stopped
# exposing the choice.
VALID_CRAWLER_MODES = ("auto", "requests", "katana")


@app.route("/scan", methods=["POST"])
def scan():
    target = request.form.get("target", "").strip()
    scope_raw = request.form.get("scope", "").strip()
    crawler = request.form.get("crawler", "auto").strip() or "auto"

    if not target:
        return render_template("index.html", error="Target is required.")

    if crawler not in VALID_CRAWLER_MODES:
        return render_template("index.html", error=f"Unknown crawler mode: {crawler!r}")

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
        return render_template("index.html", error=f"Could not start scan: {exc}")

    _apply_credential_chaining(chain, executor)

    return render_template("results.html", chain=chain, target=target, categories=categorize_chain(chain))


if __name__ == "__main__":
    # 0.0.0.0, not 127.0.0.1: inside a container, binding to loopback
    # only would make the dashboard unreachable from outside the
    # container even with a published port (see Dockerfile/
    # docker-compose.yml) — harmless to bind this way when run natively
    # too, it just additionally accepts non-loopback connections on
    # whatever interfaces this machine has.
    app.run(host="0.0.0.0", port=5500, debug=True)
