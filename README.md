# CART — Autonomous Multi-Agent Penetration Testing Engine

CART points a set of coordinating agents at a target network, discovers its
attack surface across network, web, and binary surfaces, verifies the
weaknesses it finds (not just flags them), tags each step with its PTES
phase, and produces a report with the attack path — autonomously, from one
command.

Built for the Mitigata hackathon, Problem 04 ("Security Agents").

## What it covers

| Requirement | Status |
|---|---|
| FR-1 Network discovery (hosts, open ports, services) | ✅ |
| FR-2 Web surface crawl (endpoints, forms, common issues) | ✅ |
| FR-3 Binary analysis (hardcoded secrets, unsafe functions) | ✅ |
| FR-4 Multi-agent coordination (agents hand off findings) | ✅ |
| FR-5 PTES phase tagging | ✅ |
| FR-6 Verification (confirm, don't just flag) | ✅ |
| FR-7 Report + API + README | ✅ |
| B-1 Capture planted lab flags | ✅ |
| B-2 Chain findings into a full path to a protected "crown jewel" host | ✅ |
| B-3 Suggest a fix for each finding in plain English | ✅ |
| B-4 Add a tool/agent via config, not code | ✅ |
| B-5 Live dashboard showing each agent working | ⚠️ partial — the dashboard shows every agent's findings per run, not a live in-progress feed while a stage is still running |

## Prerequisites

- Python 3.10+
- `nmap` — network discovery (FR-1)
- `binutils` (`strings`, `nm`) — binary analysis (FR-3)
- Optional, both gracefully degrade if missing:
  - `gitleaks` — preferred secret scanner for the binary agent; falls back to
    a built-in regex scan if absent.
  - `katana` — JS-aware web crawler; falls back to a native requests-based
    crawler if absent (you'll see a `crawler_fallback` note when it does).

### Installing the system tools (Debian/Ubuntu)

```bash
sudo apt install nmap binutils gitleaks
```

For `katana`:

```bash
go install github.com/projectdiscovery/katana/cmd/katana@latest
# then make sure $HOME/go/bin is on your PATH (add to ~/.bashrc / ~/.profile):
export PATH=$PATH:$HOME/go/bin
```

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Configuring scope

**Never scan anything you don't have explicit authorization for.**
`scope/manager.py` enforces this on every network call this project makes —
it's not optional and can't be bypassed by any input.

Edit `config/scope.yaml` with the IP/CIDR ranges you're authorized to probe
(the organizers give you this at kickoff):

```yaml
targets:
  - 10.10.10.0/24
allowed_ports: [22, 80, 443, 8080]
```

Or pass scope per-run instead of editing the file, with `--scope` (see below).

## Running it

### One command, full autonomous run (recommended)

Discovers → persists → verifies → PTES-tags → links the attack path → prints
the report, for everything the target's own discoveries call for (network
scan, then whatever web/binary follow-ups it produces), with no further
input:

```bash
python run_pipeline.py --target 10.10.10.5 --scope 10.10.10.0/24
```

Useful flags:
- `--ports 22,80,443,8080` — restrict the initial network scan to these
  ports. This is the main lever for a slow scan against a CIDR range (e.g. a
  `/24`) — omit it and nmap uses its own ~1000-port default set.
- `--crawler auto|requests|katana` — which web crawler to use (default
  `auto`: try katana, fall back to the native crawler if it's unavailable).
- `--db-path path/to.db` — where to persist (defaults to `store/cart.db`).

### Dashboard (simple web UI)

```bash
python webui/app.py
```

Open `http://127.0.0.1:5500`, enter a target and scope, click Run.

### Read-only REST API (FR-7)

```bash
python -m api.app
```

```
GET /targets
GET /targets/<id>/findings
GET /targets/<id>/report      # the Attack Path narrative, plain text
```

### Run a single agent in isolation (debugging)

```bash
python main.py --agent network --target 10.10.10.5 --scope 10.10.10.0/24
python main.py --agent web --target 10.10.10.5:80 --scope 10.10.10.0/24
python main.py --agent binary --target fixtures/vulnerable_binary/vuln
```

## Docker (optional, one-command setup)

```bash
docker compose up --build
```

Opens the same dashboard at `http://127.0.0.1:5500`. Reuse the same image
for anything else this project does:

```bash
docker compose run --rm cart python run_pipeline.py --target 10.10.10.5 --scope 10.10.10.0/24
```

**Note:** the Docker image intentionally ships without `katana`/`gitleaks`
(no reliable apt package for either on the base image's Debian release) —
both agents already fall back gracefully, so this costs you narrower (not
missing) coverage of those two checks. Install them inside the container
yourself if you want the fuller path.

**Networking note:** default bridge networking works for scanning anything
on the same LAN the Docker host is on. If your target network is only
reachable through a VPN client running on the *host* machine, bridge
networking won't see that traffic. On Linux, add `--network host` to the
`docker compose run` command instead. Docker Desktop on Mac/Windows has no
equivalent for that case — run `python run_pipeline.py` natively there
instead.

## Running tests

```bash
pytest -q
```

## Agents

Four agents, not three — the three required surfaces plus one custom agent
built on top of them once the engagement showed it was needed:

- **network** (`agents/network/agent.py`, FR-1) — nmap-based host/port/service
  discovery. Its findings seed every other agent's follow-up jobs.
- **web** (`agents/web/agent.py`, FR-2) — crawls (katana if available, else a
  native requests-based crawler), finds forms, endpoints, missing headers,
  reflected input, directory listings, planted flags, and JS-bundle secrets.
- **binary** (`agents/binary/agent.py`, FR-3) — inspects a given binary
  (`strings`/`nm`, gitleaks if available) for hardcoded secrets, unsafe C
  functions, and username/password pairs hardcoded together.
- **basic_auth** (`agents/basic_auth/agent.py`, custom, built during the
  engagement) — closes a gap the other three can't: an endpoint gated by an
  HTTP `Authorization` header (Basic/Bearer) rather than an HTML login form.
  No form to crawl, no POST to verify — this agent tries a credential
  discovered elsewhere in the run directly as a header against the endpoint
  that answered 401/403. This agent only ever runs when the LLM decision
  layer below explicitly approves it (fail-**closed** — see next section).

Agents hand off work through `core/orchestrator.py` (FR-4): a network job's
own findings produce the web/binary follow-up jobs, which can themselves
produce more follow-ups (e.g. a binary found during a web crawl gets handed
to the binary agent) — no hardcoded pipeline, agents run concurrently within
each wave.

## LLM-assisted decisions (optional, off by default)

Almost everything above is deterministic automation on purpose — in an
active-testing tool, "the model decided to probe something" is a liability,
not a feature. Two narrow decision points are a genuine exception, both
gated through `common/llm.py` and both off unless explicitly enabled:

1. **Follow-up job planner** (`agents/network/agent.py`,
   `agents/web/agent.py`) — once an agent's rule-based logic builds its
   candidate list of follow-up jobs, the LLM may filter/reorder *that exact
   list* down to the ones worth running next. It can never invent a job,
   target, or agent that isn't already in the candidate list (a tool-choice/
   menu pattern, not free-form generation). If the LLM is off, unavailable,
   or its call fails for any reason, this **fails open** — the original
   rule-based list runs unchanged, exactly as if the feature didn't exist.

2. **basic_auth invocation gate** (`agents/basic_auth/agent.py`) — whether to
   even attempt a discovered credential as a header-auth probe against a
   protected endpoint is a genuine LLM yes/no decision, not an automatic
   rule — there is no equivalent automated behavior for this project to fall
   back to. This **fails closed**: if the LLM is off, unavailable, or its
   call fails, nothing runs — the opposite default from #1, deliberately,
   since there's no pre-existing safe behavior to fall back to here.

To enable: copy `.env.example` to `.env`, set `OPENCODE_API_KEY` (or point
`CART_LLM_BASE_URL`/`OPENAI_API_KEY` at a real OpenAI-compatible endpoint
instead), and set `CART_LLM_FOLLOWUPS=true`. Both decision points share this
one flag and one client — there's no separate toggle per agent.

## Capturing flags (B-1)

`common/flag_patterns.py` holds the regex patterns for the lab's planted
CTF-style flags (`flag{...}` and friends). A flag gets checked for in three
places, each progressively closer to content that needs more effort to
reach:

1. **During the web crawl itself** — any page content the crawler fetches is
   scanned directly (`ctf_flag_found`).
2. **After a confirmed login** — `verification/authenticated_exploration.py`
   runs a real *authenticated crawl* (not just a re-fetch of the site root)
   from the login page's host, with the session attached to every request —
   so a flag that's only linked from a post-login page (a dashboard pointing
   at a "secrets" page, say) gets followed and checked too, not just
   whatever the pre-login crawler had already seen.
3. **A successful basic_auth header-auth probe** — the response body is
   scanned the same way before the finding is recorded.

## How it works

- `agents/network/agent.py`, `agents/web/agent.py`, `agents/binary/agent.py`,
  `agents/basic_auth/agent.py` — the four agents (see "Agents" above).
- `core/orchestrator.py` — FR-4's coordinator: starts one network job and
  runs whatever follow-up jobs each stage's own findings produce (no
  hardcoded sequence), concurrently within each wave.
- `common/llm.py` — the optional LLM decision layer (see above);
  `OPENAI_API_KEY`/`OPENCODE_API_KEY` and friends live in `.env`
  (`.env.example` has the template), never committed.
- `verification/verifier.py` — FR-6: actively re-probes a flagged
  default-credentials finding before calling it confirmed, trying any
  credential discovered elsewhere in the run first.
- `verification/credential_chaining.py` — the fallback for a credential whose
  login page was never crawled: tries it directly against a short list of
  conventional login paths.
- `verification/authenticated_exploration.py` — once a login succeeds,
  explores everything the session can now reach: every endpoint the run
  already knew about, plus a real authenticated crawl from the site root
  (see "Capturing flags" above).
- `reporting/ptes.py` / `reporting/report_generator.py` — FR-5/FR-7: maps
  each finding to a PTES phase and builds the Attack Path narrative.
- `reporting/crown_jewel.py` (B-2) — picks out the single strongest
  confirmed compromise in the attack path (a captured flag outranks a
  confirmed header-auth bypass outranks a confirmed default-credentials
  login) and names it as the run's "crown jewel."
- `reporting/remediation.py` (B-3) — a plain-English fix for every finding
  type, shown on the dashboard and appended to the text report.
- `scope/manager.py` — enforces authorized scope on every network call.
- `config/tools.yaml` — every external tool (nmap, strings, nm, katana,
  gitleaks) is declared here, not hardcoded — add a new tool (e.g. `naabu`)
  by adding an entry here plus a small parser, no agent code changes (B-4).

## Known limitations

- The web agent's reflected-input check only probes GET forms.
- Verification (FR-6) actively re-probes only `default_creds_found`; every
  other finding type is a deterministic, direct observation at discovery
  time (an open port, a regex match against fetched content, a response
  header) with nothing further to verify.
- The authenticated crawl (see "Capturing flags" above) uses the same
  same-host, bounded depth/page-limit crawl the pre-login web agent uses —
  it won't follow a link to a different host or go arbitrarily deep.
- The LLM decision layer (see above) is deliberately narrow: two bounded
  yes/no or filter-a-list decisions, not general autonomous planning. The
  rest of the system — discovery, credential chaining, verification, PTES
  tagging, crown-jewel/remediation reporting — is deterministic automation,
  by design, for a tool that's actively probing a target.