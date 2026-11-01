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
| B-4 Add a tool/agent via config, not code | ✅ |

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

## How it works

- `agents/network/agent.py`, `agents/web/agent.py`, `agents/binary/agent.py`
  — the three surface agents (FR-1/FR-2/FR-3).
- `core/orchestrator.py` — FR-4's coordinator: starts one network job and
  runs whatever follow-up jobs each stage's own findings produce (no
  hardcoded sequence), concurrently within each wave.
- `verification/verifier.py` — FR-6: actively re-probes a flagged
  default-credentials finding before calling it confirmed.
- `reporting/ptes.py` / `reporting/report_generator.py` — FR-5/FR-7: maps
  each finding to a PTES phase and builds the Attack Path narrative.
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