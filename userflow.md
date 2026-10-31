# CART — Worked Example: One Full Run

One concrete example tracing a single input through the whole system, start
to finish. Useful as a reference for what each module should actually
produce, and as the demo script for judges.

---

## The user's one input

```bash
python main.py --scope config/scope.yaml
```

`config/scope.yaml`:
```yaml
targets:
  - 10.10.10.0/24
allowed_ports: [22, 80, 443, 8080]
```

That's the only thing a human types. Everything after this is automatic.

---

## Step 1 — `main.py` seeds the first job

```json
{"job_id": "job-001", "agent": "network", "target": "10.10.10.0/24", "allowed_ports": [22, 80, 443, 8080]}
```
This row lands in `pending_jobs`.

---

## Step 2 — Network agent claims it, scans through the Scoped Executor

It finds one live host with one open port. It checks scope first
(`10.10.10.5` is inside `10.10.10.0/24` → allowed), then submits:

```json
{
  "job_id": "job-001",
  "status": "completed",
  "hosts": [
    {"ip": "10.10.10.5", "services": [{"port": 80, "protocol": "tcp", "service": "http"}]}
  ],
  "findings": [
    {
      "finding_type": "open_port",
      "description": "Port 80/tcp open",
      "host": "10.10.10.5",
      "service_port": 80,
      "evidence": {"kind": "nmap_output", "summary": "80/tcp open http"}
    }
  ],
  "follow_up_jobs": [
    {"agent": "web", "target": "10.10.10.5:80", "context": {"host_id": 1, "service_id": 1}}
  ]
}
```

---

## Step 3 — Core saves this and auto-creates the next job

No human does this — the orchestrator sees `follow_up_jobs` and enqueues:

```json
{"job_id": "job-002", "agent": "web", "target": "10.10.10.5:80"}
```

This is the "agents coordinate, work isn't repeated" requirement, happening live.

---

## Step 4 — Web agent claims job-002, crawls through the Scoped Executor

It finds `/admin` with no auth and a login form. It submits:

```json
{
  "job_id": "job-002",
  "status": "completed",
  "findings": [
    {
      "finding_type": "default_creds_found",
      "description": "/admin login form, no rate limiting",
      "host": "10.10.10.5",
      "service_port": 80,
      "evidence": {"kind": "http_response", "summary": "GET /admin -> 200, login form present"}
    }
  ]
}
```

Status is still `flagged` — a login page existing is not proof of a weakness.

---

## Step 5 — Verification engine actually tries it

It attempts `admin / admin` against the login form. It works:

```json
{
  "finding_id": 7,
  "status": "confirmed",
  "evidence": {"kind": "http_response", "summary": "POST /admin/login with admin:admin -> 302 redirect to /dashboard"}
}
```

Only now does this finding count toward the "Verified" score — before this
step it was just a flag, not a proven weakness.

---

## Step 6 — PTES tagging (automatic, from the lookup table)

| Finding type | PTES phase |
|---|---|
| `open_port` | Intelligence Gathering |
| `default_creds_found` (confirmed) | Exploitation |

---

## Step 7 — Report generator builds the attack path

```
Attack Path:
1. [Intelligence Gathering] Port 80/tcp open on 10.10.10.5
2. [Exploitation] Default credentials (admin/admin) confirmed on /admin,
   granting dashboard access
```

---

## Step 8 — What the user (or a judge) actually sees

Either the generated report file, or:

```
GET /targets/1/findings
→ [
    {
      "finding_type": "default_creds_found",
      "status": "confirmed",
      "ptes_phase": "Exploitation",
      "evidence": "POST /admin/login with admin:admin -> 302 redirect to /dashboard"
    }
  ]
```

---

## Summary

The user's only input is the scope file and one start command. Everything
from "host 10.10.10.5 exists" to "here's a confirmed, PTES-tagged attack
path" happens with no further human input — which is exactly what the
Autonomy scoring target measures.