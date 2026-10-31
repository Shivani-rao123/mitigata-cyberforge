"""
core/db.py

FR-7 (part 1/3 — the persistence piece; see reporting/report_generator.py
and api/routes.py for the other two). SQLite-backed storage for
store/schema.sql's tables. Per that schema file's own header comment,
this is the ONLY module that opens a connection or writes SQL — agents
never touch the DB directly, and nothing else in the project should
either; a caller (core/pipeline.py, api/routes.py) goes through the
`Database` class below.

Deliberately plain sqlite3 (stdlib, zero new dependency) rather than an
ORM — the schema is small and fixed, and a thin wrapper keeps every
query visible in one file instead of spread across model classes.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from common.contracts import Job

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "store" / "schema.sql"
DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "store" / "cart.db"


def _row_to_dict(row: sqlite3.Row | None) -> dict | None:
    return dict(row) if row is not None else None


class Database:
    """Thin wrapper around one sqlite3 connection. `db_path=":memory:"` is
    the normal choice for tests — a fresh, empty, isolated DB with the
    schema applied, gone when the connection closes."""

    def __init__(self, db_path: str | Path = DEFAULT_DB_PATH) -> None:
        self.db_path = str(db_path)
        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._init_schema()

    def _init_schema(self) -> None:
        with open(SCHEMA_PATH) as f:
            self._conn.executescript(f.read())
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    @contextmanager
    def _cursor(self):
        cur = self._conn.cursor()
        try:
            yield cur
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise
        finally:
            cur.close()

    # ------------------------------------------------------------------
    # targets
    # ------------------------------------------------------------------

    def insert_target(self, cidr_or_host: str) -> int:
        with self._cursor() as cur:
            cur.execute("INSERT INTO targets (cidr_or_host) VALUES (?)", (cidr_or_host,))
            return cur.lastrowid

    def list_targets(self) -> list[dict]:
        rows = self._conn.execute("SELECT * FROM targets ORDER BY id").fetchall()
        return [dict(r) for r in rows]

    def get_target(self, target_id: int) -> dict | None:
        row = self._conn.execute("SELECT * FROM targets WHERE id = ?", (target_id,)).fetchone()
        return _row_to_dict(row)

    # ------------------------------------------------------------------
    # hosts / services
    # ------------------------------------------------------------------

    def get_or_create_host(self, ip: str, hostname: str | None = None) -> int:
        """One host row per distinct IP — a second discovery of the same
        IP (e.g. re-scanning, or two jobs that both touch it) reuses the
        existing row rather than duplicating it. Updates hostname if a
        later call supplies one and the row didn't have one yet."""
        row = self._conn.execute("SELECT id, hostname FROM hosts WHERE ip = ?", (ip,)).fetchone()
        if row is not None:
            if hostname and not row["hostname"]:
                with self._cursor() as cur:
                    cur.execute("UPDATE hosts SET hostname = ? WHERE id = ?", (hostname, row["id"]))
            return row["id"]
        with self._cursor() as cur:
            cur.execute("INSERT INTO hosts (ip, hostname) VALUES (?, ?)", (ip, hostname))
            return cur.lastrowid

    def get_host(self, host_id: int) -> dict | None:
        row = self._conn.execute("SELECT * FROM hosts WHERE id = ?", (host_id,)).fetchone()
        return _row_to_dict(row)

    def get_host_by_ip(self, ip: str) -> dict | None:
        row = self._conn.execute("SELECT * FROM hosts WHERE ip = ?", (ip,)).fetchone()
        return _row_to_dict(row)

    def list_hosts(self) -> list[dict]:
        rows = self._conn.execute("SELECT * FROM hosts ORDER BY id").fetchall()
        return [dict(r) for r in rows]

    def get_or_create_service(
        self, host_id: int, port: int, protocol: str, service_name: str | None, version: str | None = None
    ) -> int:
        """One service row per (host_id, port, protocol) — re-discovering
        the same open port (e.g. a re-scan) updates service_name/version
        in place rather than duplicating the row."""
        row = self._conn.execute(
            "SELECT id FROM services WHERE host_id = ? AND port = ? AND protocol = ?",
            (host_id, port, protocol),
        ).fetchone()
        if row is not None:
            with self._cursor() as cur:
                cur.execute(
                    "UPDATE services SET service_name = ?, version = ? WHERE id = ?",
                    (service_name, version, row["id"]),
                )
            return row["id"]
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO services (host_id, port, protocol, service_name, version) "
                "VALUES (?, ?, ?, ?, ?)",
                (host_id, port, protocol, service_name, version),
            )
            return cur.lastrowid

    def list_services_for_host(self, host_id: int) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM services WHERE host_id = ? ORDER BY port", (host_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # findings
    # ------------------------------------------------------------------

    def insert_finding(
        self,
        host_id: int,
        agent: str,
        finding_type: str,
        description: str,
        evidence_summary: str | None = None,
        evidence_raw_ref: str | None = None,
        service_id: int | None = None,
        status: str = "flagged",
        ptes_phase: str | None = None,
    ) -> int:
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO findings "
                "(host_id, service_id, agent, finding_type, description, evidence_summary, "
                "evidence_raw_ref, status, ptes_phase) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    host_id,
                    service_id,
                    agent,
                    finding_type,
                    description,
                    evidence_summary,
                    evidence_raw_ref,
                    status,
                    ptes_phase,
                ),
            )
            return cur.lastrowid

    def update_finding_status(
        self, finding_id: int, status: str, evidence_summary: str | None = None
    ) -> None:
        """Called after verification moves a finding from 'flagged' to
        'confirmed' or 'false_positive'. `evidence_summary`, when given,
        replaces the stored evidence with what the verification probe
        itself observed (e.g. the actual login POST's response) —
        stronger proof than the original discovery-time evidence."""
        with self._cursor() as cur:
            if evidence_summary is not None:
                cur.execute(
                    "UPDATE findings SET status = ?, evidence_summary = ? WHERE id = ?",
                    (status, evidence_summary, finding_id),
                )
            else:
                cur.execute("UPDATE findings SET status = ? WHERE id = ?", (status, finding_id))

    def set_finding_ptes_phase(self, finding_id: int, ptes_phase: str | None) -> None:
        with self._cursor() as cur:
            cur.execute("UPDATE findings SET ptes_phase = ? WHERE id = ?", (ptes_phase, finding_id))

    def get_finding(self, finding_id: int) -> dict | None:
        row = self._conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
        return _row_to_dict(row)

    def list_findings_for_host(self, host_id: int) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM findings WHERE host_id = ? ORDER BY id", (host_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    def list_all_findings(self) -> list[dict]:
        rows = self._conn.execute("SELECT * FROM findings ORDER BY id").fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # attack_edges
    # ------------------------------------------------------------------

    def insert_attack_edge(self, from_finding_id: int, to_finding_id: int, note: str | None = None) -> int:
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO attack_edges (from_finding_id, to_finding_id, note) VALUES (?, ?, ?)",
                (from_finding_id, to_finding_id, note),
            )
            return cur.lastrowid

    def list_attack_edges(self) -> list[dict]:
        rows = self._conn.execute("SELECT * FROM attack_edges ORDER BY id").fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # pending_jobs
    # ------------------------------------------------------------------

    def insert_pending_job(
        self, job: Job, host_id: int | None = None, service_id: int | None = None
    ) -> int:
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO pending_jobs "
                "(job_id, agent, target, allowed_ports, context, status, host_id, service_id) "
                "VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)",
                (
                    job.job_id,
                    job.agent,
                    job.target,
                    json.dumps(job.allowed_ports) if job.allowed_ports is not None else None,
                    json.dumps(job.context),
                    host_id,
                    service_id,
                ),
            )
            return cur.lastrowid

    def update_job_status(self, job_id: str, status: str) -> None:
        with self._cursor() as cur:
            cur.execute("UPDATE pending_jobs SET status = ? WHERE job_id = ?", (status, job_id))

    def get_job(self, job_id: str) -> dict | None:
        row = self._conn.execute("SELECT * FROM pending_jobs WHERE job_id = ?", (job_id,)).fetchone()
        return _row_to_dict(row)

    def list_jobs(self, status: str | None = None) -> list[dict]:
        if status is not None:
            rows = self._conn.execute(
                "SELECT * FROM pending_jobs WHERE status = ? ORDER BY id", (status,)
            ).fetchall()
        else:
            rows = self._conn.execute("SELECT * FROM pending_jobs ORDER BY id").fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # scope_log
    # ------------------------------------------------------------------

    def insert_scope_log(self, target: str, in_scope: bool) -> int:
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO scope_log (target, in_scope) VALUES (?, ?)", (target, in_scope)
            )
            return cur.lastrowid

    def list_scope_log(self) -> list[dict]:
        rows = self._conn.execute("SELECT * FROM scope_log ORDER BY id").fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # cross-table convenience queries
    # ------------------------------------------------------------------

    def get_findings_for_target(self, target_id: int) -> list[dict]:
        """Findings for every host that falls within this target's
        cidr_or_host. The schema doesn't FK hosts to targets directly
        (a target is just the original input string — an IP, a hostname,
        or a CIDR range — while a host row is whatever was actually
        discovered), so this resolves the relationship the same way
        scope/manager.py decides "is this IP in scope": CIDR containment,
        computed here rather than stored, so it stays correct even if a
        target's recorded string doesn't exactly match a host's IP
        (e.g. target "10.10.10.0/24", host "10.10.10.5")."""
        import ipaddress

        target = self.get_target(target_id)
        if target is None:
            return []

        try:
            network = ipaddress.ip_network(target["cidr_or_host"], strict=False)
        except ValueError:
            # target was a hostname, not an IP/CIDR — fall back to an
            # exact string match against host ip/hostname.
            rows = self._conn.execute(
                "SELECT f.* FROM findings f JOIN hosts h ON f.host_id = h.id "
                "WHERE h.ip = ? OR h.hostname = ? ORDER BY f.id",
                (target["cidr_or_host"], target["cidr_or_host"]),
            ).fetchall()
            return [dict(r) for r in rows]

        matching_host_ids = [
            h["id"]
            for h in self.list_hosts()
            if self._ip_in_network(h["ip"], network)
        ]
        if not matching_host_ids:
            return []
        placeholders = ",".join("?" * len(matching_host_ids))
        rows = self._conn.execute(
            f"SELECT * FROM findings WHERE host_id IN ({placeholders}) ORDER BY id",
            matching_host_ids,
        ).fetchall()
        return [dict(r) for r in rows]

    @staticmethod
    def _ip_in_network(ip: str, network) -> bool:
        import ipaddress

        try:
            return ipaddress.ip_address(ip) in network
        except ValueError:
            return False
