-- store/schema.sql
-- CART shared database schema. Single source of truth for every table.
-- Only core/db.py reads or writes these tables directly — agents never
-- touch this schema or the DB connection themselves.

CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY,
    cidr_or_host TEXT NOT NULL,
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY,
    ip TEXT NOT NULL,
    hostname TEXT,
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY,
    host_id INTEGER NOT NULL REFERENCES hosts(id),
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL,       -- 'tcp' | 'udp'
    service_name TEXT,            -- http, ssh, ftp...
    version TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY,
    host_id INTEGER NOT NULL REFERENCES hosts(id),
    service_id INTEGER REFERENCES services(id),
    agent TEXT NOT NULL,              -- 'network' | 'web' | 'binary'
    finding_type TEXT NOT NULL,       -- open_port, default_creds_found, reflected_input, ...
    description TEXT NOT NULL,
    evidence_summary TEXT,
    evidence_raw_ref TEXT,
    status TEXT NOT NULL DEFAULT 'flagged',  -- flagged | confirmed | false_positive
    ptes_phase TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS attack_edges (
    id INTEGER PRIMARY KEY,
    from_finding_id INTEGER NOT NULL REFERENCES findings(id),
    to_finding_id INTEGER NOT NULL REFERENCES findings(id),
    note TEXT
);

CREATE TABLE IF NOT EXISTS pending_jobs (
    id INTEGER PRIMARY KEY,
    job_id TEXT NOT NULL UNIQUE,     -- matches Job.job_id from common/contracts.py
    agent TEXT NOT NULL,             -- which agent should pick this up
    target TEXT NOT NULL,
    allowed_ports TEXT,              -- JSON-encoded list[int], nullable
    context TEXT,                    -- JSON-encoded dict
    status TEXT NOT NULL DEFAULT 'pending',  -- pending | in_progress | done
    host_id INTEGER REFERENCES hosts(id),
    service_id INTEGER REFERENCES services(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scope_log (
    id INTEGER PRIMARY KEY,
    target TEXT NOT NULL,
    in_scope BOOLEAN NOT NULL,
    checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_pending_jobs_status_agent ON pending_jobs(status, agent);
CREATE INDEX IF NOT EXISTS idx_services_host ON services(host_id);