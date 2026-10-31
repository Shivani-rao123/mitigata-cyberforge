"""
common/contracts.py

Shared source of truth for CART. Every agent and every core module imports
from here instead of inventing its own shapes. Once this is committed to
main, only the core-platform owner should modify it, and only through a
reviewed PR both of you see.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Jobs: what the orchestrator hands to an agent, and what an agent hands back
# ---------------------------------------------------------------------------

class Job(BaseModel):
    """One unit of work assigned to a single agent."""

    job_id: str
    agent: Literal["network", "web", "binary"]
    target: str
    # Network jobs: ports to scan. Web jobs: usually None (full crawl).
    allowed_ports: list[int] | None = None
    # Free-form context passed through unchanged, e.g. {"host_id": 12, "service_id": 7}
    context: dict = Field(default_factory=dict)


class ServiceOut(BaseModel):
    """A single open service on a host, as reported by the network agent."""

    port: int
    protocol: Literal["tcp", "udp"]
    service: str  # e.g. "http", "ssh", "ftp"
    version: str | None = None


class HostOut(BaseModel):
    """A discovered host and its services."""

    ip: str
    hostname: str | None = None
    services: list[ServiceOut] = Field(default_factory=list)


class Evidence(BaseModel):
    """
    Proof behind a finding. Keep `summary` short and sanitized (truncated,
    redacted) — anything large or sensitive goes to the evidence store and
    is referenced by `raw_ref`, never embedded here directly.
    """

    kind: str  # e.g. "http_response", "nmap_output", "strings_match"
    summary: str
    raw_ref: str | None = None


class FindingOut(BaseModel):
    """A single weakness an agent is reporting, before verification."""

    finding_type: str  # e.g. "open_port", "default_creds_found", "reflected_input"
    description: str
    evidence: Evidence
    host: str | None = None
    service_port: int | None = None


class JobResult(BaseModel):
    """What an agent returns after processing a Job."""

    job_id: str
    status: Literal["completed", "failed", "partial"]
    hosts: list[HostOut] = Field(default_factory=list)
    findings: list[FindingOut] = Field(default_factory=list)
    # New jobs this result implies, e.g. an HTTP service found -> a web job.
    # Each dict matches the fields of Job minus job_id (core assigns that).
    follow_up_jobs: list[dict] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Findings as stored/returned by core (post-verification, includes DB fields)
# ---------------------------------------------------------------------------

FindingStatus = Literal["flagged", "confirmed", "false_positive"]


class StoredFinding(BaseModel):
    """A finding as it exists in the database, including verification state."""

    id: int
    host_id: int
    service_id: int | None = None
    agent: Literal["network", "web", "binary"]
    finding_type: str
    description: str
    evidence: Evidence
    status: FindingStatus = "flagged"
    ptes_phase: str | None = None