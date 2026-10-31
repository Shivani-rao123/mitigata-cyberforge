"""
core/queue.py

FR-4: the job queue half of multi-agent coordination. A minimal,
in-memory, thread-safe job queue — core/orchestrator.py enqueues a job
whenever an agent's own follow_up_jobs ask for one (network finds a web
port -> enqueues a web job; the web agent finds a downloadable binary ->
enqueues a binary job), and dequeues a whole "wave" of ready jobs at once
so the orchestrator can run them concurrently instead of one at a time.

Dedup is the other half of what a real job queue needs to do here: the
same (agent, target) pair showing up twice (e.g. two different pages
both linking the same binary) must only ever run once, or every
duplicate finding/follow-up gets duplicated right along with it.

Deliberately NOT persistent/DB-backed yet — every other piece
(core/orchestrator.py, and anything built on top of it) only talks to
this through enqueue()/dequeue_all()/__len__, so swapping this module's
internals for a table-backed queue later (once the project's real DB
exists) won't ripple out to any of them.
"""

from __future__ import annotations

import threading
from collections import deque

from common.contracts import Job


class JobQueue:
    """Thread-safe FIFO queue of Job objects, deduped by (agent, target)
    for the lifetime of this queue instance — not just "currently
    pending": a job that already ran (and was popped) is never
    re-enqueued either, so a follow-up job discovered twice by two
    different stages still only runs once."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._pending: deque[Job] = deque()
        self._seen: set[tuple[str, str]] = set()

    def enqueue(self, job: Job) -> bool:
        """Adds `job` unless its (agent, target) pair has already been
        enqueued (ever). Returns whether it was actually added — a
        caller that wants to know about a duplicate (e.g. for a log
        line) can check the return value instead of needing to."""
        key = (job.agent, job.target)
        with self._lock:
            if key in self._seen:
                return False
            self._seen.add(key)
            self._pending.append(job)
            return True

    def dequeue_all(self) -> list[Job]:
        """Pops and returns every job currently pending, as one
        atomic batch — this is what lets core/orchestrator.py run a
        whole "wave" of independent, ready jobs concurrently instead of
        draining the queue one job at a time."""
        with self._lock:
            jobs = list(self._pending)
            self._pending.clear()
            return jobs

    def __len__(self) -> int:
        with self._lock:
            return len(self._pending)
