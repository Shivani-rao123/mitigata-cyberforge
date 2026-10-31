"""
tests/core/test_queue.py

Unit tests for core/queue.py's JobQueue: dedup by (agent, target) for
the lifetime of the queue, atomic batch dequeue (what lets the
orchestrator run a whole wave concurrently), and basic thread-safety
under concurrent enqueue() calls.
"""

import threading

from common.contracts import Job
from core.queue import JobQueue


def _job(agent="web", target="1.2.3.4:80", job_id="j1"):
    return Job(job_id=job_id, agent=agent, target=target)


def test_enqueue_then_len_reflects_pending_count():
    queue = JobQueue()
    assert len(queue) == 0

    queue.enqueue(_job(job_id="j1"))
    queue.enqueue(_job(job_id="j2", target="1.2.3.4:443"))

    assert len(queue) == 2


def test_dequeue_all_pops_everything_and_clears_the_queue():
    queue = JobQueue()
    queue.enqueue(_job(job_id="j1"))
    queue.enqueue(_job(job_id="j2", target="1.2.3.4:443"))

    wave = queue.dequeue_all()

    assert [j.job_id for j in wave] == ["j1", "j2"]
    assert len(queue) == 0
    assert queue.dequeue_all() == []


def test_duplicate_agent_target_pair_is_enqueued_only_once():
    queue = JobQueue()
    added_first = queue.enqueue(_job(job_id="j1", agent="binary", target="http://x/a.bin"))
    added_second = queue.enqueue(_job(job_id="j2", agent="binary", target="http://x/a.bin"))

    assert added_first is True
    assert added_second is False
    assert len(queue) == 1


def test_dedup_persists_after_the_job_has_already_been_dequeued():
    """A job that already ran and was popped off the queue must not be
    re-enqueued just because it's no longer 'pending' — two different
    stages discovering the same follow-up must still only run it once."""
    queue = JobQueue()
    queue.enqueue(_job(job_id="j1", agent="binary", target="http://x/a.bin"))
    queue.dequeue_all()  # simulate it having run

    added_again = queue.enqueue(_job(job_id="j2", agent="binary", target="http://x/a.bin"))

    assert added_again is False
    assert len(queue) == 0


def test_same_target_different_agent_is_not_deduped():
    queue = JobQueue()
    queue.enqueue(_job(job_id="j1", agent="web", target="1.2.3.4"))
    queue.enqueue(_job(job_id="j2", agent="network", target="1.2.3.4"))

    assert len(queue) == 2


def test_concurrent_enqueues_of_the_same_job_only_admit_one():
    queue = JobQueue()
    results: list[bool] = []
    lock = threading.Lock()

    def worker(i: int) -> None:
        added = queue.enqueue(_job(job_id=f"j{i}", agent="binary", target="http://x/same.bin"))
        with lock:
            results.append(added)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert results.count(True) == 1
    assert len(queue) == 1
