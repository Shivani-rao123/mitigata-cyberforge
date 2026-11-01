"""
common/llm.py

Optional LLM-in-the-loop decision layer for which follow-up jobs an
agent should queue next. Inserts judgment at the one real decision
point in this project — follow_up_jobs — and leaves everything else
(core/orchestrator.py, core/queue.py, core/scoped_executor.py, and
every tool-execution path: nmap/katana/gitleaks/strings) completely
untouched. core/orchestrator.py already just drains whatever
follow_up_jobs dicts show up in a JobResult; it has no idea whether a
human wrote the rule that produced them or a model did, so nothing
downstream needs to change for this to exist.

Off by default: CART_LLM_FOLLOWUPS must be set to "1"/"true"/"yes" in
the environment for this to do anything at all. Every agent's existing
rule-based follow-up logic runs exactly as it always has — unchanged,
untouched, still what every test and every demo run exercises — unless
this is explicitly turned on. That's deliberate: the rule-based path is
tested and debugged; this is a bonus layer on top of it, not a
replacement path with its own parallel contract.

Deliberately NOT free-write autonomy. This is a tool-choice/menu
constraint: the caller always builds the SAME rule-based candidate
list it always would have (e.g. "every open web service", "every
binary link found while crawling"), and the model is only ever asked
to pick a subset of THAT list and put it in order — it can skip a
candidate it judges low-value, but it can never invent a job, a
target, or a context field that wasn't already in the menu. For a
security tool specifically, "the model decided to probe something" is
a liability, not a feature — every job that ever runs still has to
trace back to a rule-based candidate a human wrote and a test covers.

choose_follow_ups() returns None on ANY failure — no API key, the
`openai` package not installed, a network/timeout error, a
response that isn't valid JSON, or a response naming an index outside
the candidate menu. Callers MUST treat None as "use the rule-based
candidates unchanged", never as "run nothing" — a flaky or misconfigured
LLM call should degrade this feature back to its own off-state, not
degrade the scan itself.

Reads OPENAI_API_KEY (and the two CART_LLM_* settings below) from a
.env file in the project root if one exists (via python-dotenv) —
see .env.example for the template. A real .env is gitignored; nothing
here ever commits a key.
"""

from __future__ import annotations

import json
import os

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    # python-dotenv not installed — fine, just means OPENAI_API_KEY/
    # CART_LLM_* must already be set some other way (shell env,
    # docker-compose `environment:`, etc). Doesn't affect LLM_ENABLED's
    # own default of False either way.
    pass

from common.contracts import FindingOut, Job

LLM_ENABLED = os.environ.get("CART_LLM_FOLLOWUPS", "").strip().lower() in ("1", "true", "yes")

# A small, fast model is plenty for "rank/filter this short list of
# candidates" — this is not the kind of task that benefits from a
# larger model, and keeping it small keeps latency and cost down for
# something that runs on every single agent stage.
_MODEL = os.environ.get("CART_LLM_MODEL", "gpt-4o-mini")

# An LLM call that hangs would otherwise stall a scan stage
# indefinitely — nmap/requests calls elsewhere in this project all
# have their own bounded timeouts for the same reason.
_TIMEOUT_SECONDS = 15

_SYSTEM_PROMPT = """You are the follow-up-job planner for an authorized penetration testing agent.
You will be given the findings discovered so far in this job and a menu of CANDIDATE follow-up jobs a rule-based pass already proposed.

Choose which of these candidates are actually worth running, and in what order, given limited engagement time. You may skip a candidate you judge low-value (e.g. a duplicate-looking target, or a finding type that rarely leads anywhere useful).

You may NEVER invent a job that is not already in the candidate menu — no new targets, no new agents, no new context fields. Only select from the indices you were given.

Respond with ONLY a JSON array of zero-indexed integers naming which candidates to keep, in the order you'd run them (e.g. [2, 0, 1]). An empty array [] means none are worth running. No prose, no markdown, no explanation — the array is the entire response."""


def choose_follow_ups(
    job: Job, findings: list[FindingOut], candidates: list[dict]
) -> list[dict] | None:
    """
    `candidates` is the exact follow-up-job list a rule-based pass in
    the calling agent already built (each item the normal
    {"agent", "target", "context"} shape every agent emits today).
    `findings` is whatever that same job already found, for context —
    passed as plain finding_type/description pairs, not the full
    Evidence (no need to hand a model unredacted secrets/raw_ref data
    just to decide which follow-up jobs are worth running).

    Returns a reordered/filtered SUBSET of `candidates` on success.
    Returns None if LLM_ENABLED is False, `candidates` is empty (nothing
    to choose among), or anything at all goes wrong making/parsing the
    call — see this module's own docstring for why callers must treat
    None as "use `candidates` unchanged", not as "run nothing".
    """
    if not LLM_ENABLED or not candidates:
        return None

    try:
        from openai import OpenAI
    except ImportError:
        # Optional dependency not installed — silently behave as if
        # the feature were off, rather than crashing a scan over a
        # bonus feature nobody set up.
        return None

    try:
        client = OpenAI(timeout=_TIMEOUT_SECONDS)
        findings_summary = [
            {"finding_type": f.finding_type, "description": f.description} for f in findings
        ]
        user_content = json.dumps(
            {
                "job_agent": job.agent,
                "job_target": job.target,
                "findings_so_far": findings_summary,
                "candidates": candidates,
            }
        )
        response = client.chat.completions.create(
            model=_MODEL,
            max_tokens=256,
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": user_content},
            ],
        )
        text = (response.choices[0].message.content or "").strip()
        # Some models wrap JSON in a markdown fence even when told not
        # to — strip it rather than reject a perfectly good response
        # over formatting. Anything else malformed still falls through
        # to json.loads raising and the broad except below.
        if text.startswith("```"):
            text = text.strip("`")
            if text.startswith("json"):
                text = text[4:]
            text = text.strip()
        indices = json.loads(text)
    except Exception:
        # Deliberately broad: a network error, an auth error, a
        # timeout, an SDK-internal exception, or malformed/non-JSON
        # output should all fall back the same way — a follow-up-job
        # planner is never worth risking the run over.
        return None

    if not isinstance(indices, list):
        return None
    if not indices:
        return []  # a deliberate, valid "nothing here is worth following up"

    chosen: list[dict] = []
    seen_indices: set[int] = set()
    for i in indices:
        if not isinstance(i, int) or isinstance(i, bool) or i < 0 or i >= len(candidates):
            return None  # one bad index taints the whole response — don't half-trust it
        if i in seen_indices:
            return None
        seen_indices.add(i)
        chosen.append(candidates[i])

    return chosen
