"""
tests/common/test_llm.py

Covers common/llm.py's choose_follow_ups() — the optional, off-by-
default LLM-in-the-loop layer that picks/reorders a subset of an
agent's own rule-based follow-up-job candidates. Since `openai` is an
optional dependency (not installed in every environment — see
requirements.txt's own comment), these tests inject a fake module into
sys.modules rather than requiring the real package.
"""

from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock

import common.llm as llm_module
from common.contracts import Evidence, FindingOut, Job
from common.llm import choose_follow_ups

JOB = Job(job_id="j1", agent="network", target="10.10.10.5")
FINDINGS = [
    FindingOut(finding_type="open_port", description="d", evidence=Evidence(kind="k", summary="s"))
]
CANDIDATES = [
    {"agent": "web", "target": "10.10.10.5:80", "context": {}},
    {"agent": "web", "target": "10.10.10.5:8080", "context": {}},
    {"agent": "web", "target": "10.10.10.5:443", "context": {}},
]


def _fake_chat_completion(text):
    message = MagicMock()
    message.content = text
    choice = MagicMock()
    choice.message = message
    response = MagicMock()
    response.choices = [choice]
    return response


def _install_fake_openai(monkeypatch, response_text=None, raise_exc=None):
    fake_module = types.ModuleType("openai")

    class _FakeOpenAI:
        def __init__(self, *args, **kwargs):
            self.chat = MagicMock()
            if raise_exc is not None:
                self.chat.completions.create.side_effect = raise_exc
            else:
                self.chat.completions.create.return_value = _fake_chat_completion(response_text)

    fake_module.OpenAI = _FakeOpenAI
    monkeypatch.setitem(sys.modules, "openai", fake_module)


def test_disabled_by_default_returns_none(monkeypatch):
    monkeypatch.setattr(llm_module, "LLM_ENABLED", False)
    assert choose_follow_ups(JOB, FINDINGS, CANDIDATES) is None


def test_empty_candidates_returns_none_even_when_enabled(monkeypatch):
    monkeypatch.setattr(llm_module, "LLM_ENABLED", True)
    assert choose_follow_ups(JOB, FINDINGS, []) is None


def test_openai_not_installed_returns_none_gracefully(monkeypatch):
    monkeypatch.setattr(llm_module, "LLM_ENABLED", True)
    monkeypatch.setitem(sys.modules, "openai", None)  # simulates "not installed"
    assert choose_follow_ups(JOB, FINDINGS, CANDIDATES) is None


def test_successful_response_reorders_and_filters_candidates(monkeypatch):
    monkeypatch.setattr(llm_module, "LLM_ENABLED", True)
    _install_fake_openai(monkeypatch, response_text="[2, 0]")

    result = choose_follow_ups(JOB, FINDINGS, CANDIDATES)

    assert result == [CANDIDATES[2], CANDIDATES[0]]


def test_markdown_fenced_json_response_is_still_parsed(monkeypatch):
    monkeypatch.setattr(llm_module, "LLM_ENABLED", True)
    _install_fake_openai(monkeypatch, response_text="```json\n[1]\n```")

    result = choose_follow_ups(JOB, FINDINGS, CANDIDATES)

    assert result == [CANDIDATES[1]]


def test_empty_array_response_is_a_valid_skip_everything(monkeypatch):
    monkeypatch.setattr(llm_module, "LLM_ENABLED", True)
    _install_fake_openai(monkeypatch, response_text="[]")

    assert choose_follow_ups(JOB, FINDINGS, CANDIDATES) == []


def test_out_of_range_index_rejects_the_whole_response(monkeypatch):
    monkeypatch.setattr(llm_module, "LLM_ENABLED", True)
    _install_fake_openai(monkeypatch, response_text="[0, 99]")

    assert choose_follow_ups(JOB, FINDINGS, CANDIDATES) is None


def test_duplicate_index_rejects_the_whole_response(monkeypatch):
    monkeypatch.setattr(llm_module, "LLM_ENABLED", True)
    _install_fake_openai(monkeypatch, response_text="[0, 0]")

    assert choose_follow_ups(JOB, FINDINGS, CANDIDATES) is None


def test_non_list_json_response_rejects(monkeypatch):
    monkeypatch.setattr(llm_module, "LLM_ENABLED", True)
    _install_fake_openai(monkeypatch, response_text='{"not": "a list"}')

    assert choose_follow_ups(JOB, FINDINGS, CANDIDATES) is None


def test_unparseable_json_response_rejects(monkeypatch):
    monkeypatch.setattr(llm_module, "LLM_ENABLED", True)
    _install_fake_openai(monkeypatch, response_text="not json at all")

    assert choose_follow_ups(JOB, FINDINGS, CANDIDATES) is None


def test_boolean_in_index_list_rejects_since_bool_is_a_python_int_subclass(monkeypatch):
    monkeypatch.setattr(llm_module, "LLM_ENABLED", True)
    _install_fake_openai(monkeypatch, response_text="[true]")

    assert choose_follow_ups(JOB, FINDINGS, CANDIDATES) is None


def test_network_or_sdk_exception_returns_none(monkeypatch):
    monkeypatch.setattr(llm_module, "LLM_ENABLED", True)
    _install_fake_openai(monkeypatch, raise_exc=ConnectionError("no route to api.openai.com"))

    assert choose_follow_ups(JOB, FINDINGS, CANDIDATES) is None
