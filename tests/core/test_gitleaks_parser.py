"""
tests/core/test_gitleaks_parser.py

Unit tests for core/parsers/gitleaks.py, against gitleaks's documented
JSON report schema (a list of leak objects with RuleID/Description/
Secret/File/StartLine — stable across versions, per the module's own
caveat note about not having a live binary to verify against).
"""

import time

import pytest

from core.parsers.gitleaks import parse


def _leak(
    rule_id="aws-access-token",
    description="AWS Access Key",
    secret="AKIAABCDEFGHIJKLMNOP",
    file="config.py",
    start_line=3,
) -> dict:
    return {
        "RuleID": rule_id,
        "Description": description,
        "Secret": secret,
        "File": file,
        "StartLine": start_line,
    }


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_single_leak_is_parsed():
    import json

    raw = json.dumps([_leak()])
    findings = parse(raw)
    assert len(findings) == 1
    assert findings[0]["rule"] == "aws-access-token"
    assert findings[0]["secret"] == "AKIAABCDEFGHIJKLMNOP"
    assert findings[0]["file"] == "config.py"
    assert findings[0]["line"] == 3


def test_multiple_leaks_are_all_parsed():
    import json

    raw = json.dumps([_leak(rule_id="a"), _leak(rule_id="b"), _leak(rule_id="c")])
    findings = parse(raw)
    assert {f["rule"] for f in findings} == {"a", "b", "c"}


def test_empty_array_is_a_clean_scan_not_an_error():
    assert parse("[]") == []


def test_empty_string_output_is_treated_as_clean_scan():
    assert parse("") == []
    assert parse("   \n  ") == []


def test_falls_back_to_match_field_when_secret_is_absent():
    import json

    leak = _leak()
    del leak["Secret"]
    leak["Match"] = "fallback-matched-text"
    raw = json.dumps([leak])
    findings = parse(raw)
    assert findings[0]["secret"] == "fallback-matched-text"


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_missing_optional_fields_get_safe_defaults_not_keyerror():
    import json

    raw = json.dumps([{}])  # a leak object with literally nothing in it
    findings = parse(raw)
    assert findings[0]["rule"] == "unknown_rule"
    assert findings[0]["description"] == "Secret detected by gitleaks"
    assert findings[0]["secret"] == ""
    assert findings[0]["file"] == ""
    assert findings[0]["line"] is None


def test_non_integer_start_line_defaults_to_none_not_crash():
    import json

    leak = _leak()
    leak["StartLine"] = "not-a-number"
    raw = json.dumps([leak])
    findings = parse(raw)
    assert findings[0]["line"] is None


def test_bare_object_instead_of_array_is_treated_as_no_findings():
    import json

    # Some gitleaks versions print a summary object rather than a leak
    # array when nothing was found — treat it the same as [].
    raw = json.dumps({"LeaksFound": 0})
    assert parse(raw) == []


def test_malformed_json_raises_clear_error_not_silently_empty():
    with pytest.raises(ValueError, match="valid JSON"):
        parse("{not valid json at all")


def test_json_scalar_instead_of_array_raises_clear_error():
    import json

    with pytest.raises(ValueError, match="list of findings"):
        parse(json.dumps(42))


def test_json_array_of_non_objects_raises_clear_error():
    import json

    with pytest.raises(ValueError, match="wasn't a JSON object"):
        parse(json.dumps(["just a string", "another string"]))


def test_json_array_mixing_objects_and_non_objects_raises():
    import json

    with pytest.raises(ValueError):
        parse(json.dumps([_leak(), "not an object"]))


# ---------------------------------------------------------------------------
# Stress
# ---------------------------------------------------------------------------


def test_large_leak_count_parses_quickly():
    import json

    raw = json.dumps([_leak(rule_id=f"rule-{i}", secret=f"secret-value-{i}") for i in range(5_000)])

    start = time.monotonic()
    findings = parse(raw)
    elapsed = time.monotonic() - start

    assert elapsed < 3.0
    assert len(findings) == 5_000
    assert findings[0]["rule"] == "rule-0"
    assert findings[-1]["rule"] == "rule-4999"


def test_large_leak_count_with_huge_secret_values_parses_quickly():
    import json

    # A pathologically long single "secret" value shouldn't blow up
    # anything downstream (this parser doesn't redact — that's the
    # caller's job via common/redact.py — but it must not hang here).
    huge_secret = "x" * 200_000
    raw = json.dumps([_leak(secret=huge_secret) for _ in range(100)])

    start = time.monotonic()
    findings = parse(raw)
    elapsed = time.monotonic() - start

    assert elapsed < 3.0
    assert len(findings) == 100
    assert len(findings[0]["secret"]) == 200_000
