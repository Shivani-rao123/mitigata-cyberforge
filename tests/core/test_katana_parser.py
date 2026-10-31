"""
tests/core/test_katana_parser.py

Unit tests for core/parsers/katana.py. See that module's docstring for
the schema caveat: these fixtures encode the documented/expected katana
JSONL shape as best understood without a live binary to verify against
in the build environment — if a real katana's field names differ,
adjust both the parser's _FIELD_CANDIDATES-style lookups and these
fixtures together.
"""

import json
import time

from core.parsers.katana import parse


def _page_line(url="http://10.10.10.5/", status=200, body="", headers=None) -> str:
    return json.dumps(
        {
            "request": {"endpoint": url, "method": "GET"},
            "response": {"status_code": status, "body": body, "headers": headers or {}},
        }
    )


def _flat_page_line(url="http://10.10.10.5/", status=200, body="") -> str:
    # Alternate/older-style flat shape — the parser must tolerate this too.
    return json.dumps({"endpoint": url, "status_code": status, "body": body})


def _secret_line(source="http://10.10.10.5/app.js", value="AKIAFAKEKEY1234567890", rule="aws-key") -> str:
    return json.dumps({"type": "secret", "source": source, "data": {"value": value, "kind": rule}})


def _endpoint_line(source="http://10.10.10.5/app.js", endpoint="/api/internal/users", method="GET") -> str:
    return json.dumps(
        {"type": "endpoint", "source": source, "data": {"url": endpoint, "method": method}}
    )


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_single_page_record_is_parsed():
    raw = _page_line(url="http://10.10.10.5/admin", status=200, body="<p>hi</p>")
    result = parse(raw)

    assert len(result["pages"]) == 1
    page = result["pages"][0]
    assert page["url"] == "http://10.10.10.5/admin"
    assert page["status"] == 200
    assert page["body"] == "<p>hi</p>"
    assert result["skipped_lines"] == 0


def test_multiple_page_records_across_lines():
    raw = "\n".join([_page_line(url="http://x/a"), _page_line(url="http://x/b")])
    result = parse(raw)
    urls = {p["url"] for p in result["pages"]}
    assert urls == {"http://x/a", "http://x/b"}


def test_flat_shape_without_nested_request_response_is_tolerated():
    raw = _flat_page_line(url="http://10.10.10.5/x", status=404, body="not found")
    result = parse(raw)
    assert result["pages"][0]["url"] == "http://10.10.10.5/x"
    assert result["pages"][0]["status"] == 404


def test_forms_are_extracted_from_the_page_body():
    body = '<form action="/login" method="post"><input name="password"></form>'
    raw = _page_line(body=body)
    result = parse(raw)
    forms = result["pages"][0]["forms"]
    assert forms == [{"action": "/login", "method": "post", "inputs": ["password"]}]


def test_secret_jsluice_record_is_parsed():
    raw = _secret_line()
    result = parse(raw)
    assert result["pages"] == []
    assert len(result["js_findings"]) == 1
    finding = result["js_findings"][0]
    assert finding["finding_kind"] == "secret"
    assert finding["value"] == "AKIAFAKEKEY1234567890"
    assert finding["source"] == "http://10.10.10.5/app.js"


def test_endpoint_jsluice_record_is_parsed():
    raw = _endpoint_line()
    result = parse(raw)
    assert len(result["js_findings"]) == 1
    finding = result["js_findings"][0]
    assert finding["finding_kind"] == "endpoint"
    assert finding["endpoint"] == "/api/internal/users"
    assert finding["method"] == "GET"


def test_mixed_pages_and_js_findings_in_one_capture():
    raw = "\n".join([_page_line(url="http://x/"), _secret_line(), _endpoint_line()])
    result = parse(raw)
    assert len(result["pages"]) == 1
    assert len(result["js_findings"]) == 2


# ---------------------------------------------------------------------------
# Edge cases — malformed/incomplete input must never crash parse()
# ---------------------------------------------------------------------------


def test_empty_input_returns_empty_result():
    result = parse("")
    assert result == {"pages": [], "js_findings": [], "skipped_lines": 0}


def test_blank_lines_are_ignored_not_counted_as_skipped():
    raw = "\n\n   \n" + _page_line() + "\n\n"
    result = parse(raw)
    assert len(result["pages"]) == 1
    assert result["skipped_lines"] == 0


def test_malformed_json_line_is_skipped_not_fatal():
    raw = "\n".join([_page_line(url="http://x/good"), "{not valid json", _page_line(url="http://x/also_good")])
    result = parse(raw)
    assert len(result["pages"]) == 2
    assert result["skipped_lines"] == 1


def test_json_line_that_is_not_an_object_is_skipped():
    raw = "\n".join(['"just a string"', "42", "[1, 2, 3]", _page_line()])
    result = parse(raw)
    assert len(result["pages"]) == 1
    assert result["skipped_lines"] == 3


def test_record_missing_url_entirely_is_skipped():
    raw = json.dumps({"response": {"status_code": 200, "body": "x"}})  # no endpoint/url anywhere
    result = parse(raw)
    assert result["pages"] == []
    assert result["skipped_lines"] == 1


def test_record_with_non_string_url_is_skipped():
    raw = json.dumps({"endpoint": 12345})
    result = parse(raw)
    assert result["pages"] == []
    assert result["skipped_lines"] == 1


def test_missing_status_defaults_to_zero_not_crash():
    raw = json.dumps({"endpoint": "http://x/", "body": "hi"})  # no status field at all
    result = parse(raw)
    assert result["pages"][0]["status"] == 0


def test_non_integer_status_does_not_crash():
    raw = json.dumps({"endpoint": "http://x/", "status_code": "not-a-number"})
    result = parse(raw)
    assert result["pages"][0]["status"] == 0


def test_missing_body_defaults_to_empty_string():
    raw = json.dumps({"endpoint": "http://x/"})
    result = parse(raw)
    assert result["pages"][0]["body"] == ""
    assert result["pages"][0]["forms"] == []


def test_non_dict_headers_field_defaults_to_empty_dict():
    raw = json.dumps({"endpoint": "http://x/", "headers": "not-a-dict"})
    result = parse(raw)
    assert result["pages"][0]["headers"] == {}


def test_secret_record_missing_value_is_skipped():
    raw = json.dumps({"type": "secret", "source": "http://x/app.js", "data": {"kind": "aws-key"}})
    result = parse(raw)
    assert result["js_findings"] == []
    assert result["skipped_lines"] == 1


def test_secret_record_missing_source_is_skipped():
    raw = json.dumps({"type": "secret", "data": {"value": "x"}})
    result = parse(raw)
    assert result["js_findings"] == []
    assert result["skipped_lines"] == 1


def test_endpoint_record_missing_endpoint_is_skipped():
    raw = json.dumps({"type": "endpoint", "source": "http://x/app.js", "data": {"method": "POST"}})
    result = parse(raw)
    assert result["js_findings"] == []
    assert result["skipped_lines"] == 1


def test_unrecognized_type_field_is_treated_as_a_normal_page_attempt():
    # a "type" field that isn't "endpoint"/"secret" shouldn't be treated
    # as a js_finding at all — falls through to the normal page path,
    # and since it has no usable URL here, gets skipped.
    raw = json.dumps({"type": "something_else", "data": {}})
    result = parse(raw)
    assert result["pages"] == []
    assert result["js_findings"] == []
    assert result["skipped_lines"] == 1


# ---------------------------------------------------------------------------
# Stress: large volume + a realistic proportion of garbage lines
# ---------------------------------------------------------------------------


def test_large_capture_with_mixed_garbage_completes_quickly_and_correctly():
    lines = []
    expected_pages = 0
    expected_secrets = 0
    expected_skipped = 0

    for i in range(10_000):
        bucket = i % 10
        if bucket < 6:
            lines.append(_page_line(url=f"http://10.10.10.5/page{i}", status=200, body=f"<p>{i}</p>"))
            expected_pages += 1
        elif bucket < 8:
            lines.append(_secret_line(source=f"http://10.10.10.5/app{i}.js", value=f"SECRETVALUE{i}"))
            expected_secrets += 1
        else:
            lines.append("{this is not json" + str(i))
            expected_skipped += 1

    raw = "\n".join(lines)

    start = time.monotonic()
    result = parse(raw)
    elapsed = time.monotonic() - start

    assert elapsed < 5.0
    assert len(result["pages"]) == expected_pages
    assert len(result["js_findings"]) == expected_secrets
    assert result["skipped_lines"] == expected_skipped
