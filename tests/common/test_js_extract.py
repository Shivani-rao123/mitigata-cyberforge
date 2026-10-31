"""
tests/common/test_js_extract.py

Unit tests for common/js_extract.py's extract_js_endpoints() — the
regex-based endpoint half of the native (no-katana) JS-bundle scan used by
agents/web/agent.py's _scan_js_bundles().
"""

from common.js_extract import extract_js_endpoints


def test_empty_source_returns_no_endpoints():
    assert extract_js_endpoints("") == []
    assert extract_js_endpoints(None) == []  # type: ignore[arg-type]


def test_fetch_with_no_second_argument_defaults_to_get():
    endpoints = extract_js_endpoints('fetch("/api/users");')
    assert endpoints == [{"endpoint": "/api/users", "method": "GET"}]


def test_fetch_with_method_hint_in_options_object():
    endpoints = extract_js_endpoints(
        'fetch("/api/internal/users/export", {method: "GET"});'
    )
    assert endpoints == [{"endpoint": "/api/internal/users/export", "method": "GET"}]


def test_fetch_with_post_method_hint():
    endpoints = extract_js_endpoints(
        'fetch("/api/orders", {method: "POST", body: JSON.stringify(x)});'
    )
    assert endpoints == [{"endpoint": "/api/orders", "method": "POST"}]


def test_axios_method_call_shape():
    endpoints = extract_js_endpoints('axios.get("/api/widgets");')
    assert endpoints == [{"endpoint": "/api/widgets", "method": "GET"}]


def test_axios_post_method_call_shape():
    endpoints = extract_js_endpoints('axios.post("/api/widgets", payload);')
    assert endpoints == [{"endpoint": "/api/widgets", "method": "POST"}]


def test_axios_config_object_shape_defaults_to_get():
    endpoints = extract_js_endpoints('axios({url: "/api/config", headers: {}});')
    assert endpoints == [{"endpoint": "/api/config", "method": "GET"}]


def test_jquery_ajax_shape():
    endpoints = extract_js_endpoints('$.ajax({url: "/api/legacy", type: "GET"});')
    assert endpoints == [{"endpoint": "/api/legacy", "method": "GET"}]


def test_xhr_open_shape():
    endpoints = extract_js_endpoints('xhr.open("POST", "/api/submit");')
    assert endpoints == [{"endpoint": "/api/submit", "method": "POST"}]


def test_fragment_and_data_and_blob_urls_are_skipped():
    endpoints = extract_js_endpoints(
        'fetch("#section"); fetch("data:text/plain,x"); fetch("blob:abc123");'
    )
    assert endpoints == []


def test_multiple_call_shapes_in_one_source_all_found():
    source = """
    fetch("/api/a");
    axios.get("/api/b");
    axios.post("/api/c", {});
    axios({url: "/api/d"});
    $.ajax({url: "/api/e", type: "GET"});
    xhr.open("DELETE", "/api/f");
    """
    endpoints = extract_js_endpoints(source)
    found = {(e["endpoint"], e["method"]) for e in endpoints}
    assert found == {
        ("/api/a", "GET"),
        ("/api/b", "GET"),
        ("/api/c", "POST"),
        ("/api/d", "GET"),
        ("/api/e", "GET"),
        ("/api/f", "DELETE"),
    }


def test_does_not_match_a_concatenated_or_templated_url():
    # Documented limitation: this is regex, not a real JS parser — a URL
    # built from pieces rather than a single string literal is missed.
    endpoints = extract_js_endpoints('fetch(base + "/api/dynamic");')
    assert endpoints == []
