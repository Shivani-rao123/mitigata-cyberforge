import json
import os
from pathlib import Path
import socket
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest
import requests

from core.katana import normalize, run
from core.parsers.katana import parse
from core.scoped_executor import RealScopedExecutor, ScopeViolation
from core.tool_engine import ToolEngine, ToolExecutionError
from core.web_scope_proxy import scoped_proxy


def event(url="http://app/login", method="GET", status=200, **response):
    return json.dumps({"request": {"endpoint": url, "method": method},
                       "response": {"status_code": status, **response}}) + "\n"


def test_real_schema_forms_xhr_query_and_json_input_names():
    raw = event(technologies=["PHP:8", "WordPress"], forms=[{
        "action": "/auth", "method": "POST", "parameters": ["username", "password", "csrf"]}],
        xhr_requests=[{"endpoint": "http://app/api?q=secret", "method": "POST", "body": '{"email":"secret","roles":[]}'}])
    rows = parse(raw)
    assert rows[0]["classification"] == "form"
    assert rows[0]["forms"][0]["action"] == "http://app/auth"
    assert rows[1]["method"] == "POST" and rows[1]["source"] == "xhr"
    assert {i["name"] for i in rows[1]["inputs"]} == {"q", "email", "roles"}
    assert '"body"' not in json.dumps(rows)


def test_dedup_merges_technologies_forms_and_preserves_http_methods():
    rows = parse(event(technologies=["PHP"]) + event(technologies=["nginx"]) + event(method="POST"))
    assert len(rows) == 2
    assert rows[0]["technologies"] == ["PHP", "nginx"]


@pytest.mark.parametrize("status,classification", [(403,"protected"),(401,"protected"),(404,"missing"),(429,"rate_limited"),(500,"error")])
def test_http_classifications(status, classification):
    assert parse(event(status=status))[0]["classification"] == classification


def test_wrapper_scope_malformed_lines_and_output_cap():
    raw = event() + 'bad\n' + event("http://external/admin") + event("http://app/other")
    rows = parse(json.dumps({"events": raw, "target": "http://app/", "max_endpoints": 1, "meta": {}}))
    assert len(rows) == 1
    assert rows[0]["crawl"]["limited"]
    assert rows[0]["crawl"]["malformed_lines"] == 1


def test_missing_response_and_empty_result_are_not_success():
    rows = parse(json.dumps({"events":"", "target":"http://app/", "meta":{"error":"katana_failed"}}))
    assert rows[0]["error"] == "katana_failed" and rows[0]["status"] is None


@pytest.mark.parametrize("url", ["file:///etc/passwd", "http://u:p@app", "http://app:bad", "http://app/\nfoo", "http://app\\evil"])
def test_invalid_targets(url):
    with pytest.raises(ValueError):
        normalize(url)


def test_normalization_ipv6_idna_and_fragment():
    assert normalize("https://[::1]:443/a#x") == "https://[::1]/a"
    assert normalize("http://BÜCHER.example/") == "http://xn--bcher-kva.example/"


def test_adapter_technology_paths_and_timeout_retains_partial(monkeypatch, tmp_path):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **kw: [(2,1,6,"",("127.0.0.1",80))])
    calls = []
    class Engine:
        def run(self, name, **kw):
            assert "chrome" not in kw
            calls.append(Path(kw["seeds"]).read_text())
            Path(kw["output"]).write_text(event("http://app/", technologies=["WordPress"]))
            if len(calls) == 2:
                raise subprocess.TimeoutExpired("katana", 60)
    rows = parse(run("http://app/", {}, Engine(), lambda ip: None))
    assert "wp-login.php" in calls[1] and "wp-admin/" in calls[1]
    assert rows[0]["crawl"]["error"] == "katana_timeout"
    assert rows[0]["crawl"]["limited"]
    assert rows[0]["crawl"]["headless"] is False


def test_runtime_options_reach_katana_argv_context(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **kw: [(2, 1, 6, "", ("127.0.0.1", 80))])
    class Engine:
        def run(self, name, **kw):
            assert kw["depth"] == "4"
            assert kw["rate_limit"] == "2"
            assert kw["concurrency"] == "1"
            assert kw["crawl_duration"] == "10s"
            assert kw["request_timeout"] == "3"
            Path(kw["output"]).write_text(event("http://app/"))
    rows = parse(run("http://app/", {}, Engine(), lambda ip: None,
                     options_override={"depth": 4, "rate_limit": 2, "concurrency": 1,
                                       "crawl_duration": 10, "request_timeout": 3}))
    assert rows[0]["status"] == 200


def test_scope_refused_before_tool(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **kw: [(2,1,6,"",("192.0.2.1",80))])
    def deny(ip):
        raise ScopeViolation(ip)
    with pytest.raises(ScopeViolation):
        run("http://app/", {}, None, deny)


@pytest.fixture
def site():
    calls = []
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            calls.append(self.path)
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            if self.path == "/":
                self.wfile.write(b'<html><a href="/inputs">Input examples</a></html>')
            elif self.path == "/inputs":
                self.wfile.write(b'<html><form action="/auth"><input name="username"><textarea name="comment"></textarea><select name="choice"></select></form><script>fetch("/api/status?probe=1")</script></html>')
            else:
                self.wfile.write(b'<html>Other page</html>')
        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/", calls
    finally:
        server.shutdown()
        server.server_close()


def test_proxy_forwards_checked_origin_and_blocks_external_redirects(site):
    target, calls = site
    checked = []
    with scoped_proxy(target, checked.append) as (proxy, blocked):
        session = requests.Session()
        session.trust_env = False
        with session:
            assert session.get(target, proxies={"http":proxy}, timeout=5).status_code == 200
            assert session.get("http://external.invalid/", proxies={"http":proxy}, timeout=5).status_code == 403
        assert blocked
    assert calls == ["/"]
    assert checked and all(ip == "127.0.0.1" for ip in checked)


def test_proxy_connect_tunnel_is_guarded_and_preserves_bytes(site):
    target, calls = site
    authority = target.split("/")[2]
    with scoped_proxy(target, lambda ip: None) as (proxy, blocked):
        p = proxy.rsplit(":", 1)
        with socket.create_connection(("127.0.0.1", int(p[1])), timeout=5) as connection:
            connection.sendall(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode())
            header = b""
            while b"\r\n\r\n" not in header:
                header += connection.recv(1)
            assert b"200" in header
            connection.sendall(f"GET / HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n".encode())
            assert b"200" in connection.recv(4096)


def test_proxy_denies_rebound_ip_before_connect(site, monkeypatch):
    target, calls = site
    def deny(ip):
        raise ScopeViolation(ip)
    with scoped_proxy(target, deny) as (proxy, blocked):
        session = requests.Session()
        session.trust_env = False
        with session:
            assert session.get(target, proxies={"http":proxy}, timeout=5).status_code == 403
        assert "ScopeViolation" in blocked
    assert not calls


def test_nonzero_external_exit_is_error(monkeypatch):
    engine = ToolEngine()
    monkeypatch.setattr("shutil.which", lambda _: "nmap")
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: subprocess.CompletedProcess(a, 2, "", "bad"))
    with pytest.raises(ToolExecutionError):
        engine.run("nmap", "127.0.0.1")


def test_agent_reports_failed_tool_and_actual_xhr_method():
    from agents.web.agent import run as agent
    from common.contracts import Job
    job = Job(job_id="w", agent="web", target="127.0.0.1:8080")
    class Executor:
        def crawl(self, url):
            return parse(event(url + "/api", method="POST"))
    result = agent(job, Executor())
    assert "POST" in result.findings[0].evidence.summary
    class Failed:
        def crawl(self, url):
            raise ToolExecutionError("failed")
    assert agent(job, Failed()).status == "failed"


def test_standard_configuration_has_no_browser_flags():
    command = ToolEngine()._get_tool_config("katana")["command"]
    assert not any(token in command for token in ("-headless", "-hybrid", "-xhr-extraction", "-system-chrome", "-system-chrome-path", "-headless-options"))
    assert {"-js-crawl", "-form-extraction", "-tech-detect"} <= set(command)


@pytest.mark.skipif(os.environ.get("KATANA_LIVE_TESTS") != "1", reason="opt-in installed standard Katana integration")
def test_live_standard_katana(site):
    target, calls = site
    executor = RealScopedExecutor(lambda ip: ip == "127.0.0.1", lambda *args: None)
    pages = executor.crawl(target)
    assert pages[0].get("crawl", {}).get("headless") is False
    assert not pages[0].get("crawl", {}).get("error"), pages
    assert any(p["forms"] for p in pages), pages
    assert "/inputs" in calls
    assert any(p["url"].endswith("/inputs") and p["forms"] for p in pages), pages
