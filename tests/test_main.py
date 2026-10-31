import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest

import main
from core.scoped_executor import RealScopedExecutor
from core.tool_engine import ToolNotInstalled
from tests.mock_executor import MockScopedExecutor


def scope_file(tmp_path, ports="[80, 443, 3000]"):
    path = tmp_path / "scope.yaml"
    path.write_text(f"targets: [127.0.0.1/32]\nallowed_ports: {ports}\n")
    return str(path)


def service(port, name="http", protocol="tcp"):
    return {"port": port, "protocol": protocol, "service": name}


class Executor(MockScopedExecutor):
    def __init__(self, services):
        super().__init__(scan_result={"hosts": [{"ip": "127.0.0.1", "services": services}]})
        self.crawled = []
        self.ports = None

    def scan(self, target, allowed_ports=None):
        self.ports = allowed_ports
        return super().scan(target, allowed_ports)

    def crawl(self, url):
        self.crawled.append(url)
        return [{"url": url + "/inputs", "method": "GET", "status": 200,
                 "classification": "form", "technologies": ["PHP"], "forms": [
                     {"action": url + "/contact", "method": "POST", "fields": [{"name": "email"}]}]}]


def test_default_command_runs_network_then_web_and_saves_inventory(tmp_path, monkeypatch, capsys):
    executor = Executor([service(22, "ssh"), service(3000), service(443, "https")])
    monkeypatch.setattr(main, "RealScopedExecutor", lambda **kw: executor)
    output = tmp_path / "results.json"
    code = main.main(["--scope", scope_file(tmp_path), "--target", "127.0.0.1", "--output", str(output)])
    assert code == 0
    assert executor.ports == [80, 443, 3000]
    assert executor.crawled == ["http://127.0.0.1:3000", "https://127.0.0.1:443"]
    report = json.loads(output.read_text())
    assert len(report["web"]) == 2
    assert report["web"][0]["endpoints"][0]["forms"][0]["fields"] == [{"name": "email"}]
    assert "Form POST" in capsys.readouterr().out


def test_no_web_services_skips_katana(tmp_path, monkeypatch, capsys):
    executor = Executor([service(22, "ssh")])
    monkeypatch.setattr(main, "RealScopedExecutor", lambda **kw: executor)
    assert main.main(["--scope", scope_file(tmp_path)]) == 0
    assert not executor.crawled
    assert "Katana was not needed" in capsys.readouterr().out


def test_failed_web_job_does_not_stop_next_service(tmp_path, monkeypatch):
    executor = Executor([service(80), service(443, "https")])
    original = executor.crawl
    def crawl(url):
        if url.startswith("http:"):
            executor.crawled.append(url)
            raise ToolNotInstalled("katana missing")
        return original(url)
    executor.crawl = crawl
    monkeypatch.setattr(main, "RealScopedExecutor", lambda **kw: executor)
    assert main.main(["--scope", scope_file(tmp_path)]) == 2
    assert len(executor.crawled) == 2


def test_out_of_scope_never_reaches_tool(tmp_path, monkeypatch, capsys):
    def forbidden(*args, **kwargs):
        pytest.fail("Out-of-scope target reached tool engine")
    monkeypatch.setattr("core.tool_engine.ToolEngine.run", forbidden)
    assert main.main(["--scope", scope_file(tmp_path), "--target", "192.0.2.1"]) == 1
    assert "not within the authorized scope" in capsys.readouterr().out


def test_duplicate_followups_are_crawled_once(tmp_path, monkeypatch):
    executor = Executor([service(80), service(80)])
    monkeypatch.setattr(main, "RealScopedExecutor", lambda **kw: executor)
    assert main.main(["--scope", scope_file(tmp_path)]) == 0
    assert len(executor.crawled) == 1


def test_https_on_custom_port_and_ipv6_are_carried_to_web_agent():
    from agents.network.agent import run
    from agents.web.agent import run as web
    from common.contracts import Job
    executor = MockScopedExecutor(scan_result={"hosts": [{"ip": "::1", "services": [service(8443, "https")]}]})
    follow_up = run(Job(job_id="n", agent="network", target="::1"), executor).follow_up_jobs[0]
    urls = []
    executor.crawl = lambda url: urls.append(url) or []
    web(Job(job_id="w", **follow_up), executor)
    assert urls == ["https://[::1]:8443"]


def test_nmap_ssl_tunnel_preserves_https_service():
    from core.parsers.nmap import parse
    hosts = parse('<nmaprun><host><status state="up"/><address addr="127.0.0.1"/><ports><port protocol="tcp" portid="8443"><state state="open"/><service name="http" tunnel="ssl"/></port></ports></host></nmaprun>')["hosts"]
    assert hosts[0]["services"][0]["service"] == "https"


def test_udp_http_does_not_schedule_tcp_crawl():
    from agents.network.agent import run
    from common.contracts import Job
    executor = Executor([service(80, "http", "udp")])
    assert run(Job(job_id="n", agent="network", target="127.0.0.1"), executor).follow_up_jobs == []


def test_empty_port_allowlist_does_not_start_unrestricted_scan(tmp_path, monkeypatch):
    def forbidden(*a, **kw):
        pytest.fail("Invalid configuration started a scan")
    monkeypatch.setattr(main, "RealScopedExecutor", forbidden)
    assert main.main(["--scope", scope_file(tmp_path, "[]")]) == 1


def test_network_only_prints_web_command_without_running_katana(tmp_path, monkeypatch, capsys):
    executor = Executor([service(3000), service(8443, "https")])
    monkeypatch.setattr(main, "RealScopedExecutor", lambda **kw: executor)
    assert main.main(["--agent", "network", "--scope", scope_file(tmp_path), "--ports", "3000"]) == 0
    assert executor.ports == [3000]
    assert executor.crawled == []
    output = capsys.readouterr().out
    assert "--agent web" in output
    assert "https://127.0.0.1:8443" in output


def test_web_only_skips_nmap_passes_options_and_exports_inventory(tmp_path, monkeypatch):
    executor = Executor([])
    def no_scan(*a, **kw):
        pytest.fail("web-only mode invoked Nmap")
    executor.scan = no_scan
    captured = {}
    def create(**kwargs):
        captured.update(kwargs)
        return executor
    monkeypatch.setattr(main, "RealScopedExecutor", create)
    output = tmp_path / "web.json"
    assert main.main(["--agent", "web", "--scope", scope_file(tmp_path), "--target", "http://127.0.0.1:3000",
                      "--depth", "4", "--rate-limit", "3", "--concurrency", "1", "--crawl-duration", "10",
                      "--request-timeout", "5", "--max-endpoints", "100", "--output", str(output)]) == 0
    assert captured["web_options"] == {"depth": 4, "rate_limit": 3, "concurrency": 1,
                                        "crawl_duration": 10, "request_timeout": 5, "max_endpoints": 100}
    report = json.loads(output.read_text())
    assert report["network"] is None
    assert report["web"][0]["endpoints"][0]["forms"]


@pytest.mark.parametrize("arguments", [
    ["--agent", "web", "--target", "127.0.0.1"],
    ["--agent", "web", "--target", "http://127.0.0.1", "--ports", "80"],
    ["--agent", "network", "--depth", "3"],
    ["--depth", "0"], ["--rate-limit", "-1"], ["--concurrency", "50"],
    ["--agent", "network", "--target", "http://127.0.0.1"],
])
def test_invalid_cli_arguments_do_not_start_executor(arguments, monkeypatch):
    def forbidden(**kwargs):
        pytest.fail("Invalid arguments started executor")
    monkeypatch.setattr(main, "RealScopedExecutor", forbidden)
    with pytest.raises(SystemExit) as exc:
        main.main(arguments)
    assert exc.value.code == 2


def test_web_port_outside_scope_is_not_crawled(tmp_path, monkeypatch):
    executor = Executor([])
    monkeypatch.setattr(main, "RealScopedExecutor", lambda **kwargs: executor)
    assert main.main(["--agent", "web", "--target", "http://127.0.0.1:9000", "--scope", scope_file(tmp_path)]) == 1
    assert not executor.crawled


def test_nmap_ports_cannot_widen_scope(tmp_path, monkeypatch):
    executor = Executor([])
    monkeypatch.setattr(main, "RealScopedExecutor", lambda **kwargs: executor)
    with pytest.raises(SystemExit):
        main.main(["--agent", "network", "--ports", "9000", "--scope", scope_file(tmp_path)])
    assert executor.ports is None


@pytest.mark.skipif(os.environ.get("KATANA_LIVE_TESTS") != "1", reason="opt-in real standard Katana CLI pipeline with Nmap fixture")
def test_live_cli_network_fixture_to_real_katana(tmp_path, monkeypatch):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200 if self.path == "/" else 404)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b'<form action="/contact" method="post"><input name="email"></form>' if self.path == "/" else b"missing")
        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    Thread(target=server.serve_forever, daemon=True).start()
    class NetworkFixtureExecutor(RealScopedExecutor):
        def scan(self, target, allowed_ports=None):
            self._guard(target)
            return {"hosts": [{"ip": target, "services": [service(server.server_port)]}]}
    monkeypatch.setattr(main, "RealScopedExecutor", NetworkFixtureExecutor)
    output = tmp_path / "report.json"
    try:
        assert main.main(["--scope", scope_file(tmp_path, f"[{server.server_port}]"), "--target", "127.0.0.1", "--output", str(output)]) == 0
        report = json.loads(output.read_text())
        assert report["web"][0]["result"]["status"] == "completed"
        assert any(page["forms"] for page in report["web"][0]["endpoints"])
    finally:
        server.shutdown()
        server.server_close()
