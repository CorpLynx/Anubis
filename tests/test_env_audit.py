"""Tests for Layer 4 network exposure auditing and active API/CORS probing."""

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from types import SimpleNamespace

import pytest

from anubis.inspectors import env_audit
from anubis.inspectors.env_audit import Listener, _parse_windows_netstat, audit_network_ports, probe_ai_service
from anubis.models import ScanReport, Severity


class _OpenHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(b'{"models": []}')

    def log_message(self, *args) -> None:
        pass


class _AuthHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(401)
        self.end_headers()

    def log_message(self, *args) -> None:
        pass


class _RedirectHandler(BaseHTTPRequestHandler):
    target = ""

    def do_GET(self) -> None:
        self.send_response(302)
        self.send_header("Location", self.target)
        self.end_headers()

    def log_message(self, *args) -> None:
        pass


def _serve(handler):
    srv = HTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    return srv


@pytest.fixture
def open_server():
    srv = _serve(_OpenHandler)
    yield srv.server_address[1]
    srv.shutdown()
    srv.server_close()


@pytest.fixture
def auth_server():
    srv = _serve(_AuthHandler)
    yield srv.server_address[1]
    srv.shutdown()
    srv.server_close()


def test_probe_detects_open_api_with_wildcard_cors(open_server: int) -> None:
    unauth, cors, path = probe_ai_service(open_server, timeout=2.0)
    assert unauth and cors and path is not None


def test_probe_respects_authentication(auth_server: int) -> None:
    unauth, cors, _ = probe_ai_service(auth_server, timeout=2.0)
    assert not unauth and not cors


def test_probe_does_not_follow_redirects(open_server: int) -> None:
    redirect_handler = type(
        "RedirectToLocalServer",
        (_RedirectHandler,),
        {"target": f"http://127.0.0.1:{open_server}/"},
    )
    redirect_server = _serve(redirect_handler)
    try:
        unauth, cors, _ = probe_ai_service(redirect_server.server_address[1], timeout=2.0)
    finally:
        redirect_server.shutdown()
        redirect_server.server_close()
    assert not unauth and not cors


def test_loopback_with_wildcard_cors_is_medium(open_server: int) -> None:
    report = ScanReport(target="t")
    audit_network_ports(report, listeners=[("127.0.0.1", open_server, "Test Server")])
    assert any(f.severity == Severity.MEDIUM and "Wildcard CORS" in f.title for f in report.findings)
    assert not any(f.severity == Severity.CRITICAL for f in report.findings)


def test_wildcard_binding_with_open_api_is_critical(open_server: int) -> None:
    report = ScanReport(target="t")
    audit_network_ports(report, listeners=[("0.0.0.0", open_server, "Test Server")])
    titles = [f.title for f in report.findings if f.severity == Severity.CRITICAL]
    assert any("Exposed on All Interfaces" in t for t in titles)
    assert any("Unauthenticated" in t for t in titles)


def test_authenticated_server_yields_no_api_finding(auth_server: int) -> None:
    report = ScanReport(target="t")
    audit_network_ports(report, listeners=[("127.0.0.1", auth_server, "Test Server")])
    assert [f.severity for f in report.findings] == [Severity.PASS]


def test_no_probe_flag_skips_active_requests(open_server: int) -> None:
    report = ScanReport(target="t")
    audit_network_ports(report, probe=False, listeners=[("127.0.0.1", open_server, "Test Server")])
    assert [f.severity for f in report.findings] == [Severity.PASS]


def test_no_listeners_reports_pass() -> None:
    report = ScanReport(target="t")
    audit_network_ports(report, listeners=[])
    assert report.findings[0].severity == Severity.PASS


def test_windows_netstat_fallback_parses_ipv4_and_ipv6_listeners() -> None:
    output = (
        "Proto Local Address          Foreign Address        State           PID\n"
        "TCP   0.0.0.0:11434          0.0.0.0:0              LISTENING       1234\n"
        "TCP   [::]:1234              [::]:0                 LISTENING       5678\n"
        "TCP   127.0.0.1:8000         127.0.0.1:0            ESTABLISHED     1111\n"
    )

    listeners = _parse_windows_netstat(output)

    assert any((listener.ip, listener.port, listener.service) == ("0.0.0.0", 11434, "Ollama API") for listener in listeners)
    assert any((listener.ip, listener.port, listener.service) == ("::", 1234, "LM Studio Server") for listener in listeners)
    assert not any(listener.port == 8000 for listener in listeners)


def test_process_signature_finds_ai_runner_on_custom_port(monkeypatch) -> None:
    monkeypatch.setattr(env_audit, "_process_identity", lambda pid: ("Ollama API", "ollama.exe"))
    listeners = _parse_windows_netstat(
        "TCP 127.0.0.1:45678 0.0.0.0:0 LISTENING 9999\n"
    )

    assert len(listeners) == 1
    assert listeners[0].port == 45678
    assert listeners[0].service == "Ollama API"


def test_psutil_process_signature_finds_custom_ai_port(monkeypatch) -> None:
    connection = SimpleNamespace(
        status=env_audit.psutil.CONN_LISTEN,
        laddr=SimpleNamespace(ip="127.0.0.1", port=45678),
        pid=9999,
    )
    monkeypatch.setattr(env_audit.psutil, "net_connections", lambda **kwargs: [connection])
    monkeypatch.setattr(env_audit, "_process_identity", lambda pid: ("vLLM Server", "python.exe"))

    listeners = env_audit._collect_listeners()

    assert listeners == [Listener("127.0.0.1", 45678, "vLLM Server", "python.exe", 9999)]


def test_inaccessible_socket_table_does_not_claim_clean(monkeypatch) -> None:
    def denied(**kwargs):
        raise env_audit.psutil.AccessDenied()

    monkeypatch.setattr(env_audit.psutil, "net_connections", denied)
    monkeypatch.setattr(env_audit.sys, "platform", "linux")
    monkeypatch.setattr(env_audit.subprocess, "run", lambda *args, **kwargs: (_ for _ in ()).throw(FileNotFoundError()))
    report = ScanReport(target="t")

    audit_network_ports(report)

    assert any("Socket Table Unavailable" in f.title for f in report.findings)
    assert not any(f.severity == Severity.PASS for f in report.findings)


def test_network_finding_includes_listener_process() -> None:
    report = ScanReport(target="t")
    audit_network_ports(
        report,
        probe=False,
        listeners=[Listener("192.168.1.10", 45678, "Ollama API", "ollama.exe", 9999)],
    )
    finding = report.findings[0]
    assert finding.severity == Severity.CRITICAL
    assert "ollama.exe" in finding.description
    assert "9999" in finding.description


def test_specific_non_loopback_binding_is_not_reported_safe() -> None:
    report = ScanReport(target="t")
    audit_network_ports(
        report,
        probe=False,
        listeners=[("192.168.1.25", 11434, "Ollama API")],
    )
    assert any(
        f.severity == Severity.CRITICAL and "Non-Loopback" in f.title
        for f in report.findings
    )
    assert not any(f.severity == Severity.PASS for f in report.findings)
