"""
Layers 3, 4 & 5: Local Runner Version, Network Socket Exposure, and Agent Workspace Secret Auditor.
"""

import os
import ipaddress
import re
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

import psutil

from localguard.models import ScanReport, Severity

AI_SERVICE_PORTS: dict[int, str] = {
    11434: "Ollama API",
    1234: "LM Studio Server",
    8000: "vLLM / mlx-audio Server",
    8080: "llama.cpp Server / LocalAI",
}

# Well-known unauthenticated read endpoints per runner, used for active probing.
AI_SERVICE_ENDPOINTS: dict[int, list[str]] = {
    11434: ["/api/tags", "/api/version"],
    1234: ["/v1/models", "/api/v0/models"],
    8000: ["/v1/models", "/health"],
    8080: ["/models", "/health"],
}

PROBE_ORIGIN = "https://localguard-probe.invalid"
PROBE_TIMEOUT_SECONDS = 2.0

SECRET_FILE_NAMES = {".env", ".env.local", ".env.production", "id_rsa", "id_ed25519", "credentials"}

SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("OpenAI API Key", re.compile(r"sk-(?:proj-)?[A-Za-z0-9_\-]{32,}")),
    ("Hugging Face Token", re.compile(r"hf_[A-Za-z0-9]{30,}")),
    ("Anthropic API Key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{32,}")),
    ("GitHub PAT", re.compile(r"ghp_[A-Za-z0-9]{30,}")),
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
]


def _probe_endpoint(
    path: str, port: int, timeout: float, host: str = "127.0.0.1"
) -> tuple[Optional[int], str, bool]:
    """GET one endpoint on the selected local host. Returns status, CORS origin, and JSON-body signal."""
    url_host = f"[{host.replace('%', '%25')}]" if ":" in host else host
    url = f"http://{url_host}:{port}{path}"
    req = urllib.request.Request(url, headers={"Origin": PROBE_ORIGIN, "User-Agent": "localguard-ai-probe"})
    try:
        # Never follow redirects: a local service must not be able to make the scanner
        # contact an arbitrary external host as a side effect of an audit.
        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None

        opener = urllib.request.build_opener(_NoRedirect)
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(64)
            acao = resp.headers.get("access-control-allow-origin", "")
            return resp.status, acao, body[:1] in (b"{", b"[")
    except urllib.error.HTTPError as exc:
        # 401/403 means the API demands authentication — that is the *good* case.
        return exc.code, exc.headers.get("access-control-allow-origin", ""), False
    except Exception:
        return None, "", False


def probe_ai_service(
    port: int,
    timeout: float = PROBE_TIMEOUT_SECONDS,
    host: str = "127.0.0.1",
) -> tuple[bool, bool, Optional[str]]:
    """
    Actively probe a detected local AI server.
    Returns (unauthenticated_api, wildcard_cors, endpoint_path).
    """
    for path in AI_SERVICE_ENDPOINTS.get(port, ["/"]):
        status, acao, looks_json = _probe_endpoint(path, port, timeout, host=host)
        if status == 200 and looks_json:
            return True, acao in ("*", PROBE_ORIGIN), path
    return False, False, None


def _collect_listeners() -> list[tuple[str, int, str]]:
    """Returns [(ip, port, service)] for AI ports found LISTEN-ing, via psutil with lsof fallback."""
    listeners: list[tuple[str, int, str]] = []
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.status != psutil.CONN_LISTEN or not conn.laddr:
                continue
            if conn.laddr.port in AI_SERVICE_PORTS:
                listeners.append((conn.laddr.ip, conn.laddr.port, AI_SERVICE_PORTS[conn.laddr.port]))
    except (psutil.AccessDenied, PermissionError, OSError):
        # macOS fallback using `lsof` for current user processes without sudo
        try:
            proc = subprocess.run(
                ["lsof", "-iTCP", "-sTCP:LISTEN", "-P", "-n"],
                capture_output=True,
                text=True,
                timeout=3,
            )
            seen: set[tuple[str, int]] = set()
            for line in proc.stdout.splitlines()[1:]:
                m = re.search(r"(\S+):(\d+)\s+\(LISTEN\)", line)
                if not m:
                    continue
                ip, port_str = m.group(1), m.group(2)
                port = int(port_str)
                if port in AI_SERVICE_PORTS and (ip, port) not in seen:
                    seen.add((ip, port))
                    listeners.append((ip, port, AI_SERVICE_PORTS[port]))
        except Exception:
            pass
    return listeners


def _is_loopback(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip.split("%", 1)[0]).is_loopback
    except ValueError:
        return False


def audit_network_ports(
    report: ScanReport,
    probe: bool = True,
    timeout: float = PROBE_TIMEOUT_SECONDS,
    listeners: Optional[list[tuple[str, int, str]]] = None,
) -> None:
    """Checks if local AI runners are bound to 0.0.0.0 / wildcard interfaces and probes for open APIs."""
    if listeners is None:
        listeners = _collect_listeners()

    exposed_ports_found = 0
    local_ports_found = 0

    for ip, port, service in listeners:
        wildcard = ip in ("0.0.0.0", "::", "*")
        loopback = _is_loopback(ip)
        if not loopback:
            exposed_ports_found += 1
            exposure_title = (
                f"{service} Exposed on All Interfaces ({ip}:{port})"
                if wildcard else f"{service} Bound to Non-Loopback Interface ({ip}:{port})"
            )
            report.add(
                layer="Layer 4 (Network Exposure)",
                severity=Severity.CRITICAL,
                title=exposure_title,
                description=(
                    f"Port {port} is bound to '{ip}', so the local AI server is reachable beyond loopback "
                    "by other devices on the bound network (and may be vulnerable to browser DNS rebinding)."
                ),
                remediation="Bind strictly to 127.0.0.1 or ::1 (e.g., export OLLAMA_HOST=127.0.0.1:11434).",
                location=f"{ip}:{port}",
            )
        else:
            local_ports_found += 1
            report.add(
                layer="Layer 4 (Network Exposure)",
                severity=Severity.PASS,
                title=f"{service} Bound Safely to Loopback ({ip}:{port})",
                description=f"{service} is listening exclusively on localhost.",
                location=f"{ip}:{port}",
            )

        if not probe:
            continue

        probe_host = ("::1" if ip == "::" else "127.0.0.1") if wildcard else ip
        unauth, cors_wildcard, path = probe_ai_service(port, timeout=timeout, host=probe_host)
        if not unauth:
            continue
        if not loopback:
            report.add(
                layer="Layer 4 (Network Exposure)",
                severity=Severity.CRITICAL,
                title=f"Unauthenticated {service} API Reachable on Public Interface",
                description=(
                    f"GET {path} on port {port} returned HTTP 200 with a JSON body and no authentication. "
                    + ("The server also echoes wildcard CORS headers, so any visited website could drive it. "
                       if cors_wildcard else
                       "Any device on the network can query, load, or generate through this server. ")
                    + "This enables remote model theft, prompt injection against your agents, and RCE via "
                    "vulnerable runner parsers."
                ),
                remediation=(
                    "Restrict binding to 127.0.0.1 and/or require an API key "
                    "(e.g., --api-key for llama.cpp servers, OLLAMA_HOST=127.0.0.1 for Ollama)."
                ),
                location=f"{ip}:{port}",
            )
        elif cors_wildcard:
            report.add(
                layer="Layer 4 (Network Exposure)",
                severity=Severity.MEDIUM,
                title=f"Wildcard CORS on Loopback {service} ({ip}:{port})",
                description=(
                    f"GET {path} allows any web origin (Access-Control-Allow-Origin: *). A malicious page "
                    "opened in your browser can read completions and model lists (DNS rebinding may bypass "
                    "the loopback boundary entirely)."
                ),
                remediation="Disable wildcard CORS or require an API key for browser-embedded deployments.",
                location=f"{ip}:{port}",
            )
        else:
            report.add(
                layer="Layer 4 (Network Exposure)",
                severity=Severity.INFO,
                title=f"{service} API Open on Loopback ({ip}:{port})",
                description=(
                    f"GET {path} returned 200 without authentication. Normal for single-user local setups, "
                    "but any process running as your user can drive the model."
                ),
                location=f"{ip}:{port}",
            )

    if exposed_ports_found == 0 and local_ports_found == 0:
        report.add(
            layer="Layer 4 (Network Exposure)",
            severity=Severity.PASS,
            title="No Exposed Local AI Ports Detected",
            description="Checked ports 11434 (Ollama), 1234 (LM Studio), 8000 (vLLM/MLX), 8080 (llama.cpp).",
        )


def audit_runner_versions(report: ScanReport) -> None:
    """Checks installed Ollama version against known memory disclosure CVEs."""
    try:
        proc = subprocess.run(["ollama", "--version"], capture_output=True, text=True, timeout=2)
        output = (proc.stdout or proc.stderr).strip()
        match = re.search(r"(\d+)\.(\d+)\.(\d+)", output)
        if match:
            major, minor, patch = map(int, match.groups())
            if (major, minor, patch) < (0, 5, 0):
                report.add(
                    layer="Layer 3 (Runner Security)",
                    severity=Severity.HIGH,
                    title=f"Outdated Ollama Runner (v{major}.{minor}.{patch})",
                    description="Older Ollama versions are vulnerable to GGUF parser crashes and template CVEs.",
                    remediation="Update Ollama to the latest release.",
                )
            else:
                report.add(
                    layer="Layer 3 (Runner Security)",
                    severity=Severity.PASS,
                    title=f"Ollama Runner Detected (v{major}.{minor}.{patch})",
                    description=f"Raw version output: {output}",
                )
    except FileNotFoundError:
        report.add(
            layer="Layer 3 (Runner Security)",
            severity=Severity.INFO,
            title="Ollama Binary Not Installed",
            description="No global `ollama` CLI found in PATH (using Python/MLX directly).",
        )
    except Exception:
        pass


def audit_workspace_secrets(workspace_dir: Path, report: ScanReport) -> None:
    """Scans an AI agent's working directory for exposed .env files or hardcoded API keys."""
    if not workspace_dir.exists() or not workspace_dir.is_dir():
        return

    skip_dirs = {".git", ".venv", "venv", "tts-env", "node_modules", "__pycache__", ".cache"}
    secrets_found = 0

    for root, dirs, files in os.walk(workspace_dir):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for fname in files:
            fpath = Path(root) / fname
            if fname in SECRET_FILE_NAMES:
                report.add(
                    layer="Layer 5 (Agent Workspace)",
                    severity=Severity.HIGH,
                    title=f"Sensitive Credential File in Workspace ('{fname}')",
                    description=(
                        f"Found '{fpath}' inside agent workspace. Any local model with file-read or bash tool "
                        "access could read and exfiltrate this file."
                    ),
                    remediation="Move secrets outside the agent working tree or inject strictly via scoped OS keychain.",
                    location=str(fpath),
                )
                secrets_found += 1

            if fname.endswith((".py", ".json", ".yaml", ".yml", ".sh", ".env", ".txt")):
                try:
                    if fpath.stat().st_size > 2 * 1024 * 1024:
                        continue
                    content = fpath.read_text(encoding="utf-8", errors="ignore")
                    for label, pattern in SECRET_PATTERNS:
                        if pattern.search(content):
                            report.add(
                                layer="Layer 5 (Agent Workspace)",
                                severity=Severity.HIGH,
                                title=f"Exposed {label} in '{fname}'",
                                description=f"Detected plaintext {label} pattern inside '{fpath}'.",
                                remediation="Revoke or move the key out of the agent directory.",
                                location=str(fpath),
                            )
                            secrets_found += 1
                except Exception:
                    pass

    if secrets_found == 0:
        report.add(
            layer="Layer 5 (Agent Workspace)",
            severity=Severity.PASS,
            title="Workspace Secret Scan Clean",
            description=f"No plaintext .env files, SSH keys, or API tokens found in '{workspace_dir}'.",
            location=str(workspace_dir),
        )
