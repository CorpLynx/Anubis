"""
Layers 3, 4 & 5: Local Runner Version, Network Socket Exposure, and Agent Workspace Secret Auditor.
"""

import ipaddress
import json
import re
import subprocess
import urllib.error
import urllib.request
from datetime import date
from importlib.resources import files as package_files
from pathlib import Path
from typing import Any, Optional

import psutil

from anubis.limits import ScanBudget, ScanLimitExceeded
from anubis.models import ScanReport, Severity

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

PROBE_ORIGIN = "https://anubis-probe.invalid"
PROBE_TIMEOUT_SECONDS = 2.0

VERSION_RE = re.compile(r"(?<![\w.])v?(\d+)\.(\d+)\.(\d+)([-+][0-9A-Za-z.-]+)?")


def _load_ollama_advisory_database() -> dict[str, Any]:
    try:
        data = json.loads(package_files("anubis").joinpath("ollama_advisories.json").read_text(encoding="utf-8"))
        if data.get("schema_version") != 1 or not isinstance(data.get("advisories"), list):
            raise ValueError("unsupported advisory database schema")
        if not isinstance(data.get("snapshot_date"), str):
            raise ValueError("missing advisory snapshot date")
        return data
    except Exception as exc:
        return {"advisories": [], "snapshot_date": "", "load_error": exc.__class__.__name__}


OLLAMA_ADVISORY_DATABASE = _load_ollama_advisory_database()
OLLAMA_ADVISORIES: list[dict[str, Any]] = OLLAMA_ADVISORY_DATABASE["advisories"]
OLLAMA_ADVISORY_SNAPSHOT: str = OLLAMA_ADVISORY_DATABASE["snapshot_date"]

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
    req = urllib.request.Request(url, headers={"Origin": PROBE_ORIGIN, "User-Agent": "anubis-ai-probe"})
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


def _collect_listeners(budget: Optional[ScanBudget] = None) -> list[tuple[str, int, str]]:
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
            timeout = min(3.0, budget.remaining_seconds) if budget else 3.0
            if timeout <= 0:
                if budget:
                    budget.note("time limit")
                return listeners
            proc = subprocess.run(
                ["lsof", "-iTCP", "-sTCP:LISTEN", "-P", "-n"],
                capture_output=True,
                text=True,
                timeout=timeout,
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
    budget: Optional[ScanBudget] = None,
) -> None:
    """Checks if local AI runners are bound to 0.0.0.0 / wildcard interfaces and probes for open APIs."""
    if budget:
        try:
            budget.check_time()
        except ScanLimitExceeded:
            report.add(
                layer="Scanner",
                severity=Severity.INFO,
                title="Network Audit Skipped by Time Limit",
                description="The configured scan time limit expired before the network audit began.",
            )
            return
    if listeners is None:
        listeners = _collect_listeners(budget=budget)

    exposed_ports_found = 0
    local_ports_found = 0

    for ip, port, service in listeners:
        if budget:
            try:
                budget.check_time()
            except ScanLimitExceeded:
                report.add(
                    layer="Scanner",
                    severity=Severity.INFO,
                    title="Network Audit Budget Reached",
                    description="Stopped checking listeners at the configured time limit.",
                )
                break
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
        probe_timeout = min(timeout, budget.remaining_seconds) if budget else timeout
        if probe_timeout <= 0:
            continue
        unauth, cors_wildcard, path = probe_ai_service(port, timeout=probe_timeout, host=probe_host)
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


def _version_key(match: re.Match[str]) -> tuple[int, int, int, int]:
    major, minor, patch = (int(match.group(i)) for i in (1, 2, 3))
    suffix = match.group(4) or ""
    # Prereleases compare below the final release at the same numeric version.
    release_rank = 0 if suffix.startswith("-") else 1
    return major, minor, patch, release_rank


def _parse_advisory_version(value: str) -> Optional[tuple[int, int, int, int]]:
    if value == "0":
        return 0, 0, 0, 0
    match = VERSION_RE.fullmatch(value)
    return _version_key(match) if match else None


def _version_is_affected(version: tuple[int, int, int, int], advisory: dict[str, Any]) -> bool:
    for affected_range in advisory.get("ranges", []):
        active = False
        for event in affected_range:
            if "introduced" in event:
                introduced = _parse_advisory_version(str(event["introduced"]))
                active = introduced is not None and version >= introduced
            elif "fixed" in event:
                fixed = _parse_advisory_version(str(event["fixed"]))
                if active and fixed is not None and version < fixed:
                    return True
                active = False
            elif "last_affected" in event:
                last = _parse_advisory_version(str(event["last_affected"]))
                if active and last is not None and version <= last:
                    return True
                active = False
            elif "limit" in event:
                limit = _parse_advisory_version(str(event["limit"]))
                if active and limit is not None and version < limit:
                    return True
                active = False
        if active:
            return True
    return False


def _format_affected_ranges(advisory: dict[str, Any]) -> str:
    formatted: list[str] = []
    for events in advisory.get("ranges", []):
        start = next((e.get("introduced") for e in events if "introduced" in e), "unknown start")
        fixed = next((e.get("fixed") for e in events if "fixed" in e), None)
        last = next((e.get("last_affected") for e in events if "last_affected" in e), None)
        limit = next((e.get("limit") for e in events if "limit" in e), None)
        end = f"< {fixed}" if fixed else f"<= {last}" if last else f"< {limit}" if limit else "unbounded"
        formatted.append(f"{start} through {end}")
    return "; ".join(formatted) or "range unavailable"


def audit_runner_versions(report: ScanReport, budget: Optional[ScanBudget] = None) -> None:
    """Checks Ollama against the packaged OSV snapshot; a no-match is not a safety assertion."""
    try:
        if budget:
            budget.check_time()
        timeout = min(2.0, budget.remaining_seconds) if budget else 2.0
        if timeout <= 0:
            raise ScanLimitExceeded("scan time limit reached before runner query")
        proc = subprocess.run(["ollama", "--version"], capture_output=True, text=True, timeout=timeout)
        output = (proc.stdout or proc.stderr).strip()
        match = VERSION_RE.search(output)
        if not match:
            report.add(
                layer="Layer 3 (Runner Security)",
                severity=Severity.INFO,
                title="Ollama Version Could Not Be Parsed",
                description=f"Could not extract a semantic version from: {output[:240]!r}",
            )
            return

        if not OLLAMA_ADVISORIES:
            report.add(
                layer="Layer 3 (Runner Security)",
                severity=Severity.INFO,
                title="Ollama Advisory Database Unavailable",
                description=(
                    "The packaged OSV data could not be loaded; this runner version was not checked "
                    f"({OLLAMA_ADVISORY_DATABASE.get('load_error', 'no records')})."
                ),
                location="https://osv.dev/",
            )
            return

        try:
            snapshot_date = date.fromisoformat(OLLAMA_ADVISORY_SNAPSHOT)
            age_days = (date.today() - snapshot_date).days
            if age_days > 90:
                report.add(
                    layer="Layer 3 (Runner Security)",
                    severity=Severity.INFO,
                    title="Ollama Advisory Snapshot Is Stale",
                    description=(
                        f"The packaged OSV snapshot is {age_days} days old (dated {snapshot_date.isoformat()}); "
                        "newer advisories may be missing."
                    ),
                    remediation="Review and refresh the advisory data using scripts/update_ollama_advisories.py.",
                    location="https://osv.dev/",
                )
        except ValueError:
            report.add(
                layer="Layer 3 (Runner Security)",
                severity=Severity.INFO,
                title="Ollama Advisory Snapshot Date Invalid",
                description="The packaged advisory snapshot has an invalid date; freshness is unknown.",
                location="https://osv.dev/",
            )

        version = _version_key(match)
        version_text = ".".join(match.group(i) for i in (1, 2, 3)) + (match.group(4) or "")
        matches = [item for item in OLLAMA_ADVISORIES if _version_is_affected(version, item)]
        for advisory in matches:
            ghsa = str(advisory.get("id", "unknown-advisory"))
            summary = str(advisory.get("summary", ghsa))
            severity = Severity.__members__.get(str(advisory.get("severity", "INFO")).upper(), Severity.INFO)
            needs_review = bool(advisory.get("needs_review", True))
            if needs_review:
                severity = Severity.INFO
            report.add(
                layer="Layer 3 (Runner Security)",
                severity=severity,
                title=f"Ollama {version_text} {'May Be Affected' if needs_review else 'Affected'} by {ghsa}: {summary}",
                description=(
                    f"OSV affected range: {_format_affected_ranges(advisory)}. "
                    f"Snapshot: {OLLAMA_ADVISORY_SNAPSHOT}. Aliases: "
                    f"{', '.join(advisory.get('aliases', [])) or 'none'}. "
                    + ("Severity is informational pending maintainer review." if needs_review else "")
                ),
                remediation=(
                    "Review the affected range and curate a severity before treating this as actionable."
                    if needs_review else
                    "Upgrade to a release outside the affected range; consult the linked advisory."
                ),
                location=f"https://osv.dev/vulnerability/{ghsa}",
            )

        report.add(
            layer="Layer 3 (Runner Security)",
            severity=Severity.INFO,
            title=f"Ollama {version_text} Advisory Check Complete",
            description=(
                f"Matched {len(matches)} record(s) in the {OLLAMA_ADVISORY_SNAPSHOT} snapshot. "
                "No match is not proof that this version is vulnerability-free."
            ),
            location="https://osv.dev/",
        )
    except FileNotFoundError:
        report.add(
            layer="Layer 3 (Runner Security)",
            severity=Severity.INFO,
            title="Ollama Binary Not Installed",
            description="No global `ollama` CLI found in PATH (using Python/MLX directly).",
        )
    except ScanLimitExceeded as exc:
        report.add(
            layer="Scanner",
            severity=Severity.INFO,
            title="Runner Version Check Skipped by Time Limit",
            description=str(exc),
        )
    except Exception as exc:
        report.add(
            layer="Layer 3 (Runner Security)",
            severity=Severity.INFO,
            title="Ollama Version Check Failed",
            description=f"Could not complete the local version check ({exc.__class__.__name__}).",
        )


def audit_workspace_secrets(
    workspace_dir: Path,
    report: ScanReport,
    budget: Optional[ScanBudget] = None,
) -> None:
    """Scans an AI agent's working directory for exposed .env files or hardcoded API keys."""
    if not workspace_dir.exists() or not workspace_dir.is_dir():
        return

    own_budget = budget is None
    budget = budget or ScanBudget()
    skip_dirs = {".git", ".venv", "venv", "tts-env", "node_modules", "__pycache__", ".cache"}
    secrets_found = 0

    for fpath in budget.walk_files(workspace_dir, skip_dirs=skip_dirs):
        try:
            budget.check_time()
            fname = fpath.name
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

            if fpath.suffix.lower() in {".py", ".json", ".yaml", ".yml", ".sh", ".env", ".txt", ".toml", ".js", ".ts"} or fname.startswith(".env"):
                size = fpath.stat().st_size
                if size > 2 * 1024 * 1024:
                    budget.note("workspace single-file read limit")
                    continue
                budget.consume_bytes(size)
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
        except ScanLimitExceeded:
            break
        except OSError:
            budget.note("unreadable workspace files")

    if secrets_found == 0 and not budget.reasons and not budget.skipped_symlinks and not budget.skipped_paths:
        report.add(
            layer="Layer 5 (Agent Workspace)",
            severity=Severity.PASS,
            title="Workspace Secret Scan Clean",
            description=f"No plaintext .env files, SSH keys, or API tokens found in '{workspace_dir}'.",
            location=str(workspace_dir),
        )
    if own_budget:
        budget.add_summary_finding(report, str(workspace_dir))
