"""
Rich + Typer CLI interface for `localguard-ai`.
Provides `localguard scan <path>` and `localguard audit --workspace <dir>`.
"""

from pathlib import Path
from typing import Any, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from localguard.inspectors.env_audit import (
    audit_network_ports,
    audit_runner_versions,
    audit_workspace_secrets,
)
from localguard.inspectors.gguf_inspector import verify_gguf_file
from localguard.inspectors.jinja_ast import audit_jinja_template
from localguard.inspectors.provenance import audit_model_provenance, verify_upstream
from localguard.inspectors.safetensors_mlx import (
    inspect_model_directory,
    verify_safetensors_file,
)
from localguard.models import ScanReport, Severity

app = typer.Typer(
    name="localguard",
    help="LocalGuard-AI: Security scanner for local AI models (GGUF, MLX, Safetensors) and environments.",
    add_completion=False,
)
console = Console()

SEVERITY_COLORS: dict[Severity, str] = {
    Severity.PASS: "bold green",
    Severity.INFO: "cyan",
    Severity.LOW: "blue",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "bold red",
    Severity.CRITICAL: "bold white on red",
}


def _render_report(report: ScanReport) -> None:
    console.print(
        Panel.fit(
            f"[bold cyan]LocalGuard-AI Security Audit[/bold cyan]\nTarget: [white]{report.target}[/white]",
            border_style="cyan",
        )
    )

    table = Table(show_header=True, header_style="bold magenta", expand=True)
    table.add_column("Severity", width=10)
    table.add_column("Layer", width=24)
    table.add_column("Finding & Details")

    for f in report.findings:
        badge = f"[{SEVERITY_COLORS[f.severity]}]{f.severity.value}[/{SEVERITY_COLORS[f.severity]}]"
        body = f"[bold]{f.title}[/bold]\n{f.description}"
        if f.location:
            body += f"\n[dim]Location: {f.location}[/dim]"
        if f.remediation:
            body += f"\n[yellow]-> Fix: {f.remediation}[/yellow]"
        table.add_row(badge, f.layer, body)

    console.print(table)


def _scan_path_target(target: Path, report: ScanReport) -> dict[str, Any]:
    gguf_metadata: dict[str, Any] = {}
    if target.is_file():
        if target.suffix.lower() == ".gguf":
            meta = verify_gguf_file(target, report)
            gguf_metadata = meta
            chat_tpl = meta.get("tokenizer.chat_template")
            if isinstance(chat_tpl, str):
                audit_jinja_template(chat_tpl, f"{target.name}:tokenizer.chat_template", report)
            audit_model_provenance(target, meta, report)
        elif target.suffix.lower() == ".safetensors":
            verify_safetensors_file(target, report)
            audit_model_provenance(target, {}, report)
        else:
            # Check if file is an Ollama blob (which starts with GGUF magic bytes)
            with open(target, "rb") as f:
                magic = f.read(4)
            if magic == b"GGUF":
                meta = verify_gguf_file(target, report)
                gguf_metadata = meta
                chat_tpl = meta.get("tokenizer.chat_template")
                if isinstance(chat_tpl, str):
                    audit_jinja_template(chat_tpl, f"{target.name}:tokenizer.chat_template", report)
                audit_model_provenance(target, meta, report)
            else:
                report.add(
                    layer="Scanner",
                    severity=Severity.INFO,
                    title="Unsupported File Extension",
                    description=f"File '{target.name}' is not a .gguf or .safetensors model.",
                    location=str(target),
                )
        return gguf_metadata
    elif target.is_dir():
        gguf_files = list(target.rglob("*.gguf"))
        for gf in gguf_files:
            meta = verify_gguf_file(gf, report)
            if not gguf_metadata:
                gguf_metadata = meta
            chat_tpl = meta.get("tokenizer.chat_template")
            if isinstance(chat_tpl, str):
                audit_jinja_template(chat_tpl, f"{gf.name}:tokenizer.chat_template", report)

        templates = inspect_model_directory(target, report)
        for idx, tpl in enumerate(templates):
            audit_jinja_template(tpl, f"{target.name}:chat_template[{idx}]", report)

        audit_model_provenance(target, {}, report)
    return gguf_metadata


@app.command("scan")
def scan_command(
    path: Path = typer.Argument(..., exists=True, help="Path to a .gguf file, .safetensors file, or MLX/HF directory."),
    fail_on_high: bool = typer.Option(False, "--strict", help="Exit with code 1 if HIGH or CRITICAL issues are found."),
    online: bool = typer.Option(False, "--online", help="Verify provenance and file integrity against the live Hugging Face Hub API."),
    deep: bool = typer.Option(False, "--deep", help="With --online: stream SHA256 hashes of local weights and compare to upstream LFS OIDs."),
) -> None:
    """Scan a specific local model file (.gguf, .safetensors) or MLX / Hugging Face directory."""
    report = ScanReport(target=str(path.resolve()))
    gguf_metadata = _scan_path_target(path, report)
    if online or deep:
        verify_upstream(path, report, deep=deep, gguf_metadata=gguf_metadata)
    _render_report(report)
    if fail_on_high and report.has_critical_or_high:
        raise typer.Exit(code=1)


@app.command("audit")
def audit_command(
    workspace: Path = typer.Option(Path("."), "--workspace", "-w", help="Agent workspace directory to scan for secrets."),
    model_path: Optional[Path] = typer.Option(None, "--model", "-m", help="Optional model file or directory to scan."),
    no_probe: bool = typer.Option(False, "--no-probe", help="Skip active unauthenticated API/CORS probing of detected local servers."),
    online: bool = typer.Option(False, "--online", help="With --model: verify provenance against the live Hugging Face Hub API."),
    deep: bool = typer.Option(False, "--deep", help="With --online: stream SHA256 hash verification against upstream LFS OIDs."),
) -> None:
    """Audit the local environment (open network ports, runners, workspace secrets, and optional model)."""
    report = ScanReport(target=f"System & Workspace ({workspace.resolve()})")
    audit_runner_versions(report)
    audit_network_ports(report, probe=not no_probe)
    audit_workspace_secrets(workspace.resolve(), report)
    if model_path and model_path.exists():
        gguf_metadata = _scan_path_target(model_path, report)
        if online or deep:
            verify_upstream(model_path, report, deep=deep, gguf_metadata=gguf_metadata)
    _render_report(report)


if __name__ == "__main__":
    app()
