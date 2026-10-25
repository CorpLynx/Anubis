"""Rich and machine-readable CLI for Anubis model and host audits."""

from enum import Enum
import json
from pathlib import Path
from typing import Any, Optional

import typer
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from anubis.inspectors.env_audit import audit_network_ports, audit_runner_versions, audit_workspace_secrets
from anubis.inspectors.gguf_inspector import verify_gguf_file
from anubis.inspectors.jinja_ast import audit_jinja_template
from anubis.inspectors.ollama_models import find_ollama_models_root, inspect_ollama_models
from anubis.inspectors.provenance import audit_model_provenance, verify_upstream
from anubis.inspectors.safetensors_mlx import inspect_model_directory, verify_safetensors_file
from anubis.limits import ScanBudget, ScanLimitExceeded, parse_byte_size
from anubis.models import ScanReport, Severity
from anubis.reporting import report_to_json, report_to_sarif_json
from anubis.redteam import RedTeamReviewError, generate_redteam_hypotheses, judge_prompt_texts, worst_verdict

app = typer.Typer(
    name="anubis",
    help="Anubis: Security scanner for local AI models (GGUF, MLX, Safetensors) and environments.",
    add_completion=False,
)
console = Console()


class OutputFormat(str, Enum):
    RICH = "rich"
    JSON = "json"
    SARIF = "sarif"


class JudgeProvider(str, Enum):
    OLLAMA = "ollama"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"


class VerdictThreshold(str, Enum):
    NEVER = "never"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class FailureThreshold(str, Enum):
    NEVER = "never"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_RANK = {
    Severity.PASS: -1,
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}
SEVERITY_COLORS: dict[Severity, str] = {
    Severity.PASS: "bold green",
    Severity.INFO: "cyan",
    Severity.LOW: "blue",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "bold red",
    Severity.CRITICAL: "bold white on red",
}


def _safe_rich_text(value: str) -> str:
    clean = "".join(
        char if char in "\n\t" or char.isprintable() else f"\\u{ord(char):04x}"
        for char in value
    )
    return escape(clean)


def _render_report(
    report: ScanReport,
    output_format: OutputFormat = OutputFormat.RICH,
    include_prompt_text: bool = False,
) -> None:
    if output_format == OutputFormat.JSON:
        console.file.write(report_to_json(report, include_prompt_text=include_prompt_text) + "\n")
        console.file.flush()
        return
    if output_format == OutputFormat.SARIF:
        console.file.write(report_to_sarif_json(report) + "\n")
        console.file.flush()
        return

    console.print(
        Panel.fit(
            (
                "[bold red]Anubis Scan INCOMPLETE[/bold red]"
                if not report.complete else "[bold cyan]Anubis Security Audit[/bold cyan]"
            ) + f"\nTarget: [white]{_safe_rich_text(report.target)}[/white]",
            border_style="red" if not report.complete else "cyan",
        )
    )
    table = Table(show_header=True, header_style="bold magenta", expand=True)
    table.add_column("Severity", width=10)
    table.add_column("Layer", width=24)
    table.add_column("Finding & Details")
    for finding in report.findings:
        badge = f"[{SEVERITY_COLORS[finding.severity]}]{finding.severity.value}[/{SEVERITY_COLORS[finding.severity]}]"
        body = f"[bold]{_safe_rich_text(finding.title)}[/bold]\n{_safe_rich_text(finding.description)}"
        if finding.location:
            body += f"\n[dim]Location: {_safe_rich_text(finding.location)}[/dim]"
        if finding.remediation:
            body += f"\n[yellow]-> Fix: {_safe_rich_text(finding.remediation)}[/yellow]"
        table.add_row(badge, _safe_rich_text(finding.layer), body)
    console.print(table)


def _scan_path_target(
    target: Path,
    report: ScanReport,
    budget: ScanBudget,
    discovered_files: list[Path],
) -> dict[str, Any]:
    gguf_metadata: dict[str, Any] = {}
    files = list(budget.walk_files(target))
    discovered_files.extend(files)
    if target.is_file():
        if not files:
            return gguf_metadata
        if find_ollama_models_root(target) is not None:
            return inspect_ollama_models(target, report, budget, files=files)
        if target.suffix.lower() == ".gguf":
            metadata = verify_gguf_file(target, report, budget=budget)
            gguf_metadata = metadata
            template = metadata.get("tokenizer.chat_template")
            if isinstance(template, str):
                audit_jinja_template(template, f"{target.name}:tokenizer.chat_template", report, budget=budget)
            audit_model_provenance(target, metadata, report)
        elif target.suffix.lower() == ".safetensors":
            verify_safetensors_file(target, report, budget=budget)
            audit_model_provenance(target, {}, report)
        else:
            try:
                budget.consume_bytes(4)
                with open(target, "rb") as stream:
                    magic = stream.read(4)
            except (OSError, ScanLimitExceeded) as exc:
                report.mark_incomplete("file prefix could not be checked")
                report.add(
                    layer="Scanner",
                    severity=Severity.INFO,
                    title="File Type Check Skipped",
                    description=f"Could not inspect the file prefix ({exc.__class__.__name__}).",
                    location=str(target),
                )
                return gguf_metadata
            if magic == b"GGUF":
                metadata = verify_gguf_file(target, report, budget=budget)
                gguf_metadata = metadata
                template = metadata.get("tokenizer.chat_template")
                if isinstance(template, str):
                    audit_jinja_template(template, f"{target.name}:tokenizer.chat_template", report, budget=budget)
                audit_model_provenance(target, metadata, report)
            else:
                report.mark_incomplete(f"unsupported file type: {target.suffix or target.name}")
                report.add(
                    layer="Scanner",
                    severity=Severity.INFO,
                    title="Unsupported File Extension",
                    description=f"File '{target.name}' is not a .gguf or .safetensors model.",
                    location=str(target),
                )
        return gguf_metadata

    if target.is_dir():
        gguf_metadata = inspect_ollama_models(target, report, budget, files=files)
        for gguf_path in (candidate for candidate in files if candidate.suffix.lower() == ".gguf"):
            if budget.stop_requested:
                break
            try:
                budget.check_time()
            except ScanLimitExceeded:
                break
            metadata = verify_gguf_file(gguf_path, report, budget=budget)
            if not gguf_metadata:
                gguf_metadata = metadata
            template = metadata.get("tokenizer.chat_template")
            if isinstance(template, str):
                audit_jinja_template(template, f"{gguf_path.name}:tokenizer.chat_template", report, budget=budget)

        templates = inspect_model_directory(target, report, files=files, budget=budget)
        for index, template in enumerate(templates):
            audit_jinja_template(template, f"{target.name}:chat_template[{index}]", report, budget=budget)
        audit_model_provenance(target, {}, report)
    return gguf_metadata


def _should_fail(
    report: ScanReport,
    threshold: FailureThreshold,
    strict: bool = False,
    require_complete: bool = False,
) -> bool:
    if require_complete and not report.complete:
        return True
    if strict:
        threshold_rank = SEVERITY_RANK[Severity.HIGH]
    elif threshold == FailureThreshold.NEVER:
        return False
    else:
        threshold_rank = {
            FailureThreshold.LOW: SEVERITY_RANK[Severity.LOW],
            FailureThreshold.MEDIUM: SEVERITY_RANK[Severity.MEDIUM],
            FailureThreshold.HIGH: SEVERITY_RANK[Severity.HIGH],
            FailureThreshold.CRITICAL: SEVERITY_RANK[Severity.CRITICAL],
        }[threshold]
    return any(SEVERITY_RANK[finding.severity] >= threshold_rank for finding in report.findings)


def _make_budget(
    max_files: int,
    max_depth: int,
    max_bytes: Optional[str],
    max_seconds: float,
    follow_symlinks: bool,
    deep: bool,
) -> ScanBudget:
    try:
        byte_limit = parse_byte_size(max_bytes, deep=deep)
    except ValueError as exc:
        raise typer.BadParameter(str(exc), param_hint="--max-bytes") from exc
    return ScanBudget(
        max_files=max_files,
        max_depth=max_depth,
        max_bytes=byte_limit,
        max_seconds=max_seconds,
        follow_symlinks=follow_symlinks,
    )


def _check_prompt_text_format(include_prompt_text: bool, output_format: OutputFormat) -> None:
    if include_prompt_text and output_format != OutputFormat.JSON:
        raise typer.BadParameter("--include-prompt-text requires --format json", param_hint="--include-prompt-text")


@app.command("scan")
def scan_command(
    path: Path = typer.Argument(..., exists=True, help="Path to a .gguf file, .safetensors file, MLX/HF directory, or Ollama model store/manifest."),
    fail_on_high: bool = typer.Option(False, "--strict", help="Exit 1 for HIGH or CRITICAL findings."),
    require_complete: bool = typer.Option(False, "--require-complete", help="Exit 1 if any requested scan work was skipped or incomplete."),
    fail_on: FailureThreshold = typer.Option(FailureThreshold.NEVER, "--fail-on", help="Exit 1 when a finding reaches this severity."),
    output_format: OutputFormat = typer.Option(OutputFormat.RICH, "--format", help="Report format: rich, json, or sarif."),
    max_files: int = typer.Option(20_000, "--max-files", min=1, help="Maximum files visited across the scan."),
    max_depth: int = typer.Option(64, "--max-depth", min=0, help="Maximum directory nesting depth."),
    max_bytes: Optional[str] = typer.Option(None, "--max-bytes", help="Maximum total bytes read (e.g. 4GiB); defaults to 2GiB or 16GiB with --deep."),
    max_seconds: float = typer.Option(120.0, "--max-seconds", min=0.1, help="Maximum scan wall-clock time."),
    follow_symlinks: bool = typer.Option(False, "--follow-symlinks", help="Traverse internal directory symlinks; links outside the target root are skipped."),
    online: bool = typer.Option(False, "--online", help="Verify provenance and file integrity against the live Hugging Face Hub API."),
    deep: bool = typer.Option(False, "--deep", help="With --online: stream SHA256 hashes of local weights and compare to upstream LFS OIDs."),
    include_prompt_text: bool = typer.Option(False, "--include-prompt-text", help="With --format json: embed extracted chat-template and system-prompt text for `anubis redteam --judge`."),
) -> None:
    """Scan a local model file (.gguf, .safetensors), MLX / Hugging Face directory, or Ollama model store."""
    _check_prompt_text_format(include_prompt_text, output_format)
    report = ScanReport(target=str(path.resolve()))
    budget = _make_budget(max_files, max_depth, max_bytes, max_seconds, follow_symlinks, deep)
    discovered_files: list[Path] = []
    metadata = _scan_path_target(path, report, budget, discovered_files)
    if online or deep:
        verify_upstream(path, report, deep=deep, gguf_metadata=metadata, budget=budget, local_files=discovered_files)
    budget.add_summary_finding(report, str(path))
    _render_report(report, output_format, include_prompt_text)
    if _should_fail(report, fail_on, strict=fail_on_high, require_complete=require_complete):
        raise typer.Exit(code=1)


@app.command("audit")
def audit_command(
    workspace: Path = typer.Option(Path("."), "--workspace", "-w", help="Agent workspace directory to scan for secrets."),
    model_path: Optional[Path] = typer.Option(None, "--model", "-m", help="Optional model file or directory to scan."),
    no_probe: bool = typer.Option(False, "--no-probe", help="Skip active API/CORS probes of detected local servers."),
    online: bool = typer.Option(False, "--online", help="With --model: verify provenance against the live Hugging Face Hub API."),
    deep: bool = typer.Option(False, "--deep", help="With --online: stream SHA256 hash verification against upstream LFS OIDs."),
    fail_on_high: bool = typer.Option(False, "--strict", help="Exit 1 for HIGH or CRITICAL findings."),
    require_complete: bool = typer.Option(False, "--require-complete", help="Exit 1 if any requested scan work was skipped or incomplete."),
    fail_on: FailureThreshold = typer.Option(FailureThreshold.NEVER, "--fail-on", help="Exit 1 when a finding reaches this severity."),
    output_format: OutputFormat = typer.Option(OutputFormat.RICH, "--format", help="Report format: rich, json, or sarif."),
    max_files: int = typer.Option(20_000, "--max-files", min=1, help="Maximum files visited across the scan."),
    max_depth: int = typer.Option(64, "--max-depth", min=0, help="Maximum directory nesting depth."),
    max_bytes: Optional[str] = typer.Option(None, "--max-bytes", help="Maximum total bytes read (e.g. 4GiB); defaults to 2GiB or 16GiB with --deep."),
    max_seconds: float = typer.Option(120.0, "--max-seconds", min=0.1, help="Maximum scan wall-clock time."),
    follow_symlinks: bool = typer.Option(False, "--follow-symlinks", help="Traverse internal directory symlinks; links outside the target root are skipped."),
    include_prompt_text: bool = typer.Option(False, "--include-prompt-text", help="With --format json: embed extracted chat-template and system-prompt text for `anubis redteam --judge`."),
) -> None:
    """Audit the local environment (network, runners, workspace secrets, optional model)."""
    _check_prompt_text_format(include_prompt_text, output_format)
    report = ScanReport(target=f"System & Workspace ({workspace.resolve()})")
    budget = _make_budget(max_files, max_depth, max_bytes, max_seconds, follow_symlinks, deep)
    audit_runner_versions(report, budget=budget)
    audit_network_ports(report, probe=not no_probe, budget=budget)
    if not workspace.exists() or not workspace.is_dir():
        report.mark_incomplete("workspace directory does not exist or is not a directory")
    else:
        audit_workspace_secrets(workspace.resolve(), report, budget=budget)
    if model_path and model_path.exists():
        discovered_files: list[Path] = []
        metadata = _scan_path_target(model_path, report, budget, discovered_files)
        if online or deep:
            verify_upstream(model_path, report, deep=deep, gguf_metadata=metadata, budget=budget, local_files=discovered_files)
    elif model_path is not None:
        report.mark_incomplete("requested model path does not exist")
    budget.add_summary_finding(report, str(workspace.resolve()))
    _render_report(report, output_format, include_prompt_text)
    if _should_fail(report, fail_on, strict=fail_on_high, require_complete=require_complete):
        raise typer.Exit(code=1)


@app.command("redteam")
def redteam_command(
    report_path: Path = typer.Argument(..., exists=True, dir_okay=False, help="Anubis JSON report to review."),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="Reviewer model. Required for ollama/openai; anthropic defaults to claude-opus-5-5."),
    provider: JudgeProvider = typer.Option(JudgeProvider.OLLAMA, "--provider", help="ollama, openai (any OpenAI-compatible server: LM Studio, llama.cpp, vLLM, OpenAI), or anthropic."),
    judge: bool = typer.Option(False, "--judge", help="Judge prompt text exported with `scan --include-prompt-text` for harmful instructions, instead of generating test ideas."),
    endpoint: Optional[str] = typer.Option(None, "--endpoint", help="Server origin (ollama: http://127.0.0.1:11434, openai: http://127.0.0.1:1234). Must be loopback unless --allow-remote."),
    allow_remote: bool = typer.Option(False, "--allow-remote", help="Permit sending report data or prompt text to a non-loopback endpoint or the Anthropic API."),
    timeout: float = typer.Option(90.0, "--timeout", min=0.1, max=300.0, help="Maximum time per reviewer request in seconds."),
    max_requests: int = typer.Option(50, "--max-requests", min=1, help="With --judge: maximum model requests (bounds cost on large stores)."),
    fail_on_verdict: VerdictThreshold = typer.Option(VerdictThreshold.NEVER, "--fail-on-verdict", help="With --judge: exit 1 when any text is judged at least this bad."),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write results to a new JSON file instead of stdout."),
) -> None:
    """Ask a selected model for test ideas, or with --judge for prompt-text verdicts; never runs the scanned model."""
    try:
        if judge:
            result = judge_prompt_texts(
                report_path,
                model=model,
                provider=provider.value,
                endpoint=endpoint,
                allow_remote=allow_remote,
                timeout=timeout,
                max_requests=max_requests,
            )
        else:
            result = generate_redteam_hypotheses(
                report_path,
                model=model,
                provider=provider.value,
                endpoint=endpoint,
                allow_remote=allow_remote,
                timeout=timeout,
            )
    except RedTeamReviewError as exc:
        raise typer.BadParameter(str(exc)) from exc

    rendered = json.dumps(result, indent=2, ensure_ascii=True) + "\n"
    if output is None:
        console.file.write(rendered)
        console.file.flush()
    else:
        try:
            with output.open("x", encoding="utf-8") as stream:
                stream.write(rendered)
        except FileExistsError as exc:
            raise typer.BadParameter("output file already exists; choose a new path", param_hint="--output") from exc
        except OSError as exc:
            raise typer.BadParameter(f"could not write output ({exc.__class__.__name__})", param_hint="--output") from exc

    if judge and fail_on_verdict != VerdictThreshold.NEVER:
        worst = worst_verdict(result)
        if worst == "malicious" or (worst == "suspicious" and fail_on_verdict == VerdictThreshold.SUSPICIOUS):
            raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
