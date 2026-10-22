"""Tests for stable finding metadata and JSON/SARIF rendering."""

import json
from io import StringIO

from rich.console import Console

from anubis import cli
from anubis.models import ScanReport, Severity, stable_rule_id
from anubis.reporting import report_to_dict, report_to_json, report_to_sarif


def test_rule_ids_ignore_finding_specific_versions_and_values() -> None:
    first = stable_rule_id("Layer 3 (Runner Security)", "Ollama 0.3.14 Affected by GHSA-89qx-m49c-8crf: Read issue")
    second = stable_rule_id("Layer 3 (Runner Security)", "Ollama 0.4.1 Affected by GHSA-wrh5-cmwx-q2qr: Read issue")
    assert first == second
    assert first.startswith("ANB-RUNNER-")


def test_json_report_contains_evidence_confidence_and_summary() -> None:
    report = ScanReport(target="model.gguf")
    report.add(
        "Layer 1 (GGUF Binary)",
        Severity.CRITICAL,
        "Tensor out of bounds",
        "Tensor crosses EOF.",
        remediation="Do not load the file.",
        location="model.gguf",
    )

    payload = json.loads(report_to_json(report))

    assert payload["findings"][0]["rule_id"].startswith("ANB-GGUF-")
    assert payload["findings"][0]["evidence"] == "Tensor crosses EOF."
    assert 0 <= payload["findings"][0]["confidence"] <= 1
    assert payload["summary"]["by_severity"]["CRITICAL"] == 1
    assert report_to_dict(report)["target"] == "model.gguf"


def test_sarif_report_has_driver_rules_and_result_metadata() -> None:
    report = ScanReport(target="model.gguf")
    report.add("Layer 1 (GGUF Binary)", Severity.HIGH, "Unsafe tensor", "Bad span.", location="/models/model.gguf")

    payload = report_to_sarif(report)
    run = payload["runs"][0]
    result = run["results"][0]

    assert payload["version"] == "2.1.0"
    assert run["tool"]["driver"]["name"] == "Anubis"
    assert result["ruleId"].startswith("ANB-GGUF-")
    assert result["level"] == "error"
    assert result["properties"]["evidence"] == "Bad span."
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].endswith("/models/model.gguf")


def test_cli_json_format_emits_parseable_json(monkeypatch) -> None:
    output = StringIO()
    monkeypatch.setattr(cli, "console", Console(file=output, force_terminal=False, color_system=None, width=300))
    report = ScanReport(target="[bold red]untrusted[/bold red]")
    report.add("Scanner", Severity.INFO, "Unsupported", "No model found.")

    cli._render_report(report, cli.OutputFormat.JSON)

    payload = json.loads(output.getvalue())
    assert payload["target"] == "[bold red]untrusted[/bold red]"


def test_rich_output_escapes_untrusted_markup(monkeypatch) -> None:
    output = StringIO()
    monkeypatch.setattr(cli, "console", Console(file=output, force_terminal=False, color_system=None, width=300))
    report = ScanReport(target="[bold red]target[/bold red]")
    report.add(
        "Scanner",
        Severity.HIGH,
        "[bold red]forged[/bold red]",
        "[link=https://evil.invalid]details[/link]\x1b[2J",
    )

    cli._render_report(report)

    rendered = output.getvalue()
    assert "[bold red]target[/bold red]" in rendered
    assert "[bold red]forged[/bold red]" in rendered
    assert "[link=https://evil.invalid]details[/link]" in rendered
    assert "\\u001b" in rendered
    assert "\x1b[" not in rendered


def test_fail_on_thresholds_and_strict_alias() -> None:
    report = ScanReport(target="t")
    report.add("Layer 1 (GGUF Binary)", Severity.MEDIUM, "Warning", "review")

    assert not cli._should_fail(report, cli.FailureThreshold.NEVER)
    assert cli._should_fail(report, cli.FailureThreshold.LOW)
    assert cli._should_fail(report, cli.FailureThreshold.MEDIUM)
    assert not cli._should_fail(report, cli.FailureThreshold.HIGH)
    assert not cli._should_fail(report, cli.FailureThreshold.NEVER, strict=True)
