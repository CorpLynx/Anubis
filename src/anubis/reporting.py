"""Machine-readable Anubis reports (JSON and SARIF 2.1.0)."""

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from anubis.models import Finding, ScanReport, Severity

JSON_SCHEMA_VERSION = "1.0"
SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

SARIF_LEVELS = {
    Severity.PASS: "note",
    Severity.INFO: "note",
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}


def _finding_to_dict(finding: Finding) -> dict[str, Any]:
    return {
        "rule_id": finding.rule_id,
        "severity": finding.severity.value,
        "title": finding.title,
        "description": finding.description,
        "evidence": finding.evidence or finding.description,
        "confidence": finding.confidence,
        "layer": finding.layer,
        "location": finding.location,
        "remediation": finding.remediation,
    }


def report_to_dict(report: ScanReport, *, include_prompt_text: bool = False) -> dict[str, Any]:
    payload = {
        "schema_version": JSON_SCHEMA_VERSION,
        "tool": {"name": "Anubis", "version": "0.1.0"},
        "target": report.target,
        "summary": {
            "total": len(report.findings),
            "by_severity": report.counts_by_severity(),
            "complete": report.complete,
            "incomplete_reasons": report.incomplete_reasons,
        },
        "confidence_note": "Confidence values are rule-class estimates, not calibrated probabilities.",
        "findings": [_finding_to_dict(finding) for finding in report.findings],
    }
    if include_prompt_text:
        payload["prompt_texts"] = report.prompt_texts
    return payload


def report_to_json(report: ScanReport, *, pretty: bool = True, include_prompt_text: bool = False) -> str:
    return json.dumps(
        report_to_dict(report, include_prompt_text=include_prompt_text),
        indent=2 if pretty else None,
        ensure_ascii=True,
    )


def _sarif_file_location(location: str | None) -> dict[str, Any] | None:
    if not location:
        return None
    try:
        if urlsplit(location).scheme in {"http", "https"}:
            return None
    except ValueError:
        pass

    # Only emit SARIF artifact locations for paths, not sockets such as 127.0.0.1:11434.
    match = re.match(r"^(.*?)(?::line\s+(\d+)|:(\d+))?$", location)
    if not match:
        return None
    raw_path = match.group(1)
    is_path = Path(raw_path).is_absolute() or raw_path.startswith(("./", "../")) or "/" in raw_path or "\\" in raw_path
    if not is_path:
        return None

    try:
        uri = Path(raw_path).as_uri() if Path(raw_path).is_absolute() else Path(raw_path).as_posix()
    except (OSError, ValueError):
        uri = raw_path.replace("\\", "/")

    result: dict[str, Any] = {"physicalLocation": {"artifactLocation": {"uri": uri}}}
    line = match.group(2) or match.group(3)
    if line:
        result["physicalLocation"]["region"] = {"startLine": int(line)}
    return result


def report_to_sarif(report: ScanReport) -> dict[str, Any]:
    rule_ids = sorted({finding.rule_id for finding in report.findings})
    rule_index = {rule_id: index for index, rule_id in enumerate(rule_ids)}
    first_by_rule: dict[str, Finding] = {}
    for finding in report.findings:
        first_by_rule.setdefault(finding.rule_id, finding)

    rules = [
        {
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {"text": first_by_rule[rule_id].title},
            "fullDescription": {"text": first_by_rule[rule_id].description},
            "defaultConfiguration": {"level": SARIF_LEVELS[first_by_rule[rule_id].severity]},
        }
        for rule_id in rule_ids
    ]

    results = []
    for finding in report.findings:
        result: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "ruleIndex": rule_index[finding.rule_id],
            "level": SARIF_LEVELS[finding.severity],
            "message": {"text": finding.description},
            "properties": {
                "severity": finding.severity.value,
                "confidence": finding.confidence,
                "confidenceNote": "Rule-class estimate; not a calibrated probability.",
                "evidence": finding.evidence or finding.description,
                "layer": finding.layer,
                "target": report.target,
                "remediation": finding.remediation,
                "location": finding.location,
            },
        }
        sarif_location = _sarif_file_location(finding.location)
        if sarif_location:
            result["locations"] = [sarif_location]
        results.append(result)

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Anubis",
                        "informationUri": "https://github.com/CorpLynx/Anubis",
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {
                    "target": report.target,
                    "summary": {
                        "total": len(report.findings),
                        "bySeverity": report.counts_by_severity(),
                        "complete": report.complete,
                        "incompleteReasons": report.incomplete_reasons,
                    },
                },
            }
        ],
    }


def report_to_sarif_json(report: ScanReport, *, pretty: bool = True) -> str:
    return json.dumps(report_to_sarif(report), indent=2 if pretty else None, ensure_ascii=True)
