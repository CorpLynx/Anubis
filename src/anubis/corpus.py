"""Run the small labeled threat corpus used to watch detector regressions."""

import json
import struct
import tempfile
from pathlib import Path
from typing import Any

from anubis.inspectors.env_audit import audit_workspace_secrets
from anubis.inspectors.gguf_inspector import verify_gguf_file
from anubis.inspectors.jinja_ast import audit_jinja_template
from anubis.inspectors.ollama_models import audit_go_template
from anubis.inspectors.prompt_text import TextSegment, audit_prompt_text
from anubis.inspectors.safetensors_mlx import audit_python_file_ast, verify_safetensors_file
from anubis.models import ScanReport, Severity

SEVERITY_RANK = {
    Severity.PASS: 0,
    Severity.INFO: 1,
    Severity.LOW: 2,
    Severity.MEDIUM: 3,
    Severity.HIGH: 4,
    Severity.CRITICAL: 5,
}


def _make_gguf(path: Path, elements: int, payload_bytes: int) -> None:
    with path.open("wb") as stream:
        stream.write(b"GGUF" + struct.pack("<I", 3))
        stream.write(struct.pack("<Q", 1) + struct.pack("<Q", 0))
        name = b"weight"
        stream.write(struct.pack("<Q", len(name)) + name)
        stream.write(struct.pack("<I", 1) + struct.pack("<Q", elements))
        stream.write(struct.pack("<I", 0) + struct.pack("<Q", 0))
        padding = (32 - (stream.tell() % 32)) % 32
        stream.write(b"\x00" * padding)
        stream.write(b"\x00" * payload_bytes)


def _make_safetensors(path: Path, shape: list[int], data_bytes: int) -> None:
    header = {"weight": {"dtype": "F16", "shape": shape, "data_offsets": [0, data_bytes]}}
    encoded = json.dumps(header).encode("utf-8")
    path.write_bytes(struct.pack("<Q", len(encoded)) + encoded + b"\x00" * data_bytes)


def run_security_corpus(manifest_path: Path) -> dict[str, Any]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != 1 or not isinstance(manifest.get("cases"), list):
        raise ValueError("unsupported security corpus manifest")

    case_results: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="anubis-corpus-") as temp:
        root = Path(temp)
        for case in manifest["cases"]:
            case_id = str(case["id"])
            kind = case["kind"]
            report = ScanReport(target=f"corpus:{case_id}")
            if kind == "jinja":
                audit_jinja_template(case["template"], case_id, report)
            elif kind == "go_template":
                audit_go_template(case["template"], case_id, report)
            elif kind == "prompt_text":
                audit_prompt_text([TextSegment(case["text"])], case_id, report, subject="System Prompt")
            elif kind == "python":
                source = root / f"{case_id}.py"
                source.write_text(case["source"], encoding="utf-8")
                audit_python_file_ast(source, report)
            elif kind == "secret":
                workspace = root / case_id
                workspace.mkdir()
                content = case.get("content")
                if content is None:
                    content = case["prefix"] + case["repeat"] * int(case["count"])
                (workspace / case["filename"]).write_text(content, encoding="utf-8")
                audit_workspace_secrets(workspace, report)
            elif kind == "gguf":
                model = root / f"{case_id}.gguf"
                _make_gguf(model, int(case["elements"]), int(case["payload_bytes"]))
                verify_gguf_file(model, report)
            elif kind == "safetensors":
                model = root / f"{case_id}.safetensors"
                _make_safetensors(model, list(case["shape"]), int(case["data_bytes"]))
                verify_safetensors_file(model, report)
            else:
                raise ValueError(f"unknown corpus case kind: {kind}")

            expected = case["expected"]
            minimum = Severity[case.get("minimum_severity", "MEDIUM")] if expected == "malicious" else None
            detected = max((SEVERITY_RANK[f.severity] for f in report.findings), default=0)
            passed = (
                detected < SEVERITY_RANK[Severity.MEDIUM]
                if expected == "benign"
                else detected >= SEVERITY_RANK[minimum]
            )
            case_results.append(
                {
                    "id": case_id,
                    "kind": kind,
                    "expected": expected,
                    "pass": passed,
                    "max_severity": (
                        max(report.findings, key=lambda f: SEVERITY_RANK[f.severity]).severity.value
                        if report.findings
                        else None
                    ),
                    "rule_ids": sorted({f.rule_id for f in report.findings}),
                }
            )

    benign = [case for case in case_results if case["expected"] == "benign"]
    malicious = [case for case in case_results if case["expected"] == "malicious"]
    return {
        "schema_version": 1,
        "corpus": str(manifest_path.name),
        "cases": case_results,
        "metrics": {
            "true_positives": sum(case["pass"] and case["expected"] == "malicious" for case in case_results),
            "false_negatives": sum(not case["pass"] and case["expected"] == "malicious" for case in case_results),
            "true_negatives": sum(case["pass"] and case["expected"] == "benign" for case in case_results),
            "false_positives": sum(not case["pass"] and case["expected"] == "benign" for case in case_results),
            "benign_cases": len(benign),
            "malicious_cases": len(malicious),
        },
    }
