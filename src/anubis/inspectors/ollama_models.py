"""
Layer 2: Ollama model store inspector.
Resolves Ollama manifests (`models/manifests/<registry>/<namespace>/<model>/<tag>`) to their
content-addressed blobs and audits each layer: GGUF weights and their embedded Jinja chat
template, the Go `TEMPLATE` (message-content triggers and literal prompt text), the default
`SYSTEM` prompt, and seeded `MESSAGES`, without loading model tensors.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable, Optional

from anubis.inspectors.gguf_inspector import verify_gguf_file
from anubis.inspectors.jinja_ast import _is_benign_literal, audit_jinja_template
from anubis.inspectors.prompt_text import TextSegment, audit_prompt_text, prose_passages
from anubis.limits import ScanBudget, ScanLimitExceeded
from anubis.models import ScanReport, Severity

LAYER = "Layer 2 (Chat Template)"
MEDIA_PREFIX = "application/vnd.ollama.image."
WEIGHT_MEDIA = {"model", "adapter", "projector"}
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_TEXT_LAYER_BYTES = 1024 * 1024
DIGEST_REGEX = re.compile(r"^sha256[:-]([0-9a-f]{64})$")

# Go text/template content fields: `.Content` (messages) and legacy `.Prompt` (user turn).
GO_CONTENT_REGEX = re.compile(r"(?<![\w])(?:\$\w*)?\.(?:Content|Prompt)\b")
GO_COMPARE_FUNCS = re.compile(
    r"\b(?:eq|ne|lt|le|gt|ge|contains|hasPrefix|hasSuffix|HasPrefix|HasSuffix|Contains|index|slice)\b"
)
GO_STRING_REGEX = re.compile(r'"((?:[^"\\\n]|\\.)*)"|`([^`]*)`')
GO_VAR_ASSIGN_REGEX = re.compile(r"^\s*(\$\w+)\s*:?=\s*(.+)$", re.DOTALL)
GO_BLOCK_OPEN = re.compile(r"^(if|with|range|define|block)\b")
GO_BARE_DOT = re.compile(r"(?<![\w$.)\]])\.(?![\w])")
GO_ESCAPES = re.compile(r"\\(x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8}|[0-7]{3}|[abfnrtv\\\"'])")
_SIMPLE_ESCAPES = {"a": "\a", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v", "\\": "\\", '"': '"', "'": "'"}


class GoTemplateError(ValueError):
    """Raised when a Go template action is not terminated."""


def _decode_go_string(raw: str) -> str:
    def replace(match: re.Match[str]) -> str:
        esc = match.group(1)
        if esc[0] in "xuU":
            return chr(int(esc[1:], 16))
        if esc[0].isdigit():
            return chr(int(esc, 8))
        return _SIMPLE_ESCAPES[esc]

    return GO_ESCAPES.sub(replace, raw)


def _tokenize_go_template(template: str) -> list[tuple[str, str, int]]:
    """Split into ("text" | "action", value, line) parts, honoring quotes inside actions."""
    parts: list[tuple[str, str, int]] = []
    pos = 0
    line = 1
    while pos < len(template):
        start = template.find("{{", pos)
        if start < 0:
            parts.append(("text", template[pos:], line))
            break
        if start > pos:
            parts.append(("text", template[pos:start], line))
            line += template.count("\n", pos, start)
        cursor = start + 2
        quote: Optional[str] = None
        while cursor < len(template):
            ch = template[cursor]
            if quote:
                if ch == "\\" and quote != "`":
                    cursor += 2
                    continue
                if ch == quote:
                    quote = None
            elif ch in "\"`'":
                quote = ch
            elif template.startswith("}}", cursor):
                break
            cursor += 1
        else:
            raise GoTemplateError(f"unterminated action starting at line {line}")
        body = template[start + 2:cursor].strip()
        body = body.removeprefix("-").removesuffix("-").strip()
        if not (body.startswith("/*") and body.endswith("*/")):
            parts.append(("action", body, line))
        line += template.count("\n", start, cursor + 2)
        pos = cursor + 2
    return parts


def audit_go_template(template: str, source_label: str, report: ScanReport) -> None:
    """Audit an Ollama Go text/template for message-content triggers and injected prompt text."""
    try:
        parts = _tokenize_go_template(template)
    except GoTemplateError as exc:
        report.mark_incomplete("Ollama template syntax prevented inspection")
        report.add(
            layer=LAYER,
            severity=Severity.HIGH,
            title="Malformed Ollama Go Template",
            description=f"Template tokenizer failed: {exc}",
            location=source_label,
        )
        return

    issues_found = 0
    segments: list[TextSegment] = []
    tainted_vars: set[str] = set()
    # One entry per open block; True when `.` inside the block is message content (`with .Content`).
    dot_is_content: list[bool] = []

    def references_content(action: str) -> bool:
        stripped = GO_STRING_REGEX.sub('""', action)
        if GO_CONTENT_REGEX.search(stripped):
            return True
        if any(re.search(rf"{re.escape(var)}\b(?!\.)", stripped) for var in tainted_vars):
            return True
        return bool(dot_is_content and dot_is_content[-1] and GO_BARE_DOT.search(stripped))

    for kind, value, line in parts:
        if kind == "text":
            segments.append(TextSegment(value, line))
            continue
        literals = [_decode_go_string(dq) if dq or not bt else bt for dq, bt in GO_STRING_REGEX.findall(value)]
        segments.extend(TextSegment(lit, line) for lit in literals if lit)
        uses_content = references_content(value)

        keyword = value.split(None, 1)[0] if value.split() else ""
        if keyword == "end":
            if dot_is_content:
                dot_is_content.pop()
        elif GO_BLOCK_OPEN.match(value):
            parent = dot_is_content[-1] if dot_is_content else False
            dot_is_content.append(uses_content if keyword == "with" else parent and keyword == "if")
        assignment = GO_VAR_ASSIGN_REGEX.match(re.sub(r"^(?:if|with|range)\s+", "", value))
        if assignment and uses_content:
            tainted_vars.add(assignment.group(1))

        stripped = GO_STRING_REGEX.sub('""', value)
        suspicious = sorted({lit for lit in literals if not _is_benign_literal(lit)})
        if uses_content and suspicious and GO_COMPARE_FUNCS.search(stripped):
            report.add(
                layer=LAYER,
                severity=Severity.HIGH,
                title="Conditional Prompt Trigger on Message Content",
                description=(
                    f"Line {line} compares message content (`.Content`/`.Prompt`) against hardcoded literal(s) "
                    f"{suspicious}. This is a classic pattern for inference-time sleeper backdoors."
                ),
                remediation="Inspect the Ollama TEMPLATE around this line to verify what is injected.",
                location=f"{source_label}:line {line}",
            )
            issues_found += 1

    issues_found += audit_prompt_text(segments, source_label, report)
    report.record_prompt_text(source_label, "Ollama Go Template", template, prose_passages(segments))
    if issues_found == 0:
        report.add(
            layer=LAYER,
            severity=Severity.PASS,
            title="Ollama Go Template Clean",
            description=f"Audited {len(template):,}-character template. No content triggers or harmful prompt text found.",
            location=source_label,
        )


def find_ollama_models_root(target: Path) -> Optional[Path]:
    """Return the Ollama `models` directory for a store, model root, or path inside `manifests/`."""
    target = Path(target)
    candidates = [target, target / "models"] if target.is_dir() else []
    candidates.extend(parent for parent in [target, *target.parents] if parent.name == "manifests")
    for candidate in candidates:
        root = candidate.parent if candidate.name == "manifests" else candidate
        if (root / "manifests").is_dir() and (root / "blobs").is_dir():
            return root
    return None


def _load_manifest(path: Path, budget: ScanBudget) -> Optional[dict[str, Any]]:
    try:
        size = path.stat().st_size
        if size > MAX_MANIFEST_BYTES:
            return None
        budget.consume_bytes(size)
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(manifest, dict) or not isinstance(manifest.get("layers"), list):
        return None
    if not any(
        isinstance(layer, dict) and str(layer.get("mediaType", "")).startswith(MEDIA_PREFIX)
        for layer in manifest["layers"]
    ):
        return None
    return manifest


def _model_label(manifest_path: Path, manifests_dir: Path) -> str:
    try:
        parts = manifest_path.relative_to(manifests_dir).parts
    except ValueError:
        return manifest_path.name
    if len(parts) >= 2:
        name = "/".join(parts[1:-1]).removeprefix("library/")
        return f"{name}:{parts[-1]}"
    return parts[-1]


def _resolve_blob(blobs_dir: Path, digest: Any) -> Optional[Path]:
    """Map a manifest digest to its blob without letting the manifest choose an arbitrary path."""
    if not isinstance(digest, str):
        return None
    match = DIGEST_REGEX.match(digest)
    if not match:
        return None
    resolved_dir = blobs_dir.resolve()
    for name in (f"sha256-{match.group(1)}", f"sha256:{match.group(1)}"):
        candidate = blobs_dir / name
        try:
            if candidate.is_file() and candidate.resolve().parent == resolved_dir:
                return candidate
        except OSError:
            continue
    return None


def _read_text_layer(blob: Path, budget: ScanBudget, report: ScanReport, label: str) -> Optional[str]:
    try:
        size = blob.stat().st_size
        if size > MAX_TEXT_LAYER_BYTES:
            report.mark_incomplete("Ollama text layer exceeded the 1 MiB parsing limit")
            report.add(
                layer=LAYER,
                severity=Severity.INFO,
                title="Large Ollama Text Layer Not Inspected",
                description=f"Layer exceeds the {MAX_TEXT_LAYER_BYTES:,}-byte parsing limit.",
                location=label,
            )
            return None
        budget.consume_bytes(size)
        return blob.read_text(encoding="utf-8", errors="replace")
    except ScanLimitExceeded as exc:
        report.mark_incomplete(f"Ollama layer scan budget reached: {exc}")
        return None
    except OSError:
        report.mark_incomplete("Ollama layer could not be read")
        return None


def _message_segments(raw: str) -> list[TextSegment]:
    try:
        messages = json.loads(raw)
    except json.JSONDecodeError:
        return [TextSegment(raw)]
    if not isinstance(messages, list):
        return []
    return [
        TextSegment(message["content"])
        for message in messages
        if isinstance(message, dict) and isinstance(message.get("content"), str)
    ]


def inspect_ollama_models(
    target: Path,
    report: ScanReport,
    budget: ScanBudget,
    files: Optional[Iterable[Path]] = None,
) -> dict[str, Any]:
    """Audit every Ollama manifest at or under `target`; returns the first model's GGUF metadata."""
    models_root = find_ollama_models_root(target)
    if models_root is None:
        return {}
    manifests_dir, blobs_dir = models_root / "manifests", models_root / "blobs"
    candidates = list(files) if files is not None else list(budget.walk_files(target))
    manifest_paths = [
        path for path in candidates
        if budget._is_within(path, manifests_dir) and not path.name.startswith(".")
    ]

    first_metadata: dict[str, Any] = {}
    scanned_weights: set[Path] = set()
    for manifest_path in sorted(manifest_paths):
        if budget.stop_requested:
            break
        try:
            budget.check_time()
        except ScanLimitExceeded as exc:
            report.mark_incomplete(f"Ollama manifest scan budget reached: {exc}")
            break
        try:
            manifest = _load_manifest(manifest_path, budget)
        except ScanLimitExceeded as exc:
            report.mark_incomplete(f"Ollama manifest scan budget reached: {exc}")
            break
        if manifest is None:
            continue
        model = _model_label(manifest_path, manifests_dir)
        for layer in manifest["layers"]:
            if not isinstance(layer, dict):
                continue
            media = str(layer.get("mediaType", "")).removeprefix(MEDIA_PREFIX)
            blob = _resolve_blob(blobs_dir, layer.get("digest"))
            label = f"ollama:{model}:{media}"
            if blob is None:
                if media in WEIGHT_MEDIA | {"template", "system", "messages"}:
                    report.mark_incomplete("Ollama manifest references a missing or invalid blob")
                    report.add(
                        layer=LAYER,
                        severity=Severity.INFO,
                        title="Ollama Layer Blob Missing",
                        description=f"Manifest layer '{media}' has no readable blob for digest {str(layer.get('digest'))[:80]!r}.",
                        location=str(manifest_path),
                    )
                continue
            if media in WEIGHT_MEDIA:
                if blob in scanned_weights:
                    continue
                scanned_weights.add(blob)
                metadata = verify_gguf_file(blob, report, budget=budget)
                if not first_metadata and media == "model":
                    first_metadata = metadata
                template = metadata.get("tokenizer.chat_template")
                if isinstance(template, str):
                    audit_jinja_template(template, f"{label}:tokenizer.chat_template", report, budget=budget)
            elif media in ("template", "system", "messages"):
                text = _read_text_layer(blob, budget, report, label)
                if text is None:
                    continue
                if media == "template":
                    audit_go_template(text, label, report)
                elif media == "system":
                    audit_prompt_text([TextSegment(text, 1)], label, report, subject="System Prompt")
                    report.record_prompt_text(label, "Ollama System Prompt", text)
                else:
                    messages = _message_segments(text)
                    audit_prompt_text(messages, label, report, subject="Seeded Messages")
                    report.record_prompt_text(
                        label, "Ollama Seeded Messages", "\n\n".join(seg.text for seg in messages)
                    )
    return first_metadata
