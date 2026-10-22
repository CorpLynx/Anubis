"""
Apple Silicon MLX & Safetensors Inspector.
Verifies `.safetensors` binary headers/offsets, detects legacy pickle files,
and scans custom Python model code for dangerous imports/calls.
"""

import ast
import json
import math
import struct
from pathlib import Path

from localguard.models import ScanReport, Severity

MAX_HEADER_SIZE = 100 * 1024 * 1024  # 100 MB safety ceiling

SAFETENSORS_DTYPE_BYTES: dict[str, int] = {
    "BOOL": 1,
    "U8": 1,
    "I8": 1,
    "F8_E4M3": 1,
    "F8_E5M2": 1,
    "I16": 2,
    "U16": 2,
    "F16": 2,
    "BF16": 2,
    "I32": 4,
    "U32": 4,
    "F32": 4,
    "I64": 8,
    "U64": 8,
    "F64": 8,
}

DANGEROUS_PY_IMPORTS = {"subprocess", "pty", "socket", "shutil", "ctypes", "pickle", "marshal"}
DANGEROUS_PY_CALLS = {"eval", "exec", "compile", "__import__", "system", "popen"}


def verify_safetensors_file(path: Path, report: ScanReport) -> None:
    """Verifies the 8-byte header size and tensor data_offsets of a .safetensors file."""
    file_size = path.stat().st_size
    if file_size < 8:
        report.add(
            layer="Layer 1 (Safetensors/MLX)",
            severity=Severity.CRITICAL,
            title="Truncated Safetensors File",
            description=f"File is only {file_size} bytes (minimum 8 bytes required).",
            location=str(path),
        )
        return

    with open(path, "rb") as f:
        header_len = struct.unpack("<Q", f.read(8))[0]
        if header_len == 0 or header_len > MAX_HEADER_SIZE or (8 + header_len) > file_size:
            report.add(
                layer="Layer 1 (Safetensors/MLX)",
                severity=Severity.CRITICAL,
                title="Safetensors Header Overflow / Bomb",
                description=(
                    f"Declared JSON header length ({header_len:,} bytes) exceeds file bounds "
                    f"({file_size:,} bytes) or 100MB safety limit."
                ),
                remediation="Delete this weight file immediately.",
                location=str(path),
            )
            return

        raw_header = f.read(header_len)

    try:
        header = json.loads(raw_header.decode("utf-8"))
    except Exception as exc:
        report.add(
            layer="Layer 1 (Safetensors/MLX)",
            severity=Severity.CRITICAL,
            title="Malformed Safetensors JSON Header",
            description=f"Failed to parse JSON header: {exc}",
            location=str(path),
        )
        return

    if not isinstance(header, dict):
        report.add(
            layer="Layer 1 (Safetensors/MLX)",
            severity=Severity.CRITICAL,
            title="Malformed Safetensors JSON Header",
            description="Safetensors header JSON must be an object mapping tensor names to descriptors.",
            location=str(path),
        )
        return

    base_offset = 8 + header_len
    data_size = file_size - base_offset
    errors = 0
    tensor_count = 0
    spans: list[tuple[int, int, str]] = []

    for key, info in header.items():
        if key == "__metadata__":
            continue
        tensor_count += 1
        if not isinstance(info, dict):
            report.add(
                layer="Layer 1 (Safetensors/MLX)",
                severity=Severity.CRITICAL,
                title="Invalid Safetensors Tensor Descriptor",
                description=f"Tensor '{key}' descriptor must be a JSON object.",
                location=str(path),
            )
            errors += 1
            continue
        dtype = info.get("dtype")
        shape = info.get("shape")
        offsets = info.get("data_offsets", [])

        if (
            not isinstance(dtype, str)
            or dtype not in SAFETENSORS_DTYPE_BYTES
            or not isinstance(shape, list)
            or any(not isinstance(dim, int) or isinstance(dim, bool) or dim < 0 for dim in shape)
            or not isinstance(offsets, list)
            or len(offsets) != 2
            or any(not isinstance(offset, int) or isinstance(offset, bool) for offset in offsets)
        ):
            report.add(
                layer="Layer 1 (Safetensors/MLX)",
                severity=Severity.CRITICAL,
                title="Invalid Safetensors Tensor Descriptor",
                description=(
                    f"Tensor '{key}' must have a supported dtype, non-negative integer shape, "
                    f"and two integer data offsets; got dtype={dtype!r}, shape={shape!r}, offsets={offsets!r}."
                ),
                location=str(path),
            )
            errors += 1
            continue

        begin, end = offsets
        if begin < 0 or end < begin or end > data_size:
            report.add(
                layer="Layer 1 (Safetensors/MLX)",
                severity=Severity.CRITICAL,
                title="Safetensors Out-of-Bounds Memory Offset",
                description=(
                    f"Tensor '{key}' data_offsets [{begin}, {end}] exceed physical file size "
                    f"({file_size:,} bytes)."
                ),
                location=str(path),
            )
            errors += 1
            continue

        expected_bytes = math.prod(shape) * SAFETENSORS_DTYPE_BYTES[dtype]
        if (end - begin) != expected_bytes:
            report.add(
                layer="Layer 1 (Safetensors/MLX)",
                severity=Severity.CRITICAL,
                title="Safetensors Shape vs. Byte Length Mismatch",
                description=(
                    f"Tensor '{key}' shape {shape} ({dtype}) requires {expected_bytes:,} bytes, "
                    f"but offset span allocates {end - begin:,} bytes."
                ),
                location=str(path),
            )
            errors += 1
        else:
            spans.append((begin, end, key))

    spans.sort(key=lambda x: x[0])
    cursor = 0
    for i in range(len(spans) - 1):
        if spans[i][1] > spans[i + 1][0]:
            report.add(
                layer="Layer 1 (Safetensors/MLX)",
                severity=Severity.CRITICAL,
                title="Overlapping Safetensors Buffer Regions",
                description=f"Tensor '{spans[i][2]}' overlaps with '{spans[i + 1][2]}'.",
                location=str(path),
            )
            errors += 1

    for begin, end, name in spans:
        if begin > cursor:
            report.add(
                layer="Layer 1 (Safetensors/MLX)",
                severity=Severity.CRITICAL,
                title="Unclaimed Safetensors Data Buffer",
                description=(
                    f"Unclaimed bytes [{cursor}, {begin}) precede tensor '{name}'. "
                    "Hidden or malformed payloads may be appended between tensors."
                ),
                location=str(path),
            )
            errors += 1
        cursor = max(cursor, end)

    if cursor < data_size:
        report.add(
            layer="Layer 1 (Safetensors/MLX)",
            severity=Severity.CRITICAL,
            title="Unclaimed Safetensors Data Buffer",
            description=(
                f"The final tensor ends at byte {cursor}, but the data buffer ends at {data_size}; "
                f"{data_size - cursor} unclaimed trailing byte(s) remain."
            ),
            location=str(path),
        )
        errors += 1

    if errors == 0:
        report.add(
            layer="Layer 1 (Safetensors/MLX)",
            severity=Severity.PASS,
            title=f"Safetensors Verified ({path.name})",
            description=f"Verified {tensor_count} tensors ({file_size / (1024**2):.2f} MB). Header and offsets intact.",
            location=str(path),
        )


def audit_python_file_ast(py_path: Path, report: ScanReport) -> None:
    """Scans custom Python files inside a model directory for suspicious code execution."""
    try:
        source = py_path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(py_path))
    except Exception as exc:
        report.add(
            layer="Layer 1 (MLX/HF Code)",
            severity=Severity.MEDIUM,
            title="Unparseable Python File in Model Directory",
            description=f"Could not parse {py_path.name}: {exc}",
            location=str(py_path),
        )
        return

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root_mod = alias.name.split(".")[0]
                if root_mod in DANGEROUS_PY_IMPORTS:
                    report.add(
                        layer="Layer 1 (MLX/HF Code)",
                        severity=Severity.HIGH,
                        title=f"Suspicious Import '{alias.name}' in Model Code",
                        description=f"Custom model script '{py_path.name}' imports '{alias.name}' (line {node.lineno}).",
                        remediation="Inspect this file before loading with trust_remote_code=True.",
                        location=f"{py_path}:{node.lineno}",
                    )
        elif isinstance(node, ast.ImportFrom) and node.module:
            root_mod = node.module.split(".")[0]
            if root_mod in DANGEROUS_PY_IMPORTS:
                report.add(
                    layer="Layer 1 (MLX/HF Code)",
                    severity=Severity.HIGH,
                    title=f"Suspicious Import 'from {node.module}' in Model Code",
                    description=f"Custom model script '{py_path.name}' imports from '{node.module}' (line {node.lineno}).",
                    location=f"{py_path}:{node.lineno}",
                )
        elif isinstance(node, ast.Call):
            func_name = None
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = node.func.attr
            if func_name in DANGEROUS_PY_CALLS:
                report.add(
                    layer="Layer 1 (MLX/HF Code)",
                    severity=Severity.CRITICAL,
                    title=f"Dangerous Function Call '{func_name}()' in Model Repository",
                    description=f"Found '{func_name}()' call inside '{py_path.name}' at line {node.lineno}.",
                    remediation="Do not execute or load this repository until the line is audited.",
                    location=f"{py_path}:{node.lineno}",
                )


def inspect_model_directory(model_dir: Path, report: ScanReport) -> list[str]:
    """
    Scans an MLX or Hugging Face model directory (supporting HF Hub cache `snapshots/` layout).
    Returns any discovered Jinja2 chat templates for Layer 2 inspection.
    """
    chat_templates: list[str] = []

    # Check for dangerous pickle files
    pickle_files = list(model_dir.rglob("*.bin")) + list(model_dir.rglob("*.pt")) + list(model_dir.rglob("*.pth"))
    for pkl in pickle_files:
        report.add(
            layer="Layer 1 (Safetensors/MLX)",
            severity=Severity.HIGH,
            title=f"Legacy Pickle Weight File Detected ({pkl.name})",
            description="PyTorch/Pickle files (.bin/.pt/.pth) can execute arbitrary Python opcodes upon loading.",
            remediation="Prefer exclusively .safetensors or .gguf weights.",
            location=str(pkl),
        )

    # Verify all .safetensors shards
    st_files = list(model_dir.rglob("*.safetensors"))
    for st_file in st_files:
        verify_safetensors_file(st_file, report)

    # Scan any bundled Python scripts
    for py_file in model_dir.rglob("*.py"):
        audit_python_file_ast(py_file, report)

    # Inspect config.json for auto_map (trust_remote_code indicator) and MLX quantization metadata
    for cfg_path in model_dir.rglob("config.json"):
        try:
            cfg = json.loads(cfg_path.read_text(encoding="utf-8", errors="replace"))
            if "auto_map" in cfg:
                report.add(
                    layer="Layer 1 (MLX/HF Config)",
                    severity=Severity.HIGH,
                    title="Model Requires Remote Code Execution (auto_map)",
                    description=f"config.json defines 'auto_map': {list(cfg['auto_map'].keys())}.",
                    remediation="Ensure you trust the repository author before enabling trust_remote_code.",
                    location=str(cfg_path),
                )
            if "quantization" in cfg and isinstance(cfg["quantization"], dict):
                q = cfg["quantization"]
                report.add(
                    layer="Layer 1 (MLX Config)",
                    severity=Severity.INFO,
                    title="Apple Silicon MLX Quantization Detected",
                    description=f"MLX quantized configuration: bits={q.get('bits')}, group_size={q.get('group_size')}.",
                    location=str(cfg_path),
                )
        except Exception:
            pass

    # Extract chat templates from tokenizer_config.json or chat_template.jinja
    for tok_cfg_path in model_dir.rglob("tokenizer_config.json"):
        try:
            tok_cfg = json.loads(tok_cfg_path.read_text(encoding="utf-8", errors="replace"))
            ct = tok_cfg.get("chat_template")
            if isinstance(ct, str):
                chat_templates.append(ct)
            elif isinstance(ct, list):
                for entry in ct:
                    if isinstance(entry, dict) and "template" in entry:
                        chat_templates.append(entry["template"])
        except Exception:
            pass

    for jinja_file in model_dir.rglob("chat_template.jinja"):
        try:
            chat_templates.append(jinja_file.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            pass

    return chat_templates
