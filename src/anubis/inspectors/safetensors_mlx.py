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
from typing import Any

from anubis.limits import ScanBudget, ScanLimitExceeded
from anubis.models import ScanReport, Severity

MAX_HEADER_SIZE = 100 * 1024 * 1024  # 100 MB safety ceiling
MAX_MODEL_CONFIG_SIZE = 5 * 1024 * 1024

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

DANGEROUS_PY_IMPORTS = {
    "subprocess", "pty", "socket", "shutil", "ctypes", "pickle", "marshal",
    "os", "urllib", "requests", "http", "ftplib", "importlib",
}
DANGEROUS_PY_CALLS = {
    "eval", "exec", "compile", "__import__", "system", "popen", "run", "Popen",
    "call", "check_call", "check_output", "urlopen", "urlretrieve", "create_connection",
    "import_module", "CDLL", "PyDLL",
}
RISKY_MODULE_CALLS = {
    "os": DANGEROUS_PY_CALLS | {"remove", "unlink", "rmdir"},
    "subprocess": {"run", "Popen", "call", "check_call", "check_output"},
    "urllib": {"urlopen", "urlretrieve"},
    "requests": {"get", "post", "put", "patch", "delete", "request"},
    "socket": {"connect", "create_connection"},
    "shutil": {"rmtree", "copy", "copyfile"},
    "ctypes": {"CDLL", "PyDLL"},
    "importlib": {"import_module"},
}


def verify_safetensors_file(
    path: Path, report: ScanReport, budget: ScanBudget | None = None
) -> dict[str, Any]:
    """Verifies the 8-byte header size and tensor data_offsets of a .safetensors file."""
    try:
        file_size = path.stat().st_size
    except OSError as exc:
        report.mark_incomplete("Safetensors file could not be read")
        report.add(
            layer="Layer 1 (Safetensors/MLX)",
            severity=Severity.CRITICAL,
            title="Safetensors File Unreadable",
            description=f"Could not stat the weight file: {exc.__class__.__name__}.",
            location=str(path),
        )
        return {}
    if file_size < 8:
        report.mark_incomplete("Safetensors file is truncated")
        report.add(
            layer="Layer 1 (Safetensors/MLX)",
            severity=Severity.CRITICAL,
            title="Truncated Safetensors File",
            description=f"File is only {file_size} bytes (minimum 8 bytes required).",
            location=str(path),
        )
        return {}

    try:
        with open(path, "rb") as f:
            if budget:
                budget.consume_bytes(8)
            size_bytes = f.read(8)
            if len(size_bytes) != 8:
                raise OSError("file changed or became truncated during scan")
            header_len = struct.unpack("<Q", size_bytes)[0]
            if header_len == 0 or header_len > MAX_HEADER_SIZE or (8 + header_len) > file_size:
                report.mark_incomplete("Safetensors header was outside supported size/bounds")
                report.add(
                    layer="Layer 1 (Safetensors/MLX)",
                    severity=Severity.CRITICAL,
                    title="Safetensors Header Overflow / Bomb",
                    description=(
                        f"Declared JSON header length ({header_len:,} bytes) exceeds file bounds "
                        f"({file_size:,} bytes) or 100MB safety limit."
                    ),
                    remediation="Do not load this weight file until its header is reviewed.",
                    location=str(path),
                )
                return {}

            if budget:
                budget.consume_bytes(header_len)
            raw_header = f.read(header_len)
            if len(raw_header) != header_len:
                raise OSError("file changed or became truncated while reading its header")
    except ScanLimitExceeded as exc:
        report.mark_incomplete(f"Safetensors scan budget reached: {exc}")
        report.add(
            layer="Scanner",
            severity=Severity.INFO,
            title="Safetensors Scan Budget Reached",
            description=f"Stopped reading this header at the configured limit: {exc}.",
            location=str(path),
        )
        return {}
    except OSError as exc:
        report.mark_incomplete("Safetensors file changed or became unreadable")
        report.add(
            layer="Layer 1 (Safetensors/MLX)",
            severity=Severity.CRITICAL,
            title="Safetensors File Read Failed",
            description=f"Could not read the weight file: {exc.__class__.__name__}.",
            location=str(path),
        )
        return {}

    try:
        header = json.loads(raw_header.decode("utf-8"))
    except Exception as exc:
        report.mark_incomplete("Safetensors JSON header could not be parsed")
        report.add(
            layer="Layer 1 (Safetensors/MLX)",
            severity=Severity.CRITICAL,
            title="Malformed Safetensors JSON Header",
            description=f"Failed to parse JSON header: {exc}",
            location=str(path),
        )
        return {}

    if not isinstance(header, dict):
        report.mark_incomplete("Safetensors JSON header was not an object")
        report.add(
            layer="Layer 1 (Safetensors/MLX)",
            severity=Severity.CRITICAL,
            title="Malformed Safetensors JSON Header",
            description="Safetensors header JSON must be an object mapping tensor names to descriptors.",
            location=str(path),
        )
        return {}

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
    return header


def audit_python_file_ast(
    py_path: Path, report: ScanReport, budget: ScanBudget | None = None
) -> None:
    """Scans custom Python files inside a model directory for suspicious code execution."""
    try:
        size = py_path.stat().st_size
        if size > 2 * 1024 * 1024:
            report.mark_incomplete("model Python source exceeded the 2 MiB AST limit")
            report.add(
                layer="Layer 1 (MLX/HF Code)",
                severity=Severity.INFO,
                title="Large Model Python File Not Inspected",
                description="Python model source exceeds the 2 MiB static-analysis limit.",
                location=str(py_path),
            )
            return
        if budget:
            budget.consume_bytes(size)
        source = py_path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(py_path))
    except ScanLimitExceeded as exc:
        report.mark_incomplete(f"model Python source scan budget reached: {exc}")
        report.add(
            layer="Scanner",
            severity=Severity.INFO,
            title="Model Code Scan Budget Reached",
            description=f"Skipped Python source at the configured limit: {exc}.",
            location=str(py_path),
        )
        return
    except Exception as exc:
        report.mark_incomplete("model Python source could not be parsed")
        report.add(
            layer="Layer 1 (MLX/HF Code)",
            severity=Severity.MEDIUM,
            title="Unparseable Python File in Model Directory",
            description=f"Could not parse {py_path.name}: {exc}",
            location=str(py_path),
        )
        return

    module_aliases: dict[str, str] = {}
    call_aliases: set[str] = set(DANGEROUS_PY_CALLS)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root_mod = alias.name.split(".")[0]
                if root_mod in DANGEROUS_PY_IMPORTS:
                    bound_name = alias.asname or root_mod
                    module_aliases[bound_name] = root_mod
                    report.add(
                        layer="Layer 1 (MLX/HF Code)",
                        severity=Severity.MEDIUM,
                        title=f"Suspicious Import '{alias.name}' in Model Code",
                        description=f"Custom model script '{py_path.name}' imports '{alias.name}' (line {node.lineno}).",
                        remediation="Review network, process, and file-system capabilities before loading remote code.",
                        location=f"{py_path}:{node.lineno}",
                    )
        elif isinstance(node, ast.ImportFrom):
            if not node.module:
                continue
            root_mod = node.module.split(".")[0]
            if root_mod in DANGEROUS_PY_IMPORTS:
                report.add(
                    layer="Layer 1 (MLX/HF Code)",
                    severity=Severity.MEDIUM,
                    title=f"Suspicious Import 'from {node.module}' in Model Code",
                    description=f"Custom model script '{py_path.name}' imports from '{node.module}' (line {node.lineno}).",
                    location=f"{py_path}:{node.lineno}",
                )
                for alias in node.names:
                    if alias.name in DANGEROUS_PY_CALLS:
                        call_aliases.add(alias.asname or alias.name)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func_name: str | None = None
        if isinstance(node.func, ast.Name):
            if node.func.id in call_aliases:
                func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
            root = node.func.value
            while isinstance(root, ast.Attribute):
                root = root.value
            if isinstance(root, ast.Name):
                module = module_aliases.get(root.id)
                if module and func_name not in RISKY_MODULE_CALLS.get(module, set()):
                    func_name = None
                elif not module and func_name not in DANGEROUS_PY_CALLS:
                    func_name = None
            elif func_name not in DANGEROUS_PY_CALLS:
                func_name = None
        if func_name:
            report.add(
                layer="Layer 1 (MLX/HF Code)",
                severity=Severity.CRITICAL,
                title=f"Dangerous Function Call '{func_name}()' in Model Repository",
                description=f"Found '{func_name}()' call inside '{py_path.name}' at line {node.lineno}.",
                remediation="Do not execute or load this repository until the line is audited.",
                location=f"{py_path}:{node.lineno}",
            )


def _audit_mlx_quantization(
    tensor_shapes: dict[str, list[int]], config: dict[str, Any], config_path: Path, report: ScanReport
) -> None:
    quantization = config.get("quantization")
    if not isinstance(quantization, dict):
        return

    bits = quantization.get("bits")
    group_size = quantization.get("group_size")
    if (
        not isinstance(bits, int)
        or isinstance(bits, bool)
        or not 1 <= bits <= 8
        or not isinstance(group_size, int)
        or isinstance(group_size, bool)
        or group_size <= 0
    ):
        report.mark_incomplete("MLX quantization parameters are invalid")
        report.add(
            layer="Layer 1 (MLX Quantization)",
            severity=Severity.HIGH,
            title="Invalid MLX Quantization Parameters",
            description=f"Expected integer bits (1..8) and positive group_size; got {quantization!r}.",
            location=str(config_path),
        )
        return

    matched = 0
    errors = 0
    for scales_name, scales_shape in tensor_shapes.items():
        if not scales_name.endswith(".scales"):
            continue
        prefix = scales_name[: -len(".scales")]
        weight_name = f"{prefix}.weight"
        weight_shape = tensor_shapes.get(weight_name)
        if not weight_shape:
            report.mark_incomplete(f"weight tensor missing for quantized scales {scales_name}")
            report.add(
                layer="Layer 1 (MLX Quantization)",
                severity=Severity.HIGH,
                title=f"Quantized Scales Missing Weight Tensor ('{prefix}')",
                description=f"Found '{scales_name}' but no matching '{weight_name}' in Safetensors headers.",
                location=str(config_path),
            )
            errors += 1
            continue

        if (
            not scales_shape
            or len(weight_shape) != len(scales_shape)
            or weight_shape[:-1] != scales_shape[:-1]
            or (scales_shape[-1] * bits * group_size) % 32 != 0
            or weight_shape[-1] != (scales_shape[-1] * bits * group_size) // 32
        ):
            report.add(
                layer="Layer 1 (MLX Quantization)",
                severity=Severity.CRITICAL,
                title=f"MLX Weight/Scale Shape Ratio Mismatch ('{prefix}')",
                description=(
                    f"bits={bits}, group_size={group_size}, weight shape={weight_shape}, "
                    f"scales shape={scales_shape}; expected packed last dimension "
                    "weight[-1] = scales[-1] * bits * group_size / 32, with matching leading dimensions."
                ),
                remediation="Do not load this model until its quantization metadata and tensor shards are checked.",
                location=str(config_path),
            )
            errors += 1
            continue

        biases_shape = tensor_shapes.get(f"{prefix}.biases")
        if biases_shape is not None and biases_shape != scales_shape:
            report.add(
                layer="Layer 1 (MLX Quantization)",
                severity=Severity.CRITICAL,
                title=f"MLX Bias/Scale Shape Mismatch ('{prefix}')",
                description=f"Bias shape {biases_shape} does not match scales shape {scales_shape}.",
                location=str(config_path),
            )
            errors += 1
            continue
        matched += 1

    if matched and errors == 0:
        report.add(
            layer="Layer 1 (MLX Quantization)",
            severity=Severity.PASS,
            title="MLX Quantization Shape Ratios Verified",
            description=f"Verified {matched} weight/scale pair(s) for bits={bits}, group_size={group_size}.",
            location=str(config_path),
        )
    elif not matched and errors == 0:
        report.mark_incomplete("MLX quantization tensor ratios could not be verified")
        report.add(
            layer="Layer 1 (MLX Quantization)",
            severity=Severity.INFO,
            title="MLX Quantization Shape Ratios Not Verifiable",
            description="Quantization metadata is present, but no matching *.weight/*.scales tensors were found.",
            location=str(config_path),
        )


def inspect_model_directory(
    model_dir: Path,
    report: ScanReport,
    *,
    files: list[Path] | None = None,
    budget: ScanBudget | None = None,
) -> list[str]:
    """Inspect an MLX/HF model directory using a bounded, symlink-aware file list."""
    own_budget = budget is None
    budget = budget or ScanBudget()
    files = files if files is not None else list(budget.walk_files(model_dir))
    chat_templates: list[str] = []
    text_cache: dict[Path, str] = {}

    for pkl in (p for p in files if p.suffix.lower() in {".bin", ".pt", ".pth", ".ckpt"}):
        report.add(
            layer="Layer 1 (Safetensors/MLX)",
            severity=Severity.HIGH,
            title=f"Legacy Pickle Weight File Detected ({pkl.name})",
            description="Legacy PyTorch checkpoint files may contain pickle opcodes that execute during loading.",
            remediation="Prefer exclusively .safetensors or .gguf weights.",
            location=str(pkl),
        )

    tensor_shapes: dict[str, list[int]] = {}
    for st_file in (p for p in files if p.suffix.lower() == ".safetensors"):
        if budget.stop_requested:
            break
        header = verify_safetensors_file(st_file, report, budget=budget)
        for tensor_name, descriptor in header.items():
            if (
                tensor_name != "__metadata__"
                and isinstance(descriptor, dict)
                and isinstance(descriptor.get("shape"), list)
                and all(isinstance(d, int) and not isinstance(d, bool) and d >= 0 for d in descriptor["shape"])
            ):
                if tensor_name in tensor_shapes:
                    report.add(
                        layer="Layer 1 (Safetensors/MLX)",
                        severity=Severity.HIGH,
                        title=f"Duplicate Tensor Name Across Shards ('{tensor_name}')",
                        description="Multiple Safetensors shards declare the same tensor name.",
                        location=str(st_file),
                    )
                tensor_shapes[tensor_name] = descriptor["shape"]

    for py_file in (p for p in files if p.suffix.lower() == ".py"):
        if budget.stop_requested:
            break
        audit_python_file_ast(py_file, report, budget=budget)

    config_paths = {p for p in files if p.name in {"config.json", "tokenizer_config.json"}}
    quant_configs: list[tuple[dict[str, Any], Path]] = []
    for cfg_path in sorted(config_paths):
        if budget.stop_requested:
            break
        try:
            size = cfg_path.stat().st_size
            if size > MAX_MODEL_CONFIG_SIZE:
                report.mark_incomplete(f"model config exceeded {MAX_MODEL_CONFIG_SIZE}-byte scan limit")
                report.add(
                    layer="Layer 1 (MLX/HF Config)",
                    severity=Severity.MEDIUM,
                    title="Model Config Exceeds Scan Limit",
                    description=f"Skipped config larger than {MAX_MODEL_CONFIG_SIZE:,} bytes.",
                    location=str(cfg_path),
                )
                continue
            budget.consume_bytes(size)
            content = cfg_path.read_text(encoding="utf-8", errors="replace")
            text_cache[cfg_path] = content
            cfg = json.loads(content)
            if not isinstance(cfg, dict):
                report.mark_incomplete("model config JSON was not an object")
                report.add(
                    layer="Layer 1 (MLX/HF Config)",
                    severity=Severity.MEDIUM,
                    title="Malformed Model Config",
                    description="Expected a JSON object; static config inspection was skipped.",
                    location=str(cfg_path),
                )
                continue
            if "auto_map" in cfg or cfg.get("trust_remote_code") is True:
                auto_map = cfg.get("auto_map")
                map_keys = sorted(auto_map) if isinstance(auto_map, dict) else []
                report.add(
                    layer="Layer 1 (MLX/HF Config)",
                    severity=Severity.HIGH,
                    title="Remote-Code Mapping or trust_remote_code Flag Found",
                    description=f"Config enables custom model code; auto_map keys={map_keys!r}.",
                    remediation="Ensure you trust the repository author before enabling trust_remote_code.",
                    location=str(cfg_path),
                )
            if isinstance(cfg.get("quantization"), dict):
                quant_configs.append((cfg, cfg_path))
        except ScanLimitExceeded as exc:
            report.mark_incomplete(f"model config scan budget reached: {exc}")
            report.add(
                layer="Scanner",
                severity=Severity.INFO,
                title="Model Config Scan Budget Reached",
                description=f"Skipped config at the configured limit: {exc}.",
                location=str(cfg_path),
            )
        except (OSError, json.JSONDecodeError) as exc:
            report.mark_incomplete("model config could not be inspected")
            report.add(
                layer="Layer 1 (MLX/HF Config)",
                severity=Severity.MEDIUM,
                title="Model Config Could Not Be Inspected",
                description=f"Static config scan failed ({exc.__class__.__name__}).",
                location=str(cfg_path),
            )

    seen_quant_configs: set[tuple[int, int]] = set()
    for cfg, cfg_path in quant_configs:
        quant = cfg.get("quantization", {})
        if not isinstance(quant, dict):
            continue
        bits, group_size = quant.get("bits"), quant.get("group_size")
        signature = (bits, group_size) if isinstance(bits, int) and isinstance(group_size, int) else None
        if signature is not None and signature in seen_quant_configs:
            continue
        if signature is not None:
            seen_quant_configs.add(signature)
        _audit_mlx_quantization(tensor_shapes, cfg, cfg_path, report)

    for tok_cfg_path in (p for p in files if p.name == "tokenizer_config.json"):
        if budget.stop_requested:
            break
        try:
            if tok_cfg_path in text_cache:
                tok_cfg = json.loads(text_cache[tok_cfg_path])
            else:
                size = tok_cfg_path.stat().st_size
                if size > MAX_MODEL_CONFIG_SIZE:
                    report.mark_incomplete("tokenizer config exceeded the config scan limit")
                    continue
                budget.consume_bytes(size)
                text_cache[tok_cfg_path] = tok_cfg_path.read_text(encoding="utf-8", errors="replace")
                tok_cfg = json.loads(text_cache[tok_cfg_path])
            if not isinstance(tok_cfg, dict):
                continue
            template = tok_cfg.get("chat_template")
            if isinstance(template, str):
                chat_templates.append(template)
            elif isinstance(template, list):
                chat_templates.extend(
                    entry["template"] for entry in template
                    if isinstance(entry, dict) and isinstance(entry.get("template"), str)
                )
        except ScanLimitExceeded as exc:
            report.mark_incomplete(f"tokenizer config scan budget reached: {exc}")
            report.add(
                layer="Scanner",
                severity=Severity.INFO,
                title="Tokenizer Config Scan Budget Reached",
                description=f"Skipped tokenizer config at the configured limit: {exc}.",
                location=str(tok_cfg_path),
            )
        except (OSError, json.JSONDecodeError):
            report.mark_incomplete("tokenizer config could not be inspected")

    for jinja_file in (p for p in files if p.name == "chat_template.jinja"):
        if budget.stop_requested:
            break
        try:
            size = jinja_file.stat().st_size
            if size > 1024 * 1024:
                report.mark_incomplete("chat template exceeded 1 MiB parsing limit")
                report.add(
                    layer="Layer 2 (Chat Template)",
                    severity=Severity.INFO,
                    title="Large Chat Template Not Inspected",
                    description="Template file exceeds the 1 MiB parsing limit.",
                    location=str(jinja_file),
                )
                continue
            budget.consume_bytes(size)
            chat_templates.append(jinja_file.read_text(encoding="utf-8", errors="replace"))
        except ScanLimitExceeded as exc:
            report.mark_incomplete(f"chat template scan budget reached: {exc}")
            report.add(
                layer="Scanner",
                severity=Severity.INFO,
                title="Chat Template Scan Budget Reached",
                description=f"Skipped template at the configured limit: {exc}.",
                location=str(jinja_file),
            )
        except OSError:
            report.mark_incomplete("chat template file could not be read")

    if own_budget:
        budget.add_summary_finding(report, str(model_dir))
    return chat_templates
