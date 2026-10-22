"""
Zero-copy GGUF binary header & tensor boundary verifier.
Detects 'Bleeding Llama' heap overread vectors and extracts embedded chat templates
without requiring external C bindings or loading multi-GB weights into memory.
"""

import math
import os
import struct
from pathlib import Path
from typing import Any, Optional

from localguard.models import ScanReport, Severity

GGUF_MAGIC = b"GGUF"
DEFAULT_ALIGNMENT = 32

# GGML Quantization Type Table: type_id -> (type_name, block_size_elements, bytes_per_block)
GGML_QUANT_SIZES: dict[int, tuple[str, int, int]] = {
    0: ("F32", 1, 4),
    1: ("F16", 1, 2),
    2: ("Q4_0", 32, 18),
    3: ("Q4_1", 32, 20),
    6: ("Q5_0", 32, 22),
    7: ("Q5_1", 32, 24),
    8: ("Q8_0", 32, 34),
    9: ("Q8_1", 32, 36),
    10: ("Q2_K", 256, 84),
    11: ("Q3_K", 256, 110),
    12: ("Q4_K", 256, 144),
    13: ("Q5_K", 256, 176),
    14: ("Q6_K", 256, 210),
    15: ("Q8_K", 256, 292),
    16: ("IQ2_XXS", 256, 66),
    17: ("IQ2_XS", 256, 74),
    18: ("IQ3_XXS", 256, 98),
    19: ("IQ1_S", 256, 50),
    20: ("IQ4_NL", 32, 18),
    21: ("IQ3_S", 256, 110),
    22: ("IQ2_S", 256, 82),
    23: ("IQ4_XS", 256, 136),
    24: ("I8", 1, 1),
    25: ("I16", 1, 2),
    26: ("I32", 1, 4),
    27: ("I64", 1, 8),
    28: ("F64", 1, 8),
    29: ("IQ1_M", 256, 56),
    30: ("BF16", 1, 2),
}


class GGUFParseError(Exception):
    pass


class _BinaryReader:
    def __init__(self, f):
        self.f = f

    def read_bytes(self, n: int) -> bytes:
        data = self.f.read(n)
        if len(data) != n:
            raise GGUFParseError(f"Unexpected EOF while reading {n} bytes at offset {self.f.tell()}")
        return data

    def u8(self) -> int:
        return struct.unpack("<B", self.read_bytes(1))[0]

    def i8(self) -> int:
        return struct.unpack("<b", self.read_bytes(1))[0]

    def u16(self) -> int:
        return struct.unpack("<H", self.read_bytes(2))[0]

    def i16(self) -> int:
        return struct.unpack("<h", self.read_bytes(2))[0]

    def u32(self) -> int:
        return struct.unpack("<I", self.read_bytes(4))[0]

    def i32(self) -> int:
        return struct.unpack("<i", self.read_bytes(4))[0]

    def u64(self) -> int:
        return struct.unpack("<Q", self.read_bytes(8))[0]

    def i64(self) -> int:
        return struct.unpack("<q", self.read_bytes(8))[0]

    def f32(self) -> float:
        return struct.unpack("<f", self.read_bytes(4))[0]

    def f64(self) -> float:
        return struct.unpack("<d", self.read_bytes(8))[0]

    def boolean(self) -> bool:
        val = self.u8()
        if val not in (0, 1):
            raise GGUFParseError(f"Invalid GGUF boolean value: {val}")
        return bool(val)

    def string(self, max_len: int = 10 * 1024 * 1024) -> str:
        length = self.u64()
        if length > max_len:
            raise GGUFParseError(f"String length {length} exceeds safety cap ({max_len} bytes)")
        return self.read_bytes(length).decode("utf-8", errors="replace")

    def read_value(self, vtype: int, skip_large_arrays: bool = True) -> Any:
        if vtype == 0:
            return self.u8()
        elif vtype == 1:
            return self.i8()
        elif vtype == 2:
            return self.u16()
        elif vtype == 3:
            return self.i16()
        elif vtype == 4:
            return self.u32()
        elif vtype == 5:
            return self.i32()
        elif vtype == 6:
            return self.f32()
        elif vtype == 7:
            return self.boolean()
        elif vtype == 8:
            return self.string()
        elif vtype == 9:  # GGUF_TYPE_ARRAY
            elem_type = self.u32()
            count = self.u64()
            if count > 50_000_000:
                raise GGUFParseError(f"GGUF array count {count} exceeds safety threshold")
            # Skip large vocabulary arrays to keep scanning under 50ms
            if skip_large_arrays and count > 256:
                fixed_sizes = {0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 1, 10: 8, 11: 8, 12: 8}
                if elem_type in fixed_sizes:
                    self.f.seek(count * fixed_sizes[elem_type], os.SEEK_CUR)
                    return f"<skipped_array len={count}>"
                elif elem_type == 8:
                    for _ in range(count):
                        slen = self.u64()
                        self.f.seek(slen, os.SEEK_CUR)
                    return f"<skipped_str_array len={count}>"
            return [self.read_value(elem_type, skip_large_arrays) for _ in range(count)]
        elif vtype == 10:
            return self.u64()
        elif vtype == 11:
            return self.i64()
        elif vtype == 12:
            return self.f64()
        else:
            raise GGUFParseError(f"Unknown GGUF metadata value type ID: {vtype}")


def verify_gguf_file(path: Path, report: ScanReport) -> dict[str, Any]:
    """
    Parses a GGUF file header and verifies all tensor dimensions and offsets
    against the actual physical file size on disk.
    Returns extracted metadata (such as `tokenizer.chat_template`).
    """
    metadata: dict[str, Any] = {}
    file_size = path.stat().st_size

    try:
        with open(path, "rb") as f:
            reader = _BinaryReader(f)
            magic = reader.read_bytes(4)
            if magic != GGUF_MAGIC:
                report.add(
                    layer="Layer 1 (GGUF Binary)",
                    severity=Severity.CRITICAL,
                    title="Invalid GGUF Magic Bytes",
                    description=f"Expected b'GGUF', found {magic!r}.",
                    location=str(path),
                )
                return metadata

            version = reader.u32()
            if version not in (2, 3):
                report.add(
                    layer="Layer 1 (GGUF Binary)",
                    severity=Severity.HIGH,
                    title=f"Unsupported GGUF Version ({version})",
                    description="Only GGUF v2 and v3 specifications are standard.",
                    location=str(path),
                )

            tensor_count = reader.u64()
            kv_count = reader.u64()

            if tensor_count > 1_000_000 or kv_count > 100_000:
                report.add(
                    layer="Layer 1 (GGUF Binary)",
                    severity=Severity.CRITICAL,
                    title="Header Count Allocation Bomb",
                    description=f"Suspicious header counts: tensor_count={tensor_count}, kv_count={kv_count}.",
                    remediation="Do not load this file; it may trigger a heap allocation crash in llama.cpp/Ollama.",
                    location=str(path),
                )
                return metadata

            # Read Key-Value Metadata
            for _ in range(kv_count):
                key = reader.string(max_len=4096)
                vtype = reader.u32()
                val = reader.read_value(vtype, skip_large_arrays=True)
                metadata[key] = val

            alignment = int(metadata.get("general.alignment", DEFAULT_ALIGNMENT))
            if alignment <= 0 or (alignment & (alignment - 1)) != 0:
                report.add(
                    layer="Layer 1 (GGUF Binary)",
                    severity=Severity.HIGH,
                    title="Non-Power-of-Two Memory Alignment",
                    description=f"general.alignment is set to {alignment}, which can cause pointer miscalculation.",
                    location=str(path),
                )
                alignment = DEFAULT_ALIGNMENT

            # Read Tensor Info Headers
            tensors = []
            for _ in range(tensor_count):
                t_name = reader.string(max_len=1024)
                n_dims = reader.u32()
                if n_dims == 0 or n_dims > 8:
                    report.add(
                        layer="Layer 1 (GGUF Binary)",
                        severity=Severity.CRITICAL,
                        title="Malformed Tensor Dimensionality",
                        description=f"Tensor '{t_name}' declares n_dims={n_dims} (expected 1..8).",
                        location=str(path),
                    )
                    return metadata
                dims = [reader.u64() for _ in range(n_dims)]
                ggml_type = reader.u32()
                rel_offset = reader.u64()
                tensors.append((t_name, dims, ggml_type, rel_offset))

            header_end = f.tell()
            # Calculate aligned start of the raw data segment
            remainder = header_end % alignment
            data_section_offset = header_end if remainder == 0 else header_end + (alignment - remainder)

            # Verify every tensor's byte size and offset bounds
            spans: list[tuple[int, int, str]] = []
            overflow_errors = 0

            for t_name, dims, ggml_type, rel_offset in tensors:
                if any(d <= 0 for d in dims):
                    report.add(
                        layer="Layer 1 (GGUF Binary)",
                        severity=Severity.CRITICAL,
                        title="Zero or Negative Tensor Dimension",
                        description=f"Tensor '{t_name}' has invalid dimensions {dims}.",
                        location=str(path),
                    )
                    overflow_errors += 1
                    continue

                num_elements = math.prod(dims)
                if ggml_type not in GGML_QUANT_SIZES:
                    report.add(
                        layer="Layer 1 (GGUF Binary)",
                        severity=Severity.MEDIUM,
                        title="Unrecognized GGML Quantization Type",
                        description=f"Tensor '{t_name}' uses unknown ggml_type ID {ggml_type}.",
                        location=str(path),
                    )
                    continue

                type_name, block_size, type_size = GGML_QUANT_SIZES[ggml_type]
                if num_elements % block_size != 0:
                    report.add(
                        layer="Layer 1 (GGUF Binary)",
                        severity=Severity.CRITICAL,
                        title="Quantization Block Alignment Mismatch",
                        description=(
                            f"Tensor '{t_name}' ({type_name}) has {num_elements} elements, "
                            f"which is not divisible by block_size={block_size}."
                        ),
                        remediation="Indicates corrupted or maliciously crafted tensor dimensions.",
                        location=str(path),
                    )
                    overflow_errors += 1
                    continue

                byte_length = (num_elements // block_size) * type_size
                abs_start = data_section_offset + rel_offset
                abs_end = abs_start + byte_length

                if abs_end > file_size:
                    report.add(
                        layer="Layer 1 (GGUF Binary)",
                        severity=Severity.CRITICAL,
                        title="Tensor Out-of-Bounds Overread (Bleeding Llama Vector)",
                        description=(
                            f"Tensor '{t_name}' ({type_name}, shape={dims}) reads up to byte {abs_end:,}, "
                            f"exceeding physical file size ({file_size:,} bytes) by {abs_end - file_size:,} bytes."
                        ),
                        remediation="DELETE THIS MODEL IMMEDIATELY. Loading it can leak process heap memory.",
                        location=str(path),
                    )
                    overflow_errors += 1
                else:
                    spans.append((abs_start, abs_end, t_name))

            # Check for overlapping tensors
            spans.sort(key=lambda x: x[0])
            for idx in range(len(spans) - 1):
                cur_start, cur_end, cur_name = spans[idx]
                next_start, _, next_name = spans[idx + 1]
                if cur_end > next_start:
                    report.add(
                        layer="Layer 1 (GGUF Binary)",
                        severity=Severity.HIGH,
                        title="Overlapping Tensor Data Regions",
                        description=(
                            f"Tensor '{cur_name}' [{cur_start}..{cur_end}] overlaps with "
                            f"'{next_name}' starting at {next_start}."
                        ),
                        location=str(path),
                    )
                    overflow_errors += 1

            if overflow_errors == 0:
                report.add(
                    layer="Layer 1 (GGUF Binary)",
                    severity=Severity.PASS,
                    title="GGUF Tensor Boundary Verification Passed",
                    description=(
                        f"Verified {len(tensors)} tensors across {file_size / (1024**2):.2f} MB. "
                        "All tensor offsets and quantization blocks match physical file bounds."
                    ),
                    location=str(path),
                )

    except GGUFParseError as exc:
        report.add(
            layer="Layer 1 (GGUF Binary)",
            severity=Severity.CRITICAL,
            title="Corrupted or Truncated GGUF Header",
            description=str(exc),
            remediation="Do not load this file in Ollama or llama.cpp.",
            location=str(path),
        )

    return metadata
