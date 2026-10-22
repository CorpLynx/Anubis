"""Property-based no-crash tests complement the coverage-guided Atheris harness."""

import struct
from pathlib import Path

from hypothesis import HealthCheck, given, settings, strategies as st

from anubis.inspectors.gguf_inspector import verify_gguf_file
from anubis.inspectors.jinja_ast import audit_jinja_template
from anubis.inspectors.safetensors_mlx import verify_safetensors_file
from anubis.models import ScanReport


@settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(body=st.binary(max_size=2048))
def test_gguf_arbitrary_headers_never_escape_parser(tmp_path: Path, body: bytes) -> None:
    path = tmp_path / "generated.gguf"
    path.write_bytes(b"GGUF" + body)
    report = ScanReport(target=str(path))
    verify_gguf_file(path, report)


@settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(header=st.binary(max_size=1024))
def test_safetensors_arbitrary_json_header_never_escapes_parser(tmp_path: Path, header: bytes) -> None:
    path = tmp_path / "generated.safetensors"
    path.write_bytes(struct.pack("<Q", len(header)) + header)
    report = ScanReport(target=str(path))
    verify_safetensors_file(path, report)


@settings(max_examples=100, deadline=None)
@given(template=st.text(alphabet="{}%#@$'\"/\\ abcdef0123\n", max_size=256))
def test_jinja_arbitrary_templates_never_escape_parser(template: str) -> None:
    report = ScanReport(target="generated-template")
    audit_jinja_template(template, "generated-template", report)
    assert report.findings
