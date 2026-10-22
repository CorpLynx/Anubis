#!/usr/bin/env python3
"""Coverage-guided fuzz entry point. Usage: python scripts/fuzz_anubis.py {gguf|safetensors|jinja} [libFuzzer options]."""

from __future__ import annotations

import sys
import struct
import tempfile
from pathlib import Path

if len(sys.argv) < 2 or sys.argv[1] not in {"gguf", "safetensors", "jinja"}:
    raise SystemExit(__doc__)

mode = sys.argv.pop(1)

try:
    import atheris
except ImportError as exc:
    raise SystemExit("Atheris fuzzing requires the Linux [fuzz] extra and Clang/libFuzzer.") from exc

with atheris.instrument_imports():
    from anubis.inspectors.gguf_inspector import verify_gguf_file
    from anubis.inspectors.jinja_ast import audit_jinja_template
    from anubis.inspectors.safetensors_mlx import verify_safetensors_file
    from anubis.models import ScanReport

MAX_FUZZ_INPUT = 64 * 1024


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="anubis-fuzz-") as tmp:
        root = Path(tmp)
        fuzz_path = root / ("input.gguf" if mode == "gguf" else "input.safetensors")
        corpus = root / "corpus"
        corpus.mkdir()
        if mode == "gguf":
            (corpus / "gguf-magic-truncated").write_bytes(b"GGUF" + struct.pack("<IQQ", 3, 0, 0))
            (corpus / "arbitrary-bytes").write_bytes(b"not-a-gguf")
        elif mode == "safetensors":
            (corpus / "empty-header-object").write_bytes(struct.pack("<Q", 2) + b"{}")
            (corpus / "truncated-prefix").write_bytes(b"\x08\x00")
        else:
            (corpus / "clean-template").write_text("{% for m in messages %}{{ m.content }}{% endfor %}")
            (corpus / "broken-template").write_text("{% if x %}{{")

        @atheris.instrument_func
        def test_one_input(data: bytes) -> None:
            if len(data) > MAX_FUZZ_INPUT:
                return
            report = ScanReport(target=f"fuzz:{mode}")
            if mode == "gguf":
                fuzz_path.write_bytes(data)
                verify_gguf_file(fuzz_path, report)
            elif mode == "safetensors":
                fuzz_path.write_bytes(data)
                verify_safetensors_file(fuzz_path, report)
            else:
                audit_jinja_template(data.decode("utf-8", errors="replace"), "fuzz:jinja", report)

        fuzzer_args = sys.argv[1:]
        sys.argv = [sys.argv[0], str(corpus), *fuzzer_args]
        atheris.Setup(sys.argv, test_one_input)
        atheris.Fuzz()


if __name__ == "__main__":
    main()
