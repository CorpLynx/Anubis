#!/usr/bin/env python3
"""End-to-end CLI smoke test: scan a clean and a malicious model directory through `anubis scan`."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

CLEAN_TEMPLATE = "{% for m in messages %}<|{{ m['role'] }}|>{{ m['content'] }}\n{% endfor %}<|assistant|>"
MALICIOUS_TEMPLATE = "{{ ''.__class__.__mro__[1].__subclasses__() }}" + CLEAN_TEMPLATE


def write_model_dir(path: Path, template: str) -> Path:
    path.mkdir(parents=True)
    (path / "tokenizer_config.json").write_text(json.dumps({"chat_template": template}), encoding="utf-8")
    return path


def anubis(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "anubis.cli", "scan", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sarif", type=Path, help="Write the malicious directory's SARIF report here.")
    args = parser.parse_args()

    failures: list[str] = []
    with tempfile.TemporaryDirectory(prefix="anubis-smoke-") as tmp:
        clean = write_model_dir(Path(tmp) / "clean", CLEAN_TEMPLATE)
        malicious = write_model_dir(Path(tmp) / "malicious", MALICIOUS_TEMPLATE)

        result = anubis(str(clean), "--fail-on", "high", "--format", "json")
        if result.returncode != 0:
            failures.append(f"clean model: expected exit 0, got {result.returncode}\n{result.stdout}{result.stderr}")

        result = anubis(str(malicious), "--fail-on", "high", "--format", "json")
        if result.returncode != 1:
            failures.append(
                f"malicious model: expected exit 1, got {result.returncode}\n{result.stdout}{result.stderr}"
            )
        else:
            titles = [finding.get("title", "") for finding in json.loads(result.stdout).get("findings", [])]
            if not any("Sandbox Escape" in title for title in titles):
                failures.append(f"malicious model: no sandbox-escape finding in {titles}")

        result = anubis(str(malicious), "--format", "sarif")
        try:
            sarif = json.loads(result.stdout)
            if sarif.get("version") != "2.1.0" or not sarif["runs"][0]["results"]:
                failures.append("SARIF report has an unexpected version or no results")
        except (ValueError, KeyError, IndexError) as exc:
            failures.append(f"SARIF report is not valid: {exc}")
        else:
            if args.sarif:
                args.sarif.write_text(result.stdout, encoding="utf-8")

    for failure in failures:
        print(f"FAIL: {failure}", file=sys.stderr)
    if not failures:
        print("CLI scan smoke test passed.")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
