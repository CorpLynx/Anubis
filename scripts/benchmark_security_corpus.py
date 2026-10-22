#!/usr/bin/env python3
"""Run Anubis against the small labeled local threat corpus."""

import json
from pathlib import Path

from anubis.corpus import run_security_corpus


def main() -> int:
    manifest = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "security_corpus.json"
    result = run_security_corpus(manifest)
    print(json.dumps(result, indent=2))
    return 0 if all(case["pass"] for case in result["cases"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
