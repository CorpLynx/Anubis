"""Benchmark currently supported detection classes against a labeled corpus."""

import json
from pathlib import Path

from anubis.corpus import run_security_corpus


def test_labeled_security_corpus_has_no_known_false_positives_or_negatives() -> None:
    manifest = Path(__file__).parent / "fixtures" / "security_corpus.json"
    result = run_security_corpus(manifest)

    assert all(case["pass"] for case in result["cases"]), json.dumps(result, indent=2)
    assert result["metrics"]["true_positives"] > 0
    assert result["metrics"]["true_negatives"] > 0
    assert result["metrics"]["false_positives"] == 0
    assert result["metrics"]["false_negatives"] == 0
