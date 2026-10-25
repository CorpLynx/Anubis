"""Offline tests for Hugging Face provenance and upstream integrity checks."""

import hashlib
import urllib.error
from pathlib import Path

from anubis.inspectors import provenance
from anubis.models import ScanReport, Severity


def _repo_file(tmp_path: Path, content: bytes = b"model weights") -> Path:
    snapshot = tmp_path / "models--mlx-community--sample-model" / "snapshots" / "abc123"
    snapshot.mkdir(parents=True)
    weight = snapshot / "model.safetensors"
    weight.write_bytes(content)
    return weight


def _fake_hub(monkeypatch, weight: Path, *, author="mlx-community", downloads=1000, oid=None, size=None):
    payload_size = weight.stat().st_size if size is None else size
    info = {"author": author, "downloads": downloads, "name": "sample-model"}
    tree = [{"path": "model.safetensors", "size": payload_size, "lfs": {"oid": f"sha256:{oid}"} if oid else {}}]

    def fake_get_json(url: str, timeout: float = 6.0, budget=None):
        if "/tree/" in url:
            return tree
        return info

    monkeypatch.setattr(provenance, "_get_json", fake_get_json)


def test_hf_trusted_repo_and_deep_hash_pass(tmp_path: Path, monkeypatch) -> None:
    weight = _repo_file(tmp_path)
    oid = hashlib.sha256(weight.read_bytes()).hexdigest()
    _fake_hub(monkeypatch, weight, oid=oid)

    report = ScanReport(target=str(weight))
    provenance.verify_upstream(weight, report, deep=True)

    assert any(f.severity == Severity.INFO and "Recognized Organization" in f.title for f in report.findings)
    assert any(f.severity == Severity.PASS and "SHA256" in f.title for f in report.findings)


def test_hf_same_size_tampering_fails_sha256(tmp_path: Path, monkeypatch) -> None:
    weight = _repo_file(tmp_path, b"tampered data")
    expected_oid = hashlib.sha256(b"original data").hexdigest()
    _fake_hub(monkeypatch, weight, oid=expected_oid, size=len(b"tampered data"))

    report = ScanReport(target=str(weight))
    provenance.verify_upstream(weight, report, deep=True)

    assert any(f.severity == Severity.CRITICAL and "SHA256 Differs" in f.title for f in report.findings)


def test_hf_size_mismatch_is_high(tmp_path: Path, monkeypatch) -> None:
    weight = _repo_file(tmp_path, b"local file")
    _fake_hub(monkeypatch, weight, size=999)

    report = ScanReport(target=str(weight))
    provenance.verify_upstream(weight, report)

    assert any(f.severity == Severity.HIGH and "Size Differs" in f.title for f in report.findings)


def test_hf_missing_repo_degrades_to_finding(tmp_path: Path, monkeypatch) -> None:
    weight = _repo_file(tmp_path)

    def not_found(url: str, timeout: float = 6.0, budget=None):
        raise urllib.error.HTTPError(url, 404, "not found", {}, None)

    monkeypatch.setattr(provenance, "_get_json", not_found)
    report = ScanReport(target=str(weight))
    provenance.verify_upstream(weight, report)

    assert any(f.severity == Severity.MEDIUM and "Not Publicly Verifiable" in f.title for f in report.findings)


def test_hf_offline_fails_open_as_info(tmp_path: Path, monkeypatch) -> None:
    weight = _repo_file(tmp_path)

    def offline(url: str, timeout: float = 6.0, budget=None):
        raise TimeoutError("network unavailable")

    monkeypatch.setattr(provenance, "_get_json", offline)
    report = ScanReport(target=str(weight))
    provenance.verify_upstream(weight, report)

    assert len(report.findings) == 1
    assert report.findings[0].severity == Severity.INFO
    assert "Offline" in report.findings[0].title


def test_untrusted_low_adoption_upstream_is_medium(tmp_path: Path, monkeypatch) -> None:
    weight = _repo_file(tmp_path)
    _fake_hub(monkeypatch, weight, author="unknown-uploader", downloads=12)

    report = ScanReport(target=str(weight))
    provenance.verify_upstream(weight, report)

    assert any(f.severity == Severity.MEDIUM and "Low-Adoption" in f.title for f in report.findings)


def test_directory_name_is_only_a_heuristic_not_a_trust_pass(tmp_path: Path) -> None:
    fake_claim = tmp_path / "models--meta-llama--made-up-model"
    fake_claim.mkdir()
    report = ScanReport(target=str(fake_claim))

    provenance.audit_model_provenance(fake_claim, {}, report)

    assert any(f.severity == Severity.INFO and "Uploader Name Heuristic" in f.title for f in report.findings)
    assert not any(f.severity == Severity.PASS for f in report.findings)


def test_upstream_path_match_disambiguates_duplicate_basenames(tmp_path: Path, monkeypatch) -> None:
    snapshot = tmp_path / "models--unknown--sample" / "snapshots" / "abc123"
    nested = snapshot / "sub"
    nested.mkdir(parents=True)
    weight = nested / "model.safetensors"
    weight.write_bytes(b"local bytes")
    info = {"author": "unknown", "downloads": 1000, "name": "sample", "sha": "abc123"}
    tree = [
        {"path": "sub/model.safetensors", "size": 900},
        {"path": "other/model.safetensors", "size": weight.stat().st_size},
    ]

    def fake_get_json(url: str, timeout: float = 6.0, budget=None):
        return tree if "/tree/" in url else info

    monkeypatch.setattr(provenance, "_get_json", fake_get_json)
    report = ScanReport(target=str(snapshot))

    provenance.verify_upstream(snapshot, report)

    assert any(f.severity == Severity.HIGH and "Size Differs" in f.title for f in report.findings)
