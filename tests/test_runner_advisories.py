"""Tests for version-range matching against the curated Ollama OSV snapshot."""

from types import SimpleNamespace

from anubis.inspectors import env_audit
from anubis.models import ScanReport, Severity


def _mock_ollama(monkeypatch, output: str) -> None:
    monkeypatch.setattr(
        env_audit.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(stdout=output, stderr="", returncode=0),
    )


def test_affected_ollama_version_reports_specific_advisories(monkeypatch) -> None:
    _mock_ollama(monkeypatch, "ollama version is 0.3.14")
    report = ScanReport(target="test")

    env_audit.audit_runner_versions(report)

    assert any("GHSA-89qx-m49c-8crf" in f.title for f in report.findings)
    assert any("GHSA-wrh5-cmwx-q2qr" in f.title for f in report.findings)
    assert any(f.severity == Severity.HIGH for f in report.findings)
    assert any(f.severity == Severity.INFO and "Check Complete" in f.title for f in report.findings)


def test_fixed_release_is_not_flagged_for_fixed_advisory(monkeypatch) -> None:
    _mock_ollama(monkeypatch, "ollama version is 0.17.1")
    report = ScanReport(target="test")

    env_audit.audit_runner_versions(report)

    assert not any("GHSA-x8qc-fggm-mpqg" in f.title for f in report.findings)
    # Other advisories have later affected ranges; a fixed release is not a blanket clean bill.
    assert any("GHSA-x99g-8v8j-25j2" in f.title for f in report.findings)


def test_prerelease_before_fix_remains_affected(monkeypatch) -> None:
    _mock_ollama(monkeypatch, "ollama version is 0.17.1-rc1")
    report = ScanReport(target="test")

    env_audit.audit_runner_versions(report)

    assert any("GHSA-x8qc-fggm-mpqg" in f.title for f in report.findings)


def test_newer_unmatched_version_is_not_reported_as_pass(monkeypatch) -> None:
    _mock_ollama(monkeypatch, "ollama version is 0.40.6")
    report = ScanReport(target="test")

    env_audit.audit_runner_versions(report)

    assert not any(f.severity == Severity.PASS for f in report.findings)
    assert any(f.severity == Severity.INFO and "Check Complete" in f.title for f in report.findings)


def test_unparseable_ollama_version_is_info(monkeypatch) -> None:
    _mock_ollama(monkeypatch, "Ollama development build")
    report = ScanReport(target="test")

    env_audit.audit_runner_versions(report)

    assert len(report.findings) == 1
    assert report.findings[0].severity == Severity.INFO
    assert "Could Not Be Parsed" in report.findings[0].title
