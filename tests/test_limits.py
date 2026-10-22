"""Tests for traversal, byte, time, and symlink scan budgets."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from anubis.limits import ScanBudget, ScanLimitExceeded, parse_byte_size
from anubis.inspectors.env_audit import audit_workspace_secrets
from anubis.models import ScanReport, Severity


def test_file_count_limit_stops_walk_and_reports_incompleteness(tmp_path: Path) -> None:
    for index in range(5):
        (tmp_path / f"{index}.txt").write_text("x")
    budget = ScanBudget(max_files=2, max_depth=4, max_bytes=100, max_seconds=10)

    paths = list(budget.walk_files(tmp_path))
    report = ScanReport(target=str(tmp_path))
    budget.add_summary_finding(report, str(tmp_path))

    assert len(paths) == 2
    assert "file-count limit" in budget.reasons
    assert report.findings[0].severity == Severity.INFO
    assert "incomplete" in report.findings[0].description
    assert report.complete is False
    assert report.incomplete_reasons


def test_max_depth_does_not_descend_and_reports_skipped_directory(tmp_path: Path) -> None:
    nested = tmp_path / "one" / "two"
    nested.mkdir(parents=True)
    (nested / "secret.txt").write_text("skipped")
    budget = ScanBudget(max_files=10, max_depth=0, max_bytes=100, max_seconds=10)

    assert list(budget.walk_files(tmp_path)) == []
    assert "directory-depth limit" in budget.reasons


def test_zero_inode_fallback_uses_distinct_normalized_paths(tmp_path: Path) -> None:
    stat_without_inode = SimpleNamespace(st_dev=0, st_ino=0)
    first = ScanBudget._directory_identity(tmp_path / "one", stat_without_inode)
    second = ScanBudget._directory_identity(tmp_path / "two", stat_without_inode)

    assert first != second


def test_byte_budget_raises_before_exceeding_limit() -> None:
    budget = ScanBudget(max_files=10, max_depth=4, max_bytes=4, max_seconds=10)
    budget.consume_bytes(4)
    with pytest.raises(ScanLimitExceeded):
        budget.consume_bytes(1)
    assert budget.bytes_read == 4


def test_byte_size_parser_has_a_larger_deep_default_and_binary_suffixes() -> None:
    assert parse_byte_size(None) == 2 * 1024**3
    assert parse_byte_size(None, deep=True) == 16 * 1024**3
    assert parse_byte_size("4GiB") == 4 * 1024**3
    assert parse_byte_size("4GB") == 4 * 1000**3
    with pytest.raises(ValueError):
        parse_byte_size("0")


def test_internal_file_symlink_is_allowed_but_external_link_is_skipped(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / "blob").write_text("inside")
    outside = tmp_path / "outside.txt"
    outside.write_text("outside")
    try:
        (root / "snapshot-weight.safetensors").symlink_to(root / "blob")
        (root / "external.txt").symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation is unavailable on this platform")

    budget = ScanBudget(max_files=10, max_depth=4, max_bytes=100, max_seconds=10)
    found = {p.name for p in budget.walk_files(root)}

    assert "snapshot-weight.safetensors" in found
    assert "external.txt" not in found
    assert "symlinks outside the scan root" in budget.reasons


def test_huggingface_snapshot_blob_symlink_is_allowed(tmp_path: Path) -> None:
    hub = tmp_path / "hub"
    model = hub / "models--org--repo"
    snapshot = model / "snapshots" / "abc123"
    blobs = hub / "blobs"
    snapshot.mkdir(parents=True)
    blobs.mkdir()
    blob = blobs / "deadbeef"
    blob.write_bytes(b"weights")
    link = snapshot / "model.safetensors"
    try:
        link.symlink_to(blob)
    except OSError:
        pytest.skip("symlink creation is unavailable on this platform")
    budget = ScanBudget(max_files=10, max_depth=10, max_bytes=100, max_seconds=10)

    found = list(budget.walk_files(model))

    assert link in found
    assert not budget.reasons


def test_workspace_byte_limit_prevents_false_clean_result(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("SECRET=some-value")
    budget = ScanBudget(max_files=10, max_depth=4, max_bytes=4, max_seconds=10)
    report = ScanReport(target=str(tmp_path))

    audit_workspace_secrets(tmp_path, report, budget=budget)
    budget.add_summary_finding(report, str(tmp_path))

    assert not any(f.severity == Severity.PASS for f in report.findings)
    assert any(f.title == "Sensitive Credential File in Workspace ('.env')" for f in report.findings)
    assert any("Scan Limits" in f.title for f in report.findings)
