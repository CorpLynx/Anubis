"""Shared resource limits for directory walks and bytes read during scans."""

from __future__ import annotations

import os
import stat
import time
from pathlib import Path
from typing import Iterator

from anubis.models import ScanReport, Severity

DEFAULT_SKIP_DIRS = {
    ".git", ".venv", "venv", "node_modules", "__pycache__", ".cache", ".pytest_cache",
    ".ruff_cache", ".eggs", "build", "dist",
}


class ScanLimitExceeded(Exception):
    """Raised when a scan reaches a configured input/time budget."""


class ScanBudget:
    def __init__(
        self,
        *,
        max_files: int = 20_000,
        max_depth: int = 64,
        max_bytes: int = 2 * 1024**3,
        max_seconds: float = 120.0,
        follow_symlinks: bool = False,
    ) -> None:
        if max_files < 1 or max_depth < 0 or max_bytes < 1 or max_seconds <= 0:
            raise ValueError("scan limits must be positive (max_depth may be zero)")
        self.max_files = max_files
        self.max_depth = max_depth
        self.max_bytes = max_bytes
        self.max_seconds = max_seconds
        self.follow_symlinks = follow_symlinks
        self.started = time.monotonic()
        self.files_seen = 0
        self.entries_seen = 0
        self.bytes_read = 0
        self.skipped_symlinks = 0
        self.skipped_paths = 0
        self.reasons: set[str] = set()

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.started

    @property
    def remaining_seconds(self) -> float:
        return max(0.0, self.max_seconds - self.elapsed)

    def check_time(self) -> None:
        if self.elapsed >= self.max_seconds:
            self.reasons.add("time limit")
            raise ScanLimitExceeded("scan time limit reached")

    def consume_bytes(self, count: int) -> None:
        self.check_bytes(count)
        self.bytes_read += count

    def check_bytes(self, count: int) -> None:
        self.check_time()
        if count < 0 or self.bytes_read + count > self.max_bytes:
            self.reasons.add("total byte limit")
            raise ScanLimitExceeded("total bytes-read limit reached")

    def _claim_file(self) -> bool:
        if self.files_seen >= self.max_files:
            self.reasons.add("file-count limit")
            return False
        self.files_seen += 1
        return True

    def note(self, reason: str) -> None:
        self.reasons.add(reason)

    @property
    def stop_requested(self) -> bool:
        return bool({"time limit", "total byte limit"} & self.reasons)

    @staticmethod
    def _is_within(path: Path, root: Path) -> bool:
        try:
            root_norm = os.path.normcase(os.path.abspath(os.fspath(root)))
            path_norm = os.path.normcase(os.path.abspath(os.fspath(path)))
            return os.path.commonpath((root_norm, path_norm)) == root_norm
        except (OSError, ValueError):
            return False

    @staticmethod
    def _directory_identity(path: Path, stat_result: os.stat_result) -> tuple[str, str | int, int | None]:
        inode = getattr(stat_result, "st_ino", 0)
        if inode:
            return "inode", stat_result.st_dev, inode
        # Some Windows filesystems return zero for st_ino. A normalized canonical
        # path still detects cycles without collapsing every directory together.
        canonical = os.path.normcase(os.path.abspath(os.fspath(path.resolve(strict=False))))
        return "path", canonical, None

    def walk_files(
        self,
        root: Path,
        *,
        skip_dirs: set[str] | None = None,
    ) -> Iterator[Path]:
        """Walk regular files with bounded traversal, never following links outside root.

        File symlinks that resolve inside root are allowed (HF Hub snapshots use them).
        Directory symlinks are skipped unless `follow_symlinks=True`, and inode tracking
        prevents cycles when internal directory links are followed.
        """
        root = Path(root)
        if root.is_symlink() and not self.follow_symlinks:
            # An explicitly selected symlink file is an intentional target; directory
            # symlinks remain opt-in to avoid expanding the traversal unexpectedly.
            if root.is_file():
                if self._claim_file():
                    yield root
            else:
                self.skipped_symlinks += 1
            return
        try:
            resolved_root = root.resolve(strict=True)
        except (OSError, RuntimeError, RecursionError):
            self.skipped_paths += 1
            self.reasons.add("unreadable paths")
            return

        # Hugging Face Hub snapshots intentionally symlink files to the sibling
        # `blobs/` store. Allow that one known cache layout without opening traversal
        # to arbitrary siblings or external paths.
        hf_blob_root: Path | None = None
        if root.name.startswith("models--") and (root.parent / "blobs").is_dir():
            try:
                hf_blob_root = (root.parent / "blobs").resolve(strict=True)
            except (OSError, RuntimeError, RecursionError):
                hf_blob_root = None

        if resolved_root.is_file():
            if self._claim_file():
                yield root
            return
        if not resolved_root.is_dir():
            self.skipped_paths += 1
            return

        omitted = DEFAULT_SKIP_DIRS if skip_dirs is None else skip_dirs
        try:
            root_stat = resolved_root.stat()
            visited_dirs = {self._directory_identity(resolved_root, root_stat)}
        except OSError:
            visited_dirs = set()
        stack: list[tuple[Path, int]] = [(resolved_root, 0)]
        stop = False

        while stack and not stop:
            try:
                self.check_time()
            except ScanLimitExceeded:
                break
            directory, depth = stack.pop()
            try:
                iterator = os.scandir(directory)
            except OSError:
                self.skipped_paths += 1
                self.reasons.add("unreadable directories")
                continue

            child_dirs: list[Path] = []
            try:
                with iterator:
                    for entry in iterator:
                        try:
                            try:
                                self.check_time()
                            except ScanLimitExceeded:
                                stop = True
                                break
                            self.entries_seen += 1
                            if self.entries_seen > max(1_000, self.max_files * 2):
                                self.reasons.add("directory-entry limit")
                                stop = True
                                break
                            is_link = entry.is_symlink()
                            skip_dir_name = entry.name in omitted or entry.name.endswith(".egg-info")
                            if not is_link and skip_dir_name and entry.is_dir(follow_symlinks=False):
                                continue
                            if is_link:
                                resolved_entry = Path(entry.path).resolve(strict=False)
                                inside_scan_root = self._is_within(resolved_entry, resolved_root)
                                inside_hf_blob_store = (
                                    hf_blob_root is not None
                                    and self._is_within(resolved_entry, hf_blob_root)
                                )
                                if not inside_scan_root and not inside_hf_blob_store:
                                    self.skipped_symlinks += 1
                                    self.reasons.add("symlinks outside the scan root")
                                    continue
                                entry_stat = entry.stat(follow_symlinks=True)
                                if stat.S_ISDIR(entry_stat.st_mode):
                                    if skip_dir_name:
                                        self.skipped_symlinks += 1
                                        continue
                                    if not self.follow_symlinks:
                                        self.skipped_symlinks += 1
                                        continue
                                    is_dir = True
                                else:
                                    is_dir = False
                            else:
                                entry_stat = entry.stat(follow_symlinks=False)
                                is_dir = stat.S_ISDIR(entry_stat.st_mode)

                            if is_dir:
                                if depth >= self.max_depth:
                                    self.reasons.add("directory-depth limit")
                                    self.skipped_paths += 1
                                    continue
                                identity = self._directory_identity(Path(entry.path), entry_stat)
                                if identity in visited_dirs:
                                    self.skipped_symlinks += 1
                                    continue
                                visited_dirs.add(identity)
                                child_dirs.append(Path(entry.path))
                            elif stat.S_ISREG(entry_stat.st_mode):
                                if not self._claim_file():
                                    stop = True
                                    break
                                yield Path(entry.path)
                        except (OSError, RuntimeError, RecursionError):
                            self.skipped_paths += 1
                            self.reasons.add("unreadable paths")
            except OSError:
                self.skipped_paths += 1
                self.reasons.add("unreadable directories")
            # Push in reverse so the next pop visits directories in sorted order.
            stack.extend((path, depth + 1) for path in reversed(child_dirs))

    def add_summary_finding(self, report: ScanReport, target: str) -> None:
        if not self.reasons and not self.skipped_symlinks and not self.skipped_paths:
            return
        details = sorted(self.reasons)
        if self.skipped_symlinks:
            details.append(f"skipped {self.skipped_symlinks} symlink(s)")
        if self.skipped_paths:
            details.append(f"skipped {self.skipped_paths} unreadable/depth-limited path(s)")
        report.add(
            layer="Scanner",
            severity=Severity.INFO,
            title="Scan Limits or Path Policy Applied",
            description=(
                f"Processed {self.files_seen} file(s) across {self.entries_seen} directory entries and "
                f"{self.bytes_read:,} byte(s) in "
                f"{self.elapsed:.1f}s. " + "; ".join(details) + ". Findings may be incomplete."
            ),
            remediation="Review the scan limits and symlink policy, then rerun if complete coverage is required.",
            location=target,
        )
