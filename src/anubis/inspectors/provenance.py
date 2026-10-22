"""
Layer 5: Supply Chain & Provenance Tiering.
Evaluates model origin from Hugging Face cache paths or GGUF metadata, and can
optionally verify the model against the live Hugging Face Hub API (offline-safe:
all network failures degrade to INFO findings, never crashes).
"""

import hashlib
import json
import os
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Optional
from urllib.parse import quote

from anubis.limits import ScanBudget, ScanLimitExceeded
from anubis.models import ScanReport, Severity

RECOGNIZED_ORGS = {
    "mlx-community",
    "bartowski",
    "unsloth",
    "ggml-org",
    "meta-llama",
    "qwen",
    "mistralai",
    "google",
    "microsoft",
    "deepseek-ai",
    "hexgrad",
    "huggingfacetb",
}

HIGH_RISK_KEYWORDS = {"obliterated", "abliterated", "uncensored", "jailbroken", "dark"}

HF_API_BASE = "https://huggingface.co/api/models"
HF_REPO_URL_RE = re.compile(r"huggingface\.co/([^/\s]+/[^/\s?#]+)")
WEIGHT_SUFFIXES = {".gguf", ".safetensors", ".bin", ".pt", ".pth"}
SNAPSHOT_REVISION_RE = re.compile(r"[0-9a-fA-F]{6,64}\Z")


def _derive_repo_id(path: Path, gguf_metadata: dict[str, Any]) -> Optional[str]:
    """Resolves 'org/repo' from HF cache path layout or embedded GGUF metadata."""
    for part in path.parts:
        if part.startswith("models--"):
            segments = part.split("--")
            if len(segments) >= 3:
                return f"{segments[1]}/{segments[2]}"
            return None

    repo_url = str(gguf_metadata.get("general.repo_url", ""))
    m = HF_REPO_URL_RE.search(repo_url)
    if m:
        return m.group(1)
    return None


def _get_json(url: str, timeout: float = 6.0, budget: Optional[ScanBudget] = None) -> Any:
    """Single seam for all Hub API GETs (monkeypatched in tests)."""
    if budget:
        budget.check_time()
        timeout = min(timeout, budget.remaining_seconds)
    req = urllib.request.Request(url, headers={"User-Agent": "anubis-ai/0.1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read(32 * 1024 * 1024 + 1)
    if len(body) > 32 * 1024 * 1024:
        raise ValueError("Hugging Face API response exceeds 32 MiB safety limit")
    if budget:
        budget.consume_bytes(len(body))
    return json.loads(body.decode("utf-8"))


def _sha256_of(
    path: Path, chunk_size: int = 8 * 1024 * 1024, budget: Optional[ScanBudget] = None
) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        file_size = path.stat().st_size
        total = 0
        while True:
            read_size = min(chunk_size, file_size - total) if file_size >= total else chunk_size
            if read_size <= 0:
                break
            if budget:
                budget.check_bytes(read_size)
            chunk = f.read(read_size)
            if not chunk:
                break
            if budget:
                budget.consume_bytes(len(chunk))
            h.update(chunk)
            total += len(chunk)
    return h.hexdigest()


def _download_count(info: dict[str, Any]) -> int:
    value = info.get("downloads")
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def _select_local_snapshot(
    path: Path, budget: Optional[ScanBudget] = None
) -> tuple[Optional[Path], Optional[str], bool]:
    """Returns a specific HF snapshot root/revision when the target is in a Hub cache."""
    parts = path.parts
    if "snapshots" in parts:
        index = parts.index("snapshots")
        if index + 1 < len(parts):
            revision = parts[index + 1]
            snapshot_root = path if path.is_dir() and path.name == revision else None
            return snapshot_root, revision, False

    if not path.is_dir() or not (path / "snapshots").is_dir():
        return None, None, False

    snapshots_root = path / "snapshots"
    refs_main = path / "refs" / "main"
    try:
        ref_size = refs_main.stat().st_size
        if ref_size > 256:
            main_revision = ""
        else:
            if budget:
                budget.consume_bytes(ref_size)
            main_revision = refs_main.read_text(encoding="utf-8").strip()
    except OSError:
        main_revision = ""

    if SNAPSHOT_REVISION_RE.fullmatch(main_revision):
        selected = snapshots_root / main_revision
        if selected.is_dir():
            return selected, main_revision, False

    snapshots: list[Path] = []
    snapshot_limit = min(1000, budget.max_files if budget else 1000)
    try:
        with os.scandir(snapshots_root) as entries:
            for entry in entries:
                if budget:
                    budget.check_time()
                if len(snapshots) >= snapshot_limit:
                    if budget:
                        budget.note("snapshot revision index limit")
                    return None, None, True
                if entry.is_dir(follow_symlinks=False):
                    snapshots.append(Path(entry.path))
    except ScanLimitExceeded:
        raise
    except OSError:
        return None, None, False
    if len(snapshots) == 1:
        return snapshots[0], snapshots[0].name, False
    return None, None, len(snapshots) > 1


def verify_upstream(
    path: Path,
    report: ScanReport,
    deep: bool = False,
    timeout: float = 6.0,
    gguf_metadata: Optional[dict[str, Any]] = None,
    budget: Optional[ScanBudget] = None,
    local_files: Optional[list[Path]] = None,
) -> None:
    """
    Online provenance check against the Hugging Face Hub API.

    - Confirms the upstream repository exists and is not gated/private.
    - Compares every local weight file's size against the upstream tree.
    - With deep=True (implies streaming SHA256), verifies the file's hash against
      the upstream LFS OID, catching silently tampered weights that match on size.
    """
    repo_id = _derive_repo_id(path, gguf_metadata or {})
    if repo_id is None:
        report.mark_incomplete("HF repository ID could not be derived for online verification")
        report.add(
            layer="Layer 5 (Upstream Verification)",
            severity=Severity.INFO,
            title="Upstream Repository Not Derivable",
            description=(
                "Could not resolve an 'org/repo' identifier from the local path or file metadata; "
                "online verification skipped."
            ),
            location=str(path),
        )
        return

    try:
        snapshot_root, snapshot_revision, ambiguous_snapshots = _select_local_snapshot(path, budget)
    except ScanLimitExceeded as exc:
        report.mark_incomplete("HF snapshot reference could not be inspected within scan limits")
        report.add(
            layer="Scanner",
            severity=Severity.INFO,
            title="Snapshot Reference Check Reached Scan Budget",
            description=f"Could not inspect the local Hugging Face refs ({exc}).",
            location=str(path),
        )
        return

    try:
        encoded_repo_id = quote(repo_id, safe="/")
        info = _get_json(f"{HF_API_BASE}/{encoded_repo_id}", timeout=timeout, budget=budget)
    except urllib.error.HTTPError as exc:
        report.mark_incomplete(f"HF repository lookup did not complete successfully (HTTP {exc.code})")
        if exc.code in (401, 403, 404):
            report.add(
                layer="Layer 5 (Upstream Verification)",
                severity=Severity.MEDIUM,
                title=f"Repository '{repo_id}' Not Publicly Verifiable on HF Hub",
                description=(
                    f"Hugging Face API returned HTTP {exc.code}. The model claims to come from "
                    f"'{repo_id}', which does not exist publicly (or is gated/private). "
                    "A non-existent upstream for a file claiming that origin is a classic fake-repo supply-chain trick."
                ),
                remediation="Only accept this model if it was transferred from a verified local copy you control.",
                location=str(path),
            )
        else:
            report.add(
                layer="Layer 5 (Upstream Verification)",
                severity=Severity.INFO,
                title="Upstream Verification Inconclusive",
                description=f"Hugging Face API returned HTTP {exc.code}.",
                location=str(path),
            )
        return
    except Exception as exc:
        report.mark_incomplete("HF repository lookup was unavailable")
        report.add(
            layer="Layer 5 (Upstream Verification)",
            severity=Severity.INFO,
            title="Offline — Upstream Verification Skipped",
            description=f"Could not reach the Hugging Face API ({exc.__class__.__name__}).",
            location=str(path),
        )
        return

    if not isinstance(info, dict):
        report.mark_incomplete("HF repository API response was malformed")
        report.add(
            layer="Layer 5 (Upstream Verification)",
            severity=Severity.INFO,
            title="Malformed HF API Response",
            description="Hub API did not return a JSON object; online verification skipped.",
            location=str(path),
        )
        return

    # Tier heuristics on the confirmed upstream identity
    upstream_name = str(info.get("name") or repo_id).lower()
    matched_risk_words = [kw for kw in HIGH_RISK_KEYWORDS if kw in upstream_name]
    author = str(info.get("author") or repo_id.split("/")[0]).lower()

    if matched_risk_words:
        report.add(
            layer="Layer 5 (Upstream Verification)",
            severity=Severity.MEDIUM,
            title=f"Upstream Repo Confirms Modified Weights ({', '.join(matched_risk_words)})",
            description=(
                f"'{repo_id}' exists on the Hub and its name indicates post-training modification "
                f"(uploader: '{author}')."
            ),
            remediation="Do not grant this model autonomous shell or file-system tool access.",
            location=str(path),
        )
    elif author in RECOGNIZED_ORGS:
        downloads = _download_count(info)
        report.add(
            layer="Layer 5 (Upstream Verification)",
            severity=Severity.INFO,
            title=f"HF Hub Owner Matches Recognized Organization ('{author}')",
            description=(
                f"'{repo_id}' is listed under the recognized Hugging Face account '{author}' "
                f"({downloads:,} downloads/mo). Account identity and popularity do not establish that "
                "these local bytes are safe or unmodified; rely on the separate integrity result."
            ),
            location=str(path),
        )
    else:
        downloads = _download_count(info)
        if downloads < 100:
            report.add(
                layer="Layer 5 (Upstream Verification)",
                severity=Severity.MEDIUM,
                title=f"Low-Adoption Unverified Upstream ('{repo_id}')",
                description=(
                    f"Repository exists, but uploader '{author}' is not in the locally recognized organization "
                    f"list and the repo has {downloads} monthly downloads. Anubis has not independently reviewed it."
                ),
                remediation="Cross-check the exact repo URL with the model's documentation before use.",
                location=str(path),
            )
        else:
            report.add(
                layer="Layer 5 (Upstream Verification)",
                severity=Severity.INFO,
                title=f"Upstream Exists but Uploader Unverified ('{author}')",
                description=f"'{repo_id}' is on the Hub ({downloads} downloads/mo), but its uploader is not in the locally recognized organization list.",
                location=str(path),
            )

    if info.get("gated") or info.get("private"):
        report.add(
            layer="Layer 5 (Upstream Verification)",
            severity=Severity.INFO,
            title=f"Upstream Repository is {('gated' if info.get('gated') else 'private')}",
            description=f"'{repo_id}' requires access approval; weight redistribution may be unauthorized.",
            location=str(path),
        )

    if ambiguous_snapshots:
        report.mark_incomplete("multiple HF snapshots could not be mapped to one upstream revision")
        report.add(
            layer="Layer 5 (Upstream Verification)",
            severity=Severity.INFO,
            title="Multiple Cached Revisions Need Explicit Selection",
            description=(
                "This Hugging Face cache contains multiple snapshots and no usable refs/main pointer. "
                "Scan a specific snapshots/<revision> directory to avoid comparing old weights with the latest tree."
            ),
            location=str(path),
        )
        return

    # Per-file integrity against the upstream tree (size now, SHA256 with deep=True)
    try:
        revision = snapshot_revision or str(info.get("sha") or "main")
        tree = _get_json(
            f"{HF_API_BASE}/{encoded_repo_id}/tree/{quote(revision, safe='')}?recursive=true",
            timeout=timeout,
            budget=budget,
        )
    except Exception:
        report.mark_incomplete("HF upstream file tree was unavailable")
        report.add(
            layer="Layer 5 (Upstream Verification)",
            severity=Severity.INFO,
            title="Upstream File Tree Unavailable",
            description=f"Could not fetch the file listing for '{repo_id}'; size/hash comparison skipped.",
            location=str(path),
        )
        return

    if not isinstance(tree, list):
        report.mark_incomplete("HF upstream file tree response was malformed")
        report.add(
            layer="Layer 5 (Upstream Verification)",
            severity=Severity.INFO,
            title="Malformed HF File Tree Response",
            description="The Hub did not return a file list; local weight comparison was skipped.",
            location=str(path),
        )
        return

    remote_by_path: dict[str, dict[str, Any]] = {}
    remote_by_name: dict[str, list[dict[str, Any]]] = {}
    if isinstance(tree, list):
        for entry in tree:
            if isinstance(entry, dict) and entry.get("path"):
                remote_path = Path(str(entry["path"])).as_posix()
                remote_by_path[remote_path] = entry
                remote_by_name.setdefault(Path(remote_path).name, []).append(entry)

    if local_files is not None:
        local_weights = sorted(
            p for p in local_files if p.suffix.lower() in WEIGHT_SUFFIXES and p.is_file()
        )
        if snapshot_root is not None:
            local_weights = [p for p in local_weights if p == snapshot_root or snapshot_root in p.parents]
    elif path.is_file():
        local_weights = [path]
    elif snapshot_root is not None:
        local_weights = list((budget or ScanBudget()).walk_files(snapshot_root))
        local_weights = [p for p in local_weights if p.suffix.lower() in WEIGHT_SUFFIXES]
    else:
        local_weights = list((budget or ScanBudget()).walk_files(path))
        local_weights = [p for p in local_weights if p.suffix.lower() in WEIGHT_SUFFIXES]

    if not local_weights:
        report.mark_incomplete("no supported local weight files were available for upstream comparison")
        report.add(
            layer="Layer 5 (Upstream Verification)",
            severity=Severity.INFO,
            title="No Local Weight Files Available for Comparison",
            description="No supported local weights were enumerated within the scan limits.",
            location=str(path),
        )
        return

    size_verified = 0
    hash_verified = 0
    for local_file in local_weights:
        if budget and budget.stop_requested:
            break
        if path.is_file():
            relative_path = local_file.name
        elif snapshot_root is not None:
            relative_path = local_file.relative_to(snapshot_root).as_posix()
        else:
            relative = local_file.relative_to(path)
            parts = relative.parts
            if "snapshots" in parts:
                snapshot_index = parts.index("snapshots")
                relative = Path(*parts[snapshot_index + 2 :])
            relative_path = relative.as_posix()

        entry = remote_by_path.get(relative_path)
        if entry is None:
            basename_matches = remote_by_name.get(local_file.name, [])
            if len(basename_matches) == 1:
                entry = basename_matches[0]
        if entry is None:
            report.add(
                layer="Layer 5 (Upstream Verification)",
                severity=Severity.MEDIUM,
                title=f"Local Weight File Not Found Upstream ('{local_file.name}')",
                description=(
                    f"'{relative_path}' has no unambiguous counterpart in '{repo_id}'. The file may have been "
                    "renamed, tampered with, or the repo identifier is spoofed."
                ),
                location=str(local_file),
            )
            continue

        try:
            local_size = local_file.stat().st_size
        except OSError as exc:
            report.mark_incomplete(f"local weight could not be stat'ed: {local_file.name}")
            report.add(
                layer="Layer 5 (Upstream Verification)",
                severity=Severity.INFO,
                title=f"Local Weight File Changed During Verification ('{local_file.name}')",
                description=f"Could not stat the local file ({exc.__class__.__name__}); comparison skipped.",
                location=str(local_file),
            )
            continue

        upstream_size = entry.get("size")
        if not isinstance(upstream_size, int) or isinstance(upstream_size, bool) or upstream_size < 0:
            report.mark_incomplete(f"upstream size metadata was invalid for {local_file.name}")
            report.add(
                layer="Layer 5 (Upstream Verification)",
                severity=Severity.INFO,
                title=f"Invalid Upstream Size Metadata ('{local_file.name}')",
                description="The Hub response did not contain a valid integer file size; comparison skipped.",
                location=str(local_file),
            )
            continue
        if upstream_size != local_size:
            report.add(
                layer="Layer 5 (Upstream Verification)",
                severity=Severity.HIGH,
                title=f"File Size Differs from Upstream ('{local_file.name}')",
                description=(
                    f"Local copy is {local_size:,} bytes; upstream '{repo_id}' has {upstream_size:,} bytes. "
                    "The weights were modified after download."
                ),
                remediation="Re-download from the official repo or delete the file.",
                location=str(local_file),
            )
            continue

        lfs_value = entry.get("lfs")
        lfs = lfs_value if isinstance(lfs_value, dict) else {}
        oid = str(lfs.get("oid") or "").lower()
        if oid.startswith("sha256:"):
            oid = oid.removeprefix("sha256:")
        if deep and oid:
            try:
                local_sha256 = _sha256_of(local_file, budget=budget)
            except (OSError, ScanLimitExceeded) as exc:
                report.mark_incomplete(f"deep hash was incomplete for {local_file.name}")
                report.add(
                    layer="Layer 5 (Upstream Verification)",
                    severity=Severity.INFO,
                    title=f"Could Not Hash Local Weight File ('{local_file.name}')",
                    description=f"Hash comparison stopped ({exc.__class__.__name__}: {exc}).",
                    location=str(local_file),
                )
                continue
            if local_sha256 == oid.lower():
                hash_verified += 1
            else:
                report.add(
                    layer="Layer 5 (Upstream Verification)",
                    severity=Severity.CRITICAL,
                    title=f"SHA256 Differs from Upstream LFS OID ('{local_file.name}')",
                    description=(
                        "File size matches upstream but the content hash does not — the weights were "
                        "silently tampered with (size-preserving or padded modification)."
                    ),
                    remediation="DELETE THIS MODEL IMMEDIATELY and re-download from the verified repository.",
                    location=str(local_file),
                )
        elif deep and not oid:
            report.mark_incomplete(f"upstream provided no SHA256 OID for {local_file.name}")
            report.add(
                layer="Layer 5 (Upstream Verification)",
                severity=Severity.INFO,
                title=f"No LFS SHA256 Upstream for '{local_file.name}'",
                description="Small file is not LFS-tracked; hash verification unavailable, size matched only.",
                location=str(local_file),
            )
        else:
            size_verified += 1

    if (size_verified or hash_verified) and not any(
        f.severity in (Severity.CRITICAL, Severity.HIGH)
        and f.layer == "Layer 5 (Upstream Verification)"
        for f in report.findings
    ):
        report.add(
            layer="Layer 5 (Upstream Verification)",
            severity=Severity.PASS,
            title=(
                f"Upstream Integrity Verified ({hash_verified} SHA256, {size_verified} size-only)"
            ),
            description=(
                f"Matched {hash_verified + size_verified} local weight file(s) against the "
                f"'{repo_id}' file tree on Hugging Face. Files without upstream LFS hashes are size-only."
            ),
            location=str(path),
        )


def audit_model_provenance(path: Path, gguf_metadata: dict[str, Any], report: ScanReport) -> None:
    """Checks the uploader/organization and naming heuristics of a local model."""
    resolved = str(path.resolve())
    detected_org = None
    model_name = path.name.lower()

    # Check Hugging Face hub cache naming convention: models--<org>--<repo>
    for part in Path(resolved).parts:
        if part.startswith("models--"):
            segments = part.split("--")
            if len(segments) >= 3:
                detected_org = segments[1].lower()
                model_name = "--".join(segments[2:]).lower()
                break

    if not detected_org and gguf_metadata:
        quant_by = str(gguf_metadata.get("general.quantized_by", "")).lower()
        repo_url = str(gguf_metadata.get("general.repo_url", "")).lower()
        for org in RECOGNIZED_ORGS:
            if org in quant_by or f"/{org}/" in repo_url:
                detected_org = org
                break

    matched_risk_words = [kw for kw in HIGH_RISK_KEYWORDS if kw in model_name or kw in resolved.lower()]

    if detected_org in RECOGNIZED_ORGS and not matched_risk_words:
        report.add(
            layer="Layer 5 (Provenance)",
            severity=Severity.INFO,
            title=f"Recognized Uploader Name Heuristic ('{detected_org}')",
            description=(
                f"The local path or embedded metadata names '{detected_org}'. This value is attacker-controlled "
                "and is not proof of uploader identity, model integrity, or safety."
            ),
            location=str(path),
        )
    elif matched_risk_words:
        report.add(
            layer="Layer 5 (Provenance)",
            severity=Severity.MEDIUM,
            title=f"Uncensored / Modified Weights Heuristic ({', '.join(matched_risk_words)})",
            description=(
                "The model name contains a modification-related keyword. Names are user-controlled and this "
                "heuristic does not establish what training or weight changes were made."
            ),
            remediation="Do not grant this model autonomous shell or file-system tool access.",
            location=str(path),
        )
    else:
        report.add(
            layer="Layer 5 (Provenance)",
            severity=Severity.INFO,
            title="Unverified Local Model Provenance",
            description="Could not match a recognized uploader name; origin and integrity remain unverified.",
            remediation="Verify the SHA256 hash against the official Hugging Face repository before granting tool access.",
            location=str(path),
        )
