"""
Layer 5: Supply Chain & Provenance Tiering.
Evaluates model origin from Hugging Face cache paths or GGUF metadata, and can
optionally verify the model against the live Hugging Face Hub API (offline-safe:
all network failures degrade to INFO findings, never crashes).
"""

import hashlib
import json
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Optional
from urllib.parse import quote

from localguard.models import ScanReport, Severity

TRUSTED_ORGS = {
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


def _get_json(url: str, timeout: float = 6.0) -> Any:
    """Single seam for all Hub API GETs (monkeypatched in tests)."""
    req = urllib.request.Request(url, headers={"User-Agent": "localguard-ai/0.1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _sha256_of(path: Path, chunk_size: int = 8 * 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def verify_upstream(
    path: Path,
    report: ScanReport,
    deep: bool = False,
    timeout: float = 6.0,
    gguf_metadata: Optional[dict[str, Any]] = None,
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
        encoded_repo_id = quote(repo_id, safe="/")
        info = _get_json(f"{HF_API_BASE}/{encoded_repo_id}", timeout=timeout)
    except urllib.error.HTTPError as exc:
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
        report.add(
            layer="Layer 5 (Upstream Verification)",
            severity=Severity.INFO,
            title="Offline — Upstream Verification Skipped",
            description=f"Could not reach the Hugging Face API ({exc.__class__.__name__}).",
            location=str(path),
        )
        return

    if not isinstance(info, dict):
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
    elif author in TRUSTED_ORGS:
        downloads = int(info.get("downloads") or 0)
        report.add(
            layer="Layer 5 (Upstream Verification)",
            severity=Severity.PASS,
            title=f"HF Hub Confirms Tier-1 Source ('{author}', {downloads:,} downloads/mo)",
            description=f"Upstream repository '{repo_id}' exists and is owned by a verified organization.",
            location=str(path),
        )
    else:
        downloads = int(info.get("downloads") or 0)
        if downloads < 100:
            report.add(
                layer="Layer 5 (Upstream Verification)",
                severity=Severity.MEDIUM,
                title=f"Low-Adoption Unverified Upstream ('{repo_id}')",
                description=(
                    f"Repository exists but uploader '{author}' is not a Tier-1 organization and the repo "
                    f"has only {downloads} monthly downloads — a common profile for clone/fake repos."
                ),
                remediation="Cross-check the exact repo URL with the model's documentation before use.",
                location=str(path),
            )
        else:
            report.add(
                layer="Layer 5 (Upstream Verification)",
                severity=Severity.INFO,
                title=f"Upstream Exists but Uploader Unverified ('{author}')",
                description=f"'{repo_id}' found on the Hub ({downloads} downloads/mo) but is not a Tier-1 org.",
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

    # Per-file integrity against the upstream tree (size now, SHA256 with deep=True)
    try:
        revision = str(info.get("sha") or "main")
        tree = _get_json(
            f"{HF_API_BASE}/{encoded_repo_id}/tree/{quote(revision, safe='')}?recursive=true",
            timeout=timeout,
        )
    except Exception:
        report.add(
            layer="Layer 5 (Upstream Verification)",
            severity=Severity.INFO,
            title="Upstream File Tree Unavailable",
            description=f"Could not fetch the file listing for '{repo_id}'; size/hash comparison skipped.",
            location=str(path),
        )
        return

    remote_by_name: dict[str, list[dict[str, Any]]] = {}
    if isinstance(tree, list):
        for entry in tree:
            if isinstance(entry, dict) and entry.get("path"):
                remote_by_name.setdefault(Path(str(entry["path"])).name, []).append(entry)

    if path.is_file():
        local_weights = [path]
    else:
        local_weights = sorted(
            p for p in path.rglob("*") if p.suffix.lower() in WEIGHT_SUFFIXES and p.is_file()
        )

    size_verified = 0
    hash_verified = 0
    for local_file in local_weights:
        entries = remote_by_name.get(local_file.name)
        if not entries:
            report.add(
                layer="Layer 5 (Upstream Verification)",
                severity=Severity.MEDIUM,
                title=f"Local Weight File Not Found Upstream ('{local_file.name}')",
                description=(
                    f"'{local_file.name}' has no counterpart in '{repo_id}'. The file may have been renamed, "
                    "tampered with, or the repo identifier is spoofed."
                ),
                location=str(local_file),
            )
            continue

        local_size = local_file.stat().st_size
        size_match = next((e for e in entries if int(e.get("size") or 0) == local_size), None)
        if size_match is None:
            upstream_sizes = [int(e.get("size") or 0) for e in entries]
            report.add(
                layer="Layer 5 (Upstream Verification)",
                severity=Severity.HIGH,
                title=f"File Size Differs from Upstream ('{local_file.name}')",
                description=(
                    f"Local copy is {local_size:,} bytes; upstream '{repo_id}' has {upstream_sizes} bytes. "
                    "The weights were modified after download."
                ),
                remediation="Re-download from the official repo or delete the file.",
                location=str(local_file),
            )
            continue

        lfs = size_match.get("lfs") or {}
        oid = str(lfs.get("oid") or "").lower()
        if oid.startswith("sha256:"):
            oid = oid.removeprefix("sha256:")
        if deep and oid:
            if _sha256_of(local_file) == oid.lower():
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
        for org in TRUSTED_ORGS:
            if org in quant_by or f"/{org}/" in repo_url:
                detected_org = org
                break

    matched_risk_words = [kw for kw in HIGH_RISK_KEYWORDS if kw in model_name or kw in resolved.lower()]

    if detected_org in TRUSTED_ORGS and not matched_risk_words:
        report.add(
            layer="Layer 5 (Provenance)",
            severity=Severity.PASS,
            title=f"Trusted Supply Chain Source ('{detected_org}')",
            description=f"Model originates from verified organization/quantizer '{detected_org}'.",
            location=str(path),
        )
    elif matched_risk_words:
        report.add(
            layer="Layer 5 (Provenance)",
            severity=Severity.MEDIUM,
            title=f"Uncensored / Modified Weights Heuristic ({', '.join(matched_risk_words)})",
            description=(
                "Model name indicates post-training weight modification ('obliterated'/'uncensored'). "
                "Community fine-tunes carry higher risk of embedded fine-tuning backdoors."
            ),
            remediation="Do not grant this model autonomous shell or file-system tool access.",
            location=str(path),
        )
    else:
        report.add(
            layer="Layer 5 (Provenance)",
            severity=Severity.INFO,
            title="Unverified Local Model Provenance",
            description="Could not automatically link file to a Tier-1 Hugging Face organization.",
            remediation="Verify the SHA256 hash against the official Hugging Face repository before granting tool access.",
            location=str(path),
        )
