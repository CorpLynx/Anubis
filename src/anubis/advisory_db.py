"""Load and refresh the packaged, reviewable Ollama OSV advisory snapshot."""

import json
from datetime import date
from importlib.resources import files as package_files
from typing import Any

PACKAGE_DATA_NAME = "ollama_advisories.json"
OSV_PACKAGE = {"ecosystem": "Go", "name": "github.com/ollama/ollama"}
OSV_QUERY_URL = "https://api.osv.dev/v1/query"


def _matches_package(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and value.get("ecosystem") == OSV_PACKAGE["ecosystem"]
        and value.get("name") == OSV_PACKAGE["name"]
    )


def load_ollama_advisories() -> dict[str, Any]:
    data = json.loads(package_files("anubis").joinpath(PACKAGE_DATA_NAME).read_text(encoding="utf-8"))
    if (
        data.get("schema_version") != 1
        or not isinstance(data.get("advisories"), list)
        or not isinstance(data.get("snapshot_date"), str)
        or data.get("package") != OSV_PACKAGE
    ):
        raise ValueError("unsupported or malformed Ollama advisory database")
    return data


def normalize_osv_response(
    payload: dict[str, Any],
    previous: dict[str, Any],
    snapshot_date: str | None = None,
) -> dict[str, Any]:
    """Normalize OSV records, retaining curated severity and requiring review on changes."""
    old_by_id = {
        item["id"]: item for item in previous.get("advisories", []) if isinstance(item, dict) and item.get("id")
    }
    records: list[dict[str, Any]] = []
    for vuln in payload.get("vulns", []):
        if not isinstance(vuln, dict) or vuln.get("withdrawn"):
            continue
        package_matches = any(
            isinstance(item, dict) and _matches_package(item.get("package")) for item in vuln.get("affected", [])
        )
        if not package_matches:
            continue

        ranges: list[list[dict[str, str]]] = []
        for affected in vuln.get("affected", []):
            if not isinstance(affected, dict) or not _matches_package(affected.get("package")):
                continue
            for version_range in affected.get("ranges", []):
                if not isinstance(version_range, dict) or version_range.get("type") != "SEMVER":
                    continue
                events = version_range.get("events", [])
                normalized_events = [
                    {key: str(event[key])}
                    for event in events
                    if isinstance(event, dict)
                    for key in ("introduced", "fixed", "last_affected", "limit")
                    if key in event
                ]
                if normalized_events and all(len(event) == 1 for event in normalized_events):
                    ranges.append(normalized_events)
        if not ranges:
            continue

        advisory_id = str(vuln.get("id", ""))
        if not advisory_id:
            continue
        old = old_by_id.get(advisory_id, {})
        aliases = sorted({str(alias) for alias in vuln.get("aliases", []) if isinstance(alias, str)})
        summary = str(vuln.get("summary") or advisory_id)
        changed = bool(old) and (
            old.get("summary") != summary or old.get("aliases", []) != aliases or old.get("ranges", []) != ranges
        )
        is_new = not old
        records.append(
            {
                "id": advisory_id,
                "aliases": aliases,
                "summary": summary,
                # New/changed advisories stay informational until a maintainer reviews severity.
                "severity": "INFO" if is_new or changed else old.get("severity", "INFO"),
                "needs_review": True if is_new or changed else bool(old.get("needs_review", False)),
                "ranges": ranges,
            }
        )

    # OSV can return GHSA and Go-vuln aliases as separate records for the same issue.
    # Prefer the GHSA canonical record and deduplicate any records sharing aliases.
    records.sort(key=lambda item: (not item["id"].startswith("GHSA-"), item["id"]))
    deduplicated: list[dict[str, Any]] = []
    seen_identifiers: set[str] = set()
    for item in records:
        identifiers = {item["id"], *item["aliases"]}
        if identifiers & seen_identifiers:
            continue
        deduplicated.append(item)
        seen_identifiers.update(identifiers)
    records = sorted(deduplicated, key=lambda item: item["id"])
    old_records = sorted(previous.get("advisories", []), key=lambda item: item.get("id", ""))
    snapshot_unchanged = records == old_records and previous.get("package") == OSV_PACKAGE
    selected_snapshot_date = (
        previous.get("snapshot_date", "") if snapshot_unchanged else (snapshot_date or date.today().isoformat())
    )
    return {
        "schema_version": 1,
        "snapshot_date": selected_snapshot_date,
        "source": OSV_QUERY_URL,
        "package": OSV_PACKAGE,
        "advisories": records,
    }
