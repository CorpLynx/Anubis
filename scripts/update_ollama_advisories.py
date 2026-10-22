#!/usr/bin/env python3
"""Fetch an OSV snapshot and write a reviewable Anubis advisory-data update."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import urllib.request
from datetime import date
from pathlib import Path

from anubis.advisory_db import OSV_PACKAGE, OSV_QUERY_URL, load_ollama_advisories, normalize_osv_response


def fetch_osv_payload(timeout: float = 30.0) -> dict:
    request = urllib.request.Request(
        OSV_QUERY_URL,
        data=json.dumps({"package": OSV_PACKAGE}).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "Anubis-advisory-updater"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read(8 * 1024 * 1024 + 1)
    if len(body) > 8 * 1024 * 1024:
        raise ValueError("OSV response exceeded the 8 MiB safety limit")
    payload = json.loads(body.decode("utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("vulns", []), list):
        raise ValueError("OSV returned an unexpected response shape")
    return payload


def write_atomic(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        Path(temp_name).replace(path)
    except Exception:
        Path(temp_name).unlink(missing_ok=True)
        raise


def canonical_database(data: dict) -> dict:
    return {
        **data,
        "advisories": sorted(data.get("advisories", []), key=lambda item: item.get("id", "")),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Exit 1 if the local snapshot needs an update; do not write it.")
    parser.add_argument(
        "--database",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "src" / "anubis" / "ollama_advisories.json",
    )
    args = parser.parse_args()

    try:
        previous = json.loads(args.database.read_text(encoding="utf-8"))
        payload = fetch_osv_payload()
        updated = normalize_osv_response(payload, previous, snapshot_date=date.today().isoformat())
        canonical_previous = canonical_database(previous)
        if canonical_previous == updated:
            print(f"Ollama OSV snapshot is current ({previous.get('snapshot_date', 'unknown')}).")
            return 0
        if args.check:
            old_by_id = {item.get("id"): item for item in previous.get("advisories", [])}
            new_by_id = {item.get("id"): item for item in updated.get("advisories", [])}
            added = len(new_by_id.keys() - old_by_id.keys())
            removed = len(old_by_id.keys() - new_by_id.keys())
            changed = sum(old_by_id[item_id] != new_by_id[item_id] for item_id in old_by_id.keys() & new_by_id.keys())
            print(f"Ollama OSV snapshot needs review: {added} new, {removed} removed/withdrawn, {changed} changed advisory IDs.")
            return 1
        write_atomic(args.database, updated)
        old_ids = {item.get("id") for item in previous.get("advisories", [])}
        new_ids = {item.get("id") for item in updated.get("advisories", [])}
        print(f"Wrote OSV snapshot {updated['snapshot_date']}: {len(new_ids - old_ids)} new, {len(old_ids - new_ids)} removed/withdrawn advisory IDs.")
        print("Review the diff; new or changed advisories are informational until severity is curated.")
        return 0
    except Exception as exc:
        print(f"advisory update failed: {exc.__class__.__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
