"""Tests for OSV normalization and review gates on advisory refreshes."""

from anubis.advisory_db import OSV_PACKAGE, load_ollama_advisories, normalize_osv_response


def test_packaged_advisory_database_loads() -> None:
    database = load_ollama_advisories()
    assert database["package"] == OSV_PACKAGE
    assert database["advisories"]
    assert all({"id", "ranges", "severity", "needs_review"} <= item.keys() for item in database["advisories"])


def test_new_osv_record_is_info_until_reviewed() -> None:
    previous = {"schema_version": 1, "snapshot_date": "2026-10-22", "package": OSV_PACKAGE, "advisories": []}
    payload = {
        "vulns": [
            {
                "id": "GHSA-new1-abc2-def3",
                "summary": "New issue",
                "aliases": ["CVE-2026-12345"],
                "affected": [
                    {
                        "package": {**OSV_PACKAGE, "purl": "pkg:golang/github.com/ollama/ollama"},
                        "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}],
                    }
                ],
            }
        ]
    }

    updated = normalize_osv_response(payload, previous, snapshot_date="2026-11-01")

    assert updated["snapshot_date"] == "2026-11-01"
    assert updated["advisories"][0]["severity"] == "INFO"
    assert updated["advisories"][0]["needs_review"] is True


def test_unchanged_advisories_keep_manual_severity_and_snapshot_date() -> None:
    advisory = {
        "id": "GHSA-old1-abc2-def3",
        "aliases": [],
        "summary": "Known issue",
        "severity": "HIGH",
        "needs_review": False,
        "ranges": [[{"introduced": "0"}, {"fixed": "1.0.0"}]],
    }
    previous = {
        "schema_version": 1,
        "snapshot_date": "2026-10-22",
        "package": OSV_PACKAGE,
        "advisories": [advisory],
    }
    payload = {
        "vulns": [
            {
                "id": advisory["id"],
                "aliases": [],
                "summary": advisory["summary"],
                "affected": [{"package": OSV_PACKAGE, "ranges": [{"type": "SEMVER", "events": advisory["ranges"][0]}]}],
            }
        ]
    }

    updated = normalize_osv_response(payload, previous, snapshot_date="2026-11-01")

    assert updated["snapshot_date"] == "2026-10-22"
    assert updated["advisories"][0]["severity"] == "HIGH"
    assert updated["advisories"][0]["needs_review"] is False


def test_osv_canonical_and_go_alias_records_are_deduplicated() -> None:
    previous = {"schema_version": 1, "snapshot_date": "2026-10-22", "package": OSV_PACKAGE, "advisories": []}
    ranges = [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.0"}]}]
    vuln = {
        "id": "GHSA-abcd-1234-wxyz",
        "summary": "One advisory",
        "aliases": ["CVE-2026-1", "GO-2026-1"],
        "affected": [{"package": OSV_PACKAGE, "ranges": ranges}],
    }
    alias = {
        **vuln,
        "id": "GO-2026-1",
        "aliases": ["CVE-2026-1", "GHSA-abcd-1234-wxyz"],
    }

    updated = normalize_osv_response({"vulns": [alias, vuln]}, previous)

    assert len(updated["advisories"]) == 1
    assert updated["advisories"][0]["id"] == "GHSA-abcd-1234-wxyz"
