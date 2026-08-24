"""Validate the M10 release-hardening evidence inventory."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_PATH = PROJECT_ROOT / "docs" / "release-evidence.json"
ALLOWED_STATUSES = {
    "not_started",
    "partial",
    "implemented",
    "verified",
    "not_applicable",
}
EXPECTED_ASVS_CHAPTERS = {f"V{number}" for number in range(1, 18)}
EXPECTED_SECURITY_TESTS = set(range(1, 25))
EXPECTED_RELEASE_GATES = set(range(1, 13))


def _fail(message: str) -> None:
    raise ValueError(message)


def _validate_items(
    items: Any,
    *,
    collection_name: str,
    expected_ids: set[int] | set[str],
) -> None:
    if not isinstance(items, list):
        _fail(f"{collection_name} must be a list")
    observed_ids: list[int | str] = []
    for item in items:
        if not isinstance(item, dict):
            _fail(f"{collection_name} entries must be objects")
        item_id = item.get("id")
        observed_ids.append(item_id)
        if item.get("status") not in ALLOWED_STATUSES:
            _fail(f"{collection_name} {item_id!r} has an invalid status")
        evidence = item.get("evidence")
        if not isinstance(evidence, list) or not evidence:
            _fail(f"{collection_name} {item_id!r} must name evidence or a tracking document")
        if not all(isinstance(path, str) and path.strip() for path in evidence):
            _fail(f"{collection_name} {item_id!r} has invalid evidence paths")
        for path in evidence:
            relative_path = path.split("#", maxsplit=1)[0]
            if relative_path.startswith(("https://", "http://")):
                continue
            candidate = (PROJECT_ROOT / relative_path).resolve()
            if PROJECT_ROOT not in candidate.parents and candidate != PROJECT_ROOT:
                _fail(f"{collection_name} {item_id!r} has evidence outside the project")
            if not candidate.exists():
                _fail(f"{collection_name} {item_id!r} references missing evidence {path!r}")
        if item.get("status") == "verified" and not item.get("last_verified"):
            _fail(f"{collection_name} {item_id!r} is verified without a verification date")
        if item.get("status") == "not_applicable" and not item.get("reason"):
            _fail(f"{collection_name} {item_id!r} is not applicable without a reason")
    if len(observed_ids) != len(set(observed_ids)):
        _fail(f"{collection_name} contains duplicate identifiers")
    if set(observed_ids) != expected_ids:
        _fail(f"{collection_name} identifiers are incomplete")


def validate_release_evidence(data: Any) -> None:
    if not isinstance(data, dict):
        _fail("release evidence must be a JSON object")
    if data.get("schema_version") != 1:
        _fail("unsupported release-evidence schema version")
    asvs = data.get("asvs")
    if not isinstance(asvs, dict):
        _fail("the ASVS inventory must be an object")
    if asvs.get("version") != "5.0.0":
        _fail("the ASVS review must remain pinned to version 5.0.0")
    if asvs.get("target_level") != 2:
        _fail("the ASVS target must remain Level 2")
    _validate_items(
        asvs.get("chapters"),
        collection_name="ASVS chapters",
        expected_ids=EXPECTED_ASVS_CHAPTERS,
    )
    _validate_items(
        data.get("security_tests"),
        collection_name="security tests",
        expected_ids=EXPECTED_SECURITY_TESTS,
    )
    _validate_items(
        data.get("release_gates"),
        collection_name="release gates",
        expected_ids=EXPECTED_RELEASE_GATES,
    )


def main() -> int:
    try:
        data = json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))
        validate_release_evidence(data)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"Release evidence validation failed: {error}", file=sys.stderr)
        return 1
    print("Release evidence inventory is structurally complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
