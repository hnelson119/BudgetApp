"""Validate the M10 release-hardening and pinned ASVS evidence inventories."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from collections import Counter
from datetime import date
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_PATH = PROJECT_ROOT / "docs" / "release-evidence.json"
ASVS_INVENTORY_RELATIVE_PATH = "docs/asvs-5.0.0-level2-evidence.json"
ASVS_INVENTORY_PATH = PROJECT_ROOT / ASVS_INVENTORY_RELATIVE_PATH
ASVS_SOURCE_URL = (
    "https://raw.githubusercontent.com/OWASP/ASVS/v5.0.0/5.0/docs_en/"
    "OWASP_Application_Security_Verification_Standard_5.0.0_en.flat.json"
)
ASVS_SOURCE_SHA256 = "".join(
    (
        "8201b20eec2908c3",  # pragma: allowlist secret
        "380ac600c91c8ba7",  # pragma: allowlist secret
        "46346fbb80885936",  # pragma: allowlist secret
        "6abb232027532311",  # pragma: allowlist secret
    )
)
ASVS_SOURCE_GIT_BLOB = "".join(
    (
        "f7ae2926598c4648",  # pragma: allowlist secret
        "ff7614a6968e4c8f",  # pragma: allowlist secret
        "d89524bd",
    )
)
ASVS_CATALOG_SHA256 = "".join(
    (
        "7baeb53026600db7",  # pragma: allowlist secret
        "6513489acaccd93b",  # pragma: allowlist secret
        "a60490e785ffad80",  # pragma: allowlist secret
        "6e2c164c474ad273",  # pragma: allowlist secret
    )
)
EXPECTED_ASVS_REQUIREMENT_COUNT = 253
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
_SOURCE_ID = re.compile(r"^V([1-9]|1[0-7])\.([1-9][0-9]*)\.([1-9][0-9]*)$")
_COMMIT_SHA = re.compile(r"^[0-9a-f]{40}$")


def _fail(message: str) -> None:
    raise ValueError(message)


def _is_iso_date(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = date.fromisoformat(value)
    except ValueError:
        return False
    return parsed.isoformat() == value


def _validate_evidence_paths(evidence: Any, *, item_name: str) -> None:
    if not isinstance(evidence, list) or not evidence:
        _fail(f"{item_name} must name evidence or a tracking document")
    if not all(isinstance(path, str) and path.strip() for path in evidence):
        _fail(f"{item_name} has invalid evidence paths")
    for path in evidence:
        relative_path = path.split("#", maxsplit=1)[0]
        if relative_path.startswith(("https://", "http://")):
            continue
        candidate = (PROJECT_ROOT / relative_path).resolve()
        if PROJECT_ROOT not in candidate.parents and candidate != PROJECT_ROOT:
            _fail(f"{item_name} has evidence outside the project")
        if not candidate.exists():
            _fail(f"{item_name} references missing evidence {path!r}")


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
        status = item.get("status")
        if status not in ALLOWED_STATUSES:
            _fail(f"{collection_name} {item_id!r} has an invalid status")
        _validate_evidence_paths(item.get("evidence"), item_name=f"{collection_name} {item_id!r}")
        if status == "verified" and not _is_iso_date(item.get("last_verified")):
            _fail(f"{collection_name} {item_id!r} is verified without a verification date")
        if status == "not_applicable" and not item.get("reason"):
            _fail(f"{collection_name} {item_id!r} is not applicable without a reason")
    if len(observed_ids) != len(set(observed_ids)):
        _fail(f"{collection_name} contains duplicate identifiers")
    if set(observed_ids) != expected_ids:
        _fail(f"{collection_name} identifiers are incomplete")


def _catalog_sha256(requirements: list[dict[str, Any]]) -> str:
    catalog = [
        {
            "id": item.get("id"),
            "source_id": item.get("source_id"),
            "chapter_id": item.get("chapter_id"),
            "chapter_name": item.get("chapter_name"),
            "section_id": item.get("section_id"),
            "section_name": item.get("section_name"),
            "level": item.get("level"),
            "description": item.get("description"),
        }
        for item in requirements
    ]
    payload = json.dumps(catalog, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


def validate_asvs_inventory(data: Any) -> None:
    if not isinstance(data, dict):
        _fail("ASVS requirement inventory must be a JSON object")
    if data.get("schema_version") != 1:
        _fail("unsupported ASVS inventory schema version")
    if data.get("target_level") != 2:
        _fail("the ASVS inventory target must remain Level 2")
    if not _is_iso_date(data.get("mapping_updated")):
        _fail("the ASVS mapping update date is invalid")

    source = data.get("source")
    expected_source = {
        "version": "5.0.0",
        "tag": "v5.0.0",
        "url": ASVS_SOURCE_URL,
        "sha256": ASVS_SOURCE_SHA256,
        "git_blob": ASVS_SOURCE_GIT_BLOB,
        "license": "Creative Commons Attribution-ShareAlike 4.0 International",
    }
    if source != expected_source:
        _fail("the ASVS inventory source metadata does not match the pinned v5.0.0 artifact")

    requirements = data.get("requirements")
    if not isinstance(requirements, list):
        _fail("ASVS requirements must be a list")
    if len(requirements) != EXPECTED_ASVS_REQUIREMENT_COUNT:
        _fail(
            "ASVS requirement count is incomplete: "
            f"expected {EXPECTED_ASVS_REQUIREMENT_COUNT}, got {len(requirements)}"
        )
    if data.get("requirement_count") != len(requirements):
        _fail("the ASVS declared requirement count does not match its entries")

    observed_ids: list[str] = []
    observed_chapters: set[str] = set()
    status_counts: Counter[str] = Counter()
    applicability_counts: Counter[str] = Counter()
    for item in requirements:
        if not isinstance(item, dict):
            _fail("ASVS requirement entries must be objects")
        item_id = item.get("id")
        source_id = item.get("source_id")
        if not isinstance(source_id, str) or not (match := _SOURCE_ID.fullmatch(source_id)):
            _fail(f"ASVS requirement {item_id!r} has an invalid source identifier")
        expected_id = f"v5.0.0-{source_id.removeprefix('V')}"
        if item_id != expected_id:
            _fail(f"ASVS requirement {item_id!r} is not version-qualified correctly")
        observed_ids.append(item_id)

        chapter_id = item.get("chapter_id")
        section_id = item.get("section_id")
        if chapter_id != f"V{match.group(1)}":
            _fail(f"ASVS requirement {item_id} has a mismatched chapter")
        if section_id != f"{chapter_id}.{match.group(2)}":
            _fail(f"ASVS requirement {item_id} has a mismatched section")
        observed_chapters.add(chapter_id)
        if item.get("level") not in {1, 2}:
            _fail(f"ASVS requirement {item_id} exceeds the Level 2 target")
        for field in ("chapter_name", "section_name", "description", "assessment"):
            if not isinstance(item.get(field), str) or not item[field].strip():
                _fail(f"ASVS requirement {item_id} has an invalid {field}")

        applicability = item.get("applicability")
        status = item.get("status")
        if applicability not in {"applicable", "not_applicable"}:
            _fail(f"ASVS requirement {item_id} has an invalid applicability")
        if status not in ALLOWED_STATUSES:
            _fail(f"ASVS requirement {item_id} has an invalid status")
        if applicability == "not_applicable":
            if status != "not_applicable":
                _fail(f"ASVS requirement {item_id} excludes a feature without N/A status")
            if not isinstance(item.get("reason"), str) or not item["reason"].strip():
                _fail(f"ASVS requirement {item_id} is not applicable without a reason")
        else:
            if status == "not_applicable":
                _fail(f"ASVS requirement {item_id} is applicable but has N/A status")
            if "reason" in item:
                _fail(f"ASVS requirement {item_id} has a stale exclusion reason")
        if status == "verified":
            if not _is_iso_date(item.get("last_verified")):
                _fail(f"ASVS requirement {item_id} is verified without a valid date")
            if not isinstance(data.get("release_candidate"), str) or not _COMMIT_SHA.fullmatch(
                data["release_candidate"]
            ):
                _fail(f"ASVS requirement {item_id} is verified without a release candidate")
        elif "last_verified" in item:
            _fail(f"ASVS requirement {item_id} has a stale verification date")

        _validate_evidence_paths(item.get("evidence"), item_name=f"ASVS requirement {item_id}")
        status_counts[str(status)] += 1
        applicability_counts[str(applicability)] += 1

    if len(observed_ids) != len(set(observed_ids)):
        _fail("ASVS requirement inventory contains duplicate identifiers")
    if observed_chapters != EXPECTED_ASVS_CHAPTERS:
        _fail("ASVS requirement inventory does not cover every chapter")

    observed_catalog_sha256 = _catalog_sha256(requirements)
    if data.get("catalog_sha256") != observed_catalog_sha256:
        _fail("the ASVS declared catalog fingerprint does not match its requirement content")
    if observed_catalog_sha256 != ASVS_CATALOG_SHA256:
        _fail("the ASVS requirement catalog differs from the pinned v5.0.0 Level 2 catalog")

    expected_summary = {
        "applicability": dict(sorted(applicability_counts.items())),
        "status": dict(sorted(status_counts.items())),
    }
    if data.get("summary") != expected_summary:
        _fail("the ASVS inventory summary does not match its requirement dispositions")


def validate_release_evidence(data: Any, asvs_inventory: Any | None = None) -> None:
    if not isinstance(data, dict):
        _fail("release evidence must be a JSON object")
    if data.get("schema_version") != 2:
        _fail("unsupported release-evidence schema version")
    if not _is_iso_date(data.get("updated")):
        _fail("the release evidence update date is invalid")
    release_candidate = data.get("release_candidate")
    if release_candidate is not None and (
        not isinstance(release_candidate, str) or not _COMMIT_SHA.fullmatch(release_candidate)
    ):
        _fail("the release candidate must be null or a full lowercase commit SHA")
    status_definitions = data.get("status_definitions")
    if not isinstance(status_definitions, dict) or set(status_definitions) != ALLOWED_STATUSES:
        _fail("the release evidence status definitions are incomplete")
    asvs = data.get("asvs")
    if not isinstance(asvs, dict):
        _fail("the ASVS inventory must be an object")
    if asvs.get("version") != "5.0.0":
        _fail("the ASVS review must remain pinned to version 5.0.0")
    if asvs.get("target_level") != 2:
        _fail("the ASVS target must remain Level 2")
    if asvs.get("source") != ASVS_SOURCE_URL or asvs.get("source_sha256") != ASVS_SOURCE_SHA256:
        _fail("the release evidence does not reference the pinned ASVS source")
    if asvs.get("requirements_file") != ASVS_INVENTORY_RELATIVE_PATH:
        _fail("the release evidence references an unexpected ASVS requirement inventory")
    if asvs.get("expected_requirement_count") != EXPECTED_ASVS_REQUIREMENT_COUNT:
        _fail("the release evidence has an unexpected ASVS requirement count")

    if asvs_inventory is None:
        try:
            asvs_inventory = json.loads(ASVS_INVENTORY_PATH.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            _fail(f"the ASVS requirement inventory could not be read: {error}")
    validate_asvs_inventory(asvs_inventory)
    if asvs_inventory.get("release_candidate") != data.get("release_candidate"):
        _fail("the ASVS and release evidence inventories name different release candidates")

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
        asvs_inventory = json.loads(ASVS_INVENTORY_PATH.read_text(encoding="utf-8"))
        validate_release_evidence(data, asvs_inventory)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"Release evidence validation failed: {error}", file=sys.stderr)
        return 1
    print(
        "Release evidence inventory is structurally complete "
        f"({EXPECTED_ASVS_REQUIREMENT_COUNT} ASVS requirements)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
