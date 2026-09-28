from __future__ import annotations

import copy
import json
from datetime import date

import pytest

from scripts.check_migration_readiness import (
    EXPECTED_CONTROL_IDS,
    EXPECTED_SERVICES,
    INVENTORY_PATH,
    PROJECT_ROOT,
    validate_migration_readiness,
)


def _inventory() -> dict[str, object]:
    return json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))


def test_migration_readiness_inventory_is_complete_and_gate_wired() -> None:
    inventory = _inventory()

    validate_migration_readiness(inventory, today=date(2026, 9, 28))

    assert {item["id"] for item in inventory["controls"]} == EXPECTED_CONTROL_IDS
    assert inventory["rehearsal"]["services"] == EXPECTED_SERVICES
    assert inventory["summary"] == {
        "controls": 8,
        "repository_implemented_controls": 8,
        "release_pending_controls": 8,
        "rehearsal_services": 4,
    }


def test_migration_readiness_rejects_missing_control_and_false_verification() -> None:
    inventory = _inventory()
    missing_control = copy.deepcopy(inventory)
    missing_control["controls"].pop()
    with pytest.raises(ValueError, match="control inventory changed"):
        validate_migration_readiness(missing_control, today=date(2026, 9, 28))

    falsely_verified = copy.deepcopy(inventory)
    falsely_verified["controls"][0]["release_status"] = "verified"
    with pytest.raises(ValueError, match="control status changed"):
        validate_migration_readiness(falsely_verified, today=date(2026, 9, 28))


def test_migration_readiness_rejects_missing_evidence_and_stale_review() -> None:
    inventory = _inventory()
    missing_evidence = copy.deepcopy(inventory)
    missing_evidence["controls"][0]["evidence"] = ["docs/not-present.md"]
    with pytest.raises(ValueError, match="is missing"):
        validate_migration_readiness(missing_evidence, today=date(2026, 9, 28))

    with pytest.raises(ValueError, match="review is overdue"):
        validate_migration_readiness(inventory, today=date(2026, 12, 28))


def test_release_gate_ten_is_implemented_but_unverified() -> None:
    evidence = json.loads((PROJECT_ROOT / "docs/release-evidence.json").read_text(encoding="utf-8"))
    gate = next(item for item in evidence["release_gates"] if item["id"] == 10)

    assert gate["status"] == "implemented"
    assert "last_verified" not in gate
