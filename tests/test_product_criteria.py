from __future__ import annotations

import copy
import json
from datetime import date

import pytest

from scripts.check_product_criteria import (
    EXPECTED_IDS,
    EXPECTED_RELEASE_OBSERVATION_IDS,
    INVENTORY_PATH,
    PROJECT_ROOT,
    product_criteria,
    validate_product_criteria,
)


def _inventory() -> dict[str, object]:
    return json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))


def test_product_criteria_inventory_is_exhaustive_and_gate_wired() -> None:
    inventory = _inventory()

    validate_product_criteria(inventory, today=date(2026, 9, 28))

    assert {item["id"] for item in inventory["criteria"]} == EXPECTED_IDS
    assert set(inventory["release_observation_ids"]) == EXPECTED_RELEASE_OBSERVATION_IDS
    assert inventory["summary"] == {
        "criteria": 39,
        "repository_implemented": 39,
        "release_observation_required": 8,
    }


def test_product_criteria_match_the_approved_specification() -> None:
    inventory = _inventory()
    source = product_criteria((PROJECT_ROOT / "PRODUCT_SPEC.md").read_text(encoding="utf-8"))

    assert {item["id"]: item["criterion"] for item in inventory["criteria"]} == source


def test_product_criteria_reject_missing_criterion_and_test() -> None:
    inventory = _inventory()
    missing = copy.deepcopy(inventory)
    missing["criteria"].pop()
    with pytest.raises(ValueError, match="inventory is incomplete"):
        validate_product_criteria(missing, today=date(2026, 9, 28))

    missing_test = copy.deepcopy(inventory)
    missing_test["criteria"][0]["test_refs"] = [
        "tests/test_scheduling_periods.py::test_not_present"
    ]
    with pytest.raises(ValueError, match="references missing test"):
        validate_product_criteria(missing_test, today=date(2026, 9, 28))


def test_product_criteria_reject_missing_evidence_and_stale_review() -> None:
    inventory = _inventory()
    missing_evidence = copy.deepcopy(inventory)
    missing_evidence["criteria"][0]["evidence"] = ["docs/not-present.md"]
    with pytest.raises(ValueError, match="is missing"):
        validate_product_criteria(missing_evidence, today=date(2026, 9, 28))

    with pytest.raises(ValueError, match="review is overdue"):
        validate_product_criteria(inventory, today=date(2026, 12, 28))


def test_release_gate_one_is_implemented_but_unverified() -> None:
    evidence = json.loads((PROJECT_ROOT / "docs/release-evidence.json").read_text(encoding="utf-8"))
    gate = next(item for item in evidence["release_gates"] if item["id"] == 1)

    assert gate["status"] == "implemented"
    assert "last_verified" not in gate
