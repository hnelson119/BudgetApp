from __future__ import annotations

import copy
import json
from datetime import date

import pytest

from scripts.check_session_browser_boundary import (
    EXPECTED_CONTROL_IDS,
    INVENTORY_PATH,
    PROJECT_ROOT,
    validate_session_browser_boundary,
)


def _inventory() -> dict[str, object]:
    return json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))


def test_session_browser_inventory_is_complete_and_gate_wired() -> None:
    inventory = _inventory()

    validate_session_browser_boundary(inventory, today=date(2026, 9, 28))

    assert {item["id"] for item in inventory["controls"]} == EXPECTED_CONTROL_IDS
    assert inventory["release_boundary"]["status"] == "pending"
    assert inventory["summary"] == {
        "controls": 7,
        "repository_implemented": 7,
        "release_pending": 1,
    }


def test_session_browser_inventory_rejects_missing_control_and_false_release_pass() -> None:
    inventory = _inventory()
    missing = copy.deepcopy(inventory)
    missing["controls"].pop()
    with pytest.raises(ValueError, match="control inventory changed"):
        validate_session_browser_boundary(missing, today=date(2026, 9, 28))

    falsely_verified = copy.deepcopy(inventory)
    falsely_verified["release_boundary"]["status"] = "verified"
    with pytest.raises(ValueError, match="must remain pending"):
        validate_session_browser_boundary(falsely_verified, today=date(2026, 9, 28))


def test_session_browser_inventory_rejects_missing_evidence_test_and_stale_review() -> None:
    inventory = _inventory()
    missing_evidence = copy.deepcopy(inventory)
    missing_evidence["controls"][0]["evidence"] = ["docs/not-present.md"]
    with pytest.raises(ValueError, match="is missing"):
        validate_session_browser_boundary(missing_evidence, today=date(2026, 9, 28))

    missing_test = copy.deepcopy(inventory)
    missing_test["controls"][0]["test_refs"] = ["tests/test_authentication.py::test_not_present"]
    with pytest.raises(ValueError, match="test reference is missing"):
        validate_session_browser_boundary(missing_test, today=date(2026, 9, 28))

    with pytest.raises(ValueError, match="review is overdue"):
        validate_session_browser_boundary(inventory, today=date(2026, 12, 28))


def test_security_test_four_is_implemented_but_unverified() -> None:
    evidence = json.loads((PROJECT_ROOT / "docs/release-evidence.json").read_text(encoding="utf-8"))
    security_test = next(item for item in evidence["security_tests"] if item["id"] == 4)

    assert security_test["status"] == "implemented"
    assert "last_verified" not in security_test
