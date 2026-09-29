from __future__ import annotations

import copy
import json
from datetime import date

import pytest

from scripts.check_security_scan_boundary import (
    EXPECTED_CONTROL_IDS,
    EXPECTED_SCAN_TARGETS,
    EXPECTED_SCANNER_FINDINGS,
    INVENTORY_PATH,
    PROJECT_ROOT,
    discover_bandit_suppressions,
    discover_scanner_findings,
    validate_security_scan_boundary,
)


def _inventory() -> dict[str, object]:
    return json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))


def test_security_scan_inventory_is_complete_and_gate_wired() -> None:
    inventory = _inventory()

    validate_security_scan_boundary(inventory, today=date(2026, 9, 29))

    assert {item["id"] for item in inventory["controls"]} == EXPECTED_CONTROL_IDS
    assert {item["id"] for item in inventory["scan_targets"]} == set(EXPECTED_SCAN_TARGETS)
    assert discover_scanner_findings() == EXPECTED_SCANNER_FINDINGS
    assert inventory["summary"] == {
        "scan_targets": 8,
        "source_scans": 3,
        "dependency_scans": 2,
        "image_scans": 3,
        "scanner_findings": 5,
        "reviewed_suppressions": 1,
        "release_pending": 1,
    }


def test_security_scan_inventory_rejects_missing_target_and_suppression() -> None:
    inventory = _inventory()
    missing_target = copy.deepcopy(inventory)
    missing_target["scan_targets"].pop()
    with pytest.raises(ValueError, match="scan target inventory changed"):
        validate_security_scan_boundary(missing_target, today=date(2026, 9, 29))

    missing_suppression = copy.deepcopy(inventory)
    missing_suppression["reviewed_suppressions"].pop()
    with pytest.raises(ValueError, match="suppression inventory changed"):
        validate_security_scan_boundary(missing_suppression, today=date(2026, 9, 29))

    assert discover_bandit_suppressions() == {("deploy/pentest/authenticate-sessions.py", "B103")}


def test_security_scan_inventory_rejects_unresolved_scanner_finding() -> None:
    inventory = _inventory()
    unresolved = copy.deepcopy(inventory)
    finding = next(item for item in unresolved["scanner_findings"] if item["id"] == "M10-F022")
    finding["state"] = "Accepted"

    with pytest.raises(ValueError, match="scanner finding inventory changed"):
        validate_security_scan_boundary(unresolved, today=date(2026, 9, 29))


def test_security_scan_release_remains_pending() -> None:
    inventory = _inventory()
    falsely_verified = copy.deepcopy(inventory)
    falsely_verified["release_boundary"]["status"] = "verified"
    with pytest.raises(ValueError, match="must remain pending"):
        validate_security_scan_boundary(falsely_verified, today=date(2026, 9, 29))

    with pytest.raises(ValueError, match="review is overdue"):
        validate_security_scan_boundary(inventory, today=date(2026, 12, 29))


def test_security_test_fourteen_is_implemented_but_unverified() -> None:
    evidence = json.loads((PROJECT_ROOT / "docs/release-evidence.json").read_text(encoding="utf-8"))
    security_test = next(item for item in evidence["security_tests"] if item["id"] == 14)

    assert security_test["status"] == "implemented"
    assert "last_verified" not in security_test
