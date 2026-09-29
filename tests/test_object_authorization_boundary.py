from __future__ import annotations

import copy
import json
from datetime import date

import pytest

from scripts.check_object_authorization_boundary import (
    EXPECTED_CONTROL_IDS,
    INVENTORY_PATH,
    PROJECT_ROOT,
    discover_boundary_probes,
    discover_identifier_routes,
    validate_object_authorization_boundary,
)


def _inventory() -> dict[str, object]:
    return json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))


def test_object_authorization_inventory_is_complete_and_gate_wired() -> None:
    inventory = _inventory()

    validate_object_authorization_boundary(inventory, today=date(2026, 9, 29))

    routes = discover_identifier_routes()
    probes = discover_boundary_probes()
    assert {item["id"] for item in inventory["controls"]} == EXPECTED_CONTROL_IDS
    assert len(routes) == 38
    assert sum(len(route["methods"]) for route in routes.values()) == 66
    assert len(probes) == 41
    assert sum(len(probe["methods"]) for probe in probes.values()) == 72
    assert inventory["summary"]["bounded_checks"] == 146


def test_object_authorization_inventory_rejects_missing_operation_and_relationship() -> None:
    inventory = _inventory()
    missing_operation = copy.deepcopy(inventory)
    route = next(
        item for item in missing_operation["identifier_routes"] if item["id"] == "debts:edit"
    )
    route["methods"].remove("POST")
    with pytest.raises(ValueError, match="identifier route inventory changed"):
        validate_object_authorization_boundary(missing_operation, today=date(2026, 9, 29))

    missing_relationship = copy.deepcopy(inventory)
    missing_relationship["relationship_probes"].pop()
    with pytest.raises(ValueError, match="nested relationship probe inventory changed"):
        validate_object_authorization_boundary(missing_relationship, today=date(2026, 9, 29))


def test_object_authorization_release_remains_pending() -> None:
    inventory = _inventory()
    falsely_verified = copy.deepcopy(inventory)
    falsely_verified["release_boundary"]["status"] = "verified"
    with pytest.raises(ValueError, match="must remain pending"):
        validate_object_authorization_boundary(falsely_verified, today=date(2026, 9, 29))

    with pytest.raises(ValueError, match="review is overdue"):
        validate_object_authorization_boundary(inventory, today=date(2026, 12, 29))


def test_security_test_six_is_implemented_but_unverified() -> None:
    evidence = json.loads((PROJECT_ROOT / "docs/release-evidence.json").read_text(encoding="utf-8"))
    security_test = next(item for item in evidence["security_tests"] if item["id"] == 6)

    assert security_test["status"] == "implemented"
    assert "last_verified" not in security_test
