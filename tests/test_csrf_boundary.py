from __future__ import annotations

import copy
import json
from datetime import date

import pytest

from scripts.check_csrf_boundary import (
    EXPECTED_CONTROL_IDS,
    INVENTORY_PATH,
    PROJECT_ROOT,
    _validate_template_tokens,
    discover_mutation_routes,
    discover_probe_paths,
    validate_csrf_boundary,
)


def _inventory() -> dict[str, object]:
    return json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))


def test_csrf_inventory_is_complete_and_gate_wired() -> None:
    inventory = _inventory()

    validate_csrf_boundary(inventory, today=date(2026, 9, 29))

    assert {item["id"] for item in inventory["controls"]} == EXPECTED_CONTROL_IDS
    assert len(discover_mutation_routes()) == 63
    assert len(discover_probe_paths()) == 64
    assert inventory["summary"] == {
        "mutation_routes": 63,
        "probe_paths": 64,
        "attack_variants": 4,
        "bounded_checks": 256,
        "post_forms": 44,
        "release_pending": 1,
    }


def test_csrf_inventory_rejects_missing_route_and_unprotected_form(tmp_path) -> None:
    inventory = _inventory()
    missing = copy.deepcopy(inventory)
    missing["mutation_routes"].pop()
    with pytest.raises(ValueError, match="mutation route inventory changed"):
        validate_csrf_boundary(missing, today=date(2026, 9, 29))

    template = tmp_path / "sample" / "templates" / "sample" / "unsafe.html"
    template.parent.mkdir(parents=True)
    template.write_text('<form method="post"><button>Change</button></form>', encoding="utf-8")
    with pytest.raises(ValueError, match="POST form lacks a CSRF token"):
        _validate_template_tokens(tmp_path)


def test_csrf_inventory_rejects_missing_control_false_release_pass_and_stale_review() -> None:
    inventory = _inventory()
    missing_control = copy.deepcopy(inventory)
    missing_control["controls"].pop()
    with pytest.raises(ValueError, match="control inventory changed"):
        validate_csrf_boundary(missing_control, today=date(2026, 9, 29))

    falsely_verified = copy.deepcopy(inventory)
    falsely_verified["release_boundary"]["status"] = "verified"
    with pytest.raises(ValueError, match="must remain pending"):
        validate_csrf_boundary(falsely_verified, today=date(2026, 9, 29))

    with pytest.raises(ValueError, match="review is overdue"):
        validate_csrf_boundary(inventory, today=date(2026, 12, 29))


def test_security_test_five_is_implemented_but_unverified() -> None:
    evidence = json.loads((PROJECT_ROOT / "docs/release-evidence.json").read_text(encoding="utf-8"))
    security_test = next(item for item in evidence["security_tests"] if item["id"] == 5)

    assert security_test["status"] == "implemented"
    assert "last_verified" not in security_test
