from __future__ import annotations

import copy
import json
from datetime import date

import pytest

from scripts.check_anti_automation_policy import (
    EXPECTED_FAMILY_COUNTS,
    EXPECTED_LIMITS,
    EXPECTED_ROUTE_FILES,
    EXPECTED_RUNTIME_TESTS,
    EXPECTED_SOURCE_ASSERTIONS,
    EXPECTED_SUMMARY,
    POLICY_PATH,
    PROJECT_ROOT,
    discover_named_routes,
    validate_anti_automation_policy,
    validate_source_contract,
)


def _policy() -> dict[str, object]:
    return json.loads(POLICY_PATH.read_text(encoding="utf-8"))


def test_anti_automation_policy_accepts_every_named_application_route() -> None:
    policy = _policy()

    validate_anti_automation_policy(policy, today=date(2026, 9, 26))

    documented_routes = {
        route
        for family in policy["route_families"]
        for route in family["routes"]  # type: ignore[index]
    }
    assert documented_routes == discover_named_routes()
    assert policy["limits"] == EXPECTED_LIMITS
    assert policy["summary"] == EXPECTED_SUMMARY


def test_anti_automation_policy_pins_families_sources_tests_and_gates() -> None:
    policy = _policy()

    assert {item["id"]: len(item["routes"]) for item in policy["route_families"]} == (
        EXPECTED_FAMILY_COUNTS
    )
    assert {item["id"] for item in policy["source_assertions"]} == set(EXPECTED_SOURCE_ASSERTIONS)
    assert set(policy["runtime_tests"]) == EXPECTED_RUNTIME_TESTS
    assert len(EXPECTED_ROUTE_FILES) == 9
    assert "scripts\\check_anti_automation_policy.py" in (
        PROJECT_ROOT / "scripts/check.ps1"
    ).read_text(encoding="utf-8")
    assert "scripts/check_anti_automation_policy.py" in (
        PROJECT_ROOT / "scripts/check.sh"
    ).read_text(encoding="utf-8")


def test_anti_automation_policy_rejects_route_limit_test_and_review_drift() -> None:
    policy = _policy()

    missing_route = copy.deepcopy(policy)
    missing_route["route_families"][0]["routes"].pop()  # type: ignore[index]
    with pytest.raises(ValueError, match="route-family inventory changed"):
        validate_anti_automation_policy(missing_route, today=date(2026, 9, 26))

    moved_route = copy.deepcopy(policy)
    moved = moved_route["route_families"][0]["routes"].pop()  # type: ignore[index]
    moved_route["route_families"][1]["routes"].append(moved)  # type: ignore[index]
    moved_route["route_families"][1]["routes"].sort()  # type: ignore[index]
    with pytest.raises(
        ValueError, match=r"route-family inventory changed|route assignments changed"
    ):
        validate_anti_automation_policy(moved_route, today=date(2026, 9, 26))

    changed_limit = copy.deepcopy(policy)
    changed_limit["limits"]["data_export"]["maximum"] = 500  # type: ignore[index]
    with pytest.raises(ValueError, match="limits changed"):
        validate_anti_automation_policy(changed_limit, today=date(2026, 9, 26))

    missing_test = copy.deepcopy(policy)
    missing_test["runtime_tests"].pop()  # type: ignore[union-attr]
    with pytest.raises(ValueError, match="runtime-test inventory changed"):
        validate_anti_automation_policy(missing_test, today=date(2026, 9, 26))

    with pytest.raises(ValueError, match="review is overdue"):
        validate_anti_automation_policy(policy, today=date(2026, 12, 26))


def test_anti_automation_policy_rejects_source_contract_drift() -> None:
    source = (PROJECT_ROOT / "config/settings/base.py").read_text(encoding="utf-8")
    changed = source.replace("DATA_EXPORT_RATE_LIMIT = 5", "DATA_EXPORT_RATE_LIMIT = 4")

    with pytest.raises(ValueError, match="source contract changed"):
        validate_source_contract("configured-budgets", changed)
