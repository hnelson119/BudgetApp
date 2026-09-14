from __future__ import annotations

import copy
import json
from datetime import date

import pytest

from scripts.check_authorization_policy import (
    EXPECTED_FIELD_RULE_IDS,
    EXPECTED_FUNCTION_RULE_IDS,
    EXPECTED_ROUTE_ACCESS,
    POLICY_PATH,
    PROJECT_ROOT,
    discover_named_routes,
    validate_authorization_policy,
    validate_route_guards,
)


def _policy() -> dict[str, object]:
    return json.loads(POLICY_PATH.read_text(encoding="utf-8"))


def test_authorization_policy_accepts_complete_boundary() -> None:
    policy = _policy()

    validate_authorization_policy(policy, today=date(2026, 9, 13))

    assert policy["summary"] == {
        "consumer_states": 4,
        "route_namespaces": 9,
        "routes": 70,
        "function_rules": 11,
        "field_rules": 10,
        "source_assertions": 8,
        "known_gaps": 2,
    }
    assert {item["id"] for item in policy["function_rules"]} == EXPECTED_FUNCTION_RULE_IDS
    assert {item["id"] for item in policy["field_rules"]} == EXPECTED_FIELD_RULE_IDS


def test_authorization_policy_runs_in_both_quality_gates() -> None:
    powershell_gate = (PROJECT_ROOT / "scripts/check.ps1").read_text(encoding="utf-8")
    shell_gate = (PROJECT_ROOT / "scripts/check.sh").read_text(encoding="utf-8")

    assert "scripts\\check_authorization_policy.py" in powershell_gate
    assert "scripts/check_authorization_policy.py" in shell_gate


def test_authorization_policy_rejects_catalog_tampering() -> None:
    policy = _policy()

    missing_rule = copy.deepcopy(policy)
    missing_rule["field_rules"].pop()
    with pytest.raises(ValueError, match="field_rules inventory changed"):
        validate_authorization_policy(missing_rule, today=date(2026, 9, 13))

    permissive_default = copy.deepcopy(policy)
    permissive_default["default_decision"] = "allow"
    with pytest.raises(ValueError, match="deny by default"):
        validate_authorization_policy(permissive_default, today=date(2026, 9, 13))

    duplicate_route = copy.deepcopy(policy)
    duplicate_route["route_registry"][0]["access"]["member"].append("export")
    with pytest.raises(ValueError, match="multiple access tiers"):
        validate_authorization_policy(duplicate_route, today=date(2026, 9, 13))

    with pytest.raises(ValueError, match="review is overdue"):
        validate_authorization_policy(policy, today=date(2026, 12, 13))


def test_authorization_policy_detects_new_named_route() -> None:
    source = (PROJECT_ROOT / "core/urls.py").read_text(encoding="utf-8")
    changed = source.replace(
        "]",
        '    path("new/", views.home, name="unreviewed"),\n]',
        1,
    )

    assert set(discover_named_routes(changed, "core/urls.py")) == {
        "health-live",
        "health-ready",
        "home",
        "unreviewed",
    }


def test_authorization_policy_detects_removed_login_guard(tmp_path) -> None:
    for relative_path in ("core/urls.py", "core/views.py"):
        destination = tmp_path / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        source = (PROJECT_ROOT / relative_path).read_text(encoding="utf-8")
        if relative_path == "core/views.py":
            source = source.replace("@login_required\ndef home", "def home")
        destination.write_text(source, encoding="utf-8")

    with pytest.raises(ValueError, match="lost login guard"):
        validate_route_guards(
            relative_path="core/urls.py",
            access=EXPECTED_ROUTE_ACCESS["core/urls.py"],
            project_root=tmp_path,
        )
