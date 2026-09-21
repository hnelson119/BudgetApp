from __future__ import annotations

import copy
import json
from datetime import date

import pytest

from scripts.check_resource_demand_policy import (
    EXPECTED_DEPLOYMENT_LIMITS,
    EXPECTED_OPERATION_CONTEXTS,
    EXPECTED_REQUIRED_CHECKS,
    EXPECTED_SOURCE_ASSERTIONS,
    EXPECTED_TIMEOUTS,
    POLICY_PATH,
    PROJECT_ROOT,
    _validate_deployment_limits,
    validate_resource_demand_policy,
    validate_source_contract,
)


def _policy() -> dict[str, object]:
    return json.loads(POLICY_PATH.read_text(encoding="utf-8"))


def test_resource_demand_policy_accepts_complete_inventory() -> None:
    policy = _policy()

    validate_resource_demand_policy(policy, today=date(2026, 9, 13))

    assert {item["id"]: item["execution_context"] for item in policy["operations"]} == (
        EXPECTED_OPERATION_CONTEXTS
    )
    assert policy["deployment_limits"] == EXPECTED_DEPLOYMENT_LIMITS
    assert policy["summary"] == {
        "operations": 7,
        "interactive_operations": 5,
        "response_timeouts": 5,
        "source_assertions": 12,
        "required_checks": 8,
        "residual_risks": 3,
    }


def test_resource_demand_policy_runs_in_both_quality_gates() -> None:
    powershell_gate = (PROJECT_ROOT / "scripts/check.ps1").read_text(encoding="utf-8")
    shell_gate = (PROJECT_ROOT / "scripts/check.sh").read_text(encoding="utf-8")

    assert "scripts\\check_resource_demand_policy.py" in powershell_gate
    assert "scripts/check_resource_demand_policy.py" in shell_gate


def test_resource_demand_policy_rejects_catalog_tampering() -> None:
    policy = _policy()

    missing_operation = copy.deepcopy(policy)
    missing_operation["operations"].pop()
    with pytest.raises(ValueError, match="operation inventory changed"):
        validate_resource_demand_policy(missing_operation, today=date(2026, 9, 13))

    changed_timeout = copy.deepcopy(policy)
    changed_timeout["response_timeouts"][0]["seconds"] = 16
    with pytest.raises(ValueError, match="response-timeout inventory changed"):
        validate_resource_demand_policy(changed_timeout, today=date(2026, 9, 13))

    changed_deployment = copy.deepcopy(policy)
    changed_deployment["deployment_limits"]["web_workers"] = 3
    with pytest.raises(ValueError, match="deployment limits changed"):
        validate_resource_demand_policy(changed_deployment, today=date(2026, 9, 13))

    with pytest.raises(ValueError, match="review is overdue"):
        validate_resource_demand_policy(policy, today=date(2026, 12, 13))


def test_resource_demand_policy_pins_all_checks_and_source_assertions() -> None:
    policy = _policy()

    assert set(policy["required_checks"]) == EXPECTED_REQUIRED_CHECKS
    assert {item["id"] for item in policy["source_assertions"]} == set(EXPECTED_SOURCE_ASSERTIONS)
    assert {item["id"] for item in policy["response_timeouts"]} == set(EXPECTED_TIMEOUTS)


def test_resource_demand_policy_rejects_source_limit_drift() -> None:
    source = (PROJECT_ROOT / "config/settings/base.py").read_text(encoding="utf-8")
    changed = source.replace("CSV_IMPORT_MAX_ROWS = 10_000", "CSV_IMPORT_MAX_ROWS = 20_000")

    with pytest.raises(ValueError, match="source contract changed"):
        validate_source_contract("csv-upload-contract", changed)


def test_resource_demand_policy_rejects_runtime_quota_drift(tmp_path) -> None:
    compose = (PROJECT_ROOT / "compose.yaml").read_text(encoding="utf-8")
    nginx = (PROJECT_ROOT / "deploy/network/nginx.conf").read_text(encoding="utf-8")
    (tmp_path / "deploy/network").mkdir(parents=True)
    (tmp_path / "deploy/network/nginx.conf").write_text(nginx, encoding="utf-8")
    (tmp_path / "compose.yaml").write_text(
        compose.replace("    mem_limit: 1g\n", "    mem_limit: 128m\n"),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="runtime resource-demand deployment limits changed"):
        _validate_deployment_limits(_policy(), tmp_path)
