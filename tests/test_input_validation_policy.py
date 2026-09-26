from __future__ import annotations

import copy
import json
from datetime import date

import pytest

from scripts.check_input_validation_policy import (
    EXPECTED_BUSINESS_LIMIT_IDS,
    EXPECTED_BUSINESS_LIMIT_TESTS,
    EXPECTED_CONTEXT_RULE_IDS,
    EXPECTED_SOURCE_ASSERTIONS,
    EXPECTED_STRUCTURE_RULE_IDS,
    POLICY_PATH,
    PROJECT_ROOT,
    validate_form_source,
    validate_input_validation_policy,
    validate_source_contract,
)


def _policy() -> dict[str, object]:
    return json.loads(POLICY_PATH.read_text(encoding="utf-8"))


def test_input_validation_policy_accepts_complete_inventory() -> None:
    policy = _policy()

    validate_input_validation_policy(policy, today=date(2026, 9, 13))

    assert policy["summary"] == {
        "form_modules": 8,
        "form_classes": 49,
        "structure_rules": 10,
        "context_rules": 10,
        "business_limits": 11,
        "business_limit_tests": 26,
        "source_assertions": 13,
        "known_gaps": 1,
    }
    assert {item["id"] for item in policy["structure_rules"]} == EXPECTED_STRUCTURE_RULE_IDS
    assert {item["id"] for item in policy["context_rules"]} == EXPECTED_CONTEXT_RULE_IDS
    assert {item["id"] for item in policy["business_limits"]} == EXPECTED_BUSINESS_LIMIT_IDS
    assert {item["id"] for item in policy["business_limit_tests"]} == set(
        EXPECTED_BUSINESS_LIMIT_TESTS
    )
    assert {item["id"] for item in policy["source_assertions"]} == set(EXPECTED_SOURCE_ASSERTIONS)


def test_input_validation_policy_runs_in_both_quality_gates() -> None:
    powershell_gate = (PROJECT_ROOT / "scripts/check.ps1").read_text(encoding="utf-8")
    shell_gate = (PROJECT_ROOT / "scripts/check.sh").read_text(encoding="utf-8")

    assert "scripts\\check_input_validation_policy.py" in powershell_gate
    assert "scripts/check_input_validation_policy.py" in shell_gate


def test_input_validation_policy_rejects_catalog_tampering() -> None:
    policy = _policy()

    missing_rule = copy.deepcopy(policy)
    missing_rule["structure_rules"].pop()
    with pytest.raises(ValueError, match="structure_rules inventory changed"):
        validate_input_validation_policy(missing_rule, today=date(2026, 9, 13))

    changed_limit = copy.deepcopy(policy)
    changed_limit["source_assertions"][0]["contains"][0] = "unreviewed limit"
    with pytest.raises(ValueError, match="source assertion inventory changed"):
        validate_input_validation_policy(changed_limit, today=date(2026, 9, 13))

    missing_evidence = copy.deepcopy(policy)
    missing_evidence["context_rules"][0]["evidence"] = ["docs/does-not-exist.md"]
    with pytest.raises(ValueError, match="missing evidence path"):
        validate_input_validation_policy(missing_evidence, today=date(2026, 9, 13))

    missing_limit_test = copy.deepcopy(policy)
    missing_limit_test["business_limit_tests"][0]["tests"].pop()
    with pytest.raises(ValueError, match="business-limit test inventory changed"):
        validate_input_validation_policy(missing_limit_test, today=date(2026, 9, 13))

    with pytest.raises(ValueError, match="review is overdue"):
        validate_input_validation_policy(policy, today=date(2026, 12, 13))


def test_input_validation_policy_rejects_unclassified_form_class() -> None:
    source = (PROJECT_ROOT / "imports/forms.py").read_text(encoding="utf-8")

    with pytest.raises(ValueError, match="form class inventory changed"):
        validate_form_source(
            source + "\nclass UnreviewedInputForm(forms.Form):\n    pass\n",
            "imports/forms.py",
        )
    with pytest.raises(ValueError, match="unreviewed form module"):
        validate_form_source(
            "from django import forms\nclass NewForm(forms.Form):\n    pass\n",
            "new_app/forms.py",
        )


def test_input_validation_policy_rejects_source_limit_drift() -> None:
    source = (PROJECT_ROOT / "config/settings/base.py").read_text(encoding="utf-8")
    changed = source.replace(
        "CSV_IMPORT_MAX_ROWS = 10_000",
        "CSV_IMPORT_MAX_ROWS = 20_000",
    )

    with pytest.raises(ValueError, match="source contract changed"):
        validate_source_contract("csv-resource-contract", changed)
