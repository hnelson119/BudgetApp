from __future__ import annotations

import copy
import json
from datetime import date

import pytest

from scripts.check_incident_response import (
    EXPECTED_ACTION_IDS,
    EXPECTED_REHEARSALS,
    POLICY_PATH,
    PROJECT_ROOT,
    validate_incident_response,
)


def _policy() -> dict[str, object]:
    return json.loads(POLICY_PATH.read_text(encoding="utf-8"))


def test_incident_response_inventory_is_complete_and_gate_wired() -> None:
    policy = _policy()

    validate_incident_response(policy, today=date(2026, 9, 28))

    assert {item["id"] for item in policy["actions"]} == EXPECTED_ACTION_IDS
    assert {item["id"]: item["runner"] for item in policy["rehearsals"]} == EXPECTED_REHEARSALS
    assert policy["summary"] == {
        "actions": 10,
        "repository_implemented_actions": 10,
        "release_pending_actions": 10,
        "rehearsals": 3,
    }
    assert "scripts\\check_incident_response.py" in (PROJECT_ROOT / "scripts/check.ps1").read_text(
        encoding="utf-8"
    )
    assert "scripts/check_incident_response.py" in (PROJECT_ROOT / "scripts/check.sh").read_text(
        encoding="utf-8"
    )


def test_incident_response_inventory_rejects_missing_action_and_false_verification() -> None:
    policy = _policy()
    missing_action = copy.deepcopy(policy)
    missing_action["actions"].pop()
    with pytest.raises(ValueError, match="action inventory changed"):
        validate_incident_response(missing_action, today=date(2026, 9, 28))

    falsely_verified = copy.deepcopy(policy)
    falsely_verified["actions"][0]["release_status"] = "verified"
    with pytest.raises(ValueError, match="action status changed"):
        validate_incident_response(falsely_verified, today=date(2026, 9, 28))


def test_incident_response_inventory_rejects_missing_evidence_and_stale_review() -> None:
    policy = _policy()
    missing_evidence = copy.deepcopy(policy)
    missing_evidence["actions"][0]["evidence"] = ["docs/not-present.md"]
    with pytest.raises(ValueError, match="is missing"):
        validate_incident_response(missing_evidence, today=date(2026, 9, 28))

    with pytest.raises(ValueError, match="review is overdue"):
        validate_incident_response(policy, today=date(2026, 12, 28))


def test_release_evidence_marks_incident_response_ready_but_unverified() -> None:
    evidence = json.loads((PROJECT_ROOT / "docs/release-evidence.json").read_text(encoding="utf-8"))
    security_test = next(item for item in evidence["security_tests"] if item["id"] == 20)
    release_gate = next(item for item in evidence["release_gates"] if item["id"] == 9)

    assert security_test["status"] == "implemented"
    assert release_gate["status"] == "implemented"
    assert "last_verified" not in security_test
    assert "last_verified" not in release_gate
