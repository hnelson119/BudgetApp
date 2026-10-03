from __future__ import annotations

import copy
import json
import subprocess
import sys
from datetime import date

import pytest

from scripts.check_findings_exit_boundary import (
    EXPECTED_CONTROL_IDS,
    EXPECTED_FINDING_IDS,
    INVENTORY_PATH,
    PROJECT_ROOT,
    _validate_finding,
    parse_finding_register,
    validate_findings_exit_boundary,
)


def _inventory() -> dict[str, object]:
    return json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))


def test_findings_exit_inventory_is_complete_and_gate_wired() -> None:
    inventory = _inventory()

    validate_findings_exit_boundary(inventory, today=date(2026, 10, 2))

    assert {item["id"] for item in inventory["controls"]} == EXPECTED_CONTROL_IDS
    assert [item["id"] for item in inventory["findings"]] == EXPECTED_FINDING_IDS
    assert list(parse_finding_register()) == EXPECTED_FINDING_IDS
    assert inventory["summary"] == {
        "findings": 33,
        "critical": 1,
        "high": 7,
        "medium": 9,
        "low": 16,
        "retested": 23,
        "remediated": 10,
        "accepted": 0,
        "release_blockers": 1,
        "release_pending": 1,
    }


def test_findings_exit_inventory_rejects_invalid_state_transition() -> None:
    inventory = _inventory()
    invalid = copy.deepcopy(inventory)
    finding = next(item for item in invalid["findings"] if item["id"] == "M10-F024")
    finding["state"] = "Retested"

    with pytest.raises(ValueError, match="does not match the source register"):
        validate_findings_exit_boundary(invalid, today=date(2026, 9, 29))


def test_findings_exit_inventory_rejects_expired_or_high_acceptance() -> None:
    accepted = {
        "severity": "Medium",
        "state": "Accepted",
        "detected": "2026-08-24",
        "owner": "release owner",
        "fields": {
            "Affected environment": "isolated synthetic transport",
            "Detection": "A bounded scanner observed plaintext transport.",
            "Reason": "The transport is confined to a guarded synthetic network.",
            "Deadline": "Close before release and no later than 2026-09-30.",
            "Acceptance boundary": "No deployed plaintext transport is accepted.",
        },
    }
    with pytest.raises(ValueError, match="past its deadline"):
        _validate_finding("M10-TEST", accepted, today=date(2026, 10, 1))

    high_acceptance = copy.deepcopy(accepted)
    high_acceptance["severity"] = "High"
    with pytest.raises(ValueError, match="must be medium severity"):
        _validate_finding("M10-TEST", high_acceptance, today=date(2026, 9, 29))


def test_findings_exit_release_closure_remains_pending() -> None:
    inventory = _inventory()
    assert inventory["release_blockers"] == [
        {
            "id": "M10-F024",
            "required_transition": "Retested",
            "required_observation": (
                "Revoke every pre-upgrade authenticated and pending-MFA session, then retest "
                "administration MFA and recent-authentication enforcement on the selected release "
                "candidate."
            ),
        }
    ]

    falsely_closed = copy.deepcopy(inventory)
    falsely_closed["release_boundary"]["status"] = "complete"
    with pytest.raises(ValueError, match="must remain pending"):
        validate_findings_exit_boundary(falsely_closed, today=date(2026, 9, 29))

    required = subprocess.run(
        [sys.executable, "scripts/check_findings_exit_boundary.py", "--require-release-ready"],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert required.returncode == 1
    assert "release candidate must be selected" in required.stderr


def test_security_test_twenty_four_is_implemented_but_unverified() -> None:
    evidence = json.loads((PROJECT_ROOT / "docs/release-evidence.json").read_text(encoding="utf-8"))
    security_test = next(item for item in evidence["security_tests"] if item["id"] == 24)

    assert security_test["status"] == "implemented"
    assert "last_verified" not in security_test
