from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.check_device_test_evidence import validate_matrix, validate_run

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_release_evidence_inventory_is_complete_and_validated() -> None:
    completed = subprocess.run(
        [sys.executable, "scripts/check_release_evidence.py"],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert "structurally complete" in completed.stdout

    evidence = json.loads((PROJECT_ROOT / "docs/release-evidence.json").read_text(encoding="utf-8"))
    assert {item["id"] for item in evidence["asvs"]["chapters"]} == {
        f"V{number}" for number in range(1, 18)
    }
    assert {item["id"] for item in evidence["security_tests"]} == set(range(1, 25))
    assert {item["id"] for item in evidence["release_gates"]} == set(range(1, 13))
    assert not any(
        item["status"] == "verified"
        for collection in (
            evidence["asvs"]["chapters"],
            evidence["security_tests"],
            evidence["release_gates"],
        )
        for item in collection
    )


def test_raw_security_reports_are_ignored_and_documented_as_sensitive() -> None:
    gitignore = (PROJECT_ROOT / ".gitignore").read_text(encoding="utf-8")
    runbook = (PROJECT_ROOT / "docs/RELEASE_HARDENING.md").read_text(encoding="utf-8")

    assert "security-reports/" in gitignore
    assert "Do not commit raw ZAP sessions" in runbook
    assert "real household data" in runbook


def test_device_and_accessibility_evidence_matrix_is_complete_and_pending() -> None:
    completed = subprocess.run(
        [sys.executable, "scripts/check_device_test_evidence.py"],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert "structurally complete (0 run records)" in completed.stdout
    matrix = json.loads((PROJECT_ROOT / "docs/device-test-matrix.json").read_text(encoding="utf-8"))
    assert matrix["release_candidate"] is None
    assert {target["id"] for target in matrix["targets"]} >= {
        "desktop-edge-current",
        "desktop-firefox-current",
        "mobile-iphone-safari-current",
        "mobile-ipad-firefox-current",
        "mobile-android-chrome-current",
        "mobile-android-firefox-current",
        "screenreader-narrator-edge-current",
        "screenreader-voiceover-safari-current",
        "screenreader-talkback-chrome-current",
    }
    assert not list((PROJECT_ROOT / "docs/device-test-runs").glob("*.json"))


def test_device_run_validation_rejects_unprotected_or_overstated_evidence() -> None:
    matrix = json.loads((PROJECT_ROOT / "docs/device-test-matrix.json").read_text(encoding="utf-8"))
    scenarios, targets = validate_matrix(matrix)
    run_id = "2026-08-24-keyboard-edge-current-aaaaaaa"
    valid_run = {
        "schema_version": 1,
        "run_id": run_id,
        "target_id": "keyboard-edge-current",
        "purpose": "development_baseline",
        "tested_at": "2026-08-24",
        "candidate_commit": "a" * 40,
        "tester_role": "release owner",
        "browser_version": "151.0.0.0",
        "platform_version": "Windows test environment",
        "synthetic_data_only": True,
        "overall_status": "passed",
        "scenario_results": [{"id": "KEYBOARD-01", "status": "passed", "notes": "No finding."}],
        "supersedes": None,
    }

    validate_run(
        valid_run,
        filename=f"{run_id}.json",
        matrix=matrix,
        scenarios=scenarios,
        targets=targets,
    )
    with pytest.raises(ValueError, match="synthetic_data_only"):
        validate_run(
            valid_run | {"synthetic_data_only": False},
            filename=f"{run_id}.json",
            matrix=matrix,
            scenarios=scenarios,
            targets=targets,
        )
    with pytest.raises(ValueError, match="does not match the matrix release candidate"):
        validate_run(
            valid_run | {"purpose": "release_candidate"},
            filename=f"{run_id}.json",
            matrix=matrix,
            scenarios=scenarios,
            targets=targets,
        )
