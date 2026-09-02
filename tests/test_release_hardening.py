from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.check_adversarial_test_evidence import (
    EXPECTED_CATEGORIES,
    EXPECTED_SCENARIOS,
)
from scripts.check_adversarial_test_evidence import (
    validate_matrix as validate_adversarial_matrix,
)
from scripts.check_adversarial_test_evidence import validate_run as validate_adversarial_run
from scripts.check_device_test_evidence import validate_matrix, validate_run
from scripts.check_release_evidence import validate_asvs_inventory
from scripts.secret_scan import _is_approved_public_fingerprint

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
    inventory = json.loads(
        (PROJECT_ROOT / "docs/asvs-5.0.0-level2-evidence.json").read_text(encoding="utf-8")
    )
    assert inventory["requirement_count"] == 253
    assert {item["chapter_id"] for item in inventory["requirements"]} == {
        f"V{number}" for number in range(1, 18)
    }
    assert inventory["summary"] == {
        "applicability": {"applicable": 173, "not_applicable": 80},
        "status": {
            "implemented": 100,
            "not_applicable": 80,
            "not_started": 16,
            "partial": 57,
        },
    }
    requirements = {item["id"]: item for item in inventory["requirements"]}
    assert requirements["v5.0.0-9.1.1"]["status"] == "not_applicable"
    assert requirements["v5.0.0-10.4.1"]["status"] == "not_applicable"
    assert requirements["v5.0.0-17.3.2"]["status"] == "not_applicable"
    assert requirements["v5.0.0-12.3.1"]["status"] == "not_started"
    assert requirements["v5.0.0-16.4.3"]["status"] == "not_started"
    assert {item["id"] for item in evidence["security_tests"]} == set(range(1, 25))
    assert {item["id"] for item in evidence["release_gates"]} == set(range(1, 13))
    assert not any(
        item["status"] == "verified"
        for collection in (
            inventory["requirements"],
            evidence["security_tests"],
            evidence["release_gates"],
        )
        for item in collection
    )


def test_asvs_inventory_rejects_catalog_and_disposition_tampering() -> None:
    inventory = json.loads(
        (PROJECT_ROOT / "docs/asvs-5.0.0-level2-evidence.json").read_text(encoding="utf-8")
    )

    changed_requirement = copy.deepcopy(inventory)
    changed_requirement["requirements"][0]["description"] += " altered"
    with pytest.raises(ValueError, match="declared catalog fingerprint"):
        validate_asvs_inventory(changed_requirement)

    missing_reason = copy.deepcopy(inventory)
    excluded = next(
        item for item in missing_reason["requirements"] if item["status"] == "not_applicable"
    )
    del excluded["reason"]
    with pytest.raises(ValueError, match="not applicable without a reason"):
        validate_asvs_inventory(missing_reason)

    overstated_exclusion = copy.deepcopy(inventory)
    applicable = next(
        item for item in overstated_exclusion["requirements"] if item["status"] == "partial"
    )
    applicable["status"] = "not_applicable"
    with pytest.raises(ValueError, match="applicable but has N/A status"):
        validate_asvs_inventory(overstated_exclusion)


def test_secret_scan_only_exempts_exact_public_asvs_fingerprints() -> None:
    source_sha256 = "".join(
        (
            "8201b20eec2908c3",  # pragma: allowlist secret
            "380ac600c91c8ba7",  # pragma: allowlist secret
            "46346fbb80885936",  # pragma: allowlist secret
            "6abb232027532311",  # pragma: allowlist secret
        )
    )
    line = f'    "source_sha256": "{source_sha256}",'

    assert _is_approved_public_fingerprint("docs/release-evidence.json", line)
    assert _is_approved_public_fingerprint("docs\\release-evidence.json", line)
    assert not _is_approved_public_fingerprint("docs/other.json", line)
    assert not _is_approved_public_fingerprint(
        "docs/release-evidence.json",
        f'    "source_sha256": "{source_sha256[:-1]}0",',
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


def test_adversarial_evidence_matrix_is_complete_and_pending() -> None:
    completed = subprocess.run(
        [sys.executable, "scripts/check_adversarial_test_evidence.py"],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert "structurally complete (0 run records)" in completed.stdout
    assert "Release-candidate coverage: 0/3 required targets." in completed.stdout
    matrix = json.loads(
        (PROJECT_ROOT / "docs/adversarial-test-matrix.json").read_text(encoding="utf-8")
    )
    assert matrix["release_candidate"] is None
    assert set(matrix["categories"]) == EXPECTED_CATEGORIES
    assert {scenario["id"] for scenario in matrix["scenarios"]} == set(EXPECTED_SCENARIOS)
    assert len(matrix["scenarios"]) == 28
    targets = {target["id"]: target for target in matrix["targets"]}
    assert targets["linux-vm-private-ingress"]["execution_phase"] == "release_only"
    assert not list((PROJECT_ROOT / "docs/adversarial-test-runs").glob("*.json"))

    required = subprocess.run(
        [sys.executable, "scripts/check_adversarial_test_evidence.py", "--require-complete"],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert required.returncode == 1
    assert "release_candidate must be selected" in required.stderr


def test_adversarial_matrix_rejects_coverage_tampering() -> None:
    matrix = json.loads(
        (PROJECT_ROOT / "docs/adversarial-test-matrix.json").read_text(encoding="utf-8")
    )

    missing_scenario = copy.deepcopy(matrix)
    missing_scenario["scenarios"].pop()
    with pytest.raises(ValueError, match="scenarios are incomplete"):
        validate_adversarial_matrix(missing_scenario)

    weakened_mapping = copy.deepcopy(matrix)
    scenario = next(item for item in weakened_mapping["scenarios"] if item["id"] == "AUTHZ-01")
    scenario["security_test_ids"] = [23]
    with pytest.raises(ValueError, match="incomplete security-test coverage"):
        validate_adversarial_matrix(weakened_mapping)

    relabeled_target = copy.deepcopy(matrix)
    scenario = next(item for item in relabeled_target["scenarios"] if item["id"] == "NET-01")
    scenario["target_id"] = "synthetic-app"
    with pytest.raises(ValueError, match="invalid target"):
        validate_adversarial_matrix(relabeled_target)


def test_adversarial_run_rejects_unprotected_or_overstated_evidence() -> None:
    matrix = json.loads(
        (PROJECT_ROOT / "docs/adversarial-test-matrix.json").read_text(encoding="utf-8")
    )
    scenarios, targets = validate_adversarial_matrix(matrix)
    run_id = "2026-08-27-synthetic-postgresql-aaaaaaa"
    valid_run = {
        "schema_version": 1,
        "run_id": run_id,
        "target_id": "synthetic-postgresql",
        "purpose": "development_baseline",
        "tested_at": "2026-08-27",
        "candidate_commit": "a" * 40,
        "tester_role": "release owner",
        "environment_summary": "Disposable PostgreSQL synthetic-data target",
        "synthetic_data_only": True,
        "overall_status": "passed",
        "scenario_results": [
            {"id": scenario_id, "status": "passed", "notes": "No finding.", "finding_ids": []}
            for scenario_id in ("AUDIT-01", "AUDIT-02", "AUDIT-03", "AUDIT-04")
        ],
        "supersedes": None,
    }
    validation_arguments = {
        "filename": f"{run_id}.json",
        "matrix": matrix,
        "scenarios": scenarios,
        "targets": targets,
        "known_finding_ids": {"M10-F001"},
    }

    validate_adversarial_run(valid_run, **validation_arguments)
    with pytest.raises(ValueError, match="synthetic_data_only"):
        validate_adversarial_run(valid_run | {"synthetic_data_only": False}, **validation_arguments)
    with pytest.raises(ValueError, match="restricted environment or credential detail"):
        validate_adversarial_run(
            valid_run | {"environment_summary": "Disposable target at 192.0.2.10"},
            **validation_arguments,
        )
    with pytest.raises(ValueError, match="does not match the matrix release candidate"):
        validate_adversarial_run(
            valid_run | {"purpose": "release_candidate"}, **validation_arguments
        )

    failed_without_finding = copy.deepcopy(valid_run)
    failed_without_finding["overall_status"] = "failed"
    failed_without_finding["scenario_results"][0]["status"] = "failed"
    with pytest.raises(ValueError, match="must reference a finding"):
        validate_adversarial_run(failed_without_finding, **validation_arguments)

    unknown_finding = copy.deepcopy(failed_without_finding)
    unknown_finding["scenario_results"][0]["finding_ids"] = ["M10-F999"]
    with pytest.raises(ValueError, match="references unknown findings"):
        validate_adversarial_run(unknown_finding, **validation_arguments)

    incomplete = copy.deepcopy(valid_run)
    incomplete["scenario_results"].pop()
    with pytest.raises(ValueError, match="does not contain every scenario"):
        validate_adversarial_run(incomplete, **validation_arguments)
