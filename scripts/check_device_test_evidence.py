"""Validate the manual browser and assistive-technology test matrix and run records."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import date
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MATRIX_PATH = PROJECT_ROOT / "docs" / "device-test-matrix.json"
RUN_DIRECTORY = PROJECT_ROOT / "docs" / "device-test-runs"
EXPECTED_SCENARIOS = {
    "AUTH-01",
    "NAV-01",
    "PERIOD-01",
    "BUDGET-01",
    "SPEND-01",
    "DEBT-01",
    "GOAL-01",
    "THEME-01",
    "RESPONSIVE-01",
    "SESSION-01",
    "KEYBOARD-01",
    "SCREENREADER-01",
    "ZOOM-01",
}
EXPECTED_TARGETS = {
    "desktop-edge-current",
    "desktop-edge-previous",
    "desktop-chrome-current",
    "desktop-chrome-previous",
    "desktop-firefox-current",
    "desktop-firefox-previous",
    "desktop-safari-current",
    "mobile-iphone-safari-current",
    "mobile-iphone-firefox-current",
    "mobile-ipad-safari-current",
    "mobile-ipad-firefox-current",
    "mobile-android-chrome-current",
    "mobile-android-firefox-current",
    "keyboard-edge-current",
    "keyboard-firefox-current",
    "screenreader-narrator-edge-current",
    "screenreader-voiceover-safari-current",
    "screenreader-talkback-chrome-current",
    "zoom-edge-current",
}
EXPECTED_PROFILES = {"desktop", "mobile", "keyboard", "screen_reader", "zoom"}
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
RUN_ID_PATTERN = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}-[a-z0-9-]+$")
SCENARIO_STATUSES = {"passed", "failed", "blocked", "not_run"}


def _fail(message: str) -> None:
    raise ValueError(message)


def _objects_by_id(items: Any, collection: str) -> dict[str, dict[str, Any]]:
    if not isinstance(items, list) or not items:
        _fail(f"{collection} must be a non-empty list")
    indexed: dict[str, dict[str, Any]] = {}
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            _fail(f"{collection} entries must be objects with string identifiers")
        item_id = item["id"]
        if item_id in indexed:
            _fail(f"{collection} contains duplicate identifier {item_id!r}")
        indexed[item_id] = item
    return indexed


def validate_matrix(data: Any) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        _fail("unsupported device-test matrix schema")
    if set(data.get("profiles", [])) != EXPECTED_PROFILES:
        _fail("device-test profiles are incomplete")
    candidate = data.get("release_candidate")
    if candidate is not None and (
        not isinstance(candidate, str) or not COMMIT_PATTERN.fullmatch(candidate)
    ):
        _fail("release_candidate must be null or a full lowercase Git SHA")

    scenarios = _objects_by_id(data.get("scenarios"), "scenarios")
    if set(scenarios) != EXPECTED_SCENARIOS:
        _fail("device-test scenarios are incomplete")
    covered_profiles: set[str] = set()
    for scenario_id, scenario in scenarios.items():
        profiles = scenario.get("profiles")
        if not isinstance(scenario.get("title"), str) or not scenario["title"].strip():
            _fail(f"scenario {scenario_id!r} needs a title")
        if not isinstance(profiles, list) or not profiles or not set(profiles) <= EXPECTED_PROFILES:
            _fail(f"scenario {scenario_id!r} has invalid profiles")
        covered_profiles.update(profiles)
    if covered_profiles != EXPECTED_PROFILES:
        _fail("every device-test profile must have at least one scenario")

    targets = _objects_by_id(data.get("targets"), "targets")
    if set(targets) != EXPECTED_TARGETS:
        _fail("device-test targets are incomplete")
    for target_id, target in targets.items():
        profiles = target.get("profiles")
        if target.get("availability") not in {"required", "when available"}:
            _fail(f"target {target_id!r} has invalid availability")
        if not isinstance(profiles, list) or not profiles or not set(profiles) <= EXPECTED_PROFILES:
            _fail(f"target {target_id!r} has invalid profiles")
        for field in ("platform", "browser", "version_policy", "form_factor"):
            if not isinstance(target.get(field), str) or not target[field].strip():
                _fail(f"target {target_id!r} needs {field}")
    return scenarios, targets


def _parse_date(value: Any, label: str) -> None:
    if not isinstance(value, str):
        _fail(f"{label} must be an ISO date")
    try:
        date.fromisoformat(value)
    except ValueError as error:
        raise ValueError(f"{label} must be an ISO date") from error


def validate_run(
    data: Any,
    *,
    filename: str,
    matrix: dict[str, Any],
    scenarios: dict[str, dict[str, Any]],
    targets: dict[str, dict[str, Any]],
) -> None:
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        _fail(f"{filename} has an unsupported schema")
    required_fields = {
        "schema_version",
        "run_id",
        "target_id",
        "purpose",
        "tested_at",
        "candidate_commit",
        "tester_role",
        "browser_version",
        "platform_version",
        "synthetic_data_only",
        "overall_status",
        "scenario_results",
        "supersedes",
    }
    if set(data) != required_fields:
        _fail(f"{filename} must contain exactly the documented evidence fields")
    run_id = data.get("run_id")
    if not isinstance(run_id, str) or not RUN_ID_PATTERN.fullmatch(run_id):
        _fail(f"{filename} has an invalid run_id")
    if filename != f"{run_id}.json":
        _fail(f"{filename} must match its run_id")
    target_id = data.get("target_id")
    if target_id not in targets:
        _fail(f"{filename} references an unknown target")
    purpose = data.get("purpose")
    if purpose not in {"development_baseline", "release_candidate"}:
        _fail(f"{filename} has an invalid purpose")
    _parse_date(data.get("tested_at"), f"{filename} tested_at")
    candidate_commit = data.get("candidate_commit")
    if not isinstance(candidate_commit, str) or not COMMIT_PATTERN.fullmatch(candidate_commit):
        _fail(f"{filename} must name a full lowercase candidate Git SHA")
    expected_run_id = f"{data['tested_at']}-{target_id}-{candidate_commit[:7]}"
    if run_id != expected_run_id and not re.fullmatch(
        rf"{re.escape(expected_run_id)}-r[2-9][0-9]*", run_id
    ):
        _fail(f"{filename} run_id must bind its date, target, and candidate commit")
    for field in ("tester_role", "browser_version", "platform_version"):
        if not isinstance(data.get(field), str) or not data[field].strip():
            _fail(f"{filename} needs {field}")
    if data.get("synthetic_data_only") is not True:
        _fail(f"{filename} must confirm synthetic_data_only")
    supersedes = data.get("supersedes")
    if supersedes is not None and (
        not isinstance(supersedes, str) or not RUN_ID_PATTERN.fullmatch(supersedes)
    ):
        _fail(f"{filename} has an invalid supersedes identifier")

    result_items = _objects_by_id(data.get("scenario_results"), f"{filename} scenario_results")
    target_profiles = set(targets[target_id]["profiles"])
    expected_results = {
        scenario_id
        for scenario_id, scenario in scenarios.items()
        if target_profiles.intersection(scenario["profiles"])
    }
    if set(result_items) != expected_results:
        _fail(f"{filename} does not contain every scenario required by its target")
    statuses: list[str] = []
    for scenario_id, result in result_items.items():
        if set(result) != {"id", "status", "notes"}:
            _fail(f"{filename} scenario {scenario_id!r} has undocumented fields")
        status = result.get("status")
        if status not in SCENARIO_STATUSES:
            _fail(f"{filename} scenario {scenario_id!r} has an invalid status")
        if not isinstance(result.get("notes"), str) or not result["notes"].strip():
            _fail(f"{filename} scenario {scenario_id!r} needs sanitized notes")
        statuses.append(status)

    if "failed" in statuses:
        derived_status = "failed"
    elif "blocked" in statuses:
        derived_status = "blocked"
    elif "not_run" in statuses:
        derived_status = "partial"
    else:
        derived_status = "passed"
    if data.get("overall_status") != derived_status:
        _fail(f"{filename} overall_status must be {derived_status!r}")
    if purpose == "release_candidate" and derived_status == "passed":
        if matrix.get("release_candidate") != candidate_commit:
            _fail(f"{filename} does not match the matrix release candidate")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--require-complete",
        action="store_true",
        help="Fail unless every required target has passed for the selected release candidate.",
    )
    arguments = parser.parse_args()
    try:
        matrix = json.loads(MATRIX_PATH.read_text(encoding="utf-8"))
        scenarios, targets = validate_matrix(matrix)
        run_paths = sorted(RUN_DIRECTORY.glob("*.json"))
        observed_run_ids: set[str] = set()
        runs: list[dict[str, Any]] = []
        for run_path in run_paths:
            run = json.loads(run_path.read_text(encoding="utf-8"))
            validate_run(
                run,
                filename=run_path.name,
                matrix=matrix,
                scenarios=scenarios,
                targets=targets,
            )
            run_id = run["run_id"]
            if run_id in observed_run_ids:
                _fail(f"duplicate run identifier {run_id!r}")
            observed_run_ids.add(run_id)
            runs.append(run)
        superseded_ids = {run["supersedes"] for run in runs if run["supersedes"] is not None}
        for run in runs:
            supersedes = run["supersedes"]
            if supersedes is not None and supersedes not in observed_run_ids:
                _fail(f"run {run['run_id']!r} supersedes an unknown run")
            if supersedes == run["run_id"]:
                _fail(f"run {run['run_id']!r} cannot supersede itself")

        candidate = matrix.get("release_candidate")
        active_runs = [run for run in runs if run["run_id"] not in superseded_ids]
        active_keys: set[tuple[str, str, str]] = set()
        for run in active_runs:
            active_key = (run["purpose"], run["candidate_commit"], run["target_id"])
            if active_key in active_keys:
                _fail(
                    f"target {run['target_id']!r} has multiple active run records; "
                    "the newer record must supersede the older one"
                )
            active_keys.add(active_key)
        passing_targets = {
            run["target_id"]
            for run in active_runs
            if run["purpose"] == "release_candidate"
            and run["candidate_commit"] == candidate
            and run["overall_status"] == "passed"
        }
        required_targets = {
            target_id
            for target_id, target in targets.items()
            if target["availability"] == "required"
        }
        missing_targets = required_targets - passing_targets
        if arguments.require_complete and missing_targets:
            _fail(
                "required release-candidate targets remain incomplete: "
                + ", ".join(sorted(missing_targets))
            )
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
        print(f"Device-test evidence validation failed: {error}", file=sys.stderr)
        return 1
    print(f"Device-test evidence matrix is structurally complete ({len(run_paths)} run records).")
    print(
        f"Release-candidate coverage: {len(required_targets - missing_targets)}/"
        f"{len(required_targets)} required targets."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
