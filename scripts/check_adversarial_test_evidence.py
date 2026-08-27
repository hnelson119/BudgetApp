"""Validate the manual adversarial-test matrix and its sanitized run records."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import date
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MATRIX_PATH = PROJECT_ROOT / "docs" / "adversarial-test-matrix.json"
RUN_DIRECTORY = PROJECT_ROOT / "docs" / "adversarial-test-runs"
FINDINGS_PATH = PROJECT_ROOT / "docs" / "SECURITY_FINDINGS.md"
PROCEDURE_PATH = PROJECT_ROOT / "docs" / "ADVERSARIAL_TESTING.md"

EXPECTED_CATEGORIES = {
    "authorization",
    "session",
    "csv",
    "financial_logic",
    "audit_integrity",
    "network_boundary",
}
EXPECTED_TARGETS = {
    "synthetic-app": "development_and_release",
    "synthetic-postgresql": "development_and_release",
    "linux-vm-private-ingress": "release_only",
}
EXPECTED_SCENARIOS: dict[str, tuple[str, str, set[int], set[str]]] = {
    "AUTHZ-01": (
        "authorization",
        "synthetic-app",
        {6, 23},
        {"WSTG-ATHZ-04"},
    ),
    "AUTHZ-02": (
        "authorization",
        "synthetic-app",
        {6, 23},
        {"WSTG-ATHZ-02", "WSTG-ATHZ-03"},
    ),
    "AUTHZ-03": (
        "authorization",
        "synthetic-app",
        {6, 23},
        {"WSTG-ATHZ-03", "WSTG-BUSL-01"},
    ),
    "AUTHZ-04": (
        "authorization",
        "synthetic-app",
        {5, 23},
        {"WSTG-SESS-05"},
    ),
    "SESS-01": (
        "session",
        "synthetic-app",
        {7, 23},
        {"WSTG-ATHN-03", "WSTG-ATHN-09", "WSTG-IDNT-04"},
    ),
    "SESS-02": (
        "session",
        "synthetic-app",
        {4, 23},
        {"WSTG-SESS-03"},
    ),
    "SESS-03": (
        "session",
        "synthetic-app",
        {8, 23},
        {"WSTG-SESS-06", "WSTG-SESS-09"},
    ),
    "SESS-04": (
        "session",
        "synthetic-app",
        {4, 23},
        {"WSTG-SESS-07", "WSTG-SESS-11"},
    ),
    "SESS-05": (
        "session",
        "synthetic-app",
        {3, 4, 21, 22, 23},
        {"WSTG-ATHN-06", "WSTG-SESS-02", "WSTG-SESS-04"},
    ),
    "CSV-01": (
        "csv",
        "synthetic-app",
        {9, 23},
        {"WSTG-BUSL-08", "WSTG-BUSL-09"},
    ),
    "CSV-02": (
        "csv",
        "synthetic-app",
        {10, 11, 23},
        {"WSTG-INPV-21"},
    ),
    "CSV-03": (
        "csv",
        "synthetic-app",
        {10, 23},
        {"WSTG-BUSL-05", "WSTG-BUSL-07"},
    ),
    "CSV-04": (
        "csv",
        "synthetic-app",
        {9, 10, 23},
        {"WSTG-ATHZ-01", "WSTG-BUSL-08", "WSTG-BUSL-09"},
    ),
    "FIN-01": (
        "financial_logic",
        "synthetic-app",
        {23},
        {"WSTG-BUSL-01", "WSTG-BUSL-03"},
    ),
    "FIN-02": (
        "financial_logic",
        "synthetic-app",
        {23},
        {"WSTG-BUSL-01", "WSTG-BUSL-02", "WSTG-BUSL-03"},
    ),
    "FIN-03": (
        "financial_logic",
        "synthetic-app",
        {23},
        {"WSTG-BUSL-03", "WSTG-BUSL-06"},
    ),
    "FIN-04": (
        "financial_logic",
        "synthetic-app",
        {23},
        {"WSTG-BUSL-01", "WSTG-BUSL-03"},
    ),
    "FIN-05": (
        "financial_logic",
        "synthetic-app",
        {23},
        {"WSTG-BUSL-04", "WSTG-BUSL-05", "WSTG-BUSL-07"},
    ),
    "AUDIT-01": (
        "audit_integrity",
        "synthetic-postgresql",
        {15, 23},
        {"WSTG-BUSL-03", "WSTG-CONF-01"},
    ),
    "AUDIT-02": (
        "audit_integrity",
        "synthetic-postgresql",
        {16, 23},
        {"WSTG-BUSL-03"},
    ),
    "AUDIT-03": (
        "audit_integrity",
        "synthetic-postgresql",
        {17, 23},
        {"WSTG-BUSL-03", "WSTG-BUSL-06"},
    ),
    "AUDIT-04": (
        "audit_integrity",
        "synthetic-postgresql",
        {19, 23},
        {"WSTG-BUSL-03"},
    ),
    "NET-01": (
        "network_boundary",
        "linux-vm-private-ingress",
        {1, 23},
        {"WSTG-CONF-01"},
    ),
    "NET-02": (
        "network_boundary",
        "linux-vm-private-ingress",
        {2, 23},
        {"WSTG-CONF-01", "WSTG-CONF-05"},
    ),
    "NET-03": (
        "network_boundary",
        "linux-vm-private-ingress",
        {3, 4, 23},
        {"WSTG-ATHN-01", "WSTG-CONF-07", "WSTG-SESS-02"},
    ),
    "NET-04": (
        "network_boundary",
        "linux-vm-private-ingress",
        {12, 13, 23},
        {"WSTG-CONF-01", "WSTG-CONF-05"},
    ),
    "NET-05": (
        "network_boundary",
        "linux-vm-private-ingress",
        {3, 4, 14, 23},
        {"WSTG-ATHN-06", "WSTG-ERRH-01", "WSTG-INPV-17"},
    ),
    "NET-06": (
        "network_boundary",
        "linux-vm-private-ingress",
        {12, 14, 23},
        {"WSTG-CONF-01", "WSTG-CONF-09"},
    ),
}

COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
RUN_ID_PATTERN = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}-[a-z0-9-]+-[0-9a-f]{7}(?:-r[2-9][0-9]*)?$"
)
FINDING_ID_PATTERN = re.compile(r"^M10-F[0-9]{3}$")
FINDING_HEADING_PATTERN = re.compile(r"^## (M10-F[0-9]{3}) ", re.MULTILINE)
SENSITIVE_EVIDENCE_PATTERN = re.compile(
    r"(?:https?://|(?:[0-9]{1,3}\.){3}[0-9]{1,3}|\blocalhost\b|"
    r"\b[a-z0-9.-]+\.(?:internal|local)\b|(?:authorization|cookie|password|secret|token)\s*[:=])",
    re.IGNORECASE,
)
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


def _parse_date(value: Any, label: str) -> date:
    if not isinstance(value, str):
        _fail(f"{label} must be an ISO date")
    try:
        return date.fromisoformat(value)
    except ValueError as error:
        raise ValueError(f"{label} must be an ISO date") from error


def _require_single_line(value: Any, label: str, *, maximum: int) -> None:
    if (
        not isinstance(value, str)
        or not value.strip()
        or value != value.strip()
        or "\n" in value
        or "\r" in value
        or len(value) > maximum
    ):
        _fail(f"{label} must be a trimmed single line of at most {maximum} characters")


def _require_sanitized_line(value: Any, label: str, *, maximum: int) -> None:
    _require_single_line(value, label, maximum=maximum)
    if SENSITIVE_EVIDENCE_PATTERN.search(value):
        _fail(f"{label} appears to contain restricted environment or credential detail")


def validate_matrix(data: Any) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    required_fields = {
        "schema_version",
        "updated",
        "release_candidate",
        "categories",
        "scenarios",
        "targets",
    }
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        _fail("unsupported adversarial-test matrix schema")
    if set(data) != required_fields:
        _fail("adversarial-test matrix must contain exactly the documented fields")
    _parse_date(data.get("updated"), "matrix updated")
    if set(data.get("categories", [])) != EXPECTED_CATEGORIES:
        _fail("adversarial-test categories are incomplete")
    candidate = data.get("release_candidate")
    if candidate is not None and (
        not isinstance(candidate, str) or not COMMIT_PATTERN.fullmatch(candidate)
    ):
        _fail("release_candidate must be null or a full lowercase Git SHA")

    targets = _objects_by_id(data.get("targets"), "targets")
    if set(targets) != set(EXPECTED_TARGETS):
        _fail("adversarial-test targets are incomplete")
    for target_id, target in targets.items():
        if set(target) != {"id", "title", "execution_phase", "description"}:
            _fail(f"target {target_id!r} has undocumented fields")
        if target.get("execution_phase") != EXPECTED_TARGETS[target_id]:
            _fail(f"target {target_id!r} has an invalid execution phase")
        _require_single_line(target.get("title"), f"target {target_id!r} title", maximum=100)
        _require_single_line(
            target.get("description"), f"target {target_id!r} description", maximum=300
        )

    scenarios = _objects_by_id(data.get("scenarios"), "scenarios")
    if set(scenarios) != set(EXPECTED_SCENARIOS):
        _fail("adversarial-test scenarios are incomplete")
    procedure_references: set[str] = set()
    for scenario_id, scenario in scenarios.items():
        if set(scenario) != {
            "id",
            "title",
            "category",
            "target_id",
            "security_test_ids",
            "wstg_ids",
            "procedure_reference",
        }:
            _fail(f"scenario {scenario_id!r} has undocumented fields")
        category, target_id, security_test_ids, wstg_ids = EXPECTED_SCENARIOS[scenario_id]
        if scenario.get("category") != category:
            _fail(f"scenario {scenario_id!r} has an invalid category")
        if scenario.get("target_id") != target_id:
            _fail(f"scenario {scenario_id!r} has an invalid target")
        if set(scenario.get("security_test_ids", [])) != security_test_ids:
            _fail(f"scenario {scenario_id!r} has incomplete security-test coverage")
        if set(scenario.get("wstg_ids", [])) != wstg_ids:
            _fail(f"scenario {scenario_id!r} has incomplete WSTG coverage")
        _require_single_line(scenario.get("title"), f"scenario {scenario_id!r} title", maximum=140)
        procedure_reference = scenario.get("procedure_reference")
        if not isinstance(procedure_reference, str) or not procedure_reference.startswith(
            "docs/ADVERSARIAL_TESTING.md#"
        ):
            _fail(f"scenario {scenario_id!r} has an invalid procedure reference")
        if procedure_reference in procedure_references:
            _fail("scenario procedure references must be unique")
        procedure_references.add(procedure_reference)
    return scenarios, targets


def validate_run(
    data: Any,
    *,
    filename: str,
    matrix: dict[str, Any],
    scenarios: dict[str, dict[str, Any]],
    targets: dict[str, dict[str, Any]],
    known_finding_ids: set[str],
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
        "environment_summary",
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
    tested_at = _parse_date(data.get("tested_at"), f"{filename} tested_at")
    candidate_commit = data.get("candidate_commit")
    if not isinstance(candidate_commit, str) or not COMMIT_PATTERN.fullmatch(candidate_commit):
        _fail(f"{filename} must name a full lowercase candidate Git SHA")
    expected_run_id = f"{tested_at.isoformat()}-{target_id}-{candidate_commit[:7]}"
    if run_id != expected_run_id and not re.fullmatch(
        rf"{re.escape(expected_run_id)}-r[2-9][0-9]*", run_id
    ):
        _fail(f"{filename} run_id must bind its date, target, and candidate commit")
    _require_single_line(data.get("tester_role"), f"{filename} tester_role", maximum=100)
    _require_sanitized_line(
        data.get("environment_summary"), f"{filename} environment_summary", maximum=200
    )
    if data.get("synthetic_data_only") is not True:
        _fail(f"{filename} must confirm synthetic_data_only")
    supersedes = data.get("supersedes")
    if supersedes is not None and (
        not isinstance(supersedes, str) or not RUN_ID_PATTERN.fullmatch(supersedes)
    ):
        _fail(f"{filename} has an invalid supersedes identifier")

    result_items = _objects_by_id(data.get("scenario_results"), f"{filename} scenario_results")
    expected_results = {
        scenario_id
        for scenario_id, scenario in scenarios.items()
        if scenario["target_id"] == target_id
    }
    if set(result_items) != expected_results:
        _fail(f"{filename} does not contain every scenario required by its target")
    statuses: list[str] = []
    for scenario_id, result in result_items.items():
        if set(result) != {"id", "status", "notes", "finding_ids"}:
            _fail(f"{filename} scenario {scenario_id!r} has undocumented fields")
        status = result.get("status")
        if status not in SCENARIO_STATUSES:
            _fail(f"{filename} scenario {scenario_id!r} has an invalid status")
        _require_sanitized_line(
            result.get("notes"),
            f"{filename} scenario {scenario_id!r} notes",
            maximum=500,
        )
        finding_ids = result.get("finding_ids")
        if not isinstance(finding_ids, list) or any(
            not isinstance(item, str) or not FINDING_ID_PATTERN.fullmatch(item)
            for item in finding_ids
        ):
            _fail(f"{filename} scenario {scenario_id!r} has invalid finding identifiers")
        if len(finding_ids) != len(set(finding_ids)):
            _fail(f"{filename} scenario {scenario_id!r} repeats a finding identifier")
        unknown_findings = set(finding_ids) - known_finding_ids
        if unknown_findings:
            _fail(
                f"{filename} scenario {scenario_id!r} references unknown findings: "
                + ", ".join(sorted(unknown_findings))
            )
        if status == "failed" and not finding_ids:
            _fail(f"{filename} failed scenario {scenario_id!r} must reference a finding")
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


def _load_finding_ids() -> set[str]:
    contents = FINDINGS_PATH.read_text(encoding="utf-8")
    return set(FINDING_HEADING_PATTERN.findall(contents))


def _validate_procedure_references(scenarios: dict[str, dict[str, Any]]) -> None:
    contents = PROCEDURE_PATH.read_text(encoding="utf-8")
    for scenario_id, scenario in scenarios.items():
        anchor = scenario["procedure_reference"].partition("#")[2]
        if f'<a id="{anchor}"></a>' not in contents:
            _fail(f"scenario {scenario_id!r} references a missing procedure anchor")


def _check_supersession(runs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    runs_by_id = {run["run_id"]: run for run in runs}
    superseded_ids: set[str] = set()
    for run in runs:
        supersedes = run["supersedes"]
        if supersedes is None:
            continue
        if supersedes == run["run_id"]:
            _fail(f"run {run['run_id']!r} cannot supersede itself")
        previous = runs_by_id.get(supersedes)
        if previous is None:
            _fail(f"run {run['run_id']!r} supersedes an unknown run")
        if any(
            run[field] != previous[field] for field in ("target_id", "purpose", "candidate_commit")
        ):
            _fail(f"run {run['run_id']!r} can supersede only the same target and candidate")
        if run["tested_at"] < previous["tested_at"]:
            _fail(f"run {run['run_id']!r} cannot supersede a newer run")
        if supersedes in superseded_ids:
            _fail(f"run {supersedes!r} is superseded more than once")
        superseded_ids.add(supersedes)

    for run in runs:
        observed: set[str] = set()
        cursor = run
        while cursor["supersedes"] is not None:
            next_id = cursor["supersedes"]
            if next_id in observed:
                _fail("run supersession history contains a cycle")
            observed.add(next_id)
            cursor = runs_by_id[next_id]
    return [run for run in runs if run["run_id"] not in superseded_ids]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--require-complete",
        action="store_true",
        help="Fail unless every target passed for the selected release candidate.",
    )
    arguments = parser.parse_args()
    run_paths: list[Path] = []
    try:
        matrix = json.loads(MATRIX_PATH.read_text(encoding="utf-8"))
        scenarios, targets = validate_matrix(matrix)
        _validate_procedure_references(scenarios)
        known_finding_ids = _load_finding_ids()
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
                known_finding_ids=known_finding_ids,
            )
            run_id = run["run_id"]
            if run_id in observed_run_ids:
                _fail(f"duplicate run identifier {run_id!r}")
            observed_run_ids.add(run_id)
            runs.append(run)

        active_runs = _check_supersession(runs)
        active_keys: set[tuple[str, str, str]] = set()
        for run in active_runs:
            active_key = (run["purpose"], run["candidate_commit"], run["target_id"])
            if active_key in active_keys:
                _fail(
                    f"target {run['target_id']!r} has multiple active run records; "
                    "the newer record must supersede the older one"
                )
            active_keys.add(active_key)

        candidate = matrix.get("release_candidate")
        passing_targets = {
            run["target_id"]
            for run in active_runs
            if run["purpose"] == "release_candidate"
            and run["candidate_commit"] == candidate
            and run["overall_status"] == "passed"
        }
        required_targets = set(targets)
        missing_targets = required_targets - passing_targets
        if arguments.require_complete and (candidate is None or missing_targets):
            if candidate is None:
                _fail("release_candidate must be selected before completeness can be claimed")
            _fail(
                "required release-candidate targets remain incomplete: "
                + ", ".join(sorted(missing_targets))
            )
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
        print(f"Adversarial-test evidence validation failed: {error}", file=sys.stderr)
        return 1
    print(
        f"Adversarial-test evidence matrix is structurally complete ({len(run_paths)} run records)."
    )
    print(
        f"Release-candidate coverage: {len(required_targets - missing_targets)}/"
        f"{len(required_targets)} required targets."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
