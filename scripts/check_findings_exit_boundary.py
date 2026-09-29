"""Validate the complete security-finding register and release exit boundary."""

from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
import sys
from collections import Counter
from datetime import date
from pathlib import Path
from typing import Any, NoReturn

PROJECT_ROOT = Path(__file__).resolve().parents[1]
INVENTORY_PATH = PROJECT_ROOT / "docs" / "findings-exit-boundary.json"
FINDINGS_PATH = PROJECT_ROOT / "docs" / "SECURITY_FINDINGS.md"
MATRIX_PATH = PROJECT_ROOT / "docs" / "adversarial-test-matrix.json"

EXPECTED_CONTROL_IDS = {
    "complete-finding-register",
    "exact-candidate-closure",
    "high-critical-release-blocker",
    "state-transition-contract",
    "time-bounded-acceptance",
}
EXPECTED_FINDING_IDS = [f"M10-F{number:03d}" for number in range(1, 34)]
EXPECTED_SECURITY_EVIDENCE = {
    "SECURITY_PLAN.md#184-findings-and-exit-criteria",
    "docs/ADVERSARIAL_TESTING.md",
    "docs/SECURITY_FINDINGS.md",
    "docs/adversarial-test-runs/README.md",
    "docs/findings-exit-boundary.json",
    "scripts/check_adversarial_test_evidence.py",
    "scripts/check_findings_exit_boundary.py",
    "scripts/check_zap_reports.py",
    "tests/test_findings_exit_boundary.py",
}
ALLOWED_SEVERITIES = {"Critical", "High", "Medium", "Low"}
ALLOWED_STATES = {"Accepted", "Remediated", "Retested"}
HEADING_PATTERN = re.compile(r"(?m)^## (M10-F\d{3}) .+$")
FIELD_PATTERN = re.compile(r"(?m)^- ([A-Za-z][A-Za-z ]+): (.+(?:\n  .+)*)$")


def _fail(message: str) -> NoReturn:
    raise ValueError(message)


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        _fail(f"{label} must be non-empty text")
    return value


def _safe_path(value: Any, *, project_root: Path, label: str) -> str:
    documented = _text(value, label)
    relative = documented.split("#", maxsplit=1)[0]
    path = Path(relative)
    if path.is_absolute():
        _fail(f"{label} must be repository relative")
    resolved = (project_root / path).resolve()
    try:
        resolved.relative_to(project_root.resolve())
    except ValueError:
        _fail(f"{label} escapes the repository")
    if not resolved.exists():
        _fail(f"{label} is missing: {relative}")
    return documented


def _string_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or not value:
        _fail(f"{label} must be a non-empty list")
    values = [_text(item, f"{label} item") for item in value]
    if len(values) != len(set(values)):
        _fail(f"{label} contains duplicates")
    return values


def _test_functions(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return {
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith("test_")
    }


def parse_finding_register(
    project_root: Path = PROJECT_ROOT,
) -> dict[str, dict[str, Any]]:
    source = (project_root / "docs/SECURITY_FINDINGS.md").read_text(encoding="utf-8")
    all_headings = list(re.finditer(r"(?m)^## .+$", source))
    findings: dict[str, dict[str, Any]] = {}
    for index, heading in enumerate(all_headings):
        finding_heading = HEADING_PATTERN.fullmatch(heading.group(0))
        if finding_heading is None:
            continue
        identifier = finding_heading.group(1)
        end = all_headings[index + 1].start() if index + 1 < len(all_headings) else len(source)
        section = source[heading.end() : end]
        fields: dict[str, str] = {}
        for match in FIELD_PATTERN.finditer(section):
            label = match.group(1)
            if label in fields:
                _fail(f"finding {identifier} repeats field {label!r}")
            fields[label] = " ".join(line.strip() for line in match.group(2).splitlines())
        if identifier in findings:
            _fail(f"finding register repeats {identifier}")
        findings[identifier] = {
            "severity": fields.get("Severity"),
            "state": fields.get("State"),
            "detected": fields.get("Detected"),
            "owner": fields.get("Owner"),
            "fields": fields,
        }
    return findings


def _validate_finding(
    identifier: str,
    finding: dict[str, Any],
    *,
    today: date,
) -> None:
    severity = finding["severity"]
    state = finding["state"]
    fields = finding["fields"]
    if severity not in ALLOWED_SEVERITIES:
        _fail(f"finding {identifier} has invalid severity")
    if state not in ALLOWED_STATES:
        _fail(f"finding {identifier} has invalid state")
    try:
        detected = date.fromisoformat(_text(finding["detected"], f"{identifier} detected"))
    except ValueError as error:
        raise ValueError(f"finding {identifier} has invalid detected date") from error
    if detected > today:
        _fail(f"finding {identifier} has a future detected date")
    _text(finding["owner"], f"{identifier} owner")
    if "Detection" not in fields:
        _fail(f"finding {identifier} lacks detection evidence")
    if not ({"Affected baseline", "Affected environment"} & set(fields)):
        _fail(f"finding {identifier} lacks an affected boundary")

    if state == "Retested":
        if not {"Remediation", "Retest"}.issubset(fields):
            _fail(f"retested finding {identifier} lacks remediation or retest evidence")
    elif state == "Remediated":
        if not {"Remediation", "Automated retest"}.issubset(fields):
            _fail(f"remediated finding {identifier} lacks remediation or automated retest evidence")
        if not ({"Release boundary", "Deployment requirement"} & set(fields)):
            _fail(f"remediated finding {identifier} lacks its pending release boundary")
    else:
        if severity != "Medium":
            _fail(f"accepted finding {identifier} must be medium severity")
        required = {"Acceptance boundary", "Deadline", "Reason"}
        if not required.issubset(fields):
            _fail(f"accepted finding {identifier} lacks formal acceptance metadata")
        deadline_match = re.search(r"\d{4}-\d{2}-\d{2}", fields["Deadline"])
        if deadline_match is None:
            _fail(f"accepted finding {identifier} lacks an ISO deadline")
        deadline = date.fromisoformat(deadline_match.group(0))
        if deadline < today:
            _fail(f"accepted finding {identifier} is past its deadline")


def validate_findings_exit_boundary(
    inventory: dict[str, Any],
    *,
    project_root: Path = PROJECT_ROOT,
    today: date | None = None,
    require_release_ready: bool = False,
) -> None:
    current_date = today or date.today()
    if set(inventory) != {
        "controls",
        "findings",
        "inventory_id",
        "last_reviewed",
        "next_review_due",
        "release_blockers",
        "release_boundary",
        "schema_version",
        "security_test_id",
        "summary",
    }:
        _fail("findings-exit inventory fields changed")
    if inventory["schema_version"] != 1 or inventory["inventory_id"] != (
        "budgetapp-findings-exit-boundary-v1"
    ):
        _fail("unsupported findings-exit inventory identity")
    if inventory["security_test_id"] != 24:
        _fail("findings-exit inventory must remain bound to security test 24")
    reviewed = date.fromisoformat(_text(inventory["last_reviewed"], "last_reviewed"))
    due = date.fromisoformat(_text(inventory["next_review_due"], "next_review_due"))
    if due <= reviewed or (due - reviewed).days > 90:
        _fail("findings-exit review cadence exceeds 90 days")
    if current_date > due:
        _fail("findings-exit inventory review is overdue")

    controls = inventory.get("controls")
    if not isinstance(controls, list) or any(not isinstance(item, dict) for item in controls):
        _fail("findings-exit controls must contain objects")
    observed_controls: set[str] = set()
    test_cache: dict[str, set[str]] = {}
    for control in controls:
        if set(control) != {"evidence", "id", "objective", "repository_status", "test_refs"}:
            _fail("findings-exit control fields changed")
        identifier = _text(control["id"], "control id")
        if identifier in observed_controls:
            _fail(f"duplicate findings-exit control: {identifier}")
        observed_controls.add(identifier)
        _text(control["objective"], f"{identifier} objective")
        if control["repository_status"] != "implemented":
            _fail(f"findings-exit control is not implemented: {identifier}")
        for evidence in _string_list(control["evidence"], f"{identifier} evidence"):
            _safe_path(evidence, project_root=project_root, label=f"{identifier} evidence")
        for reference in _string_list(control["test_refs"], f"{identifier} test_refs"):
            try:
                relative, function = reference.split("::", maxsplit=1)
            except ValueError:
                _fail(f"invalid findings-exit test reference: {reference}")
            path = project_root / _safe_path(
                relative, project_root=project_root, label=f"{identifier} test"
            )
            functions = test_cache.setdefault(relative, _test_functions(path))
            if not relative.startswith("tests/") or function not in functions:
                _fail(f"findings-exit test reference is missing: {reference}")
    if observed_controls != EXPECTED_CONTROL_IDS:
        _fail("findings-exit control inventory changed")

    parsed = parse_finding_register(project_root)
    if list(parsed) != EXPECTED_FINDING_IDS:
        _fail("finding register identifiers are incomplete or out of order")
    for identifier, finding in parsed.items():
        _validate_finding(identifier, finding, today=current_date)

    documented = inventory.get("findings")
    if not isinstance(documented, list) or any(not isinstance(item, dict) for item in documented):
        _fail("findings inventory must contain objects")
    documented_by_id: dict[str, dict[str, str]] = {}
    for finding in documented:
        if set(finding) != {"id", "severity", "state"}:
            _fail("documented finding fields changed")
        identifier = _text(finding["id"], "finding id")
        if identifier in documented_by_id:
            _fail(f"findings inventory repeats {identifier}")
        documented_by_id[identifier] = {
            "severity": _text(finding["severity"], f"{identifier} severity"),
            "state": _text(finding["state"], f"{identifier} state"),
        }
    parsed_dispositions = {
        identifier: {"severity": finding["severity"], "state": finding["state"]}
        for identifier, finding in parsed.items()
    }
    if list(documented_by_id) != EXPECTED_FINDING_IDS or documented_by_id != parsed_dispositions:
        _fail("findings inventory does not match the source register")

    expected_blockers = {
        identifier
        for identifier, finding in parsed.items()
        if finding["severity"] in {"Critical", "High"} and finding["state"] != "Retested"
    }
    blockers = inventory.get("release_blockers")
    if not isinstance(blockers, list) or any(not isinstance(item, dict) for item in blockers):
        _fail("release_blockers must contain objects")
    documented_blockers: set[str] = set()
    for blocker in blockers:
        if set(blocker) != {"id", "required_observation", "required_transition"}:
            _fail("release blocker fields changed")
        identifier = _text(blocker["id"], "release blocker id")
        if identifier in documented_blockers:
            _fail(f"release blocker repeats {identifier}")
        documented_blockers.add(identifier)
        if blocker["required_transition"] != "Retested":
            _fail(f"release blocker {identifier} must require a Retested transition")
        _text(blocker["required_observation"], f"{identifier} required observation")
    if documented_blockers != expected_blockers:
        _fail("high or critical release-blocker inventory changed")

    release_boundary = inventory.get("release_boundary")
    if not isinstance(release_boundary, dict) or set(release_boundary) != {
        "candidate_source",
        "completion_command",
        "required_observation",
        "status",
    }:
        _fail("findings release-boundary fields changed")
    if release_boundary["status"] != "pending":
        _fail("findings release boundary must remain pending")
    _safe_path(
        release_boundary["candidate_source"],
        project_root=project_root,
        label="release candidate source",
    )
    if release_boundary["completion_command"] != (
        "python scripts/check_adversarial_test_evidence.py --require-complete"
    ):
        _fail("findings completion command changed")
    _text(release_boundary["required_observation"], "required release observation")

    severity_counts = Counter(finding["severity"].casefold() for finding in parsed.values())
    state_counts = Counter(finding["state"].casefold() for finding in parsed.values())
    expected_summary = {
        "findings": len(parsed),
        "critical": severity_counts["critical"],
        "high": severity_counts["high"],
        "medium": severity_counts["medium"],
        "low": severity_counts["low"],
        "retested": state_counts["retested"],
        "remediated": state_counts["remediated"],
        "accepted": state_counts["accepted"],
        "release_blockers": len(expected_blockers),
        "release_pending": 1,
    }
    if inventory.get("summary") != expected_summary:
        _fail("findings-exit summary is stale")

    adversarial_source = (project_root / "scripts/check_adversarial_test_evidence.py").read_text(
        encoding="utf-8"
    )
    for fragment in (
        'FINDING_HEADING_PATTERN = re.compile(r"^## (M10-F[0-9]{3}) "',
        "failed scenario {scenario_id!r} must reference a finding",
        '"--require-complete"',
        "release_candidate must be selected before completeness can be claimed",
    ):
        if fragment not in adversarial_source:
            _fail("adversarial finding or completion contract changed")

    release_document = json.loads(
        (project_root / "docs/release-evidence.json").read_text(encoding="utf-8")
    )
    matches = [
        item
        for item in release_document.get("security_tests", [])
        if isinstance(item, dict) and item.get("id") == 24
    ]
    if len(matches) != 1:
        _fail("security test 24 is missing or duplicated")
    security_test = matches[0]
    if security_test.get("status") != "implemented" or not EXPECTED_SECURITY_EVIDENCE.issubset(
        set(security_test.get("evidence", []))
    ):
        _fail("security test 24 is not findings-exit ready")
    if "last_verified" in security_test:
        _fail("security test 24 must remain unverified without release-candidate evidence")

    for gate_path, fragment in (
        ("scripts/check.ps1", "scripts\\check_findings_exit_boundary.py"),
        ("scripts/check.sh", "scripts/check_findings_exit_boundary.py"),
    ):
        if fragment not in (project_root / gate_path).read_text(encoding="utf-8"):
            _fail(f"findings-exit checker is missing from {gate_path}")

    if require_release_ready:
        matrix = json.loads((project_root / "docs/adversarial-test-matrix.json").read_text())
        if matrix.get("release_candidate") is None:
            _fail("release candidate must be selected before findings closure")
        if expected_blockers:
            _fail("high or critical findings remain release blockers")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--require-release-ready",
        action="store_true",
        help=(
            "Fail until the selected release candidate satisfies the final findings exit boundary."
        ),
    )
    arguments = parser.parse_args()
    try:
        inventory = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))
        validate_findings_exit_boundary(
            inventory, require_release_ready=arguments.require_release_ready
        )
        if arguments.require_release_ready:
            completed = subprocess.run(
                [
                    sys.executable,
                    "scripts/check_adversarial_test_evidence.py",
                    "--require-complete",
                ],
                cwd=PROJECT_ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            if completed.returncode != 0:
                detail = completed.stderr.strip() or completed.stdout.strip()
                _fail(f"complete adversarial release evidence is missing: {detail}")
    except (OSError, SyntaxError, json.JSONDecodeError, ValueError) as error:
        print(f"Findings-exit validation failed: {error}", file=sys.stderr)
        return 1
    summary = inventory["summary"]
    print(
        "Findings-exit inventory passed: "
        f"{summary['findings']} findings, {summary['release_blockers']} release blocker, "
        "exact-candidate closure pending."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
