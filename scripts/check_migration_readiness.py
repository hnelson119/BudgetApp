"""Validate migration-readiness policy, rehearsal, and release-gate wiring."""

from __future__ import annotations

import json
import sys
from datetime import date
from pathlib import Path
from typing import Any, NoReturn

PROJECT_ROOT = Path(__file__).resolve().parents[1]
INVENTORY_PATH = PROJECT_ROOT / "docs" / "migration-readiness.json"

EXPECTED_CONTROL_IDS = {
    "candidate-health-and-integrity",
    "clean-database-rollback",
    "forward-schema-application-rollback",
    "immutable-release-identity",
    "least-privilege-migration-role",
    "migration-review-and-classification",
    "pre-upgrade-recovery-point",
    "sanitized-release-evidence",
}
EXPECTED_SERVICES = [
    "pentest-upgrade-migrate",
    "pentest-upgrade-candidate-web",
    "pentest-upgrade-rollback-web",
    "pentest-upgrade-verify",
]
EXPECTED_SUCCESS_MARKERS = [
    "UPGRADE-01 automated checks passed",
    "ROLLBACK-01 automated checks passed",
    "Disposable forward-upgrade and clean-database rollback rehearsal completed.",
]
POLICY_CONTRACT = (
    "Never edit or delete a migration that has reached a shared environment.",
    "Prefer additive, backwards-compatible schema changes before destructive cleanup.",
    "Test forward migration and restore/rollback procedures on a copy without real data.",
    "data migrations deterministic, bounded, restart-safe, and free of network calls",
    "verified pre-upgrade snapshot restored to a new target",
)
RUNBOOK_CONTRACT = (
    "## 1. Two distinct rollback paths",
    "## 2. Release identity and prerequisites",
    "## 3. Create the rollback point",
    "## 4. Stage and apply the candidate",
    "## 5. Application-only rollback",
    "## 6. Clean-database rollback",
    "## 7. Failure and evidence rules",
    "## 8. Disposable rehearsal",
    "Never restore over, drop, truncate, or reverse-migrate the source database.",
    "APP_RELEASE=<candidate-full-commit>",
    "RESTORE_TARGET_DB=household_budget_restore_<label>",
)
EXPECTED_GATE_EVIDENCE = {
    ".github/workflows/upgrade-rehearsal.yml",
    "docs/MIGRATIONS.md",
    "docs/UPGRADE_AND_ROLLBACK.md",
    "docs/migration-readiness.json",
    "scripts/check_migration_readiness.py",
    "scripts/run-upgrade-rehearsal.sh",
    "tests/test_migration_readiness.py",
    "tests/test_upgrade_rehearsal.py",
}


def _fail(message: str) -> NoReturn:
    raise ValueError(message)


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        _fail(f"{label} must be non-empty text")
    return value


def _safe_path(value: Any, *, project_root: Path, label: str) -> str:
    relative = _text(value, label)
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
    return relative


def _evidence(value: Any, *, project_root: Path, label: str) -> list[str]:
    if not isinstance(value, list) or not value:
        _fail(f"{label} must be a non-empty list")
    paths = [_safe_path(item, project_root=project_root, label=f"{label} path") for item in value]
    if len(paths) != len(set(paths)):
        _fail(f"{label} contains duplicate paths")
    return paths


def _require_fragments(source: str, fragments: tuple[str, ...] | list[str], label: str) -> None:
    missing = [fragment for fragment in fragments if fragment not in source]
    if missing:
        _fail(f"{label} contract changed: {missing}")


def validate_migration_readiness(
    inventory: dict[str, Any],
    *,
    project_root: Path = PROJECT_ROOT,
    today: date | None = None,
) -> None:
    expected_fields = {
        "controls",
        "inventory_id",
        "last_reviewed",
        "next_review_due",
        "policy",
        "rehearsal",
        "runbook",
        "schema_version",
        "summary",
    }
    if set(inventory) != expected_fields:
        _fail("migration-readiness inventory fields changed")
    if inventory["schema_version"] != 1 or inventory["inventory_id"] != (
        "budgetapp-migration-readiness-v1"
    ):
        _fail("unsupported migration-readiness inventory identity")
    reviewed = date.fromisoformat(_text(inventory["last_reviewed"], "last_reviewed"))
    due = date.fromisoformat(_text(inventory["next_review_due"], "next_review_due"))
    if due <= reviewed or (due - reviewed).days > 90:
        _fail("migration-readiness review cadence exceeds 90 days")
    if (today or date.today()) > due:
        _fail("migration-readiness inventory review is overdue")

    policy = _safe_path(inventory["policy"], project_root=project_root, label="policy")
    runbook = _safe_path(inventory["runbook"], project_root=project_root, label="runbook")
    _require_fragments(
        (project_root / policy).read_text(encoding="utf-8"), POLICY_CONTRACT, "migration policy"
    )
    _require_fragments(
        (project_root / runbook).read_text(encoding="utf-8"), RUNBOOK_CONTRACT, "upgrade runbook"
    )

    controls = inventory.get("controls")
    if not isinstance(controls, list) or any(not isinstance(item, dict) for item in controls):
        _fail("migration-readiness controls must contain objects")
    observed: set[str] = set()
    expected_control_fields = {
        "evidence",
        "id",
        "objective",
        "release_status",
        "release_verification",
        "repository_status",
    }
    for control in controls:
        if set(control) != expected_control_fields:
            _fail("migration-readiness control fields changed")
        identifier = _text(control["id"], "control id")
        if identifier in observed:
            _fail(f"duplicate migration-readiness control: {identifier}")
        observed.add(identifier)
        _text(control["objective"], f"{identifier} objective")
        _text(control["release_verification"], f"{identifier} release_verification")
        if control["repository_status"] != "implemented" or control["release_status"] != "pending":
            _fail(f"migration-readiness control status changed: {identifier}")
        _evidence(control["evidence"], project_root=project_root, label=f"{identifier} evidence")
    if observed != EXPECTED_CONTROL_IDS:
        _fail("migration-readiness control inventory changed")

    rehearsal = inventory.get("rehearsal")
    if not isinstance(rehearsal, dict) or set(rehearsal) != {
        "limitation",
        "runners",
        "services",
        "success_markers",
        "workflow",
    }:
        _fail("migration-readiness rehearsal fields changed")
    workflow = _safe_path(rehearsal["workflow"], project_root=project_root, label="workflow")
    runners = _evidence(rehearsal["runners"], project_root=project_root, label="runners")
    if runners != ["scripts/run-upgrade-rehearsal.sh", "scripts/run-upgrade-rehearsal.ps1"]:
        _fail("migration-readiness runners changed")
    if rehearsal["services"] != EXPECTED_SERVICES:
        _fail("migration-readiness rehearsal services changed")
    if rehearsal["success_markers"] != EXPECTED_SUCCESS_MARKERS:
        _fail("migration-readiness success markers changed")
    _text(rehearsal["limitation"], "rehearsal limitation")

    workflow_source = (project_root / workflow).read_text(encoding="utf-8")
    _require_fragments(
        workflow_source,
        [
            "pull_request:",
            "permissions:\n  contents: read",
            "persist-credentials: false",
            "sh scripts/run-upgrade-rehearsal.sh",
        ],
        "upgrade workflow",
    )
    shell_source = (project_root / runners[0]).read_text(encoding="utf-8")
    for fragment in [
        "pentest-backup",
        *EXPECTED_SERVICES,
        'RESTORE_TARGET_DB="$rollback_target"',
        "PENTEST_UPGRADE_EXPECTATION=restored-baseline",  # pragma: allowlist secret
        EXPECTED_SUCCESS_MARKERS[2],
    ]:
        _require_fragments(shell_source, [fragment], "upgrade runner")
    if shell_source.index("pentest-backup") >= shell_source.index("pentest-upgrade-migrate"):
        _fail("upgrade runner no longer creates a backup before migration")

    compose_source = (project_root / "compose.pentest.yaml").read_text(encoding="utf-8")
    _require_fragments(compose_source, EXPECTED_SERVICES, "upgrade services")
    verifier_source = (project_root / "deploy/pentest/verify-upgrade-rollback.py").read_text(
        encoding="utf-8"
    )
    _require_fragments(verifier_source, EXPECTED_SUCCESS_MARKERS[:2], "upgrade verifier")

    release_document = json.loads(
        (project_root / "docs/release-evidence.json").read_text(encoding="utf-8")
    )
    gates = release_document.get("release_gates")
    if not isinstance(gates, list):
        _fail("release gates are malformed")
    matching = [item for item in gates if isinstance(item, dict) and item.get("id") == 10]
    if len(matching) != 1:
        _fail("release gate 10 is missing or duplicated")
    gate = matching[0]
    if gate.get("status") != "implemented" or not EXPECTED_GATE_EVIDENCE.issubset(
        set(gate.get("evidence", []))
    ):
        _fail("release gate 10 is not migration ready")
    if "last_verified" in gate:
        _fail("release gate 10 must remain unverified without clean-VM evidence")

    for gate_path, fragment in (
        ("scripts/check.ps1", "scripts\\check_migration_readiness.py"),
        ("scripts/check.sh", "scripts/check_migration_readiness.py"),
    ):
        if fragment not in (project_root / gate_path).read_text(encoding="utf-8"):
            _fail(f"migration-readiness checker is missing from {gate_path}")

    expected_summary = {
        "controls": len(EXPECTED_CONTROL_IDS),
        "repository_implemented_controls": len(EXPECTED_CONTROL_IDS),
        "release_pending_controls": len(EXPECTED_CONTROL_IDS),
        "rehearsal_services": len(EXPECTED_SERVICES),
    }
    if inventory.get("summary") != expected_summary:
        _fail("migration-readiness summary does not match its inventory")


def main() -> int:
    try:
        inventory = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))
        validate_migration_readiness(inventory)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"Migration-readiness validation failed: {error}", file=sys.stderr)
        return 1
    print(
        "Migration-readiness inventory passed: "
        f"{len(EXPECTED_CONTROL_IDS)} controls, {len(EXPECTED_SERVICES)} rehearsal services."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
