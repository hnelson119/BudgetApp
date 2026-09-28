"""Validate the incident-response action inventory and release-gate wiring."""

from __future__ import annotations

import json
import sys
from datetime import date
from pathlib import Path
from typing import Any, NoReturn

PROJECT_ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = PROJECT_ROOT / "docs" / "incident-response.json"
RELEASE_EVIDENCE_PATH = PROJECT_ROOT / "docs" / "release-evidence.json"

EXPECTED_ACTION_IDS = {
    "check-compromise-indicators",
    "isolate-compromised-vm",
    "preserve-logs-and-checkpoints",
    "record-incident-and-actions",
    "reenroll-users-and-devices",
    "restore-known-good-backup",
    "revoke-lost-device",
    "rotate-affected-credentials",
    "terminate-application-access",
    "verify-restored-audit-chain",
}
EXPECTED_REHEARSALS = {
    "credential-and-lost-device": "scripts/run-credential-rehearsal.sh",
    "encrypted-backup-recovery": "scripts/run-restore-rehearsal.sh",
    "private-ingress-containment": "scripts/verify-private-ingress.sh",
}
RUNBOOK_CONTRACT = (
    "## 1. Decide scope before changing anything",
    "## 2. Lost-device and account-recovery procedure",
    "## 3. Rotation rules shared by every secret",
    "## 4. MFA encryption-key rotation",
    "## 5. PostgreSQL certificate rotation",
    "## 6. Encrypted-backup repository key rotation",
    "## 7. Django signing key and audit-checkpoint key",
    "## 8. Tailscale, SSH, and identity-provider credentials",
    "## 9. Verification and sanitized evidence",
    "python manage.py revoke_user_sessions",
    "python manage.py reset_user_password",
    "python manage.py reset_user_mfa",
    "docker compose --profile maintenance run --rm mfa-key-rotate",
    "docker compose --profile maintenance run --rm restic-key-rotate",
    "docker compose exec -T security-log python -m core.security_log_collector review",
)
EXPECTED_RELEASE_EVIDENCE = {
    "docs/INCIDENT_RESPONSE.md",
    "docs/incident-response.json",
    "scripts/check_incident_response.py",
    "tests/test_incident_response.py",
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
    evidence = [
        _safe_path(item, project_root=project_root, label=f"{label} path") for item in value
    ]
    if len(evidence) != len(set(evidence)):
        _fail(f"{label} contains duplicate paths")
    return evidence


def _release_item(document: dict[str, Any], collection: str, item_id: int) -> dict[str, Any]:
    items = document.get(collection)
    if not isinstance(items, list):
        _fail(f"release evidence {collection} is malformed")
    matching = [item for item in items if isinstance(item, dict) and item.get("id") == item_id]
    if len(matching) != 1:
        _fail(f"release evidence {collection} {item_id} is missing or duplicated")
    return matching[0]


def validate_incident_response(
    policy: dict[str, Any],
    *,
    project_root: Path = PROJECT_ROOT,
    today: date | None = None,
) -> None:
    if set(policy) != {
        "actions",
        "inventory_id",
        "last_reviewed",
        "next_review_due",
        "rehearsals",
        "runbook",
        "schema_version",
        "summary",
    }:
        _fail("incident-response inventory fields changed")
    if policy["schema_version"] != 1 or policy["inventory_id"] != "budgetapp-incident-response-v1":
        _fail("unsupported incident-response inventory identity")
    reviewed = date.fromisoformat(_text(policy["last_reviewed"], "last_reviewed"))
    due = date.fromisoformat(_text(policy["next_review_due"], "next_review_due"))
    if due <= reviewed or (due - reviewed).days > 90:
        _fail("incident-response review cadence exceeds 90 days")
    if (today or date.today()) > due:
        _fail("incident-response inventory review is overdue")

    runbook = _safe_path(policy["runbook"], project_root=project_root, label="runbook")
    runbook_source = (project_root / runbook).read_text(encoding="utf-8")
    missing_contract = [fragment for fragment in RUNBOOK_CONTRACT if fragment not in runbook_source]
    if missing_contract:
        _fail(f"incident-response runbook contract changed: {missing_contract}")

    actions = policy.get("actions")
    if not isinstance(actions, list) or any(not isinstance(item, dict) for item in actions):
        _fail("incident-response actions must contain objects")
    observed_actions: set[str] = set()
    action_fields = {
        "containment",
        "evidence",
        "id",
        "objective",
        "release_status",
        "release_verification",
        "repository_status",
    }
    for action in actions:
        if set(action) != action_fields:
            _fail("incident-response action fields changed")
        identifier = _text(action["id"], "action id")
        if identifier in observed_actions:
            _fail(f"duplicate incident-response action: {identifier}")
        observed_actions.add(identifier)
        for field in ("objective", "containment", "release_verification"):
            _text(action[field], f"{identifier} {field}")
        if action["repository_status"] != "implemented" or action["release_status"] != "pending":
            _fail(f"incident-response action status changed: {identifier}")
        evidence = _evidence(
            action["evidence"], project_root=project_root, label=f"{identifier} evidence"
        )
        if runbook not in evidence:
            _fail(f"incident-response action lacks runbook evidence: {identifier}")
    if observed_actions != EXPECTED_ACTION_IDS:
        _fail("incident-response action inventory changed")

    rehearsals = policy.get("rehearsals")
    if not isinstance(rehearsals, list) or any(not isinstance(item, dict) for item in rehearsals):
        _fail("incident-response rehearsals must contain objects")
    observed_rehearsals: dict[str, str] = {}
    for rehearsal in rehearsals:
        if set(rehearsal) != {"evidence", "id", "limitation", "proves", "runner"}:
            _fail("incident-response rehearsal fields changed")
        identifier = _text(rehearsal["id"], "rehearsal id")
        runner = _safe_path(
            rehearsal["runner"], project_root=project_root, label=f"{identifier} runner"
        )
        if identifier in observed_rehearsals:
            _fail(f"duplicate incident-response rehearsal: {identifier}")
        observed_rehearsals[identifier] = runner
        _text(rehearsal["proves"], f"{identifier} proves")
        _text(rehearsal["limitation"], f"{identifier} limitation")
        _evidence(rehearsal["evidence"], project_root=project_root, label=f"{identifier} evidence")
    if observed_rehearsals != EXPECTED_REHEARSALS:
        _fail("incident-response rehearsal inventory changed")

    expected_summary = {
        "actions": len(EXPECTED_ACTION_IDS),
        "repository_implemented_actions": len(EXPECTED_ACTION_IDS),
        "release_pending_actions": len(EXPECTED_ACTION_IDS),
        "rehearsals": len(EXPECTED_REHEARSALS),
    }
    if policy.get("summary") != expected_summary:
        _fail("incident-response summary does not match its inventory")

    release_document = json.loads(
        (project_root / "docs" / "release-evidence.json").read_text(encoding="utf-8")
    )
    for collection, item_id in (("security_tests", 20), ("release_gates", 9)):
        item = _release_item(release_document, collection, item_id)
        if item.get("status") != "implemented" or not EXPECTED_RELEASE_EVIDENCE.issubset(
            set(item.get("evidence", []))
        ):
            _fail(f"release evidence {collection} {item_id} is not incident-response ready")

    powershell_gate = (project_root / "scripts" / "check.ps1").read_text(encoding="utf-8")
    shell_gate = (project_root / "scripts" / "check.sh").read_text(encoding="utf-8")
    if "scripts\\check_incident_response.py" not in powershell_gate:
        _fail("incident-response checker is missing from the PowerShell gate")
    if "scripts/check_incident_response.py" not in shell_gate:
        _fail("incident-response checker is missing from the shell gate")


def main() -> int:
    try:
        policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        validate_incident_response(policy)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"Incident-response validation failed: {error}", file=sys.stderr)
        return 1
    print(
        "Incident-response inventory passed: "
        f"{len(EXPECTED_ACTION_IDS)} actions, {len(EXPECTED_REHEARSALS)} rehearsals."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
