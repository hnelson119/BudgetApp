"""Validate the maintained logging inventory and its source-derived event catalogs."""

from __future__ import annotations

import ast
import json
import re
import sys
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[1]
INVENTORY_PATH = PROJECT_ROOT / "docs" / "logging-inventory.json"
APPLICATION_ROOTS = (
    "audit",
    "budgets",
    "core",
    "debts",
    "goals",
    "households",
    "identity",
    "imports",
    "ledger",
    "notifications",
    "periods",
    "reserves",
    "schedules",
    "spending",
)
MAINTENANCE_SCRIPTS = (
    "deploy/backup/backup.sh",
    "deploy/backup/restore-verify.sh",
    "deploy/backup/rotate-restic-key.sh",
    "deploy/postgres/rotate-admin-password.sh",
)
EXPECTED_LAYER_IDS = {
    "browser-client",
    "django-operational",
    "django-security",
    "docker-local-storage",
    "github-actions",
    "gunicorn-process",
    "maintenance-security",
    "nginx-relay",
    "postgresql",
    "protected-household-audit",
    "security-test-output",
    "security-log-archive",
    "systemd-host-journal",
    "tailscale-provider-logs",
}
EXPECTED_EVENT_GROUP_IDS = {
    "django-operational-events",
    "django-security-events",
    "maintenance-events",
    "protected-audit-actions",
    "security-archive-events",
}
EXPECTED_GAP_IDS = {
    "host-journal-release-verification",
    "optional-tailscale-flow-logging",
}
EXPECTED_UPDATE_TRIGGERS = {
    "a log producer, event, format, destination, access rule, or retention rule changes",
    "a technology-stack layer or managed provider changes",
    "a security finding or incident changes monitoring needs",
    "every release candidate",
    "the cryptographic or data-classification inventory changes",
}
EXPECTED_COMPOSE_SERVICES = {
    "backup",
    "db",
    "db-admin-key-rotate",
    "db-bootstrap",
    "import-cleanup",
    "ingress",
    "integrity",
    "mfa-key-rotate",
    "migrate",
    "notify",
    "restic-key-rotate",
    "restore-verify",
    "security-log",
    "web",
}
LAYER_FIELDS = {
    "access_control",
    "destination",
    "event_groups",
    "events",
    "evidence",
    "format",
    "id",
    "integrity_and_availability",
    "limitations",
    "retention",
    "scope",
    "sensitive_data_policy",
    "stack_layer",
    "use",
}
EVENT_GROUP_FIELDS = {"events", "id", "layer_id", "source"}
GAP_FIELDS = {"current_state", "evidence", "id", "related_asvs", "required_action"}
TEXT_LAYER_FIELDS = LAYER_FIELDS - {"event_groups", "events", "evidence", "use"}
TEXT_EVENT_GROUP_FIELDS = EVENT_GROUP_FIELDS - {"events"}
TEXT_GAP_FIELDS = GAP_FIELDS - {"evidence", "related_asvs"}
_EVENT_ID = re.compile(r"^[a-z][a-z0-9_]*(?:[._][a-z0-9_]+)+$")
_AUDIT_ACTION_ID = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+$")
_ASVS_ID = re.compile(r"^v5\.0\.0-([1-9]|1[0-7])\.[1-9][0-9]*\.[1-9][0-9]*$")
_LOG_CALL = re.compile(r'\blog\s+"(?:info|warning|error)"\s+"([a-z][a-z0-9_.-]+)"')
_FAIL_CALL = re.compile(r'\bfail\s+"([a-z][a-z0-9_.-]+)"')
_EXACT_TAILSCALE_HOST = re.compile(
    r"\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\."
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.ts\.net\b"
)
_BANNED_FIELDS = {"cookie", "credential", "password", "private_key", "secret", "token", "value"}
_PEM_MARKER = "BEGIN " + "PRIVATE" + " KEY"


def _fail(message: str) -> None:
    raise ValueError(message)


def _parse_date(value: Any, *, field: str) -> date:
    if not isinstance(value, str):
        _fail(f"{field} must be an ISO date")
    try:
        parsed = date.fromisoformat(value)
    except ValueError:
        _fail(f"{field} must be an ISO date")
    if parsed.isoformat() != value:
        _fail(f"{field} must be an ISO date")
    return parsed


def _validate_text(value: Any, *, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        _fail(f"{field} must be non-empty text")


def _validate_string_list(
    value: Any,
    *,
    field: str,
    allow_empty: bool = False,
) -> list[str]:
    if (
        not isinstance(value, list)
        or (not allow_empty and not value)
        or not all(isinstance(item, str) and item.strip() for item in value)
    ):
        _fail(f"{field} must be a {'string list' if allow_empty else 'non-empty string list'}")
    if len(value) != len(set(value)):
        _fail(f"{field} contains duplicate values")
    return value


def _validate_evidence(value: Any, *, item: str) -> None:
    paths = _validate_string_list(value, field=f"{item}.evidence")
    for path in paths:
        if path.startswith("https://"):
            continue
        if path.startswith("http://"):
            _fail(f"{item} references non-HTTPS evidence {path!r}")
        relative_path = path.split("#", maxsplit=1)[0]
        candidate = (PROJECT_ROOT / relative_path).resolve()
        if PROJECT_ROOT not in candidate.parents and candidate != PROJECT_ROOT:
            _fail(f"{item} references evidence outside the project")
        if not candidate.exists():
            _fail(f"{item} references missing evidence {path!r}")


def _validate_no_embedded_data(value: Any, *, path: tuple[str, ...] = ()) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key.casefold() in _BANNED_FIELDS:
                _fail(f"logging inventory uses prohibited raw-data field {'.'.join((*path, key))}")
            _validate_no_embedded_data(child, path=(*path, key))
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            _validate_no_embedded_data(child, path=(*path, str(index)))
        return
    if isinstance(value, str):
        if _PEM_MARKER in value:
            _fail(f"logging inventory contains private-key material at {'.'.join(path)}")
        if _EXACT_TAILSCALE_HOST.search(value):
            _fail(f"logging inventory contains an exact private hostname at {'.'.join(path)}")


def _application_python_files() -> list[Path]:
    files: list[Path] = []
    for root_name in APPLICATION_ROOTS:
        for path in (PROJECT_ROOT / root_name).rglob("*.py"):
            if "migrations" not in path.parts:
                files.append(path)
    return sorted(files)


def _literal_event_catalogs() -> tuple[set[str], set[str]]:
    log_events: set[str] = set()
    audit_actions: set[str] = set()
    for path in _application_python_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Dict):
                for key, value in zip(node.keys, node.values, strict=True):
                    if (
                        isinstance(key, ast.Constant)
                        and key.value == "event"
                        and isinstance(value, ast.Constant)
                        and isinstance(value.value, str)
                    ):
                        log_events.add(value.value)
            if isinstance(node, ast.Call):
                if (
                    isinstance(node.func, ast.Name)
                    and node.func.id == "_fixed_diagnostic"
                    and node.args
                    and isinstance(node.args[0], ast.Constant)
                    and isinstance(node.args[0].value, str)
                ):
                    log_events.add(node.args[0].value)
                for keyword in node.keywords:
                    if keyword.arg not in {"action", "audit_action"}:
                        continue
                    for child in ast.walk(keyword.value):
                        if (
                            isinstance(child, ast.Constant)
                            and isinstance(child.value, str)
                            and _AUDIT_ACTION_ID.fullmatch(child.value)
                        ):
                            audit_actions.add(child.value)
    return log_events, audit_actions


def _maintenance_events() -> set[str]:
    events: set[str] = set()
    for relative_path in MAINTENANCE_SCRIPTS:
        source = (PROJECT_ROOT / relative_path).read_text(encoding="utf-8")
        events.update(_LOG_CALL.findall(source))
        events.update(_FAIL_CALL.findall(source))
    return events


def _validate_compose_logging_policy() -> None:
    compose = yaml.safe_load((PROJECT_ROOT / "compose.yaml").read_text(encoding="utf-8"))
    services = compose.get("services")
    if not isinstance(services, dict) or set(services) != EXPECTED_COMPOSE_SERVICES:
        _fail("production Compose service inventory changed without a logging review")
    expected_policy = {"driver": "local", "options": {"max-size": "20m", "max-file": "5"}}
    for service_name, service in services.items():
        if not isinstance(service, dict) or service.get("logging") != expected_policy:
            _fail(f"Compose service {service_name!r} does not use the bounded logging policy")

    security_log = services["security-log"]
    web = services["web"]
    if (
        security_log.get("network_mode") != "none"
        or security_log.get("user") != "10003:10003"
        or security_log.get("read_only") is not True
        or security_log.get("cap_drop") != ["ALL"]
        or security_log.get("volumes")
        != ["security_log_socket:/run/security-log", "security_log_archive:/var/lib/security-log"]
    ):
        _fail("the separate security-log service boundary is incomplete")
    expected_socket_mount = {
        "type": "volume",
        "source": "security_log_socket",
        "target": "/run/security-log",
        "read_only": True,
    }
    if expected_socket_mount not in (web.get("volumes") or []):
        _fail("the web security-log socket mount is not read-only")

    dockerfile = (PROJECT_ROOT / "Dockerfile").read_text(encoding="utf-8")
    if "--access-logfile" in dockerfile or '"--error-logfile", "-"' not in dockerfile:
        _fail("Gunicorn access/error logging no longer matches the inventory")
    relay = (PROJECT_ROOT / "deploy" / "network" / "nginx.conf").read_text(encoding="utf-8")
    if "access_log off;" not in relay or "error_log /dev/stderr warn;" not in relay:
        _fail("nginx relay logging no longer matches the inventory")


def _validate_records(
    value: Any,
    *,
    collection: str,
    expected_ids: set[str],
    expected_fields: set[str],
    text_fields: set[str],
    list_fields: set[str],
    empty_list_fields: set[str] = frozenset(),
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    if not isinstance(value, list):
        _fail(f"{collection} must be a list")
    records: list[dict[str, Any]] = []
    by_id: dict[str, dict[str, Any]] = {}
    for raw_record in value:
        if not isinstance(raw_record, dict):
            _fail(f"{collection} entries must be objects")
        record_id = raw_record.get("id")
        if not isinstance(record_id, str):
            _fail(f"{collection} entry has an invalid id")
        if record_id in by_id:
            _fail(f"{collection} contains duplicate id {record_id!r}")
        if set(raw_record) != expected_fields:
            _fail(f"{collection} {record_id!r} has an incomplete or unexpected schema")
        for field in text_fields:
            _validate_text(raw_record[field], field=f"{collection}.{record_id}.{field}")
        for field in list_fields:
            _validate_string_list(
                raw_record[field],
                field=f"{collection}.{record_id}.{field}",
                allow_empty=field in empty_list_fields,
            )
        if "evidence" in raw_record:
            _validate_evidence(raw_record["evidence"], item=f"{collection}.{record_id}")
        records.append(raw_record)
        by_id[record_id] = raw_record
    if set(by_id) != expected_ids:
        _fail(f"{collection} identifiers are incomplete")
    return records, by_id


def validate_inventory(data: Any, *, today: date | None = None) -> None:
    if not isinstance(data, dict):
        _fail("logging inventory must be a JSON object")
    expected_top_level = {
        "event_groups",
        "inventory_updated",
        "known_gaps",
        "layers",
        "review",
        "schema_version",
        "scope",
        "summary",
    }
    if set(data) != expected_top_level:
        _fail("logging inventory top-level schema is incomplete or unexpected")
    if data["schema_version"] != 1:
        _fail("unsupported logging inventory schema version")

    review = data["review"]
    if not isinstance(review, dict) or set(review) != {
        "cadence_days",
        "next_review_due",
        "owner",
        "procedure",
        "update_triggers",
    }:
        _fail("logging inventory review policy is incomplete")
    if review["owner"] != "release owner" or review["procedure"] != "docs/LOGGING_INVENTORY.md":
        _fail("logging inventory review ownership or procedure changed unexpectedly")
    if review["cadence_days"] != 90:
        _fail("logging inventory review cadence must remain 90 days")
    triggers = _validate_string_list(review["update_triggers"], field="review.update_triggers")
    if set(triggers) != EXPECTED_UPDATE_TRIGGERS:
        _fail("logging inventory update triggers are incomplete")

    updated = _parse_date(data["inventory_updated"], field="inventory_updated")
    due = _parse_date(review["next_review_due"], field="review.next_review_due")
    if due != updated + timedelta(days=review["cadence_days"]):
        _fail("next logging inventory review is not exactly one cadence after the update")
    current_date = date.today() if today is None else today
    if updated > current_date:
        _fail("logging inventory update date is in the future")
    if current_date > due:
        _fail("logging inventory review is overdue")

    scope = data["scope"]
    if not isinstance(scope, dict) or set(scope) != {"excluded", "included"}:
        _fail("logging inventory scope is incomplete")
    _validate_string_list(scope["included"], field="scope.included")
    _validate_string_list(scope["excluded"], field="scope.excluded")

    layers, layers_by_id = _validate_records(
        data["layers"],
        collection="layers",
        expected_ids=EXPECTED_LAYER_IDS,
        expected_fields=LAYER_FIELDS,
        text_fields=TEXT_LAYER_FIELDS,
        list_fields=LAYER_FIELDS - TEXT_LAYER_FIELDS,
        empty_list_fields={"event_groups"},
    )
    event_groups, groups_by_id = _validate_records(
        data["event_groups"],
        collection="event_groups",
        expected_ids=EXPECTED_EVENT_GROUP_IDS,
        expected_fields=EVENT_GROUP_FIELDS,
        text_fields=TEXT_EVENT_GROUP_FIELDS,
        list_fields={"events"},
    )
    gaps, _gaps_by_id = _validate_records(
        data["known_gaps"],
        collection="known_gaps",
        expected_ids=EXPECTED_GAP_IDS,
        expected_fields=GAP_FIELDS,
        text_fields=TEXT_GAP_FIELDS,
        list_fields=GAP_FIELDS - TEXT_GAP_FIELDS,
    )

    referenced_groups: set[str] = set()
    for layer in layers:
        unknown = set(layer["event_groups"]) - set(groups_by_id)
        if unknown:
            _fail(f"layer {layer['id']!r} references unknown event groups {sorted(unknown)}")
        referenced_groups.update(layer["event_groups"])
    if referenced_groups != EXPECTED_EVENT_GROUP_IDS:
        _fail("event group inventory contains an unreferenced catalog")
    for group in event_groups:
        if group["layer_id"] not in layers_by_id:
            _fail(f"event group {group['id']!r} references an unknown layer")
        if group["id"] not in layers_by_id[group["layer_id"]]["event_groups"]:
            _fail(f"event group {group['id']!r} is not declared by its layer")
        if group["events"] != sorted(group["events"]):
            _fail(f"event group {group['id']!r} is not sorted")
        if not all(_EVENT_ID.fullmatch(event) for event in group["events"]):
            _fail(f"event group {group['id']!r} contains an invalid event identifier")

    for gap in gaps:
        if not all(_ASVS_ID.fullmatch(item) for item in gap["related_asvs"]):
            _fail(f"known gap {gap['id']!r} has an invalid ASVS identifier")
    log_events, audit_actions = _literal_event_catalogs()
    declared_log_events = (
        set(groups_by_id["django-operational-events"]["events"])
        | set(groups_by_id["django-security-events"]["events"])
        | set(groups_by_id["security-archive-events"]["events"])
    )
    if declared_log_events != log_events:
        _fail("Django structured event catalog does not match source literals")
    if groups_by_id["django-operational-events"]["events"] != [
        "http.request.completed",
        "http.request.unhandled_exception",
    ]:
        _fail("Django operational event boundary changed unexpectedly")
    if groups_by_id["security-archive-events"]["events"] != [
        "security.archive.alert_recorded",
        "security.archive.delivery_failed",
        "security.archive.ready",
        "security.archive.record_rejected",
        "security.archive.review_failed",
        "security.archive.startup_failed",
    ]:
        _fail("security-log archive event boundary changed unexpectedly")
    if set(groups_by_id["protected-audit-actions"]["events"]) != audit_actions:
        _fail("protected audit action catalog does not match source literals")
    if set(groups_by_id["maintenance-events"]["events"]) != _maintenance_events():
        _fail("maintenance event catalog does not match structured shell events")

    expected_summary = {
        "layers": len(layers),
        "event_groups": len(event_groups),
        "event_entries": sum(len(group["events"]) for group in event_groups),
        "known_gaps": len(gaps),
    }
    if data["summary"] != expected_summary:
        _fail("logging inventory summary does not match its records")

    _validate_compose_logging_policy()
    _validate_no_embedded_data(data)


def main() -> int:
    try:
        data = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))
        validate_inventory(data)
    except (OSError, SyntaxError, json.JSONDecodeError, ValueError, yaml.YAMLError) as error:
        print(f"Logging inventory validation failed: {error}", file=sys.stderr)
        return 1
    print(
        "Logging inventory is structurally complete "
        f"({len(EXPECTED_LAYER_IDS)} layers, {len(EXPECTED_EVENT_GROUP_IDS)} event groups)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
