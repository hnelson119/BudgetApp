"""Validate the sensitive-data inventory and protection-level requirements."""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import date, timedelta
from pathlib import Path
from typing import Any, NoReturn

import django
from django.apps import apps

PROJECT_ROOT = Path(__file__).resolve().parents[1]
INVENTORY_PATH = PROJECT_ROOT / "docs" / "data-classification.json"
EXPECTED_LEVEL_IDS = {"public", "internal", "confidential", "restricted"}
EXPECTED_DATASET_IDS = {
    "authentication_material",
    "authorization_schema",
    "breached_password_reference",
    "browser_session_surface",
    "deployment_secret_material",
    "encrypted_backups",
    "financial_and_audit_exports",
    "financial_records",
    "household_identity_and_membership",
    "operational_markers_and_health",
    "protected_audit_history",
    "public_static_assets",
    "release_security_evidence",
    "request_and_response_memory",
    "security_and_operational_logs",
}
EXPECTED_UPDATE_TRIGGERS = {
    "a model, field, upload, export, log, backup, secret, or client-storage surface changes",
    "a protection control or retention period changes",
    "an external service, data recipient, deployment model, or integration is added",
    (
        "the product enters a new jurisdiction or regulated, commercial, employment, health, or "
        "minors context"
    ),
    "every release candidate",
    (
        "a privacy request, security finding, or incident changes the classification or handling "
        "requirements"
    ),
}
LEVEL_FIELDS = {
    "access_control",
    "backup_and_recovery",
    "client_storage",
    "confidentiality",
    "database_level_encryption",
    "definition",
    "disposal",
    "encoding_and_masking",
    "encryption_at_rest",
    "encryption_in_transit",
    "id",
    "integrity",
    "log_access",
    "logging",
    "name",
    "privacy",
    "rank",
    "retention",
}
DATASET_FIELDS = {
    "access_control",
    "created_or_processed",
    "data_elements",
    "disposal",
    "django_models",
    "evidence",
    "id",
    "integrity",
    "level",
    "logging",
    "log_access",
    "name",
    "privacy",
    "retention",
    "scope",
    "storage",
    "transit",
}
TEXT_LEVEL_FIELDS = LEVEL_FIELDS - {"id", "rank"}
TEXT_DATASET_FIELDS = DATASET_FIELDS - {"data_elements", "django_models", "evidence", "id", "level"}
_EXACT_PRIVATE_HOST = re.compile(
    r"\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\."
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.ts\.net\b"
)
_PEM_MARKER = "BEGIN " + "PRIVATE" + " KEY"
_BANNED_VALUE_FIELDS = {
    "actual_value",
    "credential_value",
    "password_value",
    "private_key",
    "secret_value",
    "token_value",
}


def _fail(message: str) -> NoReturn:
    raise ValueError(message)


def _text(value: Any, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        _fail(f"{field} must be non-empty text")


def _string_list(value: Any, field: str, *, allow_empty: bool = False) -> list[str]:
    if (
        not isinstance(value, list)
        or (not value and not allow_empty)
        or not all(isinstance(item, str) and item.strip() for item in value)
    ):
        _fail(f"{field} must be a {'string list' if allow_empty else 'non-empty string list'}")
    if len(value) != len(set(value)):
        _fail(f"{field} contains duplicate values")
    return value


def _iso_date(value: Any, field: str) -> date:
    if not isinstance(value, str):
        _fail(f"{field} must be an ISO date")
    try:
        parsed = date.fromisoformat(value)
    except ValueError:
        _fail(f"{field} must be an ISO date")
    if parsed.isoformat() != value:
        _fail(f"{field} must be an ISO date")
    return parsed


def _evidence(project_root: Path, value: Any, item: str) -> None:
    for relative_path in _string_list(value, f"{item}.evidence"):
        path = (project_root / relative_path).resolve()
        if project_root.resolve() not in path.parents and path != project_root.resolve():
            _fail(f"{item} references evidence outside the project")
        if not path.exists():
            _fail(f"{item} references missing evidence {relative_path!r}")


def _reject_embedded_sensitive_values(value: Any, path: tuple[str, ...] = ()) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key.casefold() in _BANNED_VALUE_FIELDS:
                _fail(f"data inventory uses prohibited value field {'.'.join((*path, key))}")
            _reject_embedded_sensitive_values(child, (*path, key))
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            _reject_embedded_sensitive_values(child, (*path, str(index)))
        return
    if isinstance(value, str) and (
        _PEM_MARKER in value or _EXACT_PRIVATE_HOST.search(value) is not None
    ):
        _fail(f"data inventory contains deployment-specific material at {'.'.join(path)}")


def application_model_labels() -> set[str]:
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.test")
    django.setup()
    return {model._meta.label for model in apps.get_models()}


def _validate_review(document: dict[str, Any]) -> None:
    review = document.get("review")
    if not isinstance(review, dict) or set(review) != {
        "owner",
        "cadence_days",
        "next_review_due",
        "procedure",
        "update_triggers",
    }:
        _fail("data-classification review fields differ from the schema")
    _text(review["owner"], "review.owner")
    _text(review["procedure"], "review.procedure")
    if review["procedure"] != "docs/DATA_CLASSIFICATION.md":
        _fail("data-classification review procedure is not pinned")
    if review["cadence_days"] != 90:
        _fail("data-classification review cadence must remain 90 days")
    updated = _iso_date(document["inventory_updated"], "inventory_updated")
    due = _iso_date(review["next_review_due"], "review.next_review_due")
    if due != updated + timedelta(days=90):
        _fail("data-classification next review date differs from the cadence")
    if set(_string_list(review["update_triggers"], "review.update_triggers")) != (
        EXPECTED_UPDATE_TRIGGERS
    ):
        _fail("data-classification update triggers differ from policy")


def _validate_regulatory_scope(value: Any) -> None:
    if not isinstance(value, dict) or set(value) != {
        "baseline_commitments",
        "current_context",
        "data_subject_process",
        "formal_determination",
        "not_in_scope_yet",
        "reassessment_triggers",
    }:
        _fail("regulatory and privacy scope fields differ from the schema")
    _text(value["formal_determination"], "regulatory_and_privacy_scope.formal_determination")
    _text(value["data_subject_process"], "regulatory_and_privacy_scope.data_subject_process")
    for field in (
        "baseline_commitments",
        "current_context",
        "not_in_scope_yet",
        "reassessment_triggers",
    ):
        _string_list(value[field], f"regulatory_and_privacy_scope.{field}")


def _validate_levels(value: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(value, list):
        _fail("protection_levels must be a list")
    levels: dict[str, dict[str, Any]] = {}
    ranks: set[int] = set()
    for record in value:
        if not isinstance(record, dict) or set(record) != LEVEL_FIELDS:
            _fail("protection-level fields differ from the schema")
        identifier = record.get("id")
        if not isinstance(identifier, str) or identifier in levels:
            _fail("protection-level identifier is missing or duplicated")
        if not isinstance(record["rank"], int) or isinstance(record["rank"], bool):
            _fail(f"protection level {identifier!r} has an invalid rank")
        ranks.add(record["rank"])
        for field in TEXT_LEVEL_FIELDS:
            _text(record[field], f"protection_levels.{identifier}.{field}")
        levels[identifier] = record
    if set(levels) != EXPECTED_LEVEL_IDS or ranks != set(range(len(EXPECTED_LEVEL_IDS))):
        _fail("protection levels or ranks differ from the reviewed policy")
    return levels


def _validate_datasets(
    project_root: Path, value: Any, levels: dict[str, dict[str, Any]]
) -> tuple[dict[str, dict[str, Any]], set[str]]:
    if not isinstance(value, list):
        _fail("datasets must be a list")
    datasets: dict[str, dict[str, Any]] = {}
    classified_models: list[str] = []
    for record in value:
        if not isinstance(record, dict) or set(record) != DATASET_FIELDS:
            _fail("dataset fields differ from the schema")
        identifier = record.get("id")
        if not isinstance(identifier, str) or identifier in datasets:
            _fail("dataset identifier is missing or duplicated")
        if record["level"] not in levels:
            _fail(f"dataset {identifier!r} references an unknown protection level")
        for field in TEXT_DATASET_FIELDS:
            _text(record[field], f"datasets.{identifier}.{field}")
        _string_list(record["data_elements"], f"datasets.{identifier}.data_elements")
        classified_models.extend(
            _string_list(
                record["django_models"],
                f"datasets.{identifier}.django_models",
                allow_empty=True,
            )
        )
        _evidence(project_root, record["evidence"], identifier)
        datasets[identifier] = record
    if set(datasets) != EXPECTED_DATASET_IDS:
        _fail("dataset identifiers differ from the reviewed catalog")
    if len(classified_models) != len(set(classified_models)):
        _fail("a Django model is assigned to more than one data classification")
    current_models = application_model_labels()
    if set(classified_models) != current_models:
        missing = sorted(current_models - set(classified_models))
        stale = sorted(set(classified_models) - current_models)
        _fail(f"Django model classification is incomplete (missing={missing}, stale={stale})")
    return datasets, current_models


def validate_inventory_document(project_root: Path, document: Any) -> tuple[int, int, int]:
    if not isinstance(document, dict) or set(document) != {
        "schema_version",
        "inventory_updated",
        "review",
        "regulatory_and_privacy_scope",
        "summary",
        "protection_levels",
        "datasets",
    }:
        _fail("data-classification top-level fields differ from the schema")
    if document["schema_version"] != 1:
        _fail("data-classification schema version is invalid")
    _reject_embedded_sensitive_values(document)
    _validate_review(document)
    _validate_regulatory_scope(document["regulatory_and_privacy_scope"])
    levels = _validate_levels(document["protection_levels"])
    datasets, models = _validate_datasets(project_root, document["datasets"], levels)
    if document["summary"] != {
        "protection_levels": len(levels),
        "datasets": len(datasets),
        "classified_django_models": len(models),
    }:
        _fail("data-classification summary is stale")
    return len(levels), len(datasets), len(models)


def _require_fragments(path: Path, fragments: set[str], boundary: str) -> None:
    source = path.read_text(encoding="utf-8")
    if any(fragment not in source for fragment in fragments):
        _fail(f"{boundary} no longer satisfies the documented protection requirements")


def validate_implemented_boundaries(project_root: Path = PROJECT_ROOT) -> None:
    _require_fragments(
        project_root / "config/settings/base.py",
        {
            "SESSION_COOKIE_HTTPONLY = True",
            'SESSION_COOKIE_SAMESITE = "Strict"',
            "CSRF_COOKIE_HTTPONLY = True",
            "SESSION_COOKIE_AGE = 60 * 60 * 12",
            "CSV_IMPORT_STAGING_RETENTION_HOURS",
        },
        "base settings",
    )
    _require_fragments(
        project_root / "config/settings/hardened.py",
        {
            'required_secret_file("DJANGO_SECRET_KEY"',
            'required_secret_file("DJANGO_MFA_ENCRYPTION_KEY"',
            '"sslmode": "verify-full"',
            "SESSION_COOKIE_SECURE = True",
            "CSRF_COOKIE_SECURE = True",
        },
        "hardened settings",
    )
    _require_fragments(
        project_root / "core/middleware.py",
        {'response.headers["Cache-Control"] = "no-store, private"'},
        "authenticated response caching",
    )
    _require_fragments(
        project_root / "identity/middleware.py",
        {'response.headers["Clear-Site-Data"] = _CLEAR_SITE_DATA'},
        "terminated-session cleanup",
    )
    _require_fragments(
        project_root / "core/static/core/app.js",
        {
            'const storageKey = "household-budget-theme";',
            "clearClientStorage();",
            "clearAuthenticatedDom",
        },
        "browser data minimization",
    )
    _require_fragments(
        project_root / "imports/services/batches.py",
        {
            "ImportRow.objects.filter(batch=locked).update(raw_data={})",
            "if not 1 <= retention_hours <= 720:",
        },
        "raw import retention",
    )
    for relative_path in ("spending/views.py", "audit/views.py"):
        _require_fragments(
            project_root / relative_path,
            {
                'response.headers["Cache-Control"] = "no-store, private"',
                'response.headers["Pragma"] = "no-cache"',
            },
            "sensitive export caching",
        )
    _require_fragments(
        project_root / "docs/BACKUP_AND_RESTORE.md",
        {
            "Retention: 7 daily, 4 weekly, and 12 monthly snapshots by default.",
            "encrypted Restic",
        },
        "backup protection",
    )


def validate_data_classification(project_root: Path = PROJECT_ROOT) -> tuple[int, int, int]:
    project_root = project_root.resolve()
    document = json.loads((project_root / "docs/data-classification.json").read_text("utf-8"))
    counts = validate_inventory_document(project_root, document)
    validate_implemented_boundaries(project_root)
    return counts


def main() -> int:
    try:
        level_count, dataset_count, model_count = validate_data_classification()
    except (OSError, SyntaxError, UnicodeError, ValueError, json.JSONDecodeError) as error:
        print(f"Data-classification validation failed: {error}", file=sys.stderr)
        return 1
    print(
        "Data classification is structurally complete "
        f"({level_count} protection levels, {dataset_count} datasets, "
        f"{model_count} Django models)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
