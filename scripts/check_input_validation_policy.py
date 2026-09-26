"""Validate the complete input-form, rule, and business-limit policy."""

from __future__ import annotations

import ast
import json
import sys
from datetime import date
from pathlib import Path
from typing import Any, NoReturn

PROJECT_ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = PROJECT_ROOT / "docs" / "input-validation-policy.json"

EXPECTED_REQUIREMENTS = {
    "v5.0.0-2.1.1",
    "v5.0.0-2.1.2",
    "v5.0.0-2.1.3",
    "v5.0.0-2.3.2",
}
EXPECTED_FORM_REGISTRY = {
    "audit/forms.py": {"AuditFilterForm"},
    "budgets/forms.py": {
        "CategoryForm",
        "FixedExpenseScheduleForm",
        "HouseholdForm",
        "OccurrenceCancelForm",
        "OccurrenceMoveForm",
        "OccurrenceOverrideForm",
        "ReconciliationForm",
        "ReserveAllocationForm",
        "VariableBudgetForm",
    },
    "debts/forms.py": {
        "DebtAccountCreateForm",
        "DebtIdentityFields",
        "DebtMetadataForm",
        "DebtStatementCorrectionForm",
        "DebtStatementForm",
        "DebtStatusConfirmationForm",
        "DebtTermsForm",
        "ExtraPrincipalForm",
        "HouseholdForm",
        "MortgagePlanForm",
        "PayoffScenarioForm",
    },
    "goals/forms.py": {
        "GoalContributionForm",
        "GoalForm",
        "GoalStatusForm",
        "PriorityAllocationForm",
        "ReserveAllocationForm",
    },
    "identity/forms.py": {
        "ForgottenPasswordRecoveryForm",
        "MfaVerificationForm",
        "ReauthenticationForm",
        "RecoveryCodesConfirmationForm",
        "SecureAuthenticationForm",
        "SecurePasswordChangeForm",
        "SessionRevocationForm",
        "TotpEnrollmentForm",
    },
    "imports/forms.py": {
        "CSVAbandonForm",
        "CSVCommitForm",
        "CSVMappingForm",
        "CSVUploadForm",
    },
    "notifications/forms.py": {
        "NotificationHistoryFilterForm",
        "NotificationPreferenceForm",
    },
    "spending/forms.py": {
        "CardPaymentForm",
        "CardPurchaseRefundForm",
        "ExpenseForm",
        "FinancialAccountForm",
        "HouseholdForm",
        "IncomeForm",
        "ManualEntryForm",
        "ReversalForm",
        "TransactionFilterForm",
    },
}
EXPECTED_STRUCTURE_RULE_IDS = {
    "authentication-input",
    "bounded-text",
    "calendar-recurrence",
    "csv-upload-content",
    "enumerated-controls",
    "financial-amounts",
    "local-action-targets",
    "mfa-input",
    "opaque-identifiers",
    "scoped-object-references",
}
EXPECTED_CONTEXT_RULE_IDS = {
    "audit-range-and-chain-context",
    "csv-mapping-and-commit-state",
    "debt-terms-and-statement-consistency",
    "goal-account-debt-consistency",
    "household-object-scope",
    "ledger-balanced-entry-semantics",
    "mfa-credential-and-session-state",
    "mortgage-component-consistency",
    "reversal-refund-and-reconciliation-state",
    "schedule-field-combinations",
}
EXPECTED_BUSINESS_LIMIT_IDS = {
    "authenticated-session-limits",
    "csv-import-resource-limits",
    "debt-projection-limits",
    "login-throttle-limits",
    "mfa-code-limits",
    "money-precision-and-sign-limits",
    "notification-window-limits",
    "password-blocklist-limits",
    "percentage-rate-limits",
    "result-page-limits",
    "schedule-recurrence-limits",
}
EXPECTED_BUSINESS_LIMIT_TESTS = {
    "authenticated-session-limits": {
        "tests/test_account_security.py::test_new_login_revokes_oldest_session_at_account_limit",
        "tests/test_authentication.py::test_idle_session_is_terminated",
        "tests/test_release_hardening.py::test_session_security_policy_matches_enforced_timeouts",
    },
    "csv-import-resource-limits": {
        "tests/test_csv_imports.py::test_csv_upload_contract_matches_the_documented_release_limits",
        "tests/test_csv_imports.py::test_csv_parser_enforces_configured_byte_limit",
        "tests/test_csv_imports.py::test_csv_parser_enforces_row_and_cell_limits",
        "tests/test_csv_imports.py::test_csv_parser_enforces_column_and_header_limits",
    },
    "debt-projection-limits": {
        "tests/test_debt_projections.py::test_projection_rejects_invalid_strategy_and_too_many_debts",
        "tests/test_debt_projections.py::test_projection_validation_fails_closed",
    },
    "login-throttle-limits": {
        "tests/test_authentication.py::test_login_failures_are_rate_limited_without_storing_email",
        "tests/test_password_recovery.py::test_recovery_is_rate_limited_and_never_stores_submitted_values",
    },
    "mfa-code-limits": {
        "tests/test_mfa.py::test_mfa_services_reject_incomplete_replayed_and_malformed_credentials",
        "tests/test_mfa.py::test_enrollment_requires_recovery_confirmation_before_household_access",
        "tests/test_mfa.py::test_pending_mfa_expires_without_consuming_recovery_code",
    },
    "money-precision-and-sign-limits": {
        "tests/test_debt_accounts.py::test_debt_creation_rejects_invalid_money_terms_and_types",
        "tests/test_managed_runtime_safety.py::test_numeric_model_inventory_is_bounded",
    },
    "notification-window-limits": {
        "tests/test_notifications.py::test_notification_ui_is_scoped_csrf_protected_and_updates_preferences",
        "tests/test_notifications.py::test_notification_models_and_refresh_inputs_reject_invalid_state",
    },
    "password-blocklist-limits": {
        "tests/test_password_policy.py::test_corpus_loader_rejects_stale_or_impossible_dates",
        "tests/test_password_policy.py::test_corpus_loader_rejects_missing_oversized_and_invalid_limits",
    },
    "percentage-rate-limits": {
        "tests/test_debt_accounts.py::test_debt_creation_rejects_invalid_money_terms_and_types",
        "tests/test_debt_projections.py::test_projection_rejects_invalid_term_assumptions",
    },
    "result-page-limits": {
        "tests/test_audit_ui.py::test_audit_history_pages_enforce_fifty_record_limit",
        "tests/test_spending_ui.py::test_transaction_history_pages_enforce_fifty_record_limit",
    },
    "schedule-recurrence-limits": {
        "tests/test_scheduling_periods.py::test_recurrence_generation_rejects_invalid_windows_limits_and_overflow",
        "tests/test_scheduling_periods.py::test_period_and_occurrence_sync_reject_invalid_generation_windows",
    },
}
EXPECTED_GAP_IDS = {
    "release-candidate-validation-verification",
}
EXPECTED_SOURCE_ASSERTIONS = {
    "amount-field-contract": (
        "scripts/check_managed_runtime_safety.py",
        ("ALLOWED_DECIMAL_SPECS = {(7, 4), (18, 2)}", "if len(decimal_fields) != 38"),
    ),
    "household-membership-contract": (
        "households/services/access.py",
        (
            "def require_household_membership",
            "HouseholdMembership.objects.filter(",
            "is_active=True",
        ),
    ),
    "ledger-balance-contract": (
        "ledger/services/entries.py",
        (
            "if len(postings) < 2:",
            "if debit_total != credit_total:",
            "Every financial account must belong to the active household.",
        ),
    ),
    "recurrence-contract": (
        "schedules/recurrence.py",
        (
            "_MAX_WINDOW_DAYS = 366 * 25",
            "_MAX_OCCURRENCES = 10_000",
            "if self.interval < 1 or self.interval > 366:",
        ),
    ),
    "csv-resource-contract": (
        "config/settings/base.py",
        (
            "CSV_IMPORT_MAX_BYTES = 5 * 1024 * 1024",
            "CSV_IMPORT_MAX_ROWS = 10_000",
            "CSV_IMPORT_MAX_COLUMNS = 50",
            "CSV_IMPORT_MAX_CELL_LENGTH = 1_000",
        ),
    ),
    "session-contract": (
        "config/settings/base.py",
        (
            "SESSION_IDLE_TIMEOUT_SECONDS = 60 * 60",
            "SESSION_ABSOLUTE_TIMEOUT_SECONDS = 60 * 60 * 12",
            "MAX_CONCURRENT_SESSIONS = 5",
            "RECENT_AUTH_TIMEOUT_SECONDS = 10 * 60",
        ),
    ),
    "login-throttle-contract": (
        "config/settings/base.py",
        (
            "LOGIN_RATE_LIMIT_FAILURES = 5",
            "LOGIN_RATE_LIMIT_WINDOW_SECONDS = 15 * 60",
            "LOGIN_RATE_LIMIT_BLOCK_SECONDS = 15 * 60",
        ),
    ),
    "mfa-contract": (
        "config/settings/base.py",
        (
            "MFA_PENDING_TIMEOUT_SECONDS = 5 * 60",
            "MFA_TOTP_PERIOD_SECONDS = 30",
            "MFA_TOTP_CLOCK_DRIFT_STEPS = 1",
            "MFA_RECOVERY_CODE_COUNT = 10",
        ),
    ),
    "password-blocklist-contract": (
        "config/settings/base.py",
        (
            "BREACHED_PASSWORD_CORPUS_MINIMUM_ENTRIES = 10_000",
            "BREACHED_PASSWORD_CORPUS_MAXIMUM_AGE_DAYS = 180",
            "BREACHED_PASSWORD_CORPUS_MAXIMUM_BYTES = 25 * 1024 * 1024",
        ),
    ),
    "notification-window-contract": (
        "notifications/models.py",
        ("upcoming_due_days__lte=30", "missing_income_grace_days__lte=30"),
    ),
    "audit-page-contract": (
        "audit/views.py",
        ("paginator = Paginator(events, 50)",),
    ),
    "transaction-page-contract": (
        "spending/views.py",
        ("paginator = Paginator(entries, 50)",),
    ),
    "debt-projection-contract": (
        "debts/services/projections.py",
        ("_MAX_DEBTS = 100", "_MAX_MONTHS = 1_200"),
    ),
}


def _fail(message: str) -> NoReturn:
    raise ValueError(message)


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        _fail(f"{label} must be non-empty text")
    return value


def _string_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or not value:
        _fail(f"{label} must be a non-empty string list")
    result = [_text(item, label) for item in value]
    if len(result) != len(set(result)):
        _fail(f"{label} contains duplicates")
    return result


def _safe_path(project_root: Path, relative_path: str) -> Path:
    path = (project_root / relative_path).resolve()
    try:
        path.relative_to(project_root.resolve())
    except ValueError:
        _fail(f"path escapes the project root: {relative_path}")
    if not path.exists():
        _fail(f"missing evidence path: {relative_path}")
    return path


def _base_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _base_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def discover_form_classes(source: str, relative_path: str) -> set[str]:
    tree = ast.parse(source, filename=relative_path)
    classes = {node.name: node for node in tree.body if isinstance(node, ast.ClassDef)}
    discovered: set[str] = set()
    direct_bases = {
        "forms.Form",
        "forms.ModelForm",
        "AuthenticationForm",
        "PasswordChangeForm",
    }
    changed = True
    while changed:
        changed = False
        for name, node in classes.items():
            bases = {_base_name(base) for base in node.bases}
            if name not in discovered and (bases & direct_bases or bases & discovered):
                discovered.add(name)
                changed = True
    return discovered


def validate_form_source(source: str, relative_path: str) -> None:
    expected_classes = EXPECTED_FORM_REGISTRY.get(relative_path)
    if expected_classes is None:
        _fail(f"unreviewed form module: {relative_path}")
    discovered = discover_form_classes(source, relative_path)
    if discovered != expected_classes:
        _fail(
            f"form class inventory changed in {relative_path} "
            f"(expected={sorted(expected_classes)}, discovered={sorted(discovered)})"
        )


def validate_source_contract(assertion_id: str, source: str) -> None:
    expected = EXPECTED_SOURCE_ASSERTIONS.get(assertion_id)
    if expected is None:
        _fail(f"unreviewed source assertion: {assertion_id}")
    missing = [fragment for fragment in expected[1] if fragment not in source]
    if missing:
        _fail(f"source contract changed for {assertion_id}: missing {missing}")


def _validate_rules(
    policy: dict[str, Any], collection: str, expected_ids: set[str], project_root: Path
) -> None:
    records = policy.get(collection)
    if not isinstance(records, list):
        _fail(f"{collection} must be a list")
    if any(not isinstance(record, dict) for record in records):
        _fail(f"{collection} records must be objects")
    ids = [_text(record.get("id"), f"{collection} id") for record in records]
    if set(ids) != expected_ids or len(ids) != len(expected_ids):
        _fail(f"{collection} inventory changed")
    for record in records:
        if set(record) != {"id", "data_items", "validation", "evidence"}:
            _fail(f"{collection} record fields changed: {record.get('id')}")
        _string_list(record["data_items"], f"{record['id']} data_items")
        _text(record["validation"], f"{record['id']} validation")
        for evidence in _string_list(record["evidence"], f"{record['id']} evidence"):
            _safe_path(project_root, evidence)


def _validate_form_registry(policy: dict[str, Any], project_root: Path) -> None:
    records = policy.get("form_registry")
    if not isinstance(records, list):
        _fail("form_registry must be a list")
    documented: dict[str, set[str]] = {}
    for record in records:
        if not isinstance(record, dict) or set(record) != {"module", "path", "classes"}:
            _fail("form registry record fields changed")
        path = _text(record["path"], "form path")
        expected_module = path.removesuffix(".py").replace("/", ".")
        if _text(record["module"], "form module") != expected_module:
            _fail(f"form module does not match path: {path}")
        classes = set(_string_list(record["classes"], f"{path} classes"))
        if path in documented:
            _fail(f"duplicate form module: {path}")
        documented[path] = classes
    if documented != EXPECTED_FORM_REGISTRY:
        _fail("documented form registry changed")
    discovered_modules: dict[str, set[str]] = {}
    for source_path in sorted(project_root.glob("*/forms.py")):
        path = source_path.relative_to(project_root).as_posix()
        classes = discover_form_classes(source_path.read_text(encoding="utf-8"), path)
        if classes:
            discovered_modules[path] = classes
    if discovered_modules != EXPECTED_FORM_REGISTRY:
        _fail("production form module inventory changed")


def _validate_source_assertions(policy: dict[str, Any], project_root: Path) -> None:
    records = policy.get("source_assertions")
    if not isinstance(records, list):
        _fail("source_assertions must be a list")
    documented: dict[str, tuple[str, tuple[str, ...]]] = {}
    for record in records:
        if not isinstance(record, dict) or set(record) != {"id", "path", "contains"}:
            _fail("source assertion fields changed")
        assertion_id = _text(record["id"], "source assertion id")
        if assertion_id in documented:
            _fail(f"duplicate source assertion: {assertion_id}")
        path = _text(record["path"], f"{assertion_id} path")
        fragments = tuple(_string_list(record["contains"], f"{assertion_id} contains"))
        documented[assertion_id] = (path, fragments)
    if documented != EXPECTED_SOURCE_ASSERTIONS:
        _fail("source assertion inventory changed")
    for assertion_id, (path, _fragments) in documented.items():
        source = _safe_path(project_root, path).read_text(encoding="utf-8")
        validate_source_contract(assertion_id, source)


def _test_functions(source: str, path: str) -> set[str]:
    tree = ast.parse(source, filename=path)
    return {
        node.name for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def _validate_business_limit_tests(policy: dict[str, Any], project_root: Path) -> None:
    records = policy.get("business_limit_tests")
    if not isinstance(records, list):
        _fail("business_limit_tests must be a list")
    documented: dict[str, set[str]] = {}
    for record in records:
        if not isinstance(record, dict) or set(record) != {"id", "tests"}:
            _fail("business-limit test fields changed")
        identifier = _text(record["id"], "business-limit test id")
        if identifier in documented:
            _fail(f"duplicate business-limit test record: {identifier}")
        documented[identifier] = set(_string_list(record["tests"], f"{identifier} tests"))
    if documented != EXPECTED_BUSINESS_LIMIT_TESTS:
        _fail("business-limit test inventory changed")

    discovered: dict[str, set[str]] = {}
    for references in documented.values():
        for reference in references:
            path, separator, function = reference.partition("::")
            if not separator or not function.startswith("test_"):
                _fail(f"invalid business-limit test reference: {reference}")
            functions = discovered.setdefault(
                path,
                _test_functions(_safe_path(project_root, path).read_text(encoding="utf-8"), path),
            )
            if function not in functions:
                _fail(f"missing business-limit enforcement test: {reference}")


def validate_input_validation_policy(
    policy: dict[str, Any], *, project_root: Path = PROJECT_ROOT, today: date | None = None
) -> None:
    expected_top_level = {
        "schema_version",
        "policy_id",
        "asvs_requirements",
        "last_reviewed",
        "next_review_due",
        "validation_order",
        "form_registry",
        "structure_rules",
        "context_rules",
        "business_limits",
        "business_limit_tests",
        "source_assertions",
        "known_gaps",
        "summary",
    }
    if set(policy) != expected_top_level:
        _fail("input-validation policy fields changed")
    if policy["schema_version"] != 1:
        _fail("unsupported input-validation policy schema")
    if policy["policy_id"] != "household-budget-input-validation-v1":
        _fail("input-validation policy id changed")
    if set(_string_list(policy["asvs_requirements"], "asvs_requirements")) != EXPECTED_REQUIREMENTS:
        _fail("input-validation ASVS requirements changed")
    if len(_string_list(policy["validation_order"], "validation_order")) != 6:
        _fail("validation order must contain six stages")

    reviewed = date.fromisoformat(_text(policy["last_reviewed"], "last_reviewed"))
    due = date.fromisoformat(_text(policy["next_review_due"], "next_review_due"))
    if due <= reviewed or (due - reviewed).days > 90:
        _fail("input-validation review cadence exceeds 90 days")
    if (today or date.today()) > due:
        _fail("input-validation policy review is overdue")

    _validate_form_registry(policy, project_root)
    _validate_rules(policy, "structure_rules", EXPECTED_STRUCTURE_RULE_IDS, project_root)
    _validate_rules(policy, "context_rules", EXPECTED_CONTEXT_RULE_IDS, project_root)
    _validate_rules(policy, "business_limits", EXPECTED_BUSINESS_LIMIT_IDS, project_root)
    _validate_business_limit_tests(policy, project_root)
    _validate_source_assertions(policy, project_root)

    gaps = policy.get("known_gaps")
    if not isinstance(gaps, list):
        _fail("known_gaps must be a list")
    gap_ids: list[str] = []
    for gap in gaps:
        if not isinstance(gap, dict) or set(gap) != {
            "id",
            "asvs_requirement",
            "status",
            "description",
        }:
            _fail("known gap fields changed")
        gap_ids.append(_text(gap["id"], "known gap id"))
        _text(gap["asvs_requirement"], f"{gap['id']} requirement")
        if gap["status"] not in {"partial", "pending"}:
            _fail(f"known gap has invalid status: {gap['id']}")
        _text(gap["description"], f"{gap['id']} description")
    if set(gap_ids) != EXPECTED_GAP_IDS or len(gap_ids) != len(EXPECTED_GAP_IDS):
        _fail("known gap inventory changed")

    expected_summary = {
        "form_modules": len(EXPECTED_FORM_REGISTRY),
        "form_classes": sum(len(classes) for classes in EXPECTED_FORM_REGISTRY.values()),
        "structure_rules": len(EXPECTED_STRUCTURE_RULE_IDS),
        "context_rules": len(EXPECTED_CONTEXT_RULE_IDS),
        "business_limits": len(EXPECTED_BUSINESS_LIMIT_IDS),
        "business_limit_tests": sum(len(tests) for tests in EXPECTED_BUSINESS_LIMIT_TESTS.values()),
        "source_assertions": len(EXPECTED_SOURCE_ASSERTIONS),
        "known_gaps": len(EXPECTED_GAP_IDS),
    }
    if policy.get("summary") != expected_summary:
        _fail("input-validation policy summary is stale")


def main() -> int:
    try:
        policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        if not isinstance(policy, dict):
            _fail("input-validation policy must be a JSON object")
        validate_input_validation_policy(policy)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"input-validation policy check failed: {error}", file=sys.stderr)
        return 1
    summary = policy["summary"]
    print(
        "Input-validation policy verified: "
        f"{summary['form_classes']} forms, {summary['structure_rules']} structure rules, "
        f"{summary['context_rules']} context rules, {summary['business_limits']} business limits, "
        f"{summary['business_limit_tests']} enforcement tests."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
