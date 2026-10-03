"""Validate the exhaustive anti-automation route and enforcement inventory."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
from datetime import date
from pathlib import Path
from typing import Any, NoReturn

PROJECT_ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = PROJECT_ROOT / "docs" / "anti-automation-policy.json"

EXPECTED_LIMITS = {
    "authenticated_mutation": {"maximum": 120, "window_seconds": 300},
    "data_export": {"maximum": 5, "window_seconds": 900},
    "csv_import": {"maximum": 10, "window_seconds": 900},
    "expensive_calculation": {"maximum": 20, "window_seconds": 900},
    "identity_failure": {"maximum": 5, "window_seconds": 900, "block_seconds": 900},
}
EXPECTED_ROUTE_FILES = (
    "identity/urls.py",
    "audit/urls.py",
    "budgets/urls.py",
    "debts/urls.py",
    "goals/urls.py",
    "imports/urls.py",
    "notifications/urls.py",
    "spending/urls.py",
    "core/urls.py",
)
EXPECTED_FAMILY_COUNTS = {
    "identity-failure-throttles": 4,
    "authenticated-mutations": 45,
    "security-termination-actions": 3,
    "protected-data-exports": 2,
    "csv-import-intake": 1,
    "expensive-calculations": 2,
    "bounded-authenticated-reads": 14,
    "operational-health": 2,
}
EXPECTED_ROUTE_ASSIGNMENT_SHA256 = (
    "033a8853c844e3ede328fbe0ee67cf2eb67ee9826e57c5e45b9723b3164a5e79"  # pragma: allowlist secret
)
EXPECTED_SOURCE_ASSERTIONS = {
    "configured-budgets": (
        "config/settings/base.py",
        (
            "APPLICATION_MUTATION_RATE_LIMIT = 120",
            "DATA_EXPORT_RATE_LIMIT = 5",
            "CSV_IMPORT_RATE_LIMIT = 10",
            "EXPENSIVE_CALCULATION_RATE_LIMIT = 20",
        ),
    ),
    "mutation-middleware": (
        "identity/middleware.py",
        (
            "class ApplicationRateLimitMiddleware(MiddlewareMixin)",
            "def process_view(",
            "_MUTATING_METHODS = frozenset",
            "_SECURITY_TERMINATION_ROUTES = frozenset",
            'scope="authenticated-mutation"',
            "anti_automation.rate_limited",
        ),
    ),
    "database-counter": (
        "identity/services/application_throttling.py",
        (
            "select_for_update().get_or_create",
            "throttle.request_count >= maximum",
            'response.headers["Retry-After"]',
        ),
    ),
    "shared-export-budget": (
        "spending/views.py",
        ('scope="data-export"', "settings.DATA_EXPORT_RATE_LIMIT"),
    ),
    "shared-audit-export-budget": (
        "audit/views.py",
        ('scope="data-export"', "settings.DATA_EXPORT_RATE_LIMIT"),
    ),
    "pre-parse-import-budget": (
        "imports/views.py",
        ('scope="csv-import"', "settings.CSV_IMPORT_RATE_LIMIT"),
    ),
    "shared-projection-budget": (
        "debts/views.py",
        ('scope="expensive-calculation"', "settings.EXPENSIVE_CALCULATION_RATE_LIMIT"),
    ),
    "shared-refresh-budget": (
        "notifications/views.py",
        ('scope="expensive-calculation"', "settings.EXPENSIVE_CALCULATION_RATE_LIMIT"),
    ),
}
EXPECTED_RUNTIME_TESTS = {
    "tests/test_anti_automation.py::test_application_budget_is_atomic_bounded_and_resets_after_its_window",
    "tests/test_anti_automation.py::test_all_authenticated_mutations_share_a_fail_closed_budget",
    "tests/test_anti_automation.py::test_transaction_and_audit_exports_share_a_tighter_data_budget",
    "tests/test_anti_automation.py::test_rejected_csv_uploads_consume_the_import_budget_before_parsing",
    "tests/test_anti_automation.py::test_get_projection_and_post_refresh_share_the_expensive_calculation_budget",
    "tests/test_authentication.py::test_login_failures_are_rate_limited_without_storing_email",
    "tests/test_mfa.py::test_mfa_failures_are_rate_limited_and_audited",
    "tests/test_password_recovery.py::test_recovery_is_rate_limited_and_never_stores_submitted_values",
}
EXPECTED_SUMMARY = {
    "route_families": 8,
    "named_routes": 73,
    "source_assertions": 8,
    "runtime_tests": 8,
    "residual_risks": 2,
}


def _fail(message: str) -> NoReturn:
    raise ValueError(message)


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        _fail(f"{label} must be non-empty text")
    return value


def _string_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or not value:
        _fail(f"{label} must be a non-empty list")
    values = [_text(item, label) for item in value]
    if len(values) != len(set(values)):
        _fail(f"{label} contains duplicates")
    return values


def _safe_path(relative_path: str, *, project_root: Path) -> Path:
    if Path(relative_path).is_absolute():
        _fail(f"anti-automation evidence must be relative: {relative_path}")
    path = (project_root / relative_path).resolve()
    try:
        path.relative_to(project_root.resolve())
    except ValueError:
        _fail(f"anti-automation evidence escapes project root: {relative_path}")
    if not path.is_file():
        _fail(f"missing anti-automation evidence: {relative_path}")
    return path


def _literal_string(node: ast.AST, label: str) -> str:
    if not isinstance(node, ast.Constant) or not isinstance(node.value, str) or not node.value:
        _fail(f"{label} must be a literal string")
    return node.value


def discover_named_routes(*, project_root: Path = PROJECT_ROOT) -> set[str]:
    routes: set[str] = set()
    for relative_path in EXPECTED_ROUTE_FILES:
        path = _safe_path(relative_path, project_root=project_root)
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        namespace = ""
        for node in tree.body:
            if isinstance(node, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id == "app_name" for target in node.targets
            ):
                namespace = _literal_string(node.value, f"{relative_path} app_name")
                break
        if not namespace:
            _fail(f"missing app_name in {relative_path}")
        for node in ast.walk(tree):
            if (
                not isinstance(node, ast.Call)
                or not isinstance(node.func, ast.Name)
                or node.func.id != "path"
            ):
                continue
            name_nodes = [keyword.value for keyword in node.keywords if keyword.arg == "name"]
            if len(name_nodes) != 1:
                _fail(f"unnamed or multiply named route in {relative_path}")
            route = f"{namespace}:{_literal_string(name_nodes[0], f'{relative_path} route name')}"
            if route in routes:
                _fail(f"duplicate discovered route: {route}")
            routes.add(route)
    return routes


def _test_functions(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return {
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith("test_")
    }


def _validate_test_reference(reference: str, *, project_root: Path) -> None:
    parts = reference.split("::")
    if len(parts) != 2:
        _fail(f"invalid anti-automation test reference: {reference}")
    relative_path, test_name = parts
    path = _safe_path(relative_path, project_root=project_root)
    if test_name not in _test_functions(path):
        _fail(f"missing anti-automation test reference: {reference}")


def validate_source_contract(
    assertion_id: str,
    source: str,
    *,
    expected: dict[str, tuple[str, tuple[str, ...]]] = EXPECTED_SOURCE_ASSERTIONS,
) -> None:
    try:
        _, fragments = expected[assertion_id]
    except KeyError:
        _fail(f"unknown anti-automation source assertion: {assertion_id}")
    missing = [fragment for fragment in fragments if fragment not in source]
    if missing:
        _fail(f"anti-automation source contract changed for {assertion_id}: {missing}")


def _validate_gate_wiring(project_root: Path) -> None:
    powershell = (project_root / "scripts/check.ps1").read_text(encoding="utf-8")
    shell = (project_root / "scripts/check.sh").read_text(encoding="utf-8")
    if "scripts\\check_anti_automation_policy.py" not in powershell:
        _fail("PowerShell gate does not run the anti-automation checker")
    if "scripts/check_anti_automation_policy.py" not in shell:
        _fail("shell gate does not run the anti-automation checker")


def validate_anti_automation_policy(
    policy: dict[str, Any],
    *,
    project_root: Path = PROJECT_ROOT,
    today: date | None = None,
) -> None:
    expected_fields = {
        "policy_version",
        "title",
        "asvs_requirements",
        "last_reviewed",
        "review_interval_days",
        "limits",
        "route_families",
        "source_assertions",
        "runtime_tests",
        "residual_risks",
        "summary",
    }
    if set(policy) != expected_fields:
        _fail("anti-automation top-level fields changed")
    if policy["policy_version"] != 1:
        _fail("anti-automation policy version changed")
    _text(policy["title"], "anti-automation title")
    if policy["asvs_requirements"] != ["v5.0.0-2.4.1"]:
        _fail("anti-automation ASVS scope changed")
    if policy["limits"] != EXPECTED_LIMITS:
        _fail("anti-automation limits changed")

    try:
        last_reviewed = date.fromisoformat(_text(policy["last_reviewed"], "last reviewed"))
    except ValueError as error:
        raise ValueError("anti-automation last_reviewed is invalid") from error
    if policy["review_interval_days"] != 90:
        _fail("anti-automation review interval changed")
    check_date = today or date.today()
    if (check_date - last_reviewed).days > policy["review_interval_days"]:
        _fail("anti-automation review is overdue")

    families = policy["route_families"]
    if not isinstance(families, list) or any(not isinstance(item, dict) for item in families):
        _fail("route_families must contain objects")
    assignments: dict[str, str] = {}
    family_counts: dict[str, int] = {}
    for family in families:
        if set(family) != {"id", "risk", "control", "routes", "evidence"}:
            _fail("anti-automation route-family fields changed")
        family_id = _text(family["id"], "route family id")
        if family_id in family_counts:
            _fail(f"duplicate route family: {family_id}")
        _text(family["risk"], f"{family_id} risk")
        _text(family["control"], f"{family_id} control")
        routes = _string_list(family["routes"], f"{family_id} routes")
        if routes != sorted(routes):
            _fail(f"{family_id} routes must be sorted")
        family_counts[family_id] = len(routes)
        for route in routes:
            if route in assignments:
                _fail(f"route assigned to multiple anti-automation families: {route}")
            assignments[route] = family_id
        for evidence in _string_list(family["evidence"], f"{family_id} evidence"):
            _safe_path(evidence, project_root=project_root)
    if family_counts != EXPECTED_FAMILY_COUNTS:
        _fail("anti-automation route-family inventory changed")
    discovered = discover_named_routes(project_root=project_root)
    if set(assignments) != discovered:
        missing = sorted(discovered - set(assignments))
        extra = sorted(set(assignments) - discovered)
        _fail(f"anti-automation route coverage changed; missing={missing}, extra={extra}")
    assignment_payload = json.dumps(assignments, sort_keys=True, separators=(",", ":")).encode()
    if hashlib.sha256(assignment_payload).hexdigest() != EXPECTED_ROUTE_ASSIGNMENT_SHA256:
        _fail("anti-automation route assignments changed")

    assertions = policy["source_assertions"]
    if not isinstance(assertions, list) or any(not isinstance(item, dict) for item in assertions):
        _fail("source_assertions must contain objects")
    documented: dict[str, tuple[str, tuple[str, ...]]] = {}
    for assertion in assertions:
        if set(assertion) != {"id", "path", "contains"}:
            _fail("anti-automation source-assertion fields changed")
        assertion_id = _text(assertion["id"], "source assertion id")
        documented[assertion_id] = (
            _text(assertion["path"], f"{assertion_id} path"),
            tuple(_string_list(assertion["contains"], f"{assertion_id} fragments")),
        )
    if documented != EXPECTED_SOURCE_ASSERTIONS:
        _fail("anti-automation source assertions changed")
    for assertion_id, (relative_path, _) in documented.items():
        source = _safe_path(relative_path, project_root=project_root).read_text(encoding="utf-8")
        validate_source_contract(assertion_id, source)

    runtime_tests = set(_string_list(policy["runtime_tests"], "runtime tests"))
    if runtime_tests != EXPECTED_RUNTIME_TESTS:
        _fail("anti-automation runtime-test inventory changed")
    for reference in runtime_tests:
        _validate_test_reference(reference, project_root=project_root)
    _string_list(policy["residual_risks"], "residual risks")
    if policy["summary"] != EXPECTED_SUMMARY:
        _fail("anti-automation summary changed")
    _validate_gate_wiring(project_root)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, default=POLICY_PATH)
    args = parser.parse_args()
    policy = json.loads(args.policy.read_text(encoding="utf-8"))
    validate_anti_automation_policy(policy)
    print(
        "Anti-automation policy validated: "
        f"{policy['summary']['named_routes']} routes across "
        f"{policy['summary']['route_families']} families."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
