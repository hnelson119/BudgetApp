"""Validate function-, route-, record-, and field-level authorization policy."""

from __future__ import annotations

import ast
import json
import sys
from datetime import date
from pathlib import Path
from typing import Any, NoReturn

PROJECT_ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = PROJECT_ROOT / "docs" / "authorization-policy.json"
ACCESS_TIERS = {"public", "pending_auth", "deployment_restricted", "member", "recent_auth"}
EXPECTED_REQUIREMENTS = {"v5.0.0-8.1.1", "v5.0.0-8.1.2"}
EXPECTED_CONSUMER_STATE_IDS = {
    "active-household-member",
    "anonymous",
    "pending-mfa",
    "trusted-administrator",
}
EXPECTED_ROUTE_ACCESS = {
    "audit/urls.py": {
        "member": {"detail", "history"},
        "recent_auth": {"export"},
    },
    "budgets/urls.py": {
        "member": {
            "category-create",
            "detail",
            "fixed-create",
            "occurrence-cancel",
            "occurrence-edit",
            "occurrence-move",
            "occurrence-reconcile",
            "reserve-allocate",
            "variable-create",
            "variable-delete",
            "variable-edit",
        }
    },
    "core/urls.py": {
        "public": {"health-live"},
        "deployment_restricted": {"health-ready"},
        "member": {"home"},
    },
    "debts/urls.py": {
        "member": {
            "create",
            "detail",
            "edit",
            "list",
            "mortgage-extra-principal",
            "mortgage-plan-create",
            "mortgage-plan-revise",
            "payoff-comparison",
            "statement-correct",
            "statement-create",
            "status",
            "terms-create",
        }
    },
    "goals/urls.py": {
        "member": {
            "contribute",
            "create",
            "detail",
            "list",
            "occurrence-contribute",
            "priority-allocate",
            "reserve-allocate",
            "revise",
            "status",
        }
    },
    "identity/urls.py": {
        "public": {"login", "password-recovery"},
        "pending_auth": {"mfa-verify"},
        "member": {
            "account-security",
            "logout",
            "mfa-enroll",
            "mfa-enrollment-restart",
            "mfa-recovery-confirm",
            "reauthenticate",
        },
        "recent_auth": {"logout-all", "password-change", "session-revoke"},
    },
    "imports/urls.py": {
        "member": {
            "batch-abandon",
            "batch-commit",
            "batch-map",
            "batch-preview",
            "history",
            "upload",
        }
    },
    "notifications/urls.py": {"member": {"dismiss", "list", "preferences", "read", "refresh"}},
    "spending/urls.py": {
        "member": {
            "account-create",
            "card-payment-create",
            "card-purchase-refund",
            "expense-create",
            "income-create",
            "transaction-detail",
            "transaction-list",
            "transaction-reverse",
        },
        "recent_auth": {"transaction-export"},
    },
}
EXPECTED_FUNCTION_RULE_IDS = {
    "audit-functions",
    "budget-period-and-schedule-functions",
    "csv-import-functions",
    "debt-and-mortgage-functions",
    "goal-and-reserve-functions",
    "household-selection-and-categories",
    "notification-functions",
    "public-authentication-and-liveness",
    "session-and-account-security",
    "spending-and-ledger-functions",
    "trusted-administration-functions",
}
EXPECTED_FIELD_RULE_IDS = {
    "authentication-secret-fields",
    "export-and-browser-representations",
    "financial-input-fields",
    "household-membership-fields",
    "identity-self-fields",
    "immutable-accounting-and-revision-fields",
    "import-staging-fields",
    "protected-audit-fields",
    "recipient-notification-fields",
    "system-metadata-fields",
}
EXPECTED_SOURCE_ASSERTIONS = {
    "equal-member-role-contract": (
        "households/models.py",
        (
            "Equal application access for each person in a shared household.",
            "is_active = models.BooleanField(default=True)",
        ),
    ),
    "active-membership-contract": (
        "households/services/access.py",
        ("def require_household_membership", "user=user", "household=household", "is_active=True"),
    ),
    "notification-recipient-contract": (
        "notifications/services.py",
        (
            "Notification.objects.filter(household=household, recipient=user)",
            "if notification.recipient_id != actor.pk:",
        ),
    ),
    "account-recent-auth-contract": (
        "identity/views.py",
        (
            "if not recent_authentication_is_valid(request):",
            'reverse("identity:password-change")',
            "revoke_user_session(",
        ),
    ),
    "transaction-export-contract": (
        "spending/views.py",
        ("def transaction_export", "if not recent_authentication_is_valid(request):"),
    ),
    "audit-export-contract": (
        "audit/views.py",
        (
            "def export",
            "if not recent_authentication_is_valid(request):",
            "if not integrity.valid:",
        ),
    ),
    "import-household-contract": (
        "imports/views.py",
        ("def _batch(request", "household=household", "pk=batch_id"),
    ),
    "authorization-denial-log-contract": (
        "core/middleware.py",
        (
            "def _is_authorization_denial",
            '"event": "authorization.denied"',
            '"route": _route_name(request)',
        ),
    ),
}
EXPECTED_GAP_IDS = {
    "future-role-change-review",
    "release-candidate-authorization-verification",
}


def _fail(message: str) -> NoReturn:
    raise ValueError(message)


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        _fail(f"{label} must be non-empty text")
    return value


def _string_list(value: Any, label: str, *, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not allow_empty and not value):
        _fail(f"{label} must be a {'possibly empty ' if allow_empty else 'non-empty '}string list")
    values = [_text(item, label) for item in value]
    if len(values) != len(set(values)):
        _fail(f"{label} contains duplicates")
    return values


def _safe_path(project_root: Path, relative_path: str) -> Path:
    path = (project_root / relative_path).resolve()
    try:
        path.relative_to(project_root.resolve())
    except ValueError:
        _fail(f"path escapes project root: {relative_path}")
    if not path.exists():
        _fail(f"missing authorization evidence: {relative_path}")
    return path


def _call_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    if isinstance(node, ast.Call):
        return _call_name(node.func)
    return ""


def discover_named_routes(source: str, relative_path: str) -> dict[str, str]:
    tree = ast.parse(source, filename=relative_path)
    routes: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or _call_name(node.func) != "path" or len(node.args) < 2:
            continue
        route_name = next(
            (
                keyword.value.value
                for keyword in node.keywords
                if keyword.arg == "name"
                and isinstance(keyword.value, ast.Constant)
                and isinstance(keyword.value.value, str)
            ),
            None,
        )
        view = node.args[1]
        view_name = (
            view.attr
            if isinstance(view, ast.Attribute)
            and isinstance(view.value, ast.Name)
            and view.value.id == "views"
            else None
        )
        if route_name is None or view_name is None:
            continue
        if route_name in routes:
            _fail(f"duplicate route name in {relative_path}: {route_name}")
        routes[route_name] = view_name
    return routes


def _view_functions(
    source: str, relative_path: str
) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    tree = ast.parse(source, filename=relative_path)
    return {
        node.name: node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def validate_route_guards(
    *, relative_path: str, access: dict[str, set[str]], project_root: Path
) -> None:
    url_source = _safe_path(project_root, relative_path).read_text(encoding="utf-8")
    routes = discover_named_routes(url_source, relative_path)
    classified = set().union(*access.values())
    if set(routes) != classified:
        _fail(f"route classification changed in {relative_path}")
    view_path = relative_path.replace("urls.py", "views.py")
    view_functions = _view_functions(
        _safe_path(project_root, view_path).read_text(encoding="utf-8"),
        view_path,
    )
    for tier, route_names in access.items():
        for route_name in route_names:
            function_name = routes[route_name]
            function = view_functions.get(function_name)
            if function is None:
                _fail(f"missing routed view {view_path}:{function_name}")
            decorators = {
                _call_name(decorator).split(".")[-1] for decorator in function.decorator_list
            }
            if tier in {"member", "recent_auth"} and "login_required" not in decorators:
                _fail(f"authenticated route lost login guard: {relative_path}:{route_name}")
            if tier == "recent_auth" and not any(
                isinstance(node, ast.Name) and node.id == "recent_authentication_is_valid"
                for node in ast.walk(function)
            ):
                _fail(f"sensitive route lost recent-auth guard: {relative_path}:{route_name}")


def _validate_route_registry(policy: dict[str, Any], project_root: Path) -> None:
    records = policy.get("route_registry")
    if not isinstance(records, list):
        _fail("route_registry must be a list")
    documented: dict[str, dict[str, set[str]]] = {}
    for record in records:
        if not isinstance(record, dict) or set(record) != {"namespace", "path", "access"}:
            _fail("route registry fields changed")
        path = _text(record["path"], "route path")
        namespace = _text(record["namespace"], f"{path} namespace")
        if namespace != path.split("/", maxsplit=1)[0]:
            _fail(f"route namespace does not match path: {path}")
        access_raw = record["access"]
        if (
            not isinstance(access_raw, dict)
            or not access_raw
            or not set(access_raw) <= ACCESS_TIERS
        ):
            _fail(f"invalid route access tiers: {path}")
        access = {
            tier: set(_string_list(names, f"{path} {tier} routes"))
            for tier, names in access_raw.items()
        }
        all_names = [name for names in access.values() for name in names]
        if len(all_names) != len(set(all_names)):
            _fail(f"route appears in multiple access tiers: {path}")
        if path in documented:
            _fail(f"duplicate route namespace: {path}")
        documented[path] = access
    if documented != EXPECTED_ROUTE_ACCESS:
        _fail("authorization route registry changed")

    discovered_url_files = {
        path.relative_to(project_root).as_posix()
        for path in project_root.glob("*/urls.py")
        if path.parts[-2] != "tests"
        and discover_named_routes(path.read_text(encoding="utf-8"), path.as_posix())
    }
    if discovered_url_files != set(EXPECTED_ROUTE_ACCESS):
        _fail("named application URL-module inventory changed")
    for path, access in documented.items():
        validate_route_guards(relative_path=path, access=access, project_root=project_root)


def _validate_rule_collection(
    policy: dict[str, Any], collection: str, expected_ids: set[str], project_root: Path
) -> None:
    records = policy.get(collection)
    if not isinstance(records, list) or any(not isinstance(record, dict) for record in records):
        _fail(f"{collection} must contain objects")
    ids = [_text(record.get("id"), f"{collection} id") for record in records]
    if set(ids) != expected_ids or len(ids) != len(expected_ids):
        _fail(f"{collection} inventory changed")
    content_fields = {"permissions"} if collection == "function_rules" else {"read", "write"}
    expected_fields = {"id", "resource_attributes", "evidence"} | content_fields
    for record in records:
        if set(record) != expected_fields:
            _fail(f"{collection} fields changed: {record['id']}")
        for field in content_fields:
            _text(record[field], f"{record['id']} {field}")
        _string_list(record["resource_attributes"], f"{record['id']} resource attributes")
        for evidence in _string_list(record["evidence"], f"{record['id']} evidence"):
            _safe_path(project_root, evidence)


def _validate_source_assertions(policy: dict[str, Any], project_root: Path) -> None:
    records = policy.get("source_assertions")
    if not isinstance(records, list):
        _fail("source_assertions must be a list")
    documented: dict[str, tuple[str, tuple[str, ...]]] = {}
    for record in records:
        if not isinstance(record, dict) or set(record) != {"id", "path", "contains"}:
            _fail("source assertion fields changed")
        assertion_id = _text(record["id"], "source assertion id")
        path = _text(record["path"], f"{assertion_id} path")
        fragments = tuple(_string_list(record["contains"], f"{assertion_id} fragments"))
        if assertion_id in documented:
            _fail(f"duplicate source assertion: {assertion_id}")
        documented[assertion_id] = (path, fragments)
    if documented != EXPECTED_SOURCE_ASSERTIONS:
        _fail("authorization source assertion inventory changed")
    for assertion_id, (path, fragments) in documented.items():
        source = _safe_path(project_root, path).read_text(encoding="utf-8")
        missing = [fragment for fragment in fragments if fragment not in source]
        if missing:
            _fail(f"authorization source contract changed for {assertion_id}: {missing}")


def validate_authorization_policy(
    policy: dict[str, Any], *, project_root: Path = PROJECT_ROOT, today: date | None = None
) -> None:
    expected_fields = {
        "schema_version",
        "policy_id",
        "asvs_requirements",
        "last_reviewed",
        "next_review_due",
        "default_decision",
        "consumer_states",
        "route_registry",
        "function_rules",
        "field_rules",
        "source_assertions",
        "known_gaps",
        "summary",
    }
    if set(policy) != expected_fields:
        _fail("authorization policy fields changed")
    if policy["schema_version"] != 1 or policy["policy_id"] != "household-budget-authorization-v1":
        _fail("unsupported authorization policy identity")
    if policy["default_decision"] != "deny":
        _fail("authorization must remain deny by default")
    if set(_string_list(policy["asvs_requirements"], "ASVS requirements")) != EXPECTED_REQUIREMENTS:
        _fail("authorization ASVS requirements changed")

    reviewed = date.fromisoformat(_text(policy["last_reviewed"], "last_reviewed"))
    due = date.fromisoformat(_text(policy["next_review_due"], "next_review_due"))
    if due <= reviewed or (due - reviewed).days > 90:
        _fail("authorization policy review cadence exceeds 90 days")
    if (today or date.today()) > due:
        _fail("authorization policy review is overdue")

    states = policy.get("consumer_states")
    if not isinstance(states, list) or any(
        not isinstance(state, dict) or set(state) != {"id", "permissions"} for state in states
    ):
        _fail("consumer state fields changed")
    state_ids = [_text(state["id"], "consumer state id") for state in states]
    if set(state_ids) != EXPECTED_CONSUMER_STATE_IDS or len(state_ids) != len(
        EXPECTED_CONSUMER_STATE_IDS
    ):
        _fail("consumer state inventory changed")
    for state in states:
        _text(state["permissions"], f"{state['id']} permissions")

    _validate_route_registry(policy, project_root)
    _validate_rule_collection(policy, "function_rules", EXPECTED_FUNCTION_RULE_IDS, project_root)
    _validate_rule_collection(policy, "field_rules", EXPECTED_FIELD_RULE_IDS, project_root)
    _validate_source_assertions(policy, project_root)

    gaps = policy.get("known_gaps")
    if not isinstance(gaps, list) or any(
        not isinstance(gap, dict) or set(gap) != {"id", "status", "description"} for gap in gaps
    ):
        _fail("known authorization gap fields changed")
    gap_ids = [_text(gap["id"], "known gap id") for gap in gaps]
    if set(gap_ids) != EXPECTED_GAP_IDS or len(gap_ids) != len(EXPECTED_GAP_IDS):
        _fail("known authorization gap inventory changed")
    for gap in gaps:
        if gap["status"] not in {"pending", "trigger"}:
            _fail(f"invalid authorization gap status: {gap['id']}")
        _text(gap["description"], f"{gap['id']} description")

    expected_summary = {
        "consumer_states": len(EXPECTED_CONSUMER_STATE_IDS),
        "route_namespaces": len(EXPECTED_ROUTE_ACCESS),
        "routes": sum(
            len(names) for access in EXPECTED_ROUTE_ACCESS.values() for names in access.values()
        ),
        "function_rules": len(EXPECTED_FUNCTION_RULE_IDS),
        "field_rules": len(EXPECTED_FIELD_RULE_IDS),
        "source_assertions": len(EXPECTED_SOURCE_ASSERTIONS),
        "known_gaps": len(EXPECTED_GAP_IDS),
    }
    if policy.get("summary") != expected_summary:
        _fail("authorization policy summary is stale")


def main() -> int:
    try:
        policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        if not isinstance(policy, dict):
            _fail("authorization policy must be a JSON object")
        validate_authorization_policy(policy)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"authorization policy check failed: {error}", file=sys.stderr)
        return 1
    summary = policy["summary"]
    print(
        "Authorization policy verified: "
        f"{summary['routes']} routes, {summary['function_rules']} function rules, "
        f"{summary['field_rules']} field rules."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
