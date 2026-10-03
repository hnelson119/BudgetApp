"""Validate exhaustive direct-object authorization coverage."""

from __future__ import annotations

import ast
import json
import re
import sys
from datetime import date
from pathlib import Path
from typing import Any, NoReturn

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from scripts.check_csrf_boundary import (  # noqa: E402
    MOUNT_PREFIXES,
    STRING_SEGMENTS,
    _accepts_post,
    _call_name,
    _named_routes,
    _view_functions,
)

INVENTORY_PATH = PROJECT_ROOT / "docs" / "object-authorization-boundary.json"

ROUTE_PARAMETER_KEYS = {
    ("audit", "event_id"): "audit_event_id",
    ("budgets", "budget_id"): "variable_budget_id",
    ("budgets", "occurrence_id"): "occurrence_id",
    ("budgets", "period_id"): "pay_period_id",
    ("debts", "debt_id"): "debt_id",
    ("debts", "occurrence_id"): "occurrence_id",
    ("debts", "statement_id"): "debt_statement_id",
    ("goals", "goal_id"): "goal_id",
    ("goals", "occurrence_id"): "occurrence_id",
    ("goals", "period_id"): "pay_period_id",
    ("imports", "batch_id"): "import_batch_id",
    ("identity", "passkey_id"): "passkey_id",
    ("notifications", "notification_id"): "notification_id",
    ("spending", "account_id"): "financial_account_id",
    ("spending", "entry_id"): "journal_entry_id",
}
RELATIONSHIP_PROBES = {
    "debt-statement-relationship": {
        "template": "/debts/{own_debt_id}/statements/{debt_statement_id}/correct/",
        "foreign_keys": ["debt_statement_id"],
        "methods": ["GET", "POST"],
    },
    "goal-occurrence-relationship": {
        "template": "/goals/{own_goal_id}/occurrence/{occurrence_id}/contribute/",
        "foreign_keys": ["occurrence_id"],
        "methods": ["GET", "POST"],
    },
    "goal-reserve-relationship": {
        "template": "/goals/{own_goal_id}/reserve/{pay_period_id}/",
        "foreign_keys": ["pay_period_id"],
        "methods": ["GET", "POST"],
    },
}
EXPECTED_CONTROL_IDS = {
    "exhaustive-identifier-route-inventory",
    "foreign-and-missing-indistinguishability",
    "invariant-preserving-real-http-gate",
    "nested-relationship-isolation",
    "recipient-ownership-isolation",
    "two-way-household-isolation",
}
EXPECTED_SECURITY_EVIDENCE = {
    "deploy/pentest/run-authz-csrf.py",
    "docs/authorization-policy.json",
    "docs/object-authorization-boundary.json",
    "scripts/check_object_authorization_boundary.py",
    "scripts/run-authz-csrf.sh",
    "tests/test_authorization_policy.py",
    "tests/test_object_authorization_boundary.py",
    "tests/test_pentest_harness.py",
}
SOURCE_CONTRACTS = {
    "deploy/pentest/run-authz-csrf.py": (
        "for method in route.methods:",
        "if foreign_response.status != 404 or random_response.status != 404:",
        "foreign_response.body != random_response.body",
        "disclosed a foreign fixture reference",
        "a rejected direct-object request changed protected data",
        'directions = (\n            ("alex", "primary", "isolation"),\n'
        '            ("casey", "isolation", "primary"),',
    ),
    "scripts/run-authz-csrf.sh": (
        'project_name="budgetapp-authz-csrf"',
        "run --rm --no-deps pentest-authz-csrf",
        "--volumes --remove-orphans",
    ),
    "scripts/run-authz-csrf.ps1": (
        '$projectName = "budgetapp-authz-csrf"',
        "run --rm --no-deps pentest-authz-csrf",
        "--volumes --remove-orphans",
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
        _fail(f"{label} must be a non-empty list")
    items = [_text(item, f"{label} item") for item in value]
    if len(items) != len(set(items)):
        _fail(f"{label} contains duplicates")
    return items


def _safe_path(value: Any, *, project_root: Path, label: str) -> str:
    relative = _text(value, label).split("#", maxsplit=1)[0]
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


def _allowed_methods(function: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    allows_get = True
    allows_post = _accepts_post(function)
    for decorator in function.decorator_list:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        name = _call_name(target).split(".")[-1]
        if name == "require_POST":
            allows_get = False
        elif name == "require_GET":
            allows_post = False
        elif name == "require_http_methods" and isinstance(decorator, ast.Call):
            if not decorator.args:
                _fail(f"{function.name} has an unreadable require_http_methods decorator")
            try:
                methods = ast.literal_eval(decorator.args[0])
            except (ValueError, TypeError, SyntaxError):
                _fail(f"{function.name} has a dynamic require_http_methods decorator")
            allows_get = "GET" in methods
    return [method for method, allowed in (("GET", allows_get), ("POST", allows_post)) if allowed]


def _route_template(namespace: str, identifier: str, route_path: str) -> str:
    def replace_uuid(match: re.Match[str]) -> str:
        parameter = match.group(1)
        key = ROUTE_PARAMETER_KEYS.get((namespace, parameter))
        if key is None:
            _fail(f"identifier route needs a fixture key: {identifier}:{parameter}")
        return "{" + key + "}"

    template = re.sub(r"<uuid:([^>]+)>", replace_uuid, route_path)
    for parameter, value in STRING_SEGMENTS.get(identifier, {}).items():
        template = template.replace(f"<str:{parameter}>", value)
    if "<" in template:
        _fail(f"identifier route contains an unsupported segment: {identifier}")
    return f"{MOUNT_PREFIXES[namespace]}{template}".replace("//", "/")


def discover_identifier_routes(project_root: Path = PROJECT_ROOT) -> dict[str, dict[str, Any]]:
    discovered: dict[str, dict[str, Any]] = {}
    for namespace in MOUNT_PREFIXES:
        url_path = project_root / namespace / "urls.py"
        view_path = project_root / namespace / "views.py"
        routes = _named_routes(url_path.read_text(encoding="utf-8"), url_path.as_posix())
        functions = _view_functions(view_path.read_text(encoding="utf-8"), view_path.as_posix())
        for route_name, (route_path, view_name) in routes.items():
            if "<uuid:" not in route_path:
                continue
            identifier = f"{namespace}:{route_name}"
            function = functions.get(view_name)
            if function is None:
                _fail(f"missing routed view: {identifier}:{view_name}")
            discovered[identifier] = {
                "template": _route_template(namespace, identifier, route_path),
                "methods": _allowed_methods(function),
            }
    return discovered


def discover_boundary_probes(project_root: Path = PROJECT_ROOT) -> dict[str, dict[str, Any]]:
    relative = "deploy/pentest/run-authz-csrf.py"
    tree = ast.parse((project_root / relative).read_text(encoding="utf-8"), filename=relative)
    assignments = [
        node
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "_BOUNDARY_ROUTES"
            for target in node.targets
        )
    ]
    if len(assignments) != 1 or not isinstance(assignments[0].value, ast.Tuple):
        _fail("direct-object probe inventory is missing or dynamic")
    probes: dict[str, dict[str, Any]] = {}
    for element in assignments[0].value.elts:
        if not isinstance(element, ast.Call) or _call_name(element.func) != "BoundaryRoute":
            _fail("direct-object probe entry is dynamic")
        if len(element.args) not in {3, 4} or element.keywords:
            _fail("direct-object probe entry fields changed")
        try:
            label = ast.literal_eval(element.args[0])
            template = ast.literal_eval(element.args[1])
            foreign_keys = list(ast.literal_eval(element.args[2]))
            methods = list(ast.literal_eval(element.args[3])) if len(element.args) == 4 else ["GET"]
        except (ValueError, TypeError, SyntaxError):
            _fail("direct-object probe entry must remain static")
        if not all(isinstance(item, str) for item in (label, template, *foreign_keys, *methods)):
            _fail("direct-object probe entry contains non-text values")
        if label in probes:
            _fail(f"duplicate direct-object probe label: {label}")
        if not foreign_keys or len(foreign_keys) != len(set(foreign_keys)):
            _fail(f"invalid direct-object foreign keys: {label}")
        if methods not in (["GET"], ["POST"], ["GET", "POST"]):
            _fail(f"invalid direct-object methods: {label}")
        probes[label] = {
            "template": template,
            "foreign_keys": foreign_keys,
            "methods": methods,
        }
    return probes


def _test_functions(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return {
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith("test_")
    }


def validate_object_authorization_boundary(
    inventory: dict[str, Any],
    *,
    project_root: Path = PROJECT_ROOT,
    today: date | None = None,
) -> None:
    if set(inventory) != {
        "controls",
        "identifier_routes",
        "inventory_id",
        "last_reviewed",
        "next_review_due",
        "relationship_probes",
        "release_boundary",
        "schema_version",
        "security_test_id",
        "summary",
    }:
        _fail("object-authorization inventory fields changed")
    if inventory["schema_version"] != 1 or inventory["inventory_id"] != (
        "budgetapp-object-authorization-boundary-v1"
    ):
        _fail("unsupported object-authorization inventory identity")
    if inventory["security_test_id"] != 6:
        _fail("object-authorization inventory must remain bound to security test 6")
    reviewed = date.fromisoformat(_text(inventory["last_reviewed"], "last_reviewed"))
    due = date.fromisoformat(_text(inventory["next_review_due"], "next_review_due"))
    if due <= reviewed or (due - reviewed).days > 90:
        _fail("object-authorization review cadence exceeds 90 days")
    if (today or date.today()) > due:
        _fail("object-authorization inventory review is overdue")

    controls = inventory.get("controls")
    if not isinstance(controls, list) or any(not isinstance(item, dict) for item in controls):
        _fail("object-authorization controls must contain objects")
    observed: set[str] = set()
    test_cache: dict[str, set[str]] = {}
    for control in controls:
        if set(control) != {"evidence", "id", "objective", "repository_status", "test_refs"}:
            _fail("object-authorization control fields changed")
        identifier = _text(control["id"], "control id")
        if identifier in observed:
            _fail(f"duplicate object-authorization control: {identifier}")
        observed.add(identifier)
        _text(control["objective"], f"{identifier} objective")
        if control["repository_status"] != "implemented":
            _fail(f"object-authorization control is not implemented: {identifier}")
        for evidence in _string_list(control["evidence"], f"{identifier} evidence"):
            _safe_path(evidence, project_root=project_root, label=f"{identifier} evidence")
        for reference in _string_list(control["test_refs"], f"{identifier} test_refs"):
            try:
                relative, function = reference.split("::", maxsplit=1)
            except ValueError:
                _fail(f"invalid object-authorization test reference: {reference}")
            path = project_root / _safe_path(
                relative, project_root=project_root, label=f"{identifier} test"
            )
            functions = test_cache.setdefault(relative, _test_functions(path))
            if not relative.startswith("tests/") or function not in functions:
                _fail(f"object-authorization test reference is missing: {reference}")
    if observed != EXPECTED_CONTROL_IDS:
        _fail("object-authorization control inventory changed")

    routes = inventory.get("identifier_routes")
    if not isinstance(routes, list) or any(not isinstance(item, dict) for item in routes):
        _fail("identifier_routes must contain objects")
    documented_routes: dict[str, dict[str, Any]] = {}
    for route in routes:
        if set(route) != {"id", "methods", "template"}:
            _fail("identifier route fields changed")
        identifier = _text(route["id"], "identifier route id")
        if identifier in documented_routes:
            _fail(f"duplicate identifier route: {identifier}")
        documented_routes[identifier] = {
            "template": _text(route["template"], f"{identifier} template"),
            "methods": _string_list(route["methods"], f"{identifier} methods"),
        }
    discovered_routes = discover_identifier_routes(project_root)
    if documented_routes != discovered_routes:
        _fail("identifier route inventory changed")

    relationships = inventory.get("relationship_probes")
    if not isinstance(relationships, list) or any(
        not isinstance(item, dict) for item in relationships
    ):
        _fail("relationship_probes must contain objects")
    documented_relationships: dict[str, dict[str, Any]] = {}
    for relationship in relationships:
        if set(relationship) != {"foreign_keys", "id", "methods", "template"}:
            _fail("relationship probe fields changed")
        identifier = _text(relationship["id"], "relationship probe id")
        if identifier in documented_relationships:
            _fail(f"duplicate relationship probe: {identifier}")
        documented_relationships[identifier] = {
            "template": _text(relationship["template"], f"{identifier} template"),
            "foreign_keys": _string_list(
                relationship["foreign_keys"], f"{identifier} foreign_keys"
            ),
            "methods": _string_list(relationship["methods"], f"{identifier} methods"),
        }
    if documented_relationships != RELATIONSHIP_PROBES:
        _fail("nested relationship probe inventory changed")

    probes = discover_boundary_probes(project_root)
    relationship_labels = set(RELATIONSHIP_PROBES)
    actual_relationships = {
        label: record for label, record in probes.items() if label in relationship_labels
    }
    if actual_relationships != RELATIONSHIP_PROBES:
        _fail("nested relationship probe implementation changed")
    base_probes = {
        record["template"]: record
        for label, record in probes.items()
        if label not in relationship_labels
    }
    if len(base_probes) != len(probes) - len(relationship_labels):
        _fail("direct-object probe templates contain duplicates")
    expected_templates = {record["template"] for record in discovered_routes.values()}
    if set(base_probes) != expected_templates:
        _fail("direct-object probe route coverage changed")
    for route in discovered_routes.values():
        probe = base_probes[route["template"]]
        placeholders = re.findall(r"{([^}]+)}", route["template"])
        if probe["methods"] != route["methods"] or set(probe["foreign_keys"]) != set(placeholders):
            _fail(f"direct-object probe operation coverage changed: {route['template']}")

    release_boundary = inventory.get("release_boundary")
    if not isinstance(release_boundary, dict) or set(release_boundary) != {
        "evidence_location",
        "required_observation",
        "status",
    }:
        _fail("object-authorization release boundary fields changed")
    if release_boundary["status"] != "pending":
        _fail("object-authorization release boundary must remain pending")
    _text(release_boundary["required_observation"], "required release observation")
    _safe_path(
        release_boundary["evidence_location"],
        project_root=project_root,
        label="release evidence location",
    )

    route_operations = sum(len(route["methods"]) for route in discovered_routes.values())
    relationship_operations = sum(len(item["methods"]) for item in RELATIONSHIP_PROBES.values())
    probe_operations = route_operations + relationship_operations
    if inventory.get("summary") != {
        "identifier_routes": len(discovered_routes),
        "route_operations": route_operations,
        "relationship_operations": relationship_operations,
        "probe_operations": probe_operations,
        "household_direction_checks": probe_operations * 2,
        "recipient_checks": 2,
        "bounded_checks": probe_operations * 2 + 2,
        "release_pending": 1,
    }:
        _fail("object-authorization summary does not match the enforced boundary")

    for relative, fragments in SOURCE_CONTRACTS.items():
        source = (project_root / relative).read_text(encoding="utf-8")
        missing = [fragment for fragment in fragments if fragment not in source]
        if missing:
            _fail(f"object-authorization source contract changed in {relative}: {missing}")

    release_document = json.loads(
        (project_root / "docs/release-evidence.json").read_text(encoding="utf-8")
    )
    tests = release_document.get("security_tests")
    if not isinstance(tests, list):
        _fail("security tests are malformed")
    matching = [item for item in tests if isinstance(item, dict) and item.get("id") == 6]
    if len(matching) != 1:
        _fail("security test 6 is missing or duplicated")
    security_test = matching[0]
    if security_test.get("status") != "implemented" or not EXPECTED_SECURITY_EVIDENCE.issubset(
        set(security_test.get("evidence", []))
    ):
        _fail("security test 6 is not object-authorization ready")
    if "last_verified" in security_test:
        _fail("security test 6 must remain unverified without release-candidate evidence")

    for gate_path, fragment in (
        ("scripts/check.ps1", "scripts\\check_object_authorization_boundary.py"),
        ("scripts/check.sh", "scripts/check_object_authorization_boundary.py"),
    ):
        if fragment not in (project_root / gate_path).read_text(encoding="utf-8"):
            _fail(f"object-authorization checker is missing from {gate_path}")


def main() -> int:
    try:
        inventory = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))
        validate_object_authorization_boundary(inventory)
    except (OSError, SyntaxError, json.JSONDecodeError, ValueError) as error:
        print(f"Object-authorization validation failed: {error}", file=sys.stderr)
        return 1
    summary = inventory["summary"]
    print(
        "Object-authorization inventory passed: "
        f"{summary['identifier_routes']} identifier routes, "
        f"{summary['bounded_checks']} bounded checks, release observation pending."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
