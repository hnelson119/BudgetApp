"""Validate exhaustive CSRF coverage for every state-changing browser route."""

from __future__ import annotations

import ast
import json
import re
import sys
from datetime import date
from pathlib import Path
from typing import Any, NoReturn

PROJECT_ROOT = Path(__file__).resolve().parents[1]
INVENTORY_PATH = PROJECT_ROOT / "docs" / "csrf-boundary.json"
RANDOM_UUID = "00000000-0000-4000-8000-000000000001"

MOUNT_PREFIXES = {
    "audit": "/audit/",
    "budgets": "/budget/",
    "core": "/",
    "debts": "/debts/",
    "goals": "/goals/",
    "identity": "/accounts/",
    "imports": "/imports/",
    "notifications": "/notifications/",
    "spending": "/spending/",
}
STRING_SEGMENTS = {
    "debts:status": {"action": "archive"},
    "goals:status": {"status": "paused"},
}
EXPECTED_CONTROL_IDS = {
    "cross-session-token-rejection",
    "exhaustive-mutation-route-inventory",
    "invariant-preserving-real-http-gate",
    "middleware-and-origin-enforcement",
    "missing-and-invalid-token-rejection",
    "same-origin-token-rendering",
    "unsafe-origin-rejection",
}
EXPECTED_SECURITY_EVIDENCE = {
    "config/urls.py",
    "config/settings/base.py",
    "config/settings/production.py",
    "deploy/pentest/run-authz-csrf.py",
    "docs/authorization-policy.json",
    "docs/csrf-boundary.json",
    "scripts/check_csrf_boundary.py",
    "scripts/run-authz-csrf.sh",
    "tests/test_authorization_policy.py",
    "tests/test_admin_security.py",
    "tests/test_csrf_boundary.py",
    "tests/test_pentest_harness.py",
}
SOURCE_CONTRACTS = {
    "config/urls.py": ('path("admin/", admin.site.urls)',),
    "config/settings/base.py": (
        '"django.middleware.csrf.CsrfViewMiddleware"',
        "CSRF_COOKIE_HTTPONLY = True",
        'CSRF_COOKIE_SAMESITE = "Strict"',
    ),
    "config/settings/production.py": (
        'CSRF_TRUSTED_ORIGINS != [f"https://{ALLOWED_HOSTS[0]}"]',
        "Production CSRF origins must contain only the exact Tailscale HTTPS origin.",
    ),
    "deploy/pentest/run-authz-csrf.py": (
        '("missing", {}, "", _BASE_URL)',
        '("invalid", {"csrfmiddlewaretoken": "A" * 32}, "", _BASE_URL)',
        '{"csrfmiddlewaretoken": other_session.csrf}',
        '"http://attacker.invalid"',
        "if response.status != 403:",
        "if _critical_counts() != before:",
        'print(f"AUTHZ-04 automated checks passed',
    ),
    "scripts/run-authz-csrf.sh": (
        'project_name="budgetapp-authz-csrf"',
        "trap cleanup EXIT INT TERM",
        "run --rm --no-deps pentest-authz-csrf",
        "--volumes --remove-orphans",
    ),
    "scripts/run-authz-csrf.ps1": (
        '$projectName = "budgetapp-authz-csrf"',
        "finally",
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


def _string_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or not value:
        _fail(f"{label} must be a non-empty list")
    items = [_text(item, f"{label} item") for item in value]
    if len(items) != len(set(items)):
        _fail(f"{label} contains duplicates")
    return items


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_call_name(node.value)}.{node.attr}".strip(".")
    if isinstance(node, ast.Call):
        return _call_name(node.func)
    return ""


def _named_routes(source: str, relative_path: str) -> dict[str, tuple[str, str]]:
    tree = ast.parse(source, filename=relative_path)
    routes: dict[str, tuple[str, str]] = {}
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
        if route_name is None or not isinstance(node.args[0], ast.Constant):
            continue
        route_path = node.args[0].value
        view = node.args[1]
        view_name = (
            view.attr
            if isinstance(view, ast.Attribute)
            and isinstance(view.value, ast.Name)
            and view.value.id == "views"
            else None
        )
        if not isinstance(route_path, str) or view_name is None:
            continue
        if route_name in routes:
            _fail(f"duplicate route name in {relative_path}: {route_name}")
        routes[route_name] = (route_path, view_name)
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


def _accepts_post(function: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for decorator in function.decorator_list:
        if _call_name(decorator).split(".")[-1] == "require_POST":
            return True
        if isinstance(decorator, ast.Call) and _call_name(decorator.func).split(".")[-1] == (
            "require_http_methods"
        ):
            if not decorator.args:
                _fail(f"{function.name} has an unreadable require_http_methods decorator")
            try:
                methods = ast.literal_eval(decorator.args[0])
            except (ValueError, TypeError, SyntaxError):
                _fail(f"{function.name} has a dynamic require_http_methods decorator")
            return "POST" in methods
    return any(
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "request"
        and node.attr == "POST"
        for node in ast.walk(function)
    )


def _probe_path(namespace: str, route_name: str, route_path: str) -> str:
    identifier = f"{namespace}:{route_name}"
    string_values = STRING_SEGMENTS.get(identifier, {})

    def replace(match: re.Match[str]) -> str:
        converter, name = match.groups()
        if converter == "uuid":
            return RANDOM_UUID
        if converter == "str" and name in string_values:
            return string_values[name]
        _fail(f"mutation route needs an explicit probe segment: {identifier}:{converter}:{name}")

    concrete = re.sub(r"<([^:>]+):([^>]+)>", replace, route_path)
    return f"{MOUNT_PREFIXES[namespace]}{concrete}".replace("//", "/")


def discover_mutation_routes(project_root: Path = PROJECT_ROOT) -> dict[str, str]:
    discovered: dict[str, str] = {}
    for namespace, prefix in MOUNT_PREFIXES.items():
        del prefix
        url_path = project_root / namespace / "urls.py"
        view_path = project_root / namespace / "views.py"
        routes = _named_routes(url_path.read_text(encoding="utf-8"), url_path.as_posix())
        functions = _view_functions(view_path.read_text(encoding="utf-8"), view_path.as_posix())
        for route_name, (route_path, view_name) in routes.items():
            function = functions.get(view_name)
            if function is None:
                _fail(f"missing routed view: {namespace}:{route_name}:{view_name}")
            if _accepts_post(function):
                identifier = f"{namespace}:{route_name}"
                discovered[identifier] = _probe_path(namespace, route_name, route_path)
    return discovered


def _evaluated_string(node: ast.AST, names: dict[str, str]) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name) and node.id in names:
        return names[node.id]
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            elif isinstance(value, ast.FormattedValue):
                parts.append(_evaluated_string(value.value, names))
            else:
                _fail("CSRF probe path contains an unsupported expression")
        return "".join(parts)
    _fail("CSRF probe path must be static")


def discover_probe_paths(project_root: Path = PROJECT_ROOT) -> tuple[str, ...]:
    relative = "deploy/pentest/run-authz-csrf.py"
    tree = ast.parse((project_root / relative).read_text(encoding="utf-8"), filename=relative)
    functions = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_csrf_paths"
    ]
    if len(functions) != 1:
        _fail("CSRF probe path function is missing or duplicated")
    returns = [node for node in ast.walk(functions[0]) if isinstance(node, ast.Return)]
    if len(returns) != 1 or not isinstance(returns[0].value, (ast.Tuple, ast.List)):
        _fail("CSRF probe paths must be one static sequence")
    paths = tuple(
        _evaluated_string(node, {"object_id": RANDOM_UUID}) for node in returns[0].value.elts
    )
    if len(paths) != len(set(paths)):
        _fail("CSRF probe paths contain duplicates")
    return paths


def _test_functions(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return {
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith("test_")
    }


def _validate_template_tokens(project_root: Path) -> int:
    forms = 0
    for path in project_root.glob("*/templates/**/*.html"):
        source = path.read_text(encoding="utf-8")
        for match in re.finditer(
            r"<form\b[^>]*\bmethod=[\"']post[\"'][^>]*>(.*?)</form>",
            source,
            flags=re.IGNORECASE | re.DOTALL,
        ):
            forms += 1
            if "{% csrf_token %}" not in match.group(1):
                _fail(f"POST form lacks a CSRF token: {path.relative_to(project_root).as_posix()}")
    if forms == 0:
        _fail("no POST forms were discovered")
    return forms


def validate_csrf_boundary(
    inventory: dict[str, Any],
    *,
    project_root: Path = PROJECT_ROOT,
    today: date | None = None,
) -> None:
    if set(inventory) != {
        "controls",
        "inventory_id",
        "last_reviewed",
        "mutation_routes",
        "next_review_due",
        "release_boundary",
        "schema_version",
        "security_test_id",
        "summary",
    }:
        _fail("CSRF inventory fields changed")
    if inventory["schema_version"] != 1 or inventory["inventory_id"] != (
        "budgetapp-csrf-boundary-v1"
    ):
        _fail("unsupported CSRF inventory identity")
    if inventory["security_test_id"] != 5:
        _fail("CSRF inventory must remain bound to security test 5")
    reviewed = date.fromisoformat(_text(inventory["last_reviewed"], "last_reviewed"))
    due = date.fromisoformat(_text(inventory["next_review_due"], "next_review_due"))
    if due <= reviewed or (due - reviewed).days > 90:
        _fail("CSRF review cadence exceeds 90 days")
    if (today or date.today()) > due:
        _fail("CSRF inventory review is overdue")

    controls = inventory.get("controls")
    if not isinstance(controls, list) or any(not isinstance(item, dict) for item in controls):
        _fail("CSRF controls must contain objects")
    observed: set[str] = set()
    test_cache: dict[str, set[str]] = {}
    for control in controls:
        if set(control) != {"evidence", "id", "objective", "repository_status", "test_refs"}:
            _fail("CSRF control fields changed")
        identifier = _text(control["id"], "control id")
        if identifier in observed:
            _fail(f"duplicate CSRF control: {identifier}")
        observed.add(identifier)
        _text(control["objective"], f"{identifier} objective")
        if control["repository_status"] != "implemented":
            _fail(f"CSRF control is not implemented: {identifier}")
        for evidence in _string_list(control["evidence"], f"{identifier} evidence"):
            _safe_path(evidence, project_root=project_root, label=f"{identifier} evidence")
        for reference in _string_list(control["test_refs"], f"{identifier} test_refs"):
            try:
                relative, function = reference.split("::", maxsplit=1)
            except ValueError:
                _fail(f"invalid CSRF test reference: {reference}")
            path = project_root / _safe_path(
                relative, project_root=project_root, label=f"{identifier} test"
            )
            functions = test_cache.setdefault(relative, _test_functions(path))
            if not relative.startswith("tests/") or function not in functions:
                _fail(f"CSRF test reference is missing: {reference}")
    if observed != EXPECTED_CONTROL_IDS:
        _fail("CSRF control inventory changed")

    routes = inventory.get("mutation_routes")
    if not isinstance(routes, list) or any(not isinstance(item, dict) for item in routes):
        _fail("CSRF mutation routes must contain objects")
    documented: dict[str, str] = {}
    for route in routes:
        if set(route) != {"id", "probe_path"}:
            _fail("CSRF mutation route fields changed")
        identifier = _text(route["id"], "mutation route id")
        probe_path = _text(route["probe_path"], f"{identifier} probe path")
        if identifier in documented:
            _fail(f"duplicate CSRF mutation route: {identifier}")
        documented[identifier] = probe_path
    discovered = discover_mutation_routes(project_root)
    if documented != discovered:
        _fail("CSRF mutation route inventory changed")
    probe_paths = set(discover_probe_paths(project_root))
    expected_probe_paths = set(discovered.values()) | {"/admin/login/?next=/admin/"}
    if probe_paths != expected_probe_paths:
        _fail("CSRF real-HTTP probe coverage changed")

    template_forms = _validate_template_tokens(project_root)
    for namespace in MOUNT_PREFIXES:
        for path in (project_root / namespace).rglob("*.py"):
            if "csrf_exempt" in path.read_text(encoding="utf-8"):
                _fail(f"CSRF exemption is forbidden: {path.relative_to(project_root).as_posix()}")

    release_boundary = inventory.get("release_boundary")
    if not isinstance(release_boundary, dict) or set(release_boundary) != {
        "evidence_location",
        "required_observation",
        "status",
    }:
        _fail("CSRF release boundary fields changed")
    if release_boundary["status"] != "pending":
        _fail("CSRF release boundary must remain pending")
    _text(release_boundary["required_observation"], "required release observation")
    _safe_path(
        release_boundary["evidence_location"],
        project_root=project_root,
        label="release evidence location",
    )
    if inventory.get("summary") != {
        "mutation_routes": len(discovered),
        "probe_paths": len(expected_probe_paths),
        "attack_variants": 4,
        "bounded_checks": len(expected_probe_paths) * 4,
        "post_forms": template_forms,
        "release_pending": 1,
    }:
        _fail("CSRF summary does not match the enforced boundary")

    for relative, fragments in SOURCE_CONTRACTS.items():
        source = (project_root / relative).read_text(encoding="utf-8")
        missing = [fragment for fragment in fragments if fragment not in source]
        if missing:
            _fail(f"CSRF source contract changed in {relative}: {missing}")

    release_document = json.loads(
        (project_root / "docs/release-evidence.json").read_text(encoding="utf-8")
    )
    tests = release_document.get("security_tests")
    if not isinstance(tests, list):
        _fail("security tests are malformed")
    matching = [item for item in tests if isinstance(item, dict) and item.get("id") == 5]
    if len(matching) != 1:
        _fail("security test 5 is missing or duplicated")
    security_test = matching[0]
    if security_test.get("status") != "implemented" or not EXPECTED_SECURITY_EVIDENCE.issubset(
        set(security_test.get("evidence", []))
    ):
        _fail("security test 5 is not CSRF ready")
    if "last_verified" in security_test:
        _fail("security test 5 must remain unverified without release-candidate evidence")

    for gate_path, fragment in (
        ("scripts/check.ps1", "scripts\\check_csrf_boundary.py"),
        ("scripts/check.sh", "scripts/check_csrf_boundary.py"),
    ):
        if fragment not in (project_root / gate_path).read_text(encoding="utf-8"):
            _fail(f"CSRF checker is missing from {gate_path}")


def main() -> int:
    try:
        inventory = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))
        validate_csrf_boundary(inventory)
    except (OSError, SyntaxError, json.JSONDecodeError, ValueError) as error:
        print(f"CSRF-boundary validation failed: {error}", file=sys.stderr)
        return 1
    summary = inventory["summary"]
    print(
        "CSRF inventory passed: "
        f"{summary['mutation_routes']} mutation routes, "
        f"{summary['bounded_checks']} bounded attack checks, release observation pending."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
