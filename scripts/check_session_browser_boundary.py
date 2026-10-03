"""Validate the session-cookie and browser-state inventory."""

from __future__ import annotations

import ast
import json
import re
import sys
from datetime import date
from pathlib import Path
from typing import Any, NoReturn

PROJECT_ROOT = Path(__file__).resolve().parents[1]
INVENTORY_PATH = PROJECT_ROOT / "docs" / "session-browser-boundary.json"

EXPECTED_CONTROL_IDS = {
    "authenticated-cache-prevention",
    "browser-session-lifetime",
    "hardened-cookie-profile",
    "multi-engine-browser-gate",
    "real-http-session-probe",
    "script-readable-storage-minimization",
    "termination-client-state-cleanup",
}
EXPECTED_SECURITY_EVIDENCE = {
    ".github/workflows/browser.yml",
    "browser-tests/auth.setup.mjs",
    "browser-tests/security-accessibility.spec.mjs",
    "browser-tests/session-lifecycle.spec.mjs",
    "config/settings/hardened.py",
    "core/middleware.py",
    "core/static/core/app.js",
    "core/static/core/passkeys.js",
    "deploy/pentest/run-session-security.py",
    "docs/SESSION_SECURITY.md",
    "docs/session-browser-boundary.json",
    "scripts/check_session_browser_boundary.py",
    "tests/test_browser_harness.py",
    "tests/test_session_browser_boundary.py",
}
SOURCE_CONTRACTS = {
    "config/settings/base.py": (
        "SESSION_COOKIE_HTTPONLY = True",
        'SESSION_COOKIE_SAMESITE = "Strict"',
        "CSRF_COOKIE_HTTPONLY = True",
        'CSRF_COOKIE_SAMESITE = "Strict"',
        "SESSION_COOKIE_AGE = 60 * 60 * 12",
    ),
    "config/settings/hardened.py": (
        'SESSION_COOKIE_NAME = "__Host-budget_sessionid"',
        "SESSION_COOKIE_SECURE = True",
        "SESSION_EXPIRE_AT_BROWSER_CLOSE = True",
        "SESSION_COOKIE_DOMAIN = None",
        'SESSION_COOKIE_PATH = "/"',
        'CSRF_COOKIE_NAME = "__Host-budget_csrftoken"',
        "CSRF_COOKIE_SECURE = True",
        "CSRF_COOKIE_DOMAIN = None",
        'CSRF_COOKIE_PATH = "/"',
    ),
    "core/middleware.py": (
        'response.headers["Cache-Control"] = "no-store, private"',
        'response.headers["Pragma"] = "no-cache"',
    ),
    "identity/middleware.py": (
        'response.headers["Clear-Site-Data"] = _CLEAR_SITE_DATA',
        "if request.is_secure():",
    ),
    "core/static/core/app.js": (
        'const storageKey = "household-budget-theme";',
        "window.localStorage.setItem(storageKey, root.dataset.theme);",
        "for (const storage of [window.localStorage, window.sessionStorage])",
        "window.caches.delete(key)",
        "window.indexedDB.deleteDatabase(database.name)",
        'form.addEventListener("submit"',
        "document.body.replaceChildren(shell);",
    ),
    "deploy/pentest/run-session-security.py": (
        'cookie.path != "/"',
        "cookie.domain_specified",
        'cookie.has_nonstandard_attr("HttpOnly")',
        'cookie.get_nonstandard_attr("SameSite") != "Strict"',
        "not session_cookie.discard",
        'response.cache_control != "no-store, private"',
        'print(f"SESS-05 automated checks passed',
    ),
    "browser-tests/auth.setup.mjs": (
        "sessionCookie?.httpOnly).toBe(true)",
        'sessionCookie?.sameSite).toBe("Strict")',
        "sessionCookie?.expires).toBe(-1)",
    ),
    "browser-tests/security-accessibility.spec.mjs": (
        'headers["cache-control"]).toBe("no-store, private")',
        "Object.keys(window.localStorage)",
        "Object.keys(window.sessionStorage)",
        "expect(browserStorage.localKeys).toEqual([])",
        "expect(browserStorage.sessionKeys).toEqual([])",
    ),
    "browser-tests/session-lifecycle.spec.mjs": (
        'window.localStorage.setItem("private-local-state", "sensitive")',
        'window.sessionStorage.setItem("private-session-state", "sensitive")',
        "page.goBack()",
        "browser.newContext(",
        "toEqual({ local: [], session: [], caches: [], databases: [] })",
    ),
    ".github/workflows/browser.yml": (
        "pull_request:",
        "permissions:\n  contents: read",
        "persist-credentials: false",
        "sh scripts/run-browser-tests.sh",
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


def _test_functions(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return {
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith("test_")
    }


def validate_session_browser_boundary(
    inventory: dict[str, Any],
    *,
    project_root: Path = PROJECT_ROOT,
    today: date | None = None,
) -> None:
    if set(inventory) != {
        "controls",
        "inventory_id",
        "last_reviewed",
        "next_review_due",
        "release_boundary",
        "schema_version",
        "security_test_id",
        "summary",
    }:
        _fail("session-browser inventory fields changed")
    if inventory["schema_version"] != 1 or inventory["inventory_id"] != (
        "budgetapp-session-browser-boundary-v1"
    ):
        _fail("unsupported session-browser inventory identity")
    if inventory["security_test_id"] != 4:
        _fail("session-browser inventory must remain bound to security test 4")
    reviewed = date.fromisoformat(_text(inventory["last_reviewed"], "last_reviewed"))
    due = date.fromisoformat(_text(inventory["next_review_due"], "next_review_due"))
    if due <= reviewed or (due - reviewed).days > 90:
        _fail("session-browser review cadence exceeds 90 days")
    if (today or date.today()) > due:
        _fail("session-browser inventory review is overdue")

    controls = inventory.get("controls")
    if not isinstance(controls, list) or any(not isinstance(item, dict) for item in controls):
        _fail("session-browser controls must contain objects")
    observed: set[str] = set()
    test_cache: dict[str, set[str]] = {}
    for control in controls:
        if set(control) != {
            "evidence",
            "id",
            "objective",
            "repository_status",
            "test_refs",
        }:
            _fail("session-browser control fields changed")
        identifier = _text(control["id"], "control id")
        if identifier in observed:
            _fail(f"duplicate session-browser control: {identifier}")
        observed.add(identifier)
        _text(control["objective"], f"{identifier} objective")
        if control["repository_status"] != "implemented":
            _fail(f"session-browser control is not implemented: {identifier}")
        for evidence in _string_list(control["evidence"], f"{identifier} evidence"):
            _safe_path(evidence, project_root=project_root, label=f"{identifier} evidence")
        for reference in _string_list(control["test_refs"], f"{identifier} test_refs"):
            try:
                relative, function = reference.split("::", maxsplit=1)
            except ValueError:
                _fail(f"invalid session-browser test reference: {reference}")
            if not relative.startswith("tests/") or not function.startswith("test_"):
                _fail(f"invalid session-browser test reference: {reference}")
            path = project_root / _safe_path(
                relative, project_root=project_root, label=f"{identifier} test"
            )
            functions = test_cache.setdefault(relative, _test_functions(path))
            if function not in functions:
                _fail(f"session-browser test reference is missing: {reference}")
    if observed != EXPECTED_CONTROL_IDS:
        _fail("session-browser control inventory changed")

    release_boundary = inventory.get("release_boundary")
    if not isinstance(release_boundary, dict) or set(release_boundary) != {
        "evidence_location",
        "required_observation",
        "status",
    }:
        _fail("session-browser release boundary fields changed")
    if release_boundary["status"] != "pending":
        _fail("session-browser release boundary must remain pending")
    _text(release_boundary["required_observation"], "required release observation")
    _safe_path(
        release_boundary["evidence_location"],
        project_root=project_root,
        label="release evidence location",
    )
    if inventory.get("summary") != {
        "controls": len(EXPECTED_CONTROL_IDS),
        "repository_implemented": len(EXPECTED_CONTROL_IDS),
        "release_pending": 1,
    }:
        _fail("session-browser summary does not match its controls")

    for relative, fragments in SOURCE_CONTRACTS.items():
        source = (project_root / relative).read_text(encoding="utf-8")
        missing = [fragment for fragment in fragments if fragment not in source]
        if missing:
            _fail(f"session-browser source contract changed in {relative}: {missing}")

    runtime_javascript = {
        path.relative_to(project_root).as_posix() for path in project_root.glob("*/static/**/*.js")
    }
    if runtime_javascript != {"core/static/core/app.js", "core/static/core/passkeys.js"}:
        _fail("runtime JavaScript inventory changed; review browser-storage behavior")
    app_javascript = (project_root / "core/static/core/app.js").read_text(encoding="utf-8")
    storage_writes = re.findall(
        r"(?:localStorage|sessionStorage)\.setItem\(([^\n]+)\)", app_javascript
    )
    if storage_writes != ["storageKey, root.dataset.theme"]:
        _fail("script-readable storage writes changed")

    release_document = json.loads(
        (project_root / "docs/release-evidence.json").read_text(encoding="utf-8")
    )
    tests = release_document.get("security_tests")
    if not isinstance(tests, list):
        _fail("security tests are malformed")
    matching = [item for item in tests if isinstance(item, dict) and item.get("id") == 4]
    if len(matching) != 1:
        _fail("security test 4 is missing or duplicated")
    security_test = matching[0]
    if security_test.get("status") != "implemented" or not EXPECTED_SECURITY_EVIDENCE.issubset(
        set(security_test.get("evidence", []))
    ):
        _fail("security test 4 is not session-browser ready")
    if "last_verified" in security_test:
        _fail("security test 4 must remain unverified without release-browser evidence")

    for gate_path, fragment in (
        ("scripts/check.ps1", "scripts\\check_session_browser_boundary.py"),
        ("scripts/check.sh", "scripts/check_session_browser_boundary.py"),
    ):
        if fragment not in (project_root / gate_path).read_text(encoding="utf-8"):
            _fail(f"session-browser checker is missing from {gate_path}")


def main() -> int:
    try:
        inventory = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))
        validate_session_browser_boundary(inventory)
    except (OSError, SyntaxError, json.JSONDecodeError, ValueError) as error:
        print(f"Session-browser validation failed: {error}", file=sys.stderr)
        return 1
    print(
        "Session-browser inventory passed: "
        f"{len(EXPECTED_CONTROL_IDS)} controls, release-browser observation pending."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
