"""Validate the HTTP exposure inventory and security-test wiring."""

from __future__ import annotations

import ast
import json
import sys
from datetime import date
from pathlib import Path
from typing import Any, NoReturn

PROJECT_ROOT = Path(__file__).resolve().parents[1]
INVENTORY_PATH = PROJECT_ROOT / "docs" / "http-exposure-boundary.json"

EXPECTED_CONTROL_IDS = {
    "deployed-plain-http-boundary",
    "encrypted-internal-upstream",
    "exact-private-origin",
    "insecure-browser-redirect",
    "insecure-nonbrowser-rejection",
    "loopback-only-edge",
    "repeatable-boundary-gates",
}
EXPECTED_SECURITY_EVIDENCE = {
    ".github/workflows/http-framing.yml",
    "config/settings/production.py",
    "deploy/network/run-production-boundary.py",
    "deploy/network/verify-private-ingress.py",
    "docs/PRIVATE_INGRESS.md",
    "docs/http-exposure-boundary.json",
    "scripts/check_http_exposure_boundary.py",
    "tests/test_http_exposure_boundary.py",
    "tests/test_network_boundary.py",
}
SOURCE_CONTRACTS = {
    "config/settings/production.py": (
        "Production requires one exact lowercase Tailscale HTTPS hostname.",
        'CSRF_TRUSTED_ORIGINS != [f"https://{ALLOWED_HOSTS[0]}"]',
        "Production does not permit external redirect destinations.",
        "NonBrowserTransportBoundaryMiddleware",
    ),
    "deploy/network/nginx.conf": (
        "listen 8000;",
        "proxy_pass https://web:8443;",
        "proxy_ssl_verify on;",
        'proxy_set_header X-Forwarded-For "";',
        "proxy_set_header X-Forwarded-Proto $upstream_forwarded_proto;",
    ),
    "deploy/network/run-production-boundary.py": (
        '!= ("127.0.0.1", "8000", 8000, "tcp")',
        "The web service unexpectedly publishes a host port.",
        "The browser-page HTTPS redirect unexpectedly returned content.",
        "A non-browser endpoint transparently redirected an insecure request.",
        "NET-03 pre-deployment controls passed",
    ),
    "deploy/network/verify-private-ingress.py": (
        '"/": {"Proxy": "http://127.0.0.1:8000"}',
        "Public Funnel exposure is enabled.",
        "Plain HTTP served content instead of an exact HTTPS redirect.",
        "The application port is listening beyond IPv4 loopback.",
        "NET-03 deployment controls passed",
    ),
    ".github/workflows/http-framing.yml": (
        "pull_request:",
        "permissions:\n  contents: read",
        "persist-credentials: false",
        "sh scripts/run-network-boundary.sh",
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


def validate_http_exposure_boundary(
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
        _fail("HTTP-exposure inventory fields changed")
    if inventory["schema_version"] != 1 or inventory["inventory_id"] != (
        "budgetapp-http-exposure-boundary-v1"
    ):
        _fail("unsupported HTTP-exposure inventory identity")
    if inventory["security_test_id"] != 3:
        _fail("HTTP-exposure inventory must remain bound to security test 3")
    reviewed = date.fromisoformat(_text(inventory["last_reviewed"], "last_reviewed"))
    due = date.fromisoformat(_text(inventory["next_review_due"], "next_review_due"))
    if due <= reviewed or (due - reviewed).days > 90:
        _fail("HTTP-exposure review cadence exceeds 90 days")
    if (today or date.today()) > due:
        _fail("HTTP-exposure inventory review is overdue")

    controls = inventory.get("controls")
    if not isinstance(controls, list) or any(not isinstance(item, dict) for item in controls):
        _fail("HTTP-exposure controls must contain objects")
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
            _fail("HTTP-exposure control fields changed")
        identifier = _text(control["id"], "control id")
        if identifier in observed:
            _fail(f"duplicate HTTP-exposure control: {identifier}")
        observed.add(identifier)
        _text(control["objective"], f"{identifier} objective")
        if control["repository_status"] != "implemented":
            _fail(f"HTTP-exposure control is not implemented: {identifier}")
        for evidence in _string_list(control["evidence"], f"{identifier} evidence"):
            _safe_path(evidence, project_root=project_root, label=f"{identifier} evidence")
        for reference in _string_list(control["test_refs"], f"{identifier} test_refs"):
            try:
                relative, function = reference.split("::", maxsplit=1)
            except ValueError:
                _fail(f"invalid HTTP-exposure test reference: {reference}")
            if not relative.startswith("tests/") or not function.startswith("test_"):
                _fail(f"invalid HTTP-exposure test reference: {reference}")
            path = project_root / _safe_path(
                relative, project_root=project_root, label=f"{identifier} test"
            )
            functions = test_cache.setdefault(relative, _test_functions(path))
            if function not in functions:
                _fail(f"HTTP-exposure test reference is missing: {reference}")
    if observed != EXPECTED_CONTROL_IDS:
        _fail("HTTP-exposure control inventory changed")

    release_boundary = inventory.get("release_boundary")
    if not isinstance(release_boundary, dict) or set(release_boundary) != {
        "evidence_location",
        "required_observation",
        "status",
    }:
        _fail("HTTP-exposure release boundary fields changed")
    if release_boundary["status"] != "pending":
        _fail("HTTP-exposure release boundary must remain pending")
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
        _fail("HTTP-exposure summary does not match its controls")

    for relative, fragments in SOURCE_CONTRACTS.items():
        source = (project_root / relative).read_text(encoding="utf-8")
        missing = [fragment for fragment in fragments if fragment not in source]
        if missing:
            _fail(f"HTTP-exposure source contract changed in {relative}: {missing}")

    release_document = json.loads(
        (project_root / "docs/release-evidence.json").read_text(encoding="utf-8")
    )
    tests = release_document.get("security_tests")
    if not isinstance(tests, list):
        _fail("security tests are malformed")
    matching = [item for item in tests if isinstance(item, dict) and item.get("id") == 3]
    if len(matching) != 1:
        _fail("security test 3 is missing or duplicated")
    security_test = matching[0]
    if security_test.get("status") != "implemented" or not EXPECTED_SECURITY_EVIDENCE.issubset(
        set(security_test.get("evidence", []))
    ):
        _fail("security test 3 is not HTTP-exposure ready")
    if "last_verified" in security_test:
        _fail("security test 3 must remain unverified without deployed evidence")

    for gate_path, fragment in (
        ("scripts/check.ps1", "scripts\\check_http_exposure_boundary.py"),
        ("scripts/check.sh", "scripts/check_http_exposure_boundary.py"),
    ):
        if fragment not in (project_root / gate_path).read_text(encoding="utf-8"):
            _fail(f"HTTP-exposure checker is missing from {gate_path}")


def main() -> int:
    try:
        inventory = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))
        validate_http_exposure_boundary(inventory)
    except (OSError, SyntaxError, json.JSONDecodeError, ValueError) as error:
        print(f"HTTP-exposure validation failed: {error}", file=sys.stderr)
        return 1
    print(
        "HTTP-exposure inventory passed: "
        f"{len(EXPECTED_CONTROL_IDS)} controls, deployed observation pending."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
