"""Validate the exhaustive product-criteria inventory and release-gate wiring."""

from __future__ import annotations

import ast
import json
import re
import sys
from datetime import date
from pathlib import Path
from typing import Any, NoReturn

PROJECT_ROOT = Path(__file__).resolve().parents[1]
INVENTORY_PATH = PROJECT_ROOT / "docs" / "product-criteria.json"
SOURCE_PATH = PROJECT_ROOT / "PRODUCT_SPEC.md"

EXPECTED_IDS = set(range(1, 40))
EXPECTED_RELEASE_OBSERVATION_IDS = {17, 18, 19, 26, 28, 29, 30, 39}
EXPECTED_GATE_EVIDENCE = {
    "PRODUCT_SPEC.md",
    "docs/product-criteria.json",
    "scripts/check_product_criteria.py",
    "tests/test_product_criteria.py",
}
_CRITERION = re.compile(r"^(\d+)\. (.+)$", re.MULTILINE)
_TEST_REF = re.compile(r"^(tests/[a-z0-9_]+\.py)::(test_[a-zA-Z0-9_]+)$")


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


def product_criteria(source: str) -> dict[int, str]:
    try:
        section = source.split("## 23. Critical acceptance criteria", maxsplit=1)[1].split(
            "## 24. Design references", maxsplit=1
        )[0]
    except IndexError:
        _fail("PRODUCT_SPEC critical-criteria section changed")
    matches = _CRITERION.findall(section)
    criteria = {int(identifier): text for identifier, text in matches}
    if len(matches) != len(EXPECTED_IDS) or set(criteria) != EXPECTED_IDS:
        _fail("PRODUCT_SPEC critical criteria are incomplete or renumbered")
    return criteria


def _test_functions(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return {
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith("test_")
    }


def validate_product_criteria(
    inventory: dict[str, Any],
    *,
    project_root: Path = PROJECT_ROOT,
    today: date | None = None,
) -> None:
    if set(inventory) != {
        "criteria",
        "inventory_id",
        "last_reviewed",
        "next_review_due",
        "release_observation_ids",
        "schema_version",
        "source",
        "summary",
    }:
        _fail("product-criteria inventory fields changed")
    if inventory["schema_version"] != 1 or inventory["inventory_id"] != (
        "budgetapp-product-criteria-v1"
    ):
        _fail("unsupported product-criteria inventory identity")
    reviewed = date.fromisoformat(_text(inventory["last_reviewed"], "last_reviewed"))
    due = date.fromisoformat(_text(inventory["next_review_due"], "next_review_due"))
    if due <= reviewed or (due - reviewed).days > 90:
        _fail("product-criteria review cadence exceeds 90 days")
    if (today or date.today()) > due:
        _fail("product-criteria inventory review is overdue")
    if inventory["source"] != "PRODUCT_SPEC.md#23-critical-acceptance-criteria":
        _fail("product-criteria source changed")

    source_criteria = product_criteria(
        (project_root / "PRODUCT_SPEC.md").read_text(encoding="utf-8")
    )
    criteria = inventory.get("criteria")
    if not isinstance(criteria, list) or any(not isinstance(item, dict) for item in criteria):
        _fail("product criteria must contain objects")
    observed_ids: set[int] = set()
    observed_order: list[int] = []
    observed_release_ids: set[int] = set()
    test_cache: dict[str, set[str]] = {}
    expected_fields = {
        "criterion",
        "evidence",
        "id",
        "release_observation_required",
        "repository_status",
        "test_refs",
    }
    for item in criteria:
        if set(item) != expected_fields:
            _fail("product-criterion fields changed")
        identifier = item["id"]
        if not isinstance(identifier, int) or identifier in observed_ids:
            _fail(f"invalid or duplicate product criterion: {identifier!r}")
        observed_ids.add(identifier)
        observed_order.append(identifier)
        if item["criterion"] != source_criteria.get(identifier):
            _fail(f"product criterion {identifier} differs from PRODUCT_SPEC")
        if item["repository_status"] != "implemented":
            _fail(f"product criterion {identifier} is not repository implemented")
        release_required = item["release_observation_required"]
        if not isinstance(release_required, bool):
            _fail(f"product criterion {identifier} has an invalid release boundary")
        if release_required:
            observed_release_ids.add(identifier)

        for evidence in _string_list(item["evidence"], f"criterion {identifier} evidence"):
            _safe_path(
                evidence, project_root=project_root, label=f"criterion {identifier} evidence"
            )
        for reference in _string_list(item["test_refs"], f"criterion {identifier} test_refs"):
            match = _TEST_REF.fullmatch(reference)
            if match is None:
                _fail(f"criterion {identifier} has invalid test reference {reference!r}")
            relative, function = match.groups()
            path = project_root / relative
            _safe_path(relative, project_root=project_root, label=f"criterion {identifier} test")
            functions = test_cache.setdefault(relative, _test_functions(path))
            if function not in functions:
                _fail(f"criterion {identifier} references missing test {reference!r}")
    if observed_ids != EXPECTED_IDS or observed_order != list(range(1, 40)):
        _fail("product-criteria inventory is incomplete")
    if observed_release_ids != EXPECTED_RELEASE_OBSERVATION_IDS:
        _fail("product-criteria release-observation boundary changed")
    if inventory.get("release_observation_ids") != sorted(EXPECTED_RELEASE_OBSERVATION_IDS):
        _fail("product-criteria release-observation summary changed")

    expected_summary = {
        "criteria": len(EXPECTED_IDS),
        "repository_implemented": len(EXPECTED_IDS),
        "release_observation_required": len(EXPECTED_RELEASE_OBSERVATION_IDS),
    }
    if inventory.get("summary") != expected_summary:
        _fail("product-criteria summary does not match its entries")

    release_document = json.loads(
        (project_root / "docs/release-evidence.json").read_text(encoding="utf-8")
    )
    gates = release_document.get("release_gates")
    if not isinstance(gates, list):
        _fail("release gates are malformed")
    matching = [item for item in gates if isinstance(item, dict) and item.get("id") == 1]
    if len(matching) != 1:
        _fail("release gate 1 is missing or duplicated")
    gate = matching[0]
    if gate.get("status") != "implemented" or not EXPECTED_GATE_EVIDENCE.issubset(
        set(gate.get("evidence", []))
    ):
        _fail("release gate 1 is not product-criteria ready")
    if "last_verified" in gate:
        _fail("release gate 1 must remain unverified without release-candidate evidence")

    for gate_path, fragment in (
        ("scripts/check.ps1", "scripts\\check_product_criteria.py"),
        ("scripts/check.sh", "scripts/check_product_criteria.py"),
    ):
        if fragment not in (project_root / gate_path).read_text(encoding="utf-8"):
            _fail(f"product-criteria checker is missing from {gate_path}")


def main() -> int:
    try:
        inventory = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))
        validate_product_criteria(inventory)
    except (OSError, SyntaxError, json.JSONDecodeError, ValueError) as error:
        print(f"Product-criteria validation failed: {error}", file=sys.stderr)
        return 1
    print(
        "Product-criteria inventory passed: "
        f"{len(EXPECTED_IDS)} criteria, "
        f"{len(EXPECTED_RELEASE_OBSERVATION_IDS)} release observations pending."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
