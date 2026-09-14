from __future__ import annotations

import copy
import json
from datetime import date

import pytest

from scripts.check_context_sanitization import (
    EXPECTED_CONTEXT_IDS,
    EXPECTED_SQL_CALLS,
    POLICY_PATH,
    PROJECT_ROOT,
    scan_sql_calls,
    validate_context_sanitization,
)


def _policy() -> dict[str, object]:
    return json.loads(POLICY_PATH.read_text(encoding="utf-8"))


def test_context_sanitization_accepts_complete_boundary() -> None:
    policy = _policy()

    runtime_count = validate_context_sanitization(policy, today=date(2026, 9, 13))

    assert runtime_count == 218
    assert {item["id"] for item in policy["contexts"]} == EXPECTED_CONTEXT_IDS
    assert policy["summary"] == {
        "contexts": 11,
        "sql_calls": 25,
        "required_boundary_checks": 9,
        "source_assertions": 6,
    }


def test_context_sanitization_runs_in_both_quality_gates() -> None:
    powershell_gate = (PROJECT_ROOT / "scripts/check.ps1").read_text(encoding="utf-8")
    shell_gate = (PROJECT_ROOT / "scripts/check.sh").read_text(encoding="utf-8")

    assert "scripts\\check_context_sanitization.py" in powershell_gate
    assert "scripts/check_context_sanitization.py" in shell_gate


def test_context_sanitization_rejects_catalog_tampering() -> None:
    policy = _policy()

    missing_context = copy.deepcopy(policy)
    missing_context["contexts"].pop()
    with pytest.raises(ValueError, match="dangerous-context inventory changed"):
        validate_context_sanitization(missing_context, today=date(2026, 9, 13))

    changed_sql = copy.deepcopy(policy)
    changed_sql["sql_calls"][0]["count"] = 2
    with pytest.raises(ValueError, match="documented SQL call inventory changed"):
        validate_context_sanitization(changed_sql, today=date(2026, 9, 13))

    with pytest.raises(ValueError, match="review is overdue"):
        validate_context_sanitization(policy, today=date(2026, 12, 13))


def test_context_sanitization_rejects_dynamic_sql() -> None:
    with pytest.raises(ValueError, match="dynamic SQL text"):
        scan_sql_calls("cursor.execute(query, [value])\n", "core/unsafe.py")


def test_context_sanitization_accepts_module_level_literal_sql() -> None:
    calls = scan_sql_calls(
        'CREATE_TABLE_SQL = "CREATE TABLE example (id int)"\n'
        "schema_editor.execute(CREATE_TABLE_SQL)\n",
        "core/migration.py",
    )

    assert calls == {"schema_editor.execute": 1}


def test_context_sanitization_rejects_reassigned_literal_sql() -> None:
    with pytest.raises(ValueError, match="dynamic SQL text"):
        scan_sql_calls(
            'query = "SELECT 1"\nquery = request.GET["query"]\ncursor.execute(query)\n',
            "core/unsafe.py",
        )


def test_context_sanitization_detects_new_literal_sql() -> None:
    calls = scan_sql_calls('cursor.execute("SELECT 1")\n', "core/new_query.py")

    assert calls == {"cursor.execute": 1}
    assert "core/new_query.py" not in EXPECTED_SQL_CALLS
