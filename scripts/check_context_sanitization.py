"""Validate all reviewed dangerous data contexts and raw SQL call sites."""

from __future__ import annotations

import ast
import json
import sys
from collections import Counter
from datetime import date
from pathlib import Path
from typing import Any, NoReturn

PROJECT_ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = PROJECT_ROOT / "docs" / "context-sanitization.json"
RUNTIME_ROOTS = (
    "audit",
    "budgets",
    "config",
    "core",
    "debts",
    "goals",
    "households",
    "identity",
    "imports",
    "ledger",
    "notifications",
    "periods",
    "reserves",
    "schedules",
    "spending",
)
EXPECTED_CONTEXT_IDS = {
    "browser-html-and-javascript",
    "csv-spreadsheet",
    "database-sql",
    "email-protocol",
    "filesystem-path",
    "format-grammar",
    "operating-system-command",
    "redirect-and-action-url",
    "regular-expression",
    "server-template-selection",
    "structured-logging",
}
ALLOWED_STATUSES = {"absent", "allowlisted", "encoded", "escaped", "parameterized", "redacted"}
EXPECTED_SQL_CALLS = {
    "audit/checkpoints.py": Counter({"cursor.execute": 1}),
    "audit/migrations/0002_postgresql_protected_schema.py": Counter({"schema_editor.execute": 2}),
    "audit/migrations/0004_postgresql_protect_checkpoints.py": Counter(
        {"schema_editor.execute": 2}
    ),
    "audit/services.py": Counter({"cursor.execute": 1}),
    "budgets/migrations/0002_postgresql_protect_reconciliations.py": Counter(
        {"schema_editor.execute": 2}
    ),
    "core/views.py": Counter({"cursor.execute": 1}),
    "debts/migrations/0002_postgresql_protect_history.py": Counter({"schema_editor.execute": 2}),
    "debts/migrations/0004_postgresql_protect_mortgage_history.py": Counter(
        {"schema_editor.execute": 2}
    ),
    "goals/migrations/0002_postgresql_protect_history.py": Counter({"schema_editor.execute": 2}),
    "ledger/migrations/0002_postgresql_protect_history.py": Counter({"schema_editor.execute": 2}),
    "periods/migrations/0002_postgresql_period_guards.py": Counter({"schema_editor.execute": 2}),
    "reserves/migrations/0002_postgresql_protect_entries.py": Counter({"schema_editor.execute": 2}),
    "reserves/migrations/0004_cardpaymentreserveentry.py": Counter({"schema_editor.execute": 2}),
    "schedules/migrations/0002_postgresql_protect_revisions.py": Counter(
        {"schema_editor.execute": 2}
    ),
}
EXPECTED_BOUNDARY_CHECKS = {
    "scripts/check_authorization_policy.py",
    "scripts/check_communication_inventory.py",
    "scripts/check_format_string_safety.py",
    "scripts/check_input_validation_policy.py",
    "scripts/check_logging_inventory.py",
    "scripts/check_os_command_safety.py",
    "scripts/check_output_encoding.py",
    "scripts/check_regex_safety.py",
    "scripts/check_template_safety.py",
}
EXPECTED_SOURCE_ASSERTIONS = {
    "csv-formula-contract": (
        "spending/services/exports.py",
        (
            '_FORMULA_PREFIXES = ("=", "+", "-", "@")',
            "candidate = value.lstrip()",
            'return f"\'{value}"',
        ),
    ),
    "redirect-contract": (
        "core/middleware.py",
        (
            "def _redirect_location_is_allowed",
            'location != location.strip() or "\\\\" in location',
            "require_https=True",
        ),
    ),
    "notification-action-contract": (
        "notifications/models.py",
        (
            "def internal_action_url",
            'if not self.action_url or "\\\\" in self.action_url:',
            'if parsed.scheme or parsed.netloc or not parsed.path.startswith("/"):',
        ),
    ),
    "checkpoint-filename-contract": (
        "audit/management/commands/verify_audit_checkpoint.py",
        (
            "if Path(supplied_name).name != supplied_name:",
            "Provide a checkpoint filename, not a path.",
        ),
    ),
    "email-disabled-contract": (
        "config/settings/hardened.py",
        ('EMAIL_BACKEND = "django.core.mail.backends.dummy.EmailBackend"',),
    ),
    "logging-redaction-contract": (
        "core/logging.py",
        (
            "def redact_text",
            '_SENSITIVE_ASSIGNMENT.sub(r"\\1\\2[REDACTED]", text)',
            '_EMAIL_ADDRESS.sub("[REDACTED_EMAIL]", text)',
        ),
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
        _fail(f"missing context evidence: {relative_path}")
    return path


def _attribute_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _attribute_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def scan_sql_calls(source: str, relative_path: str) -> Counter[str]:
    tree = ast.parse(source, filename=relative_path)
    stored_names = Counter(
        node.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)
    )
    module_literal_sql_names = {
        target.id
        for statement in tree.body
        if isinstance(statement, ast.Assign)
        and isinstance(statement.value, ast.Constant)
        and isinstance(statement.value.value, str)
        for target in statement.targets
        if isinstance(target, ast.Name)
    }
    literal_sql_names = {name for name in module_literal_sql_names if stored_names[name] == 1}
    calls: Counter[str] = Counter()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        qualified = _attribute_name(node.func)
        operation = qualified.rsplit(".", maxsplit=1)[-1]
        if operation not in {"execute", "executemany", "raw", "extra"}:
            continue
        literal_argument = bool(
            node.args
            and (
                (isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str))
                or (isinstance(node.args[0], ast.Name) and node.args[0].id in literal_sql_names)
            )
        )
        if not literal_argument:
            _fail(f"dynamic SQL text in {relative_path}:{node.lineno}")
        receiver = qualified.rsplit(".", maxsplit=1)[0].rsplit(".", maxsplit=1)[-1]
        calls[f"{receiver}.{operation}"] += 1
    return calls


def discover_sql_calls(project_root: Path = PROJECT_ROOT) -> tuple[int, dict[str, Counter[str]]]:
    files: list[Path] = []
    for root_name in RUNTIME_ROOTS:
        root = project_root / root_name
        if not root.is_dir():
            _fail(f"missing production root: {root_name}")
        files.extend(root.rglob("*.py"))
    discovered: dict[str, Counter[str]] = {}
    for path in sorted(files):
        relative_path = path.relative_to(project_root).as_posix()
        calls = scan_sql_calls(path.read_text(encoding="utf-8"), relative_path)
        if calls:
            discovered[relative_path] = calls
    return len(files), discovered


def _validate_sql_inventory(policy: dict[str, Any], project_root: Path) -> int:
    records = policy.get("sql_calls")
    if not isinstance(records, list):
        _fail("sql_calls must be a list")
    documented: dict[str, Counter[str]] = {}
    for record in records:
        if not isinstance(record, dict) or set(record) != {
            "path",
            "operation",
            "count",
            "parameterization",
        }:
            _fail("SQL inventory fields changed")
        path = _text(record["path"], "SQL path")
        operation = _text(record["operation"], f"{path} SQL operation")
        count = record["count"]
        if not isinstance(count, int) or isinstance(count, bool) or count < 1:
            _fail(f"invalid SQL call count: {path}")
        _text(record["parameterization"], f"{path} parameterization")
        documented.setdefault(path, Counter())[operation] += count
    if documented != EXPECTED_SQL_CALLS:
        _fail("documented SQL call inventory changed")
    runtime_count, discovered = discover_sql_calls(project_root)
    if discovered != EXPECTED_SQL_CALLS:
        _fail(
            "runtime SQL call inventory changed "
            f"(expected={EXPECTED_SQL_CALLS}, discovered={discovered})"
        )
    return runtime_count


def _validate_boundary_checks(policy: dict[str, Any], project_root: Path) -> None:
    checks = set(_string_list(policy.get("required_boundary_checks"), "boundary checks"))
    if checks != EXPECTED_BOUNDARY_CHECKS:
        _fail("required context boundary checks changed")
    powershell_gate = _safe_path(project_root, "scripts/check.ps1").read_text(encoding="utf-8")
    shell_gate = _safe_path(project_root, "scripts/check.sh").read_text(encoding="utf-8")
    for check in checks:
        _safe_path(project_root, check)
        if check.replace("/", "\\") not in powershell_gate or check not in shell_gate:
            _fail(f"context boundary check is not wired into both gates: {check}")


def _validate_source_assertions(policy: dict[str, Any], project_root: Path) -> None:
    records = policy.get("source_assertions")
    if not isinstance(records, list):
        _fail("source_assertions must be a list")
    documented: dict[str, tuple[str, tuple[str, ...]]] = {}
    for record in records:
        if not isinstance(record, dict) or set(record) != {"id", "path", "contains"}:
            _fail("context source assertion fields changed")
        assertion_id = _text(record["id"], "source assertion id")
        path = _text(record["path"], f"{assertion_id} path")
        fragments = tuple(_string_list(record["contains"], f"{assertion_id} fragments"))
        if assertion_id in documented:
            _fail(f"duplicate source assertion: {assertion_id}")
        documented[assertion_id] = (path, fragments)
    if documented != EXPECTED_SOURCE_ASSERTIONS:
        _fail("context source assertion inventory changed")
    for assertion_id, (path, fragments) in documented.items():
        source = _safe_path(project_root, path).read_text(encoding="utf-8")
        missing = [fragment for fragment in fragments if fragment not in source]
        if missing:
            _fail(f"context source contract changed for {assertion_id}: {missing}")


def validate_context_sanitization(
    policy: dict[str, Any], *, project_root: Path = PROJECT_ROOT, today: date | None = None
) -> int:
    expected_fields = {
        "schema_version",
        "policy_id",
        "asvs_requirement",
        "last_reviewed",
        "next_review_due",
        "rule",
        "contexts",
        "sql_calls",
        "required_boundary_checks",
        "source_assertions",
        "summary",
    }
    if set(policy) != expected_fields:
        _fail("context-sanitization policy fields changed")
    if (
        policy["schema_version"] != 1
        or policy["policy_id"] != "household-budget-context-sanitization-v1"
    ):
        _fail("unsupported context-sanitization policy identity")
    if policy["asvs_requirement"] != "v5.0.0-1.3.3":
        _fail("context-sanitization ASVS requirement changed")
    _text(policy["rule"], "context rule")

    reviewed = date.fromisoformat(_text(policy["last_reviewed"], "last_reviewed"))
    due = date.fromisoformat(_text(policy["next_review_due"], "next_review_due"))
    if due <= reviewed or (due - reviewed).days > 90:
        _fail("context-sanitization review cadence exceeds 90 days")
    if (today or date.today()) > due:
        _fail("context-sanitization review is overdue")

    contexts = policy.get("contexts")
    if not isinstance(contexts, list) or any(not isinstance(item, dict) for item in contexts):
        _fail("contexts must contain objects")
    ids = [_text(item.get("id"), "context id") for item in contexts]
    if set(ids) != EXPECTED_CONTEXT_IDS or len(ids) != len(EXPECTED_CONTEXT_IDS):
        _fail("dangerous-context inventory changed")
    for item in contexts:
        if set(item) != {
            "id",
            "status",
            "untrusted_data",
            "sink",
            "treatment",
            "evidence",
        }:
            _fail(f"dangerous-context fields changed: {item['id']}")
        if item["status"] not in ALLOWED_STATUSES:
            _fail(f"invalid context status: {item['id']}")
        _string_list(item["untrusted_data"], f"{item['id']} untrusted data")
        _text(item["sink"], f"{item['id']} sink")
        _text(item["treatment"], f"{item['id']} treatment")
        for evidence in _string_list(item["evidence"], f"{item['id']} evidence"):
            _safe_path(project_root, evidence)

    runtime_count = _validate_sql_inventory(policy, project_root)
    _validate_boundary_checks(policy, project_root)
    _validate_source_assertions(policy, project_root)
    expected_summary = {
        "contexts": len(EXPECTED_CONTEXT_IDS),
        "sql_calls": sum(sum(calls.values()) for calls in EXPECTED_SQL_CALLS.values()),
        "required_boundary_checks": len(EXPECTED_BOUNDARY_CHECKS),
        "source_assertions": len(EXPECTED_SOURCE_ASSERTIONS),
    }
    if policy.get("summary") != expected_summary:
        _fail("context-sanitization summary is stale")
    return runtime_count


def main() -> int:
    try:
        policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        if not isinstance(policy, dict):
            _fail("context-sanitization policy must be a JSON object")
        runtime_count = validate_context_sanitization(policy)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"context-sanitization check failed: {error}", file=sys.stderr)
        return 1
    print(
        "Context-sanitization boundary passed: "
        f"{runtime_count} runtime files, {len(EXPECTED_CONTEXT_IDS)} contexts, "
        f"{sum(sum(calls.values()) for calls in EXPECTED_SQL_CALLS.values())} SQL calls."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
