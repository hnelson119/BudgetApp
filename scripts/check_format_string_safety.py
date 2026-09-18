"""Enforce code-owned format strings throughout the production runtime."""

from __future__ import annotations

import ast
import sys
from collections import Counter
from pathlib import Path
from string import Formatter
from typing import Any, NoReturn

PROJECT_ROOT = Path(__file__).resolve().parents[1]
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
RUNTIME_ENTRY_POINTS = ("manage.py",)
EXPECTED_NUMERIC_MODULO = Counter(
    {
        ("core/management/commands/seed_pentest_data.py", "(today.weekday() - 3) % 7"): 2,
        ("debts/services/projections.py", "month_index % 12"): 1,
        ("identity/services/mfa.py", "(8 - len(secret) % 8) % 8"): 1,
        ("identity/services/mfa.py", "len(secret) % 8"): 1,
        ("identity/services/mfa.py", "binary % 1000000"): 1,
        ("schedules/recurrence.py", "(weekday - first.weekday()) % 7"): 1,
        ("schedules/recurrence.py", "(last.weekday() - weekday) % 7"): 1,
        ("schedules/recurrence.py", "week_index % rule.interval"): 1,
        ("schedules/recurrence.py", "(month_index - anchor_month) % rule.interval"): 1,
        ("schedules/recurrence.py", "(year - rule.start_date.year) % rule.interval"): 1,
    }
)
EXPECTED_HANDLER_FORMAT = Counter({("core/logging.py", "self.format(record)"): 1})
EXPECTED_IMPORT_DATE_FORMATS = {
    "auto": ("%Y-%m-%d", "%m/%d/%Y", "%m/%d/%y", "%m-%d-%Y"),
    "iso": ("%Y-%m-%d",),
    "us_slash": ("%m/%d/%Y", "%m/%d/%y"),
    "us_dash": ("%m-%d-%Y",),
}
REVIEWED_DYNAMIC_STRPTIME = (
    "imports/services/batches.py",
    "datetime.strptime(normalized, pattern)",
)
LOGGING_METHODS = {"critical", "debug", "error", "exception", "info", "log", "warning"}


def _fail(message: str) -> NoReturn:
    raise ValueError(message)


def _runtime_python_files(project_root: Path) -> list[Path]:
    files: list[Path] = []
    for root_name in RUNTIME_ROOTS:
        root = project_root / root_name
        if not root.is_dir():
            _fail(f"missing production runtime root {root_name!r}")
        files.extend(root.rglob("*.py"))
    for relative_path in RUNTIME_ENTRY_POINTS:
        path = project_root / relative_path
        if not path.is_file():
            _fail(f"missing production runtime entry point {relative_path!r}")
        files.append(path)
    return sorted(files)


def _literal_string(node: ast.expr | None) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes))


def _module_aliases(tree: ast.AST) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Import):
            continue
        for imported in node.names:
            local_name = imported.asname or imported.name.split(".", maxsplit=1)[0]
            aliases[local_name] = imported.name
    return aliases


def _call_name(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


def _call_argument(node: ast.Call, position: int, keyword_name: str) -> ast.expr | None:
    if len(node.args) > position:
        return node.args[position]
    return next(
        (keyword.value for keyword in node.keywords if keyword.arg == keyword_name),
        None,
    )


def _validated_date_format_allowlist(tree: ast.AST, relative_path: str) -> bool:
    if relative_path != REVIEWED_DYNAMIC_STRPTIME[0]:
        return False
    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == "_DATE_FORMATS"
            and node.value is not None
        ):
            continue
        try:
            value: Any = ast.literal_eval(node.value)
        except (TypeError, ValueError):
            _fail("CSV date-format allowlist must contain only literals")
        if value != EXPECTED_IMPORT_DATE_FORMATS:
            _fail("CSV date-format allowlist differs from the reviewed grammar set")
        return True
    _fail("CSV date-format allowlist is missing")


def _validate_imports(tree: ast.AST, relative_path: str) -> None:
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom):
            continue
        imported_names = {imported.name: imported for imported in node.names}
        if (
            node.module == "builtins"
            and (imported := imported_names.get("format")) is not None
            and imported.asname is not None
        ):
            _fail(f"aliased built-in format is prohibited in {relative_path}:{node.lineno}")
        if node.module == "django.utils.html":
            for name in ("format_html", "format_html_join"):
                imported = imported_names.get(name)
                if imported is not None and imported.asname is not None:
                    _fail(f"aliased {name} is prohibited in {relative_path}:{node.lineno}")
        if node.module == "string" and {"Formatter", "Template"} & set(imported_names):
            _fail(f"runtime string templates are prohibited in {relative_path}:{node.lineno}")


def _validate_format_method(
    node: ast.Call,
    relative_path: str,
    observed_handler_format: Counter[tuple[str, str]],
) -> None:
    assert isinstance(node.func, ast.Attribute)
    expression = ast.unparse(node)
    key = (relative_path, expression)
    if key in EXPECTED_HANDLER_FORMAT:
        observed_handler_format[key] += 1
        return
    if not _literal_string(node.func.value):
        _fail(f"format method receiver must be a literal string in {relative_path}:{node.lineno}")
    _validate_literal_fields(node.func.value, relative_path, node.lineno)


def _validate_literal_fields(node: ast.expr | None, relative_path: str, line: int) -> None:
    if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
        _fail(f"format grammar must be a literal string in {relative_path}:{line}")
    try:
        fields = list(Formatter().parse(node.value))
    except ValueError as error:
        raise ValueError(f"invalid literal format grammar in {relative_path}:{line}") from error
    if any(spec and ("{" in spec or "}" in spec) for _, _, spec, _ in fields):
        _fail(f"nested dynamic format specification is prohibited in {relative_path}:{line}")


def _validate_call(
    node: ast.Call,
    aliases: dict[str, str],
    relative_path: str,
    date_allowlist_valid: bool,
    observed_handler_format: Counter[tuple[str, str]],
) -> None:
    name = _call_name(node)
    if name in {"format", "format_map"} and isinstance(node.func, ast.Attribute):
        if isinstance(node.func.value, ast.Name):
            module = aliases.get(node.func.value.id, node.func.value.id)
            if module.split(".", maxsplit=1)[0] == "builtins" and name == "format":
                spec = _call_argument(node, 1, "format_spec")
                if spec is not None and not _literal_string(spec):
                    _fail(f"format specification must be literal in {relative_path}:{node.lineno}")
                return
        _validate_format_method(node, relative_path, observed_handler_format)
        return
    if name == "format" and isinstance(node.func, ast.Name):
        spec = _call_argument(node, 1, "format_spec")
        if spec is not None and not _literal_string(spec):
            _fail(f"format specification must be literal in {relative_path}:{node.lineno}")
    if name == "format_html":
        if not _literal_string(_call_argument(node, 0, "format_string")):
            _fail(f"HTML format string must be literal in {relative_path}:{node.lineno}")
        _validate_literal_fields(
            _call_argument(node, 0, "format_string"), relative_path, node.lineno
        )
    if name == "format_html_join":
        separator = _call_argument(node, 0, "sep")
        format_string = _call_argument(node, 1, "format_string")
        if not _literal_string(separator) or not _literal_string(format_string):
            _fail(f"HTML join format strings must be literal in {relative_path}:{node.lineno}")
        _validate_literal_fields(format_string, relative_path, node.lineno)
    if name == "strftime":
        if not _literal_string(_call_argument(node, 0, "format")):
            _fail(f"datetime format string must be literal in {relative_path}:{node.lineno}")
    if name == "strptime":
        format_argument = _call_argument(node, 1, "format")
        reviewed = (
            date_allowlist_valid and (relative_path, ast.unparse(node)) == REVIEWED_DYNAMIC_STRPTIME
        )
        if not _literal_string(format_argument) and not reviewed:
            _fail(f"datetime parse format must be literal in {relative_path}:{node.lineno}")
    if name in {"Formatter", "Template"} and isinstance(node.func, ast.Attribute):
        if isinstance(node.func.value, ast.Name):
            module = aliases.get(node.func.value.id, node.func.value.id)
            if module.split(".", maxsplit=1)[0] == "string":
                _fail(f"runtime string templates are prohibited in {relative_path}:{node.lineno}")
    if name in LOGGING_METHODS and isinstance(node.func, ast.Attribute):
        receiver = node.func.value
        if isinstance(receiver, ast.Name) and receiver.id != "messages":
            message_position = 1 if name == "log" else 0
            if not _literal_string(_call_argument(node, message_position, "msg")):
                _fail(f"log message format must be literal in {relative_path}:{node.lineno}")


def validate_format_string_safety(project_root: Path = PROJECT_ROOT) -> tuple[int, int, int]:
    project_root = project_root.resolve()
    observed_modulo: Counter[tuple[str, str]] = Counter()
    observed_handler_format: Counter[tuple[str, str]] = Counter()
    files = _runtime_python_files(project_root)
    for path in files:
        relative_path = path.relative_to(project_root).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative_path)
        aliases = _module_aliases(tree)
        date_allowlist_valid = _validated_date_format_allowlist(tree, relative_path)
        _validate_imports(tree, relative_path)
        for node in ast.walk(tree):
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
                key = (relative_path, ast.unparse(node))
                if key not in EXPECTED_NUMERIC_MODULO:
                    _fail(
                        f"unreviewed percent-format or modulo expression in "
                        f"{relative_path}:{node.lineno}"
                    )
                observed_modulo[key] += 1
            elif isinstance(node, ast.FormattedValue) and node.format_spec is not None:
                if any(isinstance(item, ast.FormattedValue) for item in ast.walk(node.format_spec)):
                    _fail(f"dynamic f-string format is prohibited in {relative_path}:{node.lineno}")
            elif isinstance(node, ast.Call):
                _validate_call(
                    node,
                    aliases,
                    relative_path,
                    date_allowlist_valid,
                    observed_handler_format,
                )
    if project_root == PROJECT_ROOT.resolve():
        if observed_modulo != EXPECTED_NUMERIC_MODULO:
            _fail("reviewed numeric modulo inventory is stale")
        if observed_handler_format != EXPECTED_HANDLER_FORMAT:
            _fail("reviewed logging.Handler format inventory is stale")
    return len(files), sum(observed_modulo.values()), sum(observed_handler_format.values())


def main() -> int:
    try:
        file_count, modulo_count, handler_format_count = validate_format_string_safety()
    except (OSError, SyntaxError, UnicodeError, ValueError) as error:
        print(f"Format-string safety validation failed: {error}", file=sys.stderr)
        return 1
    print(
        "Format-string safety boundary passed "
        f"({file_count} runtime Python files, {modulo_count} numeric modulo expressions, "
        f"{handler_format_count} reviewed handler formatter)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
