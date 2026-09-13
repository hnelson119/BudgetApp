"""Reject unreviewed dynamic regular expressions in the production application."""

from __future__ import annotations

import ast
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
APPLICATION_ROOTS = (
    "audit",
    "budgets",
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
REGEX_FUNCTIONS = {
    "compile",
    "findall",
    "finditer",
    "fullmatch",
    "match",
    "search",
    "split",
    "sub",
    "subn",
}
REGEX_CONSTRUCTORS = {"RegexField", "RegexValidator"}
CONTEXT_PATTERN_PATH = Path("identity/password_validation.py")


def _fail(message: str) -> None:
    raise ValueError(message)


def _application_python_files(project_root: Path) -> list[Path]:
    files: list[Path] = []
    for root_name in APPLICATION_ROOTS:
        root = project_root / root_name
        if not root.is_dir():
            _fail(f"missing production application root {root_name!r}")
        files.extend(
            path
            for path in root.rglob("*.py")
            if "migrations" not in path.relative_to(project_root).parts
        )
    return sorted(files)


def _is_re_call(node: ast.AST, name: str) -> bool:
    return bool(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "re"
        and node.func.attr == name
    )


def _call_name(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


def _pattern_argument(node: ast.Call, *, keyword: str) -> ast.AST | None:
    if node.args:
        return node.args[0]
    for item in node.keywords:
        if item.arg == keyword:
            return item.value
    return None


def _is_static_pattern(node: ast.AST | None) -> bool:
    return bool(
        isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)) and node.value
    )


def _escaped_alternatives(node: ast.AST) -> bool:
    if not (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "join"
        and isinstance(node.func.value, ast.Constant)
        and node.func.value.value == "|"
        and len(node.args) == 1
        and not node.keywords
        and isinstance(node.args[0], ast.GeneratorExp)
    ):
        return False
    generator = node.args[0]
    escaped_value = generator.elt
    return bool(
        len(generator.generators) == 1
        and isinstance(generator.generators[0].target, ast.Name)
        and generator.generators[0].target.id == "value"
        and not generator.generators[0].ifs
        and not generator.generators[0].is_async
        and isinstance(escaped_value, ast.Call)
        and _is_re_call(escaped_value, "escape")
        and len(escaped_value.args) == 1
        and isinstance(escaped_value.args[0], ast.Name)
        and escaped_value.args[0].id == "value"
        and not escaped_value.keywords
    )


def _uses_only_escaped_alternatives(node: ast.AST | None) -> bool:
    if not isinstance(node, ast.JoinedStr):
        return False
    interpolations = [item for item in node.values if isinstance(item, ast.FormattedValue)]
    return bool(
        len(interpolations) == 1
        and isinstance(interpolations[0].value, ast.Name)
        and interpolations[0].value.id == "alternatives"
        and interpolations[0].conversion == -1
        and interpolations[0].format_spec is None
        and all(isinstance(item, (ast.Constant, ast.FormattedValue)) for item in node.values)
    )


def _approved_context_pattern_calls(tree: ast.AST, relative_path: Path) -> set[int]:
    if relative_path != CONTEXT_PATTERN_PATH:
        return set()
    approved: set[int] = set()
    for class_node in (node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)):
        if class_node.name != "ContextSpecificPasswordValidator":
            continue
        for method in (node for node in class_node.body if isinstance(node, ast.FunctionDef)):
            if method.name != "__init__":
                continue
            alternative_stores = [
                node
                for node in ast.walk(method)
                if isinstance(node, ast.Name)
                and node.id == "alternatives"
                and isinstance(node.ctx, ast.Store)
            ]
            alternatives = [
                node.value
                for node in method.body
                if isinstance(node, ast.Assign)
                and any(
                    isinstance(target, ast.Name) and target.id == "alternatives"
                    for target in node.targets
                )
            ]
            pattern_calls = [
                node.value
                for node in method.body
                if isinstance(node, ast.Assign)
                and any(
                    isinstance(target, ast.Attribute)
                    and isinstance(target.value, ast.Name)
                    and target.value.id == "self"
                    and target.attr == "pattern"
                    for target in node.targets
                )
                and isinstance(node.value, ast.Call)
                and _is_re_call(node.value, "compile")
            ]
            if len(alternative_stores) != 1 or len(alternatives) != 1 or len(pattern_calls) != 1:
                continue
            pattern_argument = _pattern_argument(pattern_calls[0], keyword="pattern")
            if _escaped_alternatives(alternatives[0]) and _uses_only_escaped_alternatives(
                pattern_argument
            ):
                approved.add(id(pattern_calls[0]))
    return approved


def validate_regex_safety(project_root: Path = PROJECT_ROOT) -> list[tuple[Path, int]]:
    project_root = project_root.resolve()
    regex_calls: list[tuple[Path, int]] = []
    for path in _application_python_files(project_root):
        relative_path = path.relative_to(project_root)
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(relative_path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for imported in node.names:
                    if imported.name == "regex" or imported.name.startswith("regex."):
                        _fail(f"{relative_path.as_posix()} imports an unreviewed regex engine")
                    if imported.name == "re" and imported.asname not in (None, "re"):
                        _fail(f"{relative_path.as_posix()} aliases the regular-expression module")
            if isinstance(node, ast.ImportFrom) and node.module in {"re", "regex"}:
                _fail(f"{relative_path.as_posix()} imports an unreviewed regex symbol directly")
            if isinstance(node, ast.ImportFrom):
                for imported in node.names:
                    if imported.name in REGEX_CONSTRUCTORS and imported.asname not in (
                        None,
                        imported.name,
                    ):
                        _fail(f"{relative_path.as_posix()} aliases a Django regex constructor")

        approved_dynamic = _approved_context_pattern_calls(tree, relative_path)
        for node in (item for item in ast.walk(tree) if isinstance(item, ast.Call)):
            name = _call_name(node)
            if _is_re_call(node, name or "") and name in REGEX_FUNCTIONS:
                pattern = _pattern_argument(node, keyword="pattern")
                if not _is_static_pattern(pattern) and id(node) not in approved_dynamic:
                    _fail(
                        f"{relative_path.as_posix()}:{node.lineno} uses an unreviewed dynamic "
                        "regular expression"
                    )
                regex_calls.append((relative_path, node.lineno))
            elif name in REGEX_CONSTRUCTORS:
                pattern = _pattern_argument(node, keyword="regex")
                if not _is_static_pattern(pattern):
                    _fail(
                        f"{relative_path.as_posix()}:{node.lineno} uses an unreviewed dynamic "
                        "Django regular expression"
                    )
                regex_calls.append((relative_path, node.lineno))
    return regex_calls


def main() -> int:
    try:
        regex_calls = validate_regex_safety()
    except (OSError, SyntaxError, ValueError) as error:
        print(f"Regular-expression safety validation failed: {error}", file=sys.stderr)
        return 1
    print(
        "Regular-expression safety inventory passed "
        f"({len(regex_calls)} static or escaped pattern uses)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
