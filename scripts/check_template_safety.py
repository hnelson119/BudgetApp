"""Enforce the production template-selection and construction boundary."""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path, PurePosixPath
from typing import NoReturn

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
TEMPLATE_ROOTS = (
    "audit/templates",
    "budgets/templates",
    "core/templates",
    "debts/templates",
    "goals/templates",
    "identity/templates",
    "imports/templates",
    "notifications/templates",
    "spending/templates",
)
TEMPLATE_CALL_ARGUMENTS = {
    "render": (1, "template_name", False),
    "render_to_string": (0, "template_name", False),
    "get_template": (0, "template_name", False),
    "select_template": (0, "template_name_list", True),
    "TemplateResponse": (1, "template", True),
    "SimpleTemplateResponse": (0, "template", True),
}
DYNAMIC_TEMPLATE_APIS = {"Engine", "Template", "from_string"}
TRACKED_IMPORTS = {
    "django.shortcuts": {"render"},
    "django.template.loader": {"get_template", "render_to_string", "select_template"},
    "django.template.response": {"SimpleTemplateResponse", "TemplateResponse"},
}
TEMPLATE_DEPENDENCY_PATTERN = re.compile(
    r"{%\s*(?P<tag>extends|include)\s+(?P<expression>.+?)%}",
    re.IGNORECASE | re.DOTALL,
)
QUOTED_TEMPLATE_NAME_PATTERN = re.compile(r"^(?P<quote>['\"])(?P<name>[^'\"]+)(?P=quote)(?:\s|$)")


def _fail(message: str) -> NoReturn:
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


def _template_inventory(project_root: Path) -> tuple[set[str], list[Path]]:
    template_names: set[str] = set()
    template_files: list[Path] = []
    for relative_root in TEMPLATE_ROOTS:
        root = project_root / relative_root
        if not root.is_dir():
            _fail(f"missing production template root {relative_root!r}")
        for path in sorted(root.rglob("*.html")):
            template_names.add(path.relative_to(root).as_posix())
            template_files.append(path)
    return template_names, template_files


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


def _literal_template_names(node: ast.expr | None, *, allow_sequence: bool) -> list[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if allow_sequence and isinstance(node, (ast.List, ast.Tuple)):
        names: list[str] = []
        for item in node.elts:
            if not isinstance(item, ast.Constant) or not isinstance(item.value, str):
                _fail("template selection must use only literal template names")
            names.append(item.value)
        return names
    _fail("template selection must use a literal template name")


def _validate_template_name(name: str, template_names: set[str], location: str) -> None:
    if not name or "\\" in name:
        _fail(f"invalid template name {name!r} in {location}")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        _fail(f"invalid template name {name!r} in {location}")
    if name not in template_names:
        _fail(f"unknown template name {name!r} in {location}")


def _validate_python_templates(project_root: Path, template_names: set[str]) -> int:
    selection_count = 0
    for path in _application_python_files(project_root):
        relative_path = path.relative_to(project_root).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative_path)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                imported_names = {imported.name: imported for imported in node.names}
                if node.module is not None and node.module.startswith("django.template"):
                    dangerous_imports = DYNAMIC_TEMPLATE_APIS & set(imported_names)
                    if dangerous_imports:
                        imported_name = sorted(dangerous_imports)[0]
                        _fail(
                            f"dynamic template API {imported_name} is prohibited in "
                            f"{relative_path}:{node.lineno}"
                        )
                tracked_names = TRACKED_IMPORTS.get(node.module or "", set())
                aliased_names = sorted(
                    name
                    for name in tracked_names & set(imported_names)
                    if imported_names[name].asname is not None
                )
                if aliased_names:
                    _fail(
                        f"aliased template API {aliased_names[0]} is prohibited in "
                        f"{relative_path}:{node.lineno}"
                    )
            if not isinstance(node, ast.Call):
                continue
            name = _call_name(node)
            if name in DYNAMIC_TEMPLATE_APIS:
                _fail(f"dynamic template API {name} is prohibited in {relative_path}:{node.lineno}")
            if name not in TEMPLATE_CALL_ARGUMENTS:
                continue
            position, keyword_name, allow_sequence = TEMPLATE_CALL_ARGUMENTS[name]
            argument = _call_argument(node, position, keyword_name)
            try:
                names = _literal_template_names(argument, allow_sequence=allow_sequence)
            except ValueError as error:
                raise ValueError(f"{error} in {relative_path}:{node.lineno}") from error
            for template_name in names:
                _validate_template_name(
                    template_name,
                    template_names,
                    f"{relative_path}:{node.lineno}",
                )
            selection_count += 1
    return selection_count


def _validate_template_dependencies(
    project_root: Path, template_names: set[str], template_files: list[Path]
) -> int:
    dependency_count = 0
    for path in template_files:
        relative_path = path.relative_to(project_root).as_posix()
        content = path.read_text(encoding="utf-8")
        for match in TEMPLATE_DEPENDENCY_PATTERN.finditer(content):
            expression = match.group("expression").strip()
            literal_match = QUOTED_TEMPLATE_NAME_PATTERN.match(expression)
            if literal_match is None:
                _fail(
                    f"dynamic {match.group('tag').casefold()} template is prohibited in "
                    f"{relative_path}"
                )
            _validate_template_name(
                literal_match.group("name"),
                template_names,
                relative_path,
            )
            dependency_count += 1
    return dependency_count


def validate_template_safety(project_root: Path = PROJECT_ROOT) -> tuple[int, int, int]:
    project_root = project_root.resolve()
    template_names, template_files = _template_inventory(project_root)
    selection_count = _validate_python_templates(project_root, template_names)
    dependency_count = _validate_template_dependencies(project_root, template_names, template_files)
    return len(template_files), selection_count, dependency_count


def main() -> int:
    try:
        template_count, selection_count, dependency_count = validate_template_safety()
    except (OSError, SyntaxError, UnicodeError, ValueError) as error:
        print(f"Template-safety validation failed: {error}", file=sys.stderr)
        return 1
    print(
        "Template-safety boundary passed "
        f"({template_count} templates, {selection_count} fixed selections, "
        f"{dependency_count} fixed dependencies)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
