"""Enforce the browser-script and JSON output-encoding boundary."""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CLIENT_SURFACE_ROOTS = (
    "audit/templates",
    "budgets/templates",
    "core/static",
    "core/templates",
    "debts/templates",
    "goals/templates",
    "identity/templates",
    "imports/templates",
    "notifications/templates",
    "spending/templates",
)
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
INLINE_SCRIPT_PATTERN = re.compile(
    r"<script\b(?![^>]*\bsrc\s*=)[^>]*>.*?</script\s*>",
    re.IGNORECASE | re.DOTALL,
)
UNSAFE_TEMPLATE_PATTERNS = (
    ("disabled template auto-escaping", re.compile(r"{%\s*autoescape\s+off\s*%}", re.IGNORECASE)),
    ("trusted safe template filter", re.compile(r"(?:\|\s*safe\b|{%\s*filter\s+safe\s*%})")),
)
UNSAFE_JAVASCRIPT_PATTERNS = (
    (
        "HTML parsing sink",
        re.compile(
            r"(?:\.\s*(?:innerHTML|outerHTML)\s*=|"
            r"\[\s*['\"](?:innerHTML|outerHTML)['\"]\s*\]\s*=|"
            r"\b(?:insertAdjacentHTML|setHTMLUnsafe)\s*\(|"
            r"\[\s*['\"](?:insertAdjacentHTML|setHTMLUnsafe)['\"]\s*\]\s*\(|"
            r"\bdocument\s*(?:\.\s*(?:write|writeln)|"
            r"\[\s*['\"](?:write|writeln)['\"]\s*\])\s*\()",
            re.IGNORECASE,
        ),
    ),
    (
        "dynamic JavaScript execution",
        re.compile(r"(?:\beval\s*\(|\bFunction\s*\()", re.IGNORECASE),
    ),
    (
        "string timer execution",
        re.compile(r"\b(?:setTimeout|setInterval)\s*\(\s*['\"]", re.IGNORECASE),
    ),
    (
        "dynamic event-handler attribute",
        re.compile(
            r"(?:\.\s*setAttribute|\[\s*['\"]setAttribute['\"]\s*\])"
            r"\s*\(\s*['\"]on[a-z]+['\"]",
            re.IGNORECASE,
        ),
    ),
)
UNSAFE_PYTHON_HTML_APIS = {"SafeString", "SafeText", "mark_safe"}
DJANGO_SAFESTRING_MODULE = "django.utils.safestring"
SCRIPT_OR_JSON_MEDIA_TYPES = {
    "application/javascript",
    "application/json",
    "application/ld+json",
    "text/javascript",
}


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


def _production_client_files(project_root: Path) -> list[Path]:
    files: list[Path] = []
    for relative_root in CLIENT_SURFACE_ROOTS:
        root = project_root / relative_root
        if not root.is_dir():
            _fail(f"missing production client root {relative_root!r}")
        files.extend(path for path in root.rglob("*") if path.is_file())
    return sorted(files)


def _call_name(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


def _validate_client_output(project_root: Path) -> tuple[int, int]:
    template_count = 0
    script_count = 0
    for path in _production_client_files(project_root):
        suffix = path.suffix.casefold()
        if suffix not in {".html", ".js"}:
            continue
        relative_path = path.relative_to(project_root).as_posix()
        content = path.read_text(encoding="utf-8")
        if suffix == ".html":
            template_count += 1
            if INLINE_SCRIPT_PATTERN.search(content):
                _fail(f"inline executable script is prohibited in {relative_path}")
            for description, pattern in UNSAFE_TEMPLATE_PATTERNS:
                if pattern.search(content):
                    _fail(f"{description} is prohibited in {relative_path}")
            continue
        script_count += 1
        for description, pattern in UNSAFE_JAVASCRIPT_PATTERNS:
            if pattern.search(content):
                _fail(f"{description} is prohibited in {relative_path}")
    return template_count, script_count


def _validate_python_output(project_root: Path) -> int:
    json_response_count = 0
    for path in _application_python_files(project_root):
        relative_path = path.relative_to(project_root).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative_path)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == DJANGO_SAFESTRING_MODULE:
                imported_unsafe_apis = UNSAFE_PYTHON_HTML_APIS & {
                    imported.name for imported in node.names
                }
                if imported_unsafe_apis:
                    imported_api = sorted(imported_unsafe_apis)[0]
                    _fail(
                        f"trusted HTML API {imported_api} is prohibited in "
                        f"{relative_path}:{node.lineno}"
                    )
            if isinstance(node, ast.ImportFrom) and node.module == "django.http":
                aliased_json_response = next(
                    (
                        imported
                        for imported in node.names
                        if imported.name == "JsonResponse" and imported.asname is not None
                    ),
                    None,
                )
                if aliased_json_response is not None:
                    _fail(f"aliased JsonResponse is prohibited in {relative_path}:{node.lineno}")
            if (
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name == "__html__"
            ):
                _fail(f"custom trusted HTML is prohibited in {relative_path}:{node.lineno}")
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                media_type = node.value.split(";", maxsplit=1)[0].strip().casefold()
                if media_type in SCRIPT_OR_JSON_MEDIA_TYPES:
                    _fail(
                        f"manual script or JSON media response is prohibited in "
                        f"{relative_path}:{node.lineno}"
                    )
            if not isinstance(node, ast.Call):
                continue
            name = _call_name(node)
            if name in UNSAFE_PYTHON_HTML_APIS:
                _fail(f"trusted HTML API {name} is prohibited in {relative_path}:{node.lineno}")
            if name == "JsonResponse":
                if len(node.args) != 1 or any(
                    keyword.arg in ("encoder", None) for keyword in node.keywords
                ):
                    _fail(
                        f"custom JsonResponse encoding is prohibited in "
                        f"{relative_path}:{node.lineno}"
                    )
                json_response_count += 1
    return json_response_count


def validate_output_encoding(project_root: Path = PROJECT_ROOT) -> tuple[int, int, int]:
    project_root = project_root.resolve()
    template_count, script_count = _validate_client_output(project_root)
    json_response_count = _validate_python_output(project_root)
    return template_count, script_count, json_response_count


def main() -> int:
    try:
        template_count, script_count, json_response_count = validate_output_encoding()
    except (OSError, SyntaxError, UnicodeError, ValueError) as error:
        print(f"Output-encoding validation failed: {error}", file=sys.stderr)
        return 1
    print(
        "Output-encoding boundary passed "
        f"({template_count} templates, {script_count} scripts, "
        f"{json_response_count} encoder-backed JSON responses)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
