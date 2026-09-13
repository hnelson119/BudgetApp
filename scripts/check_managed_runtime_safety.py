"""Enforce managed-memory, bounded-numeric, and resource-release boundaries."""

from __future__ import annotations

import ast
import os
import sys
from collections import Counter
from pathlib import Path
from typing import NoReturn

import django
from django.apps import apps
from django.db import models

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
FINANCIAL_ROOTS = {
    "budgets",
    "debts",
    "goals",
    "imports",
    "ledger",
    "notifications",
    "periods",
    "reserves",
    "schedules",
    "spending",
}
PROHIBITED_NATIVE_MODULES = {
    "array",
    "cffi",
    "ctypes",
    "cython",
    "mmap",
    "multiprocessing.shared_memory",
    "numba",
    "numpy",
}
NATIVE_SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".pxd", ".pyx", ".rs", ".wasm"}
EXPECTED_MEMORY_OPERATIONS = {
    "core/security_log_collector.py": Counter({"memoryview": 1}),
}
EXPECTED_STRUCT_OPERATIONS = {
    "identity/services/mfa.py": Counter({"struct.pack:>Q": 1, "struct.unpack:>I": 1}),
}
EXPECTED_DESCRIPTOR_OPERATIONS = {
    "audit/checkpoints.py": Counter({"os.open": 1, "os.fdopen": 1, "os.close": 1}),
    "core/management/commands/seed_pentest_data.py": Counter({"os.open": 1, "os.close": 1}),
    "core/pentest_fixture.py": Counter({"os.open": 1, "os.close": 1}),
    "core/security_log_collector.py": Counter({"os.open": 1, "os.close": 4}),
    "identity/management/commands/build_breached_password_corpus.py": Counter(
        {"os.open": 1, "os.fdopen": 1, "os.close": 1}
    ),
    "identity/password_validation.py": Counter({"os.open": 1, "os.fdopen": 1, "os.close": 1}),
}
EXPECTED_CONTEXT_RESOURCES = {
    "core/logging.py": Counter({"socket.socket": 1}),
    "core/security_log_collector.py": Counter({"socket.socket": 1}),
    "identity/management/commands/build_breached_password_corpus.py": Counter(
        {"tempfile.NamedTemporaryFile": 1}
    ),
}
ALLOWED_DECIMAL_SPECS = {(7, 4), (18, 2)}
ALLOWED_INTEGER_FIELD_TYPES = {
    "BigIntegerField",
    "PositiveBigIntegerField",
    "PositiveIntegerField",
    "PositiveSmallIntegerField",
}


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
            _fail(f"missing production entry point {relative_path!r}")
        files.append(path)
    return sorted(files)


def _aliases(tree: ast.AST, relative_path: str) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for imported in node.names:
                root = imported.name.split(".", maxsplit=1)[0]
                aliases[imported.asname or root] = imported.name if imported.asname else root
                if any(
                    imported.name == module or imported.name.startswith(f"{module}.")
                    for module in PROHIBITED_NATIVE_MODULES
                ):
                    _fail(f"unsafe native-memory module in {relative_path}:{node.lineno}")
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if any(
                module == item or module.startswith(f"{item}.")
                for item in PROHIBITED_NATIVE_MODULES
            ):
                _fail(f"unsafe native-memory module in {relative_path}:{node.lineno}")
            for imported in node.names:
                aliases[imported.asname or imported.name] = f"{module}.{imported.name}"
    return aliases


def _qualified_name(node: ast.AST, aliases: dict[str, str]) -> str:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        prefix = _qualified_name(node.value, aliases)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _literal_format(node: ast.Call, relative_path: str) -> str:
    if (
        not node.args
        or not isinstance(node.args[0], ast.Constant)
        or not isinstance(node.args[0].value, str)
    ):
        _fail(f"struct format must be a literal in {relative_path}:{node.lineno}")
    return node.args[0].value


def scan_source(
    source: str, relative_path: str
) -> tuple[Counter[str], Counter[str], Counter[str], Counter[str]]:
    tree = ast.parse(source, filename=relative_path)
    aliases = _aliases(tree, relative_path)
    with_resources = {
        id(item.context_expr)
        for node in ast.walk(tree)
        if isinstance(node, (ast.With, ast.AsyncWith))
        for item in node.items
    }
    memory: Counter[str] = Counter()
    structs: Counter[str] = Counter()
    descriptors: Counter[str] = Counter()
    context_resources: Counter[str] = Counter()
    for node in ast.walk(tree):
        if isinstance(node, (ast.LShift, ast.RShift)):
            _fail(f"fixed-width shift arithmetic is prohibited in {relative_path}")
        if not isinstance(node, ast.Call):
            continue
        qualified = _qualified_name(node.func, aliases)
        if qualified == "memoryview":
            if relative_path != "core/security_log_collector.py":
                _fail(f"unreviewed buffer view in {relative_path}:{node.lineno}")
            memory[qualified] += 1
        if qualified in {"struct.pack", "struct.unpack"}:
            operation = f"{qualified}:{_literal_format(node, relative_path)}"
            if relative_path != "identity/services/mfa.py" or operation not in {
                "struct.pack:>Q",
                "struct.unpack:>I",
            }:
                _fail(f"unreviewed fixed-width conversion in {relative_path}:{node.lineno}")
            structs[operation] += 1
        if qualified in {"os.open", "os.fdopen", "os.close"}:
            descriptors[qualified] += 1
            if qualified == "os.fdopen" and id(node) not in with_resources:
                _fail(f"fdopen resource is not context-managed in {relative_path}:{node.lineno}")
        if qualified in {"socket.socket", "tempfile.NamedTemporaryFile"}:
            if id(node) not in with_resources:
                _fail(f"resource is not context-managed in {relative_path}:{node.lineno}")
            context_resources[qualified] += 1
        if relative_path.split("/", maxsplit=1)[0] in FINANCIAL_ROOTS and qualified == "float":
            _fail(
                f"binary floating-point conversion in financial code {relative_path}:{node.lineno}"
            )
    return memory, structs, descriptors, context_resources


def _validate_exact_inventory(
    discovered: dict[str, Counter[str]], expected: dict[str, Counter[str]], name: str
) -> None:
    if discovered != expected:
        missing = sorted(set(expected) - set(discovered))
        added = sorted(set(discovered) - set(expected))
        changed = sorted(
            path for path in set(discovered) & set(expected) if discovered[path] != expected[path]
        )
        _fail(f"{name} inventory changed (missing={missing}, added={added}, changed={changed})")


def validate_numeric_models() -> tuple[int, int]:
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.test")
    django.setup()
    decimal_fields = [
        field
        for model in apps.get_models()
        for field in model._meta.get_fields()
        if isinstance(field, models.DecimalField)
    ]
    decimal_specs = {(field.max_digits, field.decimal_places) for field in decimal_fields}
    if len(decimal_fields) != 38 or decimal_specs != ALLOWED_DECIMAL_SPECS:
        _fail("bounded decimal-field inventory changed")
    integer_fields = [
        field
        for model in apps.get_models()
        for field in model._meta.get_fields()
        if isinstance(field, models.IntegerField) and not isinstance(field, models.AutoField)
    ]
    integer_types = {type(field).__name__ for field in integer_fields}
    if len(integer_fields) != 37 or integer_types != ALLOWED_INTEGER_FIELD_TYPES:
        _fail("bounded integer-field inventory changed")
    return len(decimal_fields), len(integer_fields)


def validate_managed_runtime_safety(
    project_root: Path = PROJECT_ROOT,
) -> tuple[int, int, int, int]:
    project_root = project_root.resolve()
    for root_name in RUNTIME_ROOTS:
        native_sources = [
            path
            for path in (project_root / root_name).rglob("*")
            if path.is_file() and path.suffix.casefold() in NATIVE_SOURCE_SUFFIXES
        ]
        if native_sources:
            _fail(f"native runtime source is prohibited: {native_sources[0]}")
    memory_files: dict[str, Counter[str]] = {}
    struct_files: dict[str, Counter[str]] = {}
    descriptor_files: dict[str, Counter[str]] = {}
    context_files: dict[str, Counter[str]] = {}
    runtime_files = _runtime_python_files(project_root)
    for path in runtime_files:
        relative_path = path.relative_to(project_root).as_posix()
        memory, structs, descriptors, contexts = scan_source(
            path.read_text(encoding="utf-8"), relative_path
        )
        if memory:
            memory_files[relative_path] = memory
        if structs:
            struct_files[relative_path] = structs
        if descriptors:
            descriptor_files[relative_path] = descriptors
        if contexts:
            context_files[relative_path] = contexts
    _validate_exact_inventory(memory_files, EXPECTED_MEMORY_OPERATIONS, "managed buffer")
    _validate_exact_inventory(struct_files, EXPECTED_STRUCT_OPERATIONS, "fixed-width conversion")
    _validate_exact_inventory(
        descriptor_files, EXPECTED_DESCRIPTOR_OPERATIONS, "file-descriptor release"
    )
    _validate_exact_inventory(context_files, EXPECTED_CONTEXT_RESOURCES, "context-managed resource")
    client_source = (project_root / "core/static/core/app.js").read_text(encoding="utf-8")
    prohibited_client_tokens = {
        "ArrayBuffer",
        "SharedArrayBuffer",
        "DataView",
        "WebAssembly",
        "parseFloat(",
        "parseInt(",
    }
    if any(token in client_source for token in prohibited_client_tokens):
        _fail("production JavaScript leaves the reviewed managed-memory and numeric boundary")
    decimal_count, integer_count = validate_numeric_models()
    return len(runtime_files), decimal_count, integer_count, len(descriptor_files)


def main() -> int:
    try:
        runtime_count, decimal_count, integer_count, descriptor_file_count = (
            validate_managed_runtime_safety()
        )
    except (OSError, SyntaxError, UnicodeError, ValueError) as error:
        print(f"Managed-runtime safety validation failed: {error}", file=sys.stderr)
        return 1
    print(
        "Managed-runtime safety boundary passed "
        f"({runtime_count} Python files, {decimal_count} decimal fields, "
        f"{integer_count} integer fields, {descriptor_file_count} descriptor files)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
