"""Enforce the reviewed, single-pass input decoding boundary."""

from __future__ import annotations

import ast
import sys
from collections import Counter
from pathlib import Path
from typing import NoReturn

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
EXPECTED_DECODING_OPERATIONS: dict[str, Counter[str]] = {
    "audit/management/commands/verify_audit_checkpoint.py": Counter({"json.loads": 1}),
    "core/pentest_fixture.py": Counter({"json.loads": 1}),
    "core/security_log_collector.py": Counter({"json.loads": 2, "bytes.decode:utf-8:strict": 1}),
    "identity/management/commands/build_breached_password_corpus.py": Counter(
        {"bytes.decode:utf-8:strict": 1}
    ),
    "identity/password_validation.py": Counter(
        {
            "bytes.decode:ascii:strict": 1,
            "bytes.decode:utf-8:strict": 1,
            "json.loads": 1,
        }
    ),
    "identity/services/mfa.py": Counter(
        {"bytes.decode:utf-8:strict": 4, "json.loads": 1, "base64.b32decode": 1}
    ),
    "imports/services/parsing.py": Counter({"bytes.decode:utf-8-sig:strict": 1}),
}
FORBIDDEN_DECODERS = {
    "base64.a85decode",
    "base64.b16decode",
    "base64.b64decode",
    "base64.b85decode",
    "base64.decodebytes",
    "base64.urlsafe_b64decode",
    "binascii.a2b_base64",
    "codecs.decode",
    "html.unescape",
    "urllib.parse.parse_qs",
    "urllib.parse.parse_qsl",
    "urllib.parse.unquote",
    "urllib.parse.unquote_plus",
}
FORBIDDEN_IMPORTS = FORBIDDEN_DECODERS | {
    "pickle.loads",
    "yaml.load",
    "yaml.unsafe_load",
}
ALLOWED_TEXT_ENCODINGS = {"ascii", "utf-8", "utf-8-sig"}


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


def _aliases(tree: ast.AST, relative_path: str) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for imported in node.names:
                local_name = imported.asname or imported.name.split(".", maxsplit=1)[0]
                aliases[local_name] = (
                    imported.name if imported.asname else imported.name.split(".", maxsplit=1)[0]
                )
                if imported.name in FORBIDDEN_IMPORTS:
                    _fail(f"forbidden decoder imported in {relative_path}:{node.lineno}")
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for imported in node.names:
                qualified = f"{module}.{imported.name}" if module else imported.name
                aliases[imported.asname or imported.name] = qualified
                if qualified in FORBIDDEN_IMPORTS:
                    _fail(f"forbidden decoder imported in {relative_path}:{node.lineno}")
    return aliases


def _qualified_name(node: ast.AST, aliases: dict[str, str]) -> str:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        prefix = _qualified_name(node.value, aliases)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _literal_string(node: ast.AST, field: str, relative_path: str, line: int) -> str:
    if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
        _fail(f"{field} must be a literal string in {relative_path}:{line}")
    return node.value.casefold()


def _decode_operation(node: ast.Call, relative_path: str) -> str:
    encoding = (
        _literal_string(node.args[0], "decode encoding", relative_path, node.lineno)
        if node.args
        else "utf-8"
    )
    if len(node.args) > 2:
        _fail(f"decode has unexpected arguments in {relative_path}:{node.lineno}")
    errors = (
        _literal_string(node.args[1], "decode errors", relative_path, node.lineno)
        if len(node.args) == 2
        else "strict"
    )
    for keyword in node.keywords:
        if keyword.arg != "errors":
            _fail(f"decode has an unexpected keyword in {relative_path}:{node.lineno}")
        errors = _literal_string(keyword.value, "decode errors", relative_path, node.lineno)
    if encoding not in ALLOWED_TEXT_ENCODINGS or errors != "strict":
        _fail(f"non-canonical text decoding in {relative_path}:{node.lineno}")
    return f"bytes.decode:{encoding}:{errors}"


def decoding_operations(source: str, relative_path: str) -> Counter[str]:
    tree = ast.parse(source, filename=relative_path)
    aliases = _aliases(tree, relative_path)
    operations: Counter[str] = Counter()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        qualified = _qualified_name(node.func, aliases)
        if qualified in FORBIDDEN_DECODERS or qualified.endswith(
            (".unquote", ".unquote_plus", ".unescape")
        ):
            _fail(f"forbidden repeated-decoding API in {relative_path}:{node.lineno}")
        if isinstance(node.func, ast.Attribute) and node.func.attr == "decode":
            operations[_decode_operation(node, relative_path)] += 1
        elif qualified in {"json.load", "json.loads"}:
            operations[qualified] += 1
        elif qualified.startswith("base64.") and qualified.endswith("decode"):
            operations[qualified] += 1
    return operations


def validate_source_decoding(
    source: str, relative_path: str, expected: Counter[str]
) -> Counter[str]:
    operations = decoding_operations(source, relative_path)
    if operations != expected:
        _fail(
            f"decoding inventory changed in {relative_path}: "
            f"expected {dict(expected)}, found {dict(operations)}"
        )
    return operations


def validate_canonical_decoding(project_root: Path = PROJECT_ROOT) -> tuple[int, int, int]:
    project_root = project_root.resolve()
    discovered_files: dict[str, Counter[str]] = {}
    runtime_files = _runtime_python_files(project_root)
    for path in runtime_files:
        relative_path = path.relative_to(project_root).as_posix()
        operations = decoding_operations(path.read_text(encoding="utf-8"), relative_path)
        if operations:
            discovered_files[relative_path] = operations
    if discovered_files != EXPECTED_DECODING_OPERATIONS:
        missing = sorted(set(EXPECTED_DECODING_OPERATIONS) - set(discovered_files))
        added = sorted(set(discovered_files) - set(EXPECTED_DECODING_OPERATIONS))
        changed = sorted(
            path
            for path in set(discovered_files) & set(EXPECTED_DECODING_OPERATIONS)
            if discovered_files[path] != EXPECTED_DECODING_OPERATIONS[path]
        )
        _fail(
            "canonical decoding inventory changed "
            f"(missing={missing}, added={added}, changed={changed})"
        )
    return (
        len(runtime_files),
        len(discovered_files),
        sum(sum(operations.values()) for operations in discovered_files.values()),
    )


def main() -> int:
    try:
        runtime_count, file_count, operation_count = validate_canonical_decoding()
    except (OSError, SyntaxError, UnicodeError, ValueError) as error:
        print(f"Canonical input-decoding validation failed: {error}", file=sys.stderr)
        return 1
    print(
        "Canonical input-decoding boundary passed "
        f"({runtime_count} runtime Python files, {file_count} decoding files, "
        f"{operation_count} reviewed operations)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
