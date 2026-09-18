"""Enforce the production runtime's zero-child-process boundary."""

from __future__ import annotations

import ast
import sys
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
PROHIBITED_PROCESS_MODULES = {"commands", "ctypes", "multiprocessing", "pty", "subprocess"}
OS_PROCESS_APIS = {
    "execl",
    "execle",
    "execlp",
    "execlpe",
    "execv",
    "execve",
    "execvp",
    "execvpe",
    "fork",
    "forkpty",
    "popen",
    "posix_spawn",
    "posix_spawnp",
    "spawnl",
    "spawnle",
    "spawnlp",
    "spawnlpe",
    "spawnv",
    "spawnve",
    "spawnvp",
    "spawnvpe",
    "startfile",
    "system",
}
ASYNCIO_PROCESS_APIS = {"create_subprocess_exec", "create_subprocess_shell"}


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


def _module_aliases(tree: ast.AST) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Import):
            continue
        for imported in node.names:
            local_name = imported.asname or imported.name.split(".", maxsplit=1)[0]
            aliases[local_name] = imported.name
    return aliases


def _attribute_call(node: ast.Call) -> tuple[str, str] | None:
    if not isinstance(node.func, ast.Attribute) or not isinstance(node.func.value, ast.Name):
        return None
    return node.func.value.id, node.func.attr


def _validate_import(node: ast.Import | ast.ImportFrom, relative_path: str) -> None:
    if isinstance(node, ast.Import):
        prohibited = sorted(
            imported.name
            for imported in node.names
            if imported.name.split(".", maxsplit=1)[0] in PROHIBITED_PROCESS_MODULES
        )
        if prohibited:
            _fail(
                f"process-capable module {prohibited[0]} is prohibited in "
                f"{relative_path}:{node.lineno}"
            )
        return

    module = node.module or ""
    module_root = module.split(".", maxsplit=1)[0]
    if module_root in PROHIBITED_PROCESS_MODULES:
        _fail(f"process-capable module {module} is prohibited in {relative_path}:{node.lineno}")
    imported_names = {imported.name for imported in node.names}
    if module_root in {"os", "asyncio", "importlib"} and "*" in imported_names:
        _fail(f"wildcard runtime imports are prohibited in {relative_path}:{node.lineno}")
    if module == "os" and imported_names & OS_PROCESS_APIS:
        api = sorted(imported_names & OS_PROCESS_APIS)[0]
        _fail(f"OS process API {api} is prohibited in {relative_path}:{node.lineno}")
    if module_root == "asyncio" and imported_names & ASYNCIO_PROCESS_APIS:
        api = sorted(imported_names & ASYNCIO_PROCESS_APIS)[0]
        _fail(f"async process API {api} is prohibited in {relative_path}:{node.lineno}")
    if module == "importlib" and "import_module" in imported_names:
        _fail(f"dynamic module loading is prohibited in {relative_path}:{node.lineno}")


def _validate_call(node: ast.Call, aliases: dict[str, str], relative_path: str) -> None:
    if isinstance(node.func, ast.Name) and node.func.id == "__import__":
        _fail(f"dynamic module loading is prohibited in {relative_path}:{node.lineno}")
    if (
        isinstance(node.func, ast.Name)
        and node.func.id == "getattr"
        and node.args
        and isinstance(node.args[0], ast.Name)
    ):
        target_module = aliases.get(node.args[0].id, node.args[0].id)
        target_root = target_module.split(".", maxsplit=1)[0]
        requested_api = node.args[1] if len(node.args) > 1 else None
        literal_safe_api = (
            isinstance(requested_api, ast.Constant)
            and isinstance(requested_api.value, str)
            and requested_api.value not in OS_PROCESS_APIS | ASYNCIO_PROCESS_APIS
        )
        if target_root in {"os", "asyncio"} and not literal_safe_api:
            _fail(f"dynamic process API lookup is prohibited in {relative_path}:{node.lineno}")
    attribute_call = _attribute_call(node)
    if attribute_call is None:
        return
    local_module, api = attribute_call
    module = aliases.get(local_module, local_module)
    module_root = module.split(".", maxsplit=1)[0]
    if module_root == "os" and api in OS_PROCESS_APIS:
        _fail(f"OS process API {api} is prohibited in {relative_path}:{node.lineno}")
    if module_root == "asyncio" and api in ASYNCIO_PROCESS_APIS:
        _fail(f"async process API {api} is prohibited in {relative_path}:{node.lineno}")
    if module_root == "importlib" and api == "import_module":
        _fail(f"dynamic module loading is prohibited in {relative_path}:{node.lineno}")


def validate_os_command_safety(project_root: Path = PROJECT_ROOT) -> int:
    project_root = project_root.resolve()
    files = _runtime_python_files(project_root)
    for path in files:
        relative_path = path.relative_to(project_root).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative_path)
        aliases = _module_aliases(tree)
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                _validate_import(node, relative_path)
            elif isinstance(node, ast.Call):
                _validate_call(node, aliases, relative_path)
            elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                module_root = aliases.get(node.value.id, node.value.id).split(".", maxsplit=1)[0]
                if (module_root == "os" and node.attr in OS_PROCESS_APIS) or (
                    module_root == "asyncio" and node.attr in ASYNCIO_PROCESS_APIS
                ):
                    _fail(f"process API reference is prohibited in {relative_path}:{node.lineno}")
    return len(files)


def main() -> int:
    try:
        file_count = validate_os_command_safety()
    except (OSError, SyntaxError, UnicodeError, ValueError) as error:
        print(f"OS-command safety validation failed: {error}", file=sys.stderr)
        return 1
    print(f"OS-command safety boundary passed ({file_count} runtime Python files; 0 launch APIs).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
