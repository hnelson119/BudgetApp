from __future__ import annotations

from pathlib import Path

import pytest

from scripts.check_os_command_safety import (
    PROJECT_ROOT,
    RUNTIME_ENTRY_POINTS,
    RUNTIME_ROOTS,
    validate_os_command_safety,
)
from scripts.check_output_encoding import APPLICATION_ROOTS


def _runtime_tree(tmp_path: Path) -> Path:
    for root_name in RUNTIME_ROOTS:
        root = tmp_path / root_name
        root.mkdir(parents=True)
        (root / "safe.py").write_text(
            "import os\nVALUE = os.getenv('SAFE_CONFIGURATION', '')\n",
            encoding="utf-8",
        )
    for relative_path in RUNTIME_ENTRY_POINTS:
        (tmp_path / relative_path).write_text("VALUE = 1\n", encoding="utf-8")
    return tmp_path


def test_os_command_inventory_accepts_the_production_runtime() -> None:
    assert validate_os_command_safety() > 0


def test_os_command_inventory_tracks_all_application_roots_and_configuration() -> None:
    assert RUNTIME_ROOTS == (*APPLICATION_ROOTS[:2], "config", *APPLICATION_ROOTS[2:])
    assert RUNTIME_ENTRY_POINTS == ("manage.py",)


def test_os_command_inventory_runs_in_both_quality_gates() -> None:
    powershell_gate = (PROJECT_ROOT / "scripts/check.ps1").read_text(encoding="utf-8")
    shell_gate = (PROJECT_ROOT / "scripts/check.sh").read_text(encoding="utf-8")

    assert "scripts\\check_os_command_safety.py" in powershell_gate
    assert "scripts/check_os_command_safety.py" in shell_gate


@pytest.mark.parametrize(
    ("source", "message"),
    (
        ("import subprocess\n", "process-capable module subprocess"),
        ("from subprocess import run as launch\n", "process-capable module subprocess"),
        ("import ctypes.util\n", "process-capable module ctypes.util"),
        ("from multiprocessing import Process\n", "process-capable module multiprocessing"),
        ("from os import popen as launch\n", "OS process API popen"),
        ("from os import *\n", "wildcard runtime imports"),
        ("from asyncio.subprocess import create_subprocess_exec\n", "async process API"),
        ("import os\nlaunch = os.system\n", "process API reference"),
        (
            "import os as operating_system\noperating_system.system(user_value)\n",
            "OS process API system",
        ),
        ("import os\nos.execvp(program, arguments)\n", "OS process API execvp"),
        ("import os\nos.fork()\n", "OS process API fork"),
        (
            "import asyncio as event_loop\nevent_loop.create_subprocess_shell(user_value)\n",
            "async process API create_subprocess_shell",
        ),
        ("import importlib\nimportlib.import_module(user_value)\n", "dynamic module loading"),
        ("VALUE = __import__(user_value)\n", "dynamic module loading"),
        ("import os\nVALUE = getattr(os, user_value)\n", "dynamic process API lookup"),
    ),
)
def test_os_command_inventory_rejects_process_and_dynamic_import_apis(
    tmp_path: Path, source: str, message: str
) -> None:
    project_root = _runtime_tree(tmp_path)
    (project_root / "core/unsafe.py").write_text(source, encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        validate_os_command_safety(project_root)


def test_os_command_inventory_allows_non_process_calls_named_execute(tmp_path: Path) -> None:
    project_root = _runtime_tree(tmp_path)
    (project_root / "core/database.py").write_text(
        "def run(cursor):\n    cursor.execute('SELECT 1')\n",
        encoding="utf-8",
    )

    assert validate_os_command_safety(project_root) > 0
