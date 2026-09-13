from __future__ import annotations

import pytest

from scripts.check_managed_runtime_safety import (
    PROJECT_ROOT,
    RUNTIME_ENTRY_POINTS,
    RUNTIME_ROOTS,
    scan_source,
    validate_managed_runtime_safety,
    validate_numeric_models,
)
from scripts.check_os_command_safety import RUNTIME_ROOTS as COMMAND_RUNTIME_ROOTS


def test_managed_runtime_safety_accepts_the_production_boundary() -> None:
    runtime_count, decimal_count, integer_count, descriptor_file_count = (
        validate_managed_runtime_safety()
    )

    assert runtime_count > 0
    assert decimal_count == 38
    assert integer_count == 37
    assert descriptor_file_count == 6


def test_managed_runtime_safety_tracks_the_complete_runtime() -> None:
    assert RUNTIME_ROOTS == COMMAND_RUNTIME_ROOTS
    assert RUNTIME_ENTRY_POINTS == ("manage.py",)


def test_managed_runtime_safety_runs_in_both_quality_gates() -> None:
    powershell_gate = (PROJECT_ROOT / "scripts/check.ps1").read_text(encoding="utf-8")
    shell_gate = (PROJECT_ROOT / "scripts/check.sh").read_text(encoding="utf-8")

    assert "scripts\\check_managed_runtime_safety.py" in powershell_gate
    assert "scripts/check_managed_runtime_safety.py" in shell_gate


@pytest.mark.parametrize(
    "source",
    (
        "import ctypes\n",
        "import ctypes as ffi\n",
        "from cffi import FFI\n",
        "from multiprocessing.shared_memory import SharedMemory\n",
        "import numpy.core\n",
    ),
)
def test_managed_runtime_safety_rejects_native_memory_modules(source: str) -> None:
    with pytest.raises(ValueError):
        scan_source(source, "core/unsafe.py")


def test_managed_runtime_safety_rejects_unreviewed_buffer_views() -> None:
    with pytest.raises(ValueError):
        scan_source("value = memoryview(payload)\n", "core/unsafe.py")


@pytest.mark.parametrize(
    "source",
    (
        'import struct\nvalue = struct.unpack("@P", payload)\n',
        "import struct\nvalue = struct.pack(format_string, number)\n",
    ),
)
def test_managed_runtime_safety_rejects_unreviewed_fixed_width_conversions(
    source: str,
) -> None:
    with pytest.raises(ValueError):
        scan_source(source, "identity/services/mfa.py")


def test_managed_runtime_safety_rejects_binary_float_in_financial_code() -> None:
    with pytest.raises(ValueError):
        scan_source("amount = float(raw)\n", "ledger/services/unsafe.py")


@pytest.mark.parametrize(
    "source",
    (
        "import socket\ntransport = socket.socket()\n",
        "import os\nstream = os.fdopen(descriptor)\n",
        "import tempfile\ntemporary = tempfile.NamedTemporaryFile()\n",
    ),
)
def test_managed_runtime_safety_rejects_unmanaged_resources(source: str) -> None:
    with pytest.raises(ValueError):
        scan_source(source, "core/unsafe.py")


def test_managed_runtime_safety_rejects_shift_arithmetic() -> None:
    with pytest.raises(ValueError):
        scan_source("value = raw << 64\n", "core/unsafe.py")


def test_numeric_model_inventory_is_bounded() -> None:
    assert validate_numeric_models() == (38, 37)
