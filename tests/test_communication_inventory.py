from __future__ import annotations

import copy
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from scripts.check_communication_inventory import (
    INVENTORY_PATH,
    PROJECT_ROOT,
    RUNTIME_ENTRY_POINTS,
    RUNTIME_ROOTS,
    validate_communication_inventory,
    validate_inventory_document,
    validate_runtime_network_clients,
)
from scripts.check_os_command_safety import RUNTIME_ROOTS as COMMAND_RUNTIME_ROOTS


def _runtime_tree(tmp_path: Path) -> Path:
    for root_name in RUNTIME_ROOTS:
        root = tmp_path / root_name
        root.mkdir(parents=True)
        (root / "safe.py").write_text("VALUE = 1\n", encoding="utf-8")
    for relative_path in RUNTIME_ENTRY_POINTS:
        (tmp_path / relative_path).write_text("VALUE = 1\n", encoding="utf-8")
    for relative_path in ("core/logging.py", "core/security_log_collector.py"):
        path = tmp_path / relative_path
        path.write_text(
            "import socket\nFAMILY = socket.AF_UNIX\nTYPE = socket.SOCK_DGRAM\n",
            encoding="utf-8",
        )
    return tmp_path


def test_communication_inventory_accepts_the_production_boundary() -> None:
    flow_count, external_count, runtime_count, socket_count = validate_communication_inventory()

    assert flow_count == 10
    assert external_count == 6
    assert runtime_count > 0
    assert socket_count == 2


def test_communication_inventory_tracks_the_complete_runtime() -> None:
    assert RUNTIME_ROOTS == COMMAND_RUNTIME_ROOTS
    assert RUNTIME_ENTRY_POINTS == ("manage.py",)


def test_communication_inventory_runs_in_both_quality_gates() -> None:
    powershell_gate = (PROJECT_ROOT / "scripts/check.ps1").read_text(encoding="utf-8")
    shell_gate = (PROJECT_ROOT / "scripts/check.sh").read_text(encoding="utf-8")

    assert "scripts\\check_communication_inventory.py" in powershell_gate
    assert "scripts/check_communication_inventory.py" in shell_gate


@pytest.mark.parametrize(
    "mutation",
    (
        lambda document: document["flows"].pop(),
        lambda document: document["external_services"].pop(),
        lambda document: document["flows"][0].update(user_supplied_destination=True),
        lambda document: document.update(
            user_supplied_external_destinations=["https://user.invalid"]
        ),
        lambda document: document["flows"][0].update(evidence=[]),
    ),
)
def test_communication_inventory_rejects_catalog_and_destination_tampering(
    mutation: Callable[[dict[str, Any]], object],
) -> None:
    document = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))
    tampered = copy.deepcopy(document)
    mutation(tampered)

    with pytest.raises(ValueError):
        validate_inventory_document(PROJECT_ROOT, tampered)


@pytest.mark.parametrize(
    "source",
    (
        "import requests\n",
        "import urllib.request as client\n",
        "from urllib import request\n",
        "from http import client\n",
        "import smtplib\n",
        "import socket\nVALUE = socket.AF_INET\nTYPE = socket.SOCK_DGRAM\n",
    ),
)
def test_communication_inventory_rejects_runtime_network_clients(
    tmp_path: Path, source: str
) -> None:
    project_root = _runtime_tree(tmp_path)
    (project_root / "core/unsafe.py").write_text(source, encoding="utf-8")

    with pytest.raises(ValueError):
        validate_runtime_network_clients(project_root)


def test_communication_inventory_allows_local_url_parsing(tmp_path: Path) -> None:
    project_root = _runtime_tree(tmp_path)
    (project_root / "core/parsing.py").write_text(
        "from urllib.parse import urlsplit\nVALUE = urlsplit('/local/path')\n",
        encoding="utf-8",
    )

    assert validate_runtime_network_clients(project_root)[1] == 2


@pytest.mark.parametrize(
    "extra_source",
    (
        "from socket import AF_INET\n",
        "from socket import *\n",
        "import socket as connection\n",
        "FAMILY = getattr(socket, selected_family)\n",
        "FAMILY = getattr(socket, 'AF_INET')\n",
    ),
)
def test_reviewed_socket_files_cannot_hide_internet_capabilities(
    tmp_path: Path, extra_source: str
) -> None:
    project_root = _runtime_tree(tmp_path)
    (project_root / "core/logging.py").write_text(
        "import socket\nFAMILY = socket.AF_UNIX\nTYPE = socket.SOCK_DGRAM\n" + extra_source,
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        validate_runtime_network_clients(project_root)
