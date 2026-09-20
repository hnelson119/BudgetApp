from __future__ import annotations

import copy
import json
import subprocess
import sys
from collections import Counter
from datetime import date
from pathlib import Path
from typing import Any

import pytest

from scripts.check_hash_function_policy import (
    EXPECTED_NON_PYTHON_OPERATIONS,
    EXPECTED_PYTHON_OPERATIONS,
    discover_non_python_hash_operations,
    discover_python_hash_operations,
    scan_non_python_hash_operations,
    scan_python_hash_operations,
    validate_hash_function_policy,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = PROJECT_ROOT / "docs/hash-function-policy.json"


def _load_policy() -> dict[str, Any]:
    return json.loads(POLICY_PATH.read_text(encoding="utf-8"))


def test_hash_function_policy_is_complete_and_in_both_gates() -> None:
    completed = subprocess.run(
        [sys.executable, "scripts/check_hash_function_policy.py"],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert "26 files, 35 operations, 6 bounded SHA-1" in completed.stdout
    assert "scripts\\check_hash_function_policy.py" in (
        PROJECT_ROOT / "scripts/check.ps1"
    ).read_text(encoding="utf-8")
    assert "scripts/check_hash_function_policy.py" in (PROJECT_ROOT / "scripts/check.sh").read_text(
        encoding="utf-8"
    )


def test_hash_operation_inventory_is_source_derived() -> None:
    assert discover_python_hash_operations() == EXPECTED_PYTHON_OPERATIONS
    assert discover_non_python_hash_operations() == EXPECTED_NON_PYTHON_OPERATIONS
    assert sum(sum(items.values()) for items in EXPECTED_PYTHON_OPERATIONS.values()) == 33
    assert sum(sum(items.values()) for items in EXPECTED_NON_PYTHON_OPERATIONS.values()) == 2


def test_data_authentication_and_integrity_hashes_have_collision_resistant_profiles() -> None:
    policy = _load_policy()
    approved = policy["approved_hash_functions"]

    assert {item["id"] for item in approved} == {"sha256", "sha512"}
    assert all(item["digest_bits"] >= 256 for item in approved)
    for exception in policy["compatibility_exceptions"]:
        restrictions = " ".join(exception["restrictions"])
        assert "signatures" in restrictions
        assert "integrity" in restrictions


def test_hash_function_policy_rejects_tampering_and_stale_reviews() -> None:
    policy = _load_policy()
    validate_hash_function_policy(policy, today=date(2026, 9, 13))

    missing_operation = copy.deepcopy(policy)
    missing_operation["python_operation_inventory"] = missing_operation[
        "python_operation_inventory"
    ][1:]
    with pytest.raises(ValueError, match="documented Python hash-operation inventory changed"):
        validate_hash_function_policy(missing_operation, today=date(2026, 9, 13))

    expanded_exception = copy.deepcopy(policy)
    expanded_exception["compatibility_exceptions"][0]["operations"].append(
        {
            "path": "identity/unsafe.py",
            "operations": {"hashlib.sha1": 1},
            "purpose": "Unreviewed use",
            "status": "compatibility_only",
        }
    )
    with pytest.raises(ValueError, match="SHA-1 compatibility exception inventory changed"):
        validate_hash_function_policy(expanded_exception, today=date(2026, 9, 13))

    with pytest.raises(ValueError, match="review is overdue"):
        validate_hash_function_policy(policy, today=date(2026, 12, 13))


def test_python_scanner_rejects_weak_dynamic_and_implicit_sha1_hashes() -> None:
    with pytest.raises(ValueError, match="unapproved hashlib attribute"):
        scan_python_hash_operations(
            "import hashlib\nhashlib.md5(b'unsafe').hexdigest()\n", "identity/unsafe.py"
        )
    with pytest.raises(ValueError, match="unapproved hash algorithm"):
        scan_python_hash_operations(
            "import hashlib\nhashlib.new('sha256', b'unsafe').hexdigest()\n",
            "identity/dynamic.py",
        )
    with pytest.raises(ValueError, match="usedforsecurity=False"):
        scan_python_hash_operations(
            "import hashlib\nhashlib.sha1(b'compat').hexdigest()\n", "identity/implicit.py"
        )
    with pytest.raises(ValueError, match="indirect hashlib function reference"):
        scan_python_hash_operations(
            "import hashlib\nhasher = hashlib.sha256\nhasher(b'indirect')\n",
            "identity/indirect.py",
        )
    with pytest.raises(ValueError, match="direct Django signing import"):
        scan_python_hash_operations(
            "from django.core.signing import dumps\ndumps({'unsafe': True})\n",
            "identity/signing.py",
        )


def test_scanners_expose_new_reviewable_calls() -> None:
    assert scan_python_hash_operations(
        "import hashlib\nhashlib.sha256(b'new').hexdigest()\n", "identity/new.py"
    ) == Counter({"hashlib.sha256": 1})
    assert scan_non_python_hash_operations(
        'import { createHash } from "node:crypto";\ncreateHash("sha512");\n',
        "browser-tests/new.mjs",
    ) == Counter({"node.createHash:sha512": 1})
    with pytest.raises(ValueError, match="unapproved JavaScript hash algorithm"):
        scan_non_python_hash_operations('createHash("md5");\n', "browser-tests/unsafe.mjs")
    with pytest.raises(ValueError, match="dynamic JavaScript hash selection"):
        scan_non_python_hash_operations(
            "createHash(selectedAlgorithm);\n", "browser-tests/dynamic.mjs"
        )


def test_discovery_includes_production_clients_and_maintenance_scripts(tmp_path: Path) -> None:
    client = tmp_path / "core/static/core/app.js"
    client.parent.mkdir(parents=True)
    client.write_text('crypto.subtle.digest("SHA-1", payload);', encoding="utf-8")
    with pytest.raises(ValueError, match="unreviewed Web Crypto"):
        discover_non_python_hash_operations(tmp_path)

    client.write_text("// no browser hashing", encoding="utf-8")
    script = tmp_path / "deploy/pentest/unsafe.sh"
    script.parent.mkdir(parents=True)
    script.write_text("md5sum artifact", encoding="utf-8")
    with pytest.raises(ValueError, match="unapproved shell hash"):
        discover_non_python_hash_operations(tmp_path)


def test_md5_remains_a_test_settings_exception_only() -> None:
    policy = _load_policy()
    assert policy["test_only_exception"]["settings"] == "config.settings.test"
    assert policy["test_only_exception"]["algorithm"] == "MD5"
    assert EXPECTED_PYTHON_OPERATIONS.keys().isdisjoint({"config/settings/test.py"})
