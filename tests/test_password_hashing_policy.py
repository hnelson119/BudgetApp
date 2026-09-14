from __future__ import annotations

import copy
import json
from datetime import date

import pytest
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password, identify_hasher
from django.test import override_settings

from scripts.check_password_hashing_policy import (
    EXPECTED_CONSUMER_IDS,
    EXPECTED_OPERATION_INVENTORY,
    EXPECTED_SETTINGS,
    POLICY_PATH,
    PROJECT_ROOT,
    scan_password_operations,
    validate_password_hashing_policy,
)

PRODUCTION_HASHERS = ["django.contrib.auth.hashers.PBKDF2PasswordHasher"]


def _policy() -> dict[str, object]:
    return json.loads(POLICY_PATH.read_text(encoding="utf-8"))


def test_password_hashing_policy_accepts_complete_inventory() -> None:
    policy = _policy()

    validate_password_hashing_policy(policy, today=date(2026, 9, 13))

    assert {item["id"] for item in policy["consumers"]} == EXPECTED_CONSUMER_IDS
    assert policy["summary"] == {
        "consumers": 3,
        "operation_files": 6,
        "operations": 14,
        "source_assertions": 5,
        "production_hashers": 1,
        "test_only_hashers": 1,
    }


def test_password_hashing_policy_runs_in_both_quality_gates() -> None:
    powershell_gate = (PROJECT_ROOT / "scripts/check.ps1").read_text(encoding="utf-8")
    shell_gate = (PROJECT_ROOT / "scripts/check.sh").read_text(encoding="utf-8")

    assert "scripts\\check_password_hashing_policy.py" in powershell_gate
    assert "scripts/check_password_hashing_policy.py" in shell_gate


def test_password_hashing_policy_rejects_catalog_tampering() -> None:
    policy = _policy()

    changed_profile = copy.deepcopy(policy)
    changed_profile["production_profile"]["iterations"] = 100_000
    with pytest.raises(ValueError, match="production password-hashing profile changed"):
        validate_password_hashing_policy(changed_profile, today=date(2026, 9, 13))

    missing_operation = copy.deepcopy(policy)
    missing_operation["operation_inventory"].pop()
    with pytest.raises(ValueError, match="documented password-hashing operation inventory changed"):
        validate_password_hashing_policy(missing_operation, today=date(2026, 9, 13))

    with pytest.raises(ValueError, match="review is overdue"):
        validate_password_hashing_policy(policy, today=date(2026, 12, 13))


def test_password_hashing_policy_rejects_direct_password_field_writes() -> None:
    with pytest.raises(ValueError, match="direct password-field write"):
        scan_password_operations("user.password = candidate\n", "identity/unsafe.py")


def test_password_hashing_policy_detects_new_api_calls() -> None:
    operations = scan_password_operations(
        "user.set_password(candidate)\nuser.check_password(candidate)\n",
        "identity/new_flow.py",
    )

    assert operations == {"object.set_password": 1, "object.check_password": 1}
    assert "identity/new_flow.py" not in EXPECTED_OPERATION_INVENTORY


@override_settings(PASSWORD_HASHERS=PRODUCTION_HASHERS)
def test_production_password_hashes_are_salted_pbkdf2_sha256() -> None:
    user = get_user_model()(email="password-hash@example.com")
    password = "correct horse battery storage"  # pragma: allowlist secret

    user.set_password(password)
    first = user.password
    user.set_password(password)
    second = user.password

    first_hasher = identify_hasher(first)
    assert first_hasher.algorithm == "pbkdf2_sha256"
    assert first_hasher.iterations == 1_000_000
    assert first.split("$")[2] != second.split("$")[2]
    assert check_password(password, first) is True
    assert check_password("incorrect password", first) is False


def test_password_hasher_settings_are_explicit_and_test_only_md5_isolated() -> None:
    assert EXPECTED_SETTINGS == {
        "base.py": ("django.contrib.auth.hashers.PBKDF2PasswordHasher",),
        "test.py": ("django.contrib.auth.hashers.MD5PasswordHasher",),
    }
