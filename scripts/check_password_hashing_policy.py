"""Validate the production password hasher, settings, and credential API inventory."""

from __future__ import annotations

import ast
import json
import sys
from collections import Counter
from datetime import date
from pathlib import Path
from typing import Any, NoReturn

import django
from django.contrib.auth.hashers import PBKDF2PasswordHasher

PROJECT_ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = PROJECT_ROOT / "docs" / "password-hashing-policy.json"
IDENTITY_ROOT = PROJECT_ROOT / "identity"
SETTINGS_ROOT = PROJECT_ROOT / "config" / "settings"

EXPECTED_CONSUMER_IDS = {
    "account-passwords",
    "dummy-verification-hashes",
    "mfa-recovery-codes",
}
EXPECTED_OPERATION_INVENTORY = {
    "identity/forms.py": Counter({"object.check_password": 1}),
    "identity/management/commands/reset_user_password.py": Counter(
        {"object.check_password": 1, "object.set_password": 1}
    ),
    "identity/managers.py": Counter({"object.set_password": 1}),
    "identity/services/mfa.py": Counter({"hasher.check_password": 2, "hasher.make_password": 2}),
    "identity/services/recovery.py": Counter(
        {
            "hasher.check_password": 1,
            "hasher.make_password": 1,
            "object.set_password": 1,
        }
    ),
    "identity/views.py": Counter({"object.check_password": 2, "object.set_password": 1}),
}
EXPECTED_SETTINGS = {
    "base.py": ("django.contrib.auth.hashers.PBKDF2PasswordHasher",),
    "test.py": ("django.contrib.auth.hashers.MD5PasswordHasher",),
}
EXPECTED_SETTINGS_INHERITANCE = {
    "hardened.py": "from .base import *",
    "integrity.py": "from .base import *",
    "pentest.py": "from .hardened import *",
    "production.py": "from .hardened import *",
}
EXPECTED_TEST_EXCEPTION = {
    "settings": "config.settings.test",
    "class": "django.contrib.auth.hashers.MD5PasswordHasher",
    "purpose": "Fast synthetic in-memory unit-test credentials only",
    "prohibited_targets": [
        "hardened",
        "production",
        "pentest",
        "browser",
        "migration",
        "backup",
        "restore",
        "release candidate",
    ],
    "evidence": [
        "config/settings/test.py",
        "tests/test_password_hashing_policy.py",
        "tests/test_production_settings.py",
    ],
}
EXPECTED_UPGRADE_REQUIREMENTS = {
    "review the replacement primitive and parameters in the cryptographic inventory",
    "measure the release-host encode and verify cost with synthetic values",
    "retain the previous approved verifier until every active stored encoding is upgraded",
    (
        "exercise login, password change, recovery, console reset, MFA recovery codes, throttling, "
        "and session revocation"
    ),
    (
        "force credential reset and revoke sessions when compromise rather than routine "
        "obsolescence motivates the change"
    ),
}
EXPECTED_SOURCE_ASSERTIONS = {
    "base-hasher-contract": (
        "config/settings/base.py",
        ('PASSWORD_HASHERS = ["django.contrib.auth.hashers.PBKDF2PasswordHasher"]',),
    ),
    "cryptographic-inventory-contract": (
        "docs/cryptographic-inventory.json",
        (
            '"id": "django-pbkdf2-hmac-sha256"',
            "1,000,000 iterations",
            '"id": "test-md5-password-hasher"',
        ),
    ),
    "login-throttle-contract": (
        "config/settings/base.py",
        ("LOGIN_RATE_LIMIT_FAILURES = 5", "LOGIN_RATE_LIMIT_WINDOW_SECONDS = 15 * 60"),
    ),
    "production-dependency-contract": ("requirements-prod.lock", ("Django==5.2.17",)),
    "test-hasher-contract": (
        "config/settings/test.py",
        ('PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]',),
    ),
}


def _fail(message: str) -> NoReturn:
    raise ValueError(message)


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        _fail(f"{label} must be non-empty text")
    return value


def _string_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or not value:
        _fail(f"{label} must be a non-empty string list")
    values = [_text(item, label) for item in value]
    if len(values) != len(set(values)):
        _fail(f"{label} contains duplicates")
    return values


def _safe_path(relative_path: str, *, project_root: Path = PROJECT_ROOT) -> Path:
    if Path(relative_path).is_absolute():
        _fail(f"password-hashing evidence must be relative: {relative_path}")
    path = (project_root / relative_path).resolve()
    try:
        path.relative_to(project_root.resolve())
    except ValueError:
        _fail(f"password-hashing evidence escapes project root: {relative_path}")
    if not path.exists():
        _fail(f"missing password-hashing evidence: {relative_path}")
    return path


def _literal_string_sequence(node: ast.expr, label: str) -> tuple[str, ...]:
    if not isinstance(node, (ast.List, ast.Tuple)):
        _fail(f"{label} must be a literal string sequence")
    values: list[str] = []
    for element in node.elts:
        if not isinstance(element, ast.Constant) or not isinstance(element.value, str):
            _fail(f"{label} must be a literal string sequence")
        values.append(element.value)
    return tuple(values)


def scan_password_operations(source: str, relative_path: str) -> Counter[str]:
    tree = ast.parse(source, filename=relative_path)
    operations: Counter[str] = Counter()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(alias.name == "django.contrib.auth.hashers" for alias in node.names):
                _fail(
                    "password hasher module import is not reviewed in "
                    f"{relative_path}:{node.lineno}"
                )
        if isinstance(node, ast.ImportFrom) and node.module == "django.contrib.auth.hashers":
            for imported in node.names:
                if imported.name not in {"check_password", "make_password"} or imported.asname:
                    _fail(
                        f"password hasher import is not reviewed in {relative_path}:{node.lineno}"
                    )
        if (
            isinstance(node, ast.Attribute)
            and node.attr == "password"
            and isinstance(node.ctx, (ast.Store, ast.Del))
        ):
            _fail(f"direct password-field write in {relative_path}:{node.lineno}")
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name) and node.func.id in {"check_password", "make_password"}:
            operations[f"hasher.{node.func.id}"] += 1
        elif isinstance(node.func, ast.Attribute) and node.func.attr in {
            "check_password",
            "set_password",
        }:
            operations[f"object.{node.func.attr}"] += 1
    return operations


def discover_password_operations(
    project_root: Path = PROJECT_ROOT,
) -> dict[str, Counter[str]]:
    discovered: dict[str, Counter[str]] = {}
    identity_root = project_root / "identity"
    for path in sorted(identity_root.rglob("*.py")):
        relative = path.relative_to(project_root).as_posix()
        if "/migrations/" in f"/{relative}":
            continue
        operations = scan_password_operations(path.read_text(encoding="utf-8"), relative)
        if operations:
            discovered[relative] = operations
    return discovered


def _discover_settings(project_root: Path) -> dict[str, tuple[str, ...]]:
    discovered: dict[str, tuple[str, ...]] = {}
    for path in sorted((project_root / "config/settings").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        assignments = [
            node.value
            for node in tree.body
            if isinstance(node, (ast.Assign, ast.AnnAssign))
            and (
                (
                    isinstance(node, ast.Assign)
                    and any(
                        isinstance(target, ast.Name) and target.id == "PASSWORD_HASHERS"
                        for target in node.targets
                    )
                )
                or (
                    isinstance(node, ast.AnnAssign)
                    and isinstance(node.target, ast.Name)
                    and node.target.id == "PASSWORD_HASHERS"
                )
            )
        ]
        if len(assignments) > 1:
            _fail(f"multiple PASSWORD_HASHERS assignments in {path.name}")
        if assignments:
            discovered[path.name] = _literal_string_sequence(
                assignments[0], f"{path.name} PASSWORD_HASHERS"
            )
    return discovered


def _validate_runtime_primitive() -> None:
    hasher = PBKDF2PasswordHasher()
    actual = {
        "class": "django.contrib.auth.hashers.PBKDF2PasswordHasher",
        "algorithm": hasher.algorithm,
        "pseudorandom_function": f"HMAC-{hasher.digest().name.upper().replace('SHA', 'SHA-')}",
        "iterations": hasher.iterations,
        "salt_entropy_bits": hasher.salt_entropy,
        "django_version": django.get_version(),
    }
    expected = {
        "class": "django.contrib.auth.hashers.PBKDF2PasswordHasher",
        "algorithm": "pbkdf2_sha256",
        "pseudorandom_function": "HMAC-SHA-256",
        "iterations": 1_000_000,
        "salt_entropy_bits": 128,
        "django_version": "5.2.17",
    }
    if actual != expected:
        _fail(f"production password-hashing primitive changed: {actual}")


def _validate_settings(project_root: Path) -> None:
    if _discover_settings(project_root) != EXPECTED_SETTINGS:
        _fail("password hasher settings inventory changed")
    for relative_name, fragment in EXPECTED_SETTINGS_INHERITANCE.items():
        source = (project_root / "config/settings" / relative_name).read_text(encoding="utf-8")
        if fragment not in source:
            _fail(f"password hasher inheritance changed in {relative_name}")


def _validate_operations(policy: dict[str, Any], project_root: Path) -> None:
    records = policy.get("operation_inventory")
    if not isinstance(records, list) or any(not isinstance(item, dict) for item in records):
        _fail("operation_inventory must contain objects")
    documented: dict[str, Counter[str]] = {}
    for record in records:
        if set(record) != {"path", "operations"}:
            _fail("password-hashing operation fields changed")
        path = _text(record["path"], "operation path")
        raw_operations = record["operations"]
        if not isinstance(raw_operations, dict) or not raw_operations:
            _fail(f"password-hashing operations are invalid for {path}")
        operations: Counter[str] = Counter()
        for operation, count in raw_operations.items():
            operation = _text(operation, f"{path} operation")
            if not isinstance(count, int) or isinstance(count, bool) or count < 1:
                _fail(f"password-hashing operation count is invalid for {path}")
            operations[operation] += count
        if path in documented:
            _fail(f"duplicate password-hashing operation path: {path}")
        documented[path] = operations
    if documented != EXPECTED_OPERATION_INVENTORY:
        _fail("documented password-hashing operation inventory changed")
    discovered = discover_password_operations(project_root)
    if discovered != EXPECTED_OPERATION_INVENTORY:
        _fail(
            "runtime password-hashing operation inventory changed "
            f"(expected={EXPECTED_OPERATION_INVENTORY}, discovered={discovered})"
        )


def _validate_consumers(policy: dict[str, Any], project_root: Path) -> None:
    consumers = policy.get("consumers")
    if not isinstance(consumers, list) or any(not isinstance(item, dict) for item in consumers):
        _fail("password-hashing consumers must contain objects")
    fields = {"id", "purpose", "data", "storage", "evidence"}
    identifiers: set[str] = set()
    for consumer in consumers:
        if set(consumer) != fields:
            _fail("password-hashing consumer fields changed")
        identifier = _text(consumer["id"], "consumer id")
        if identifier in identifiers:
            _fail(f"duplicate password-hashing consumer: {identifier}")
        identifiers.add(identifier)
        for field in ("purpose", "data", "storage"):
            _text(consumer[field], f"{identifier} {field}")
        for evidence in _string_list(consumer["evidence"], f"{identifier} evidence"):
            _safe_path(evidence, project_root=project_root)
    if identifiers != EXPECTED_CONSUMER_IDS:
        _fail("password-hashing consumer inventory changed")


def validate_source_contract(
    assertion_id: str,
    source: str,
    *,
    expected: dict[str, tuple[str, tuple[str, ...]]] = EXPECTED_SOURCE_ASSERTIONS,
) -> None:
    try:
        _, fragments = expected[assertion_id]
    except KeyError:
        _fail(f"unknown password-hashing source assertion: {assertion_id}")
    missing = [fragment for fragment in fragments if fragment not in source]
    if missing:
        _fail(f"password-hashing source contract changed for {assertion_id}: {missing}")


def _validate_source_assertions(policy: dict[str, Any], project_root: Path) -> None:
    assertions = policy.get("source_assertions")
    if not isinstance(assertions, list) or any(not isinstance(item, dict) for item in assertions):
        _fail("password-hashing source_assertions must contain objects")
    documented: dict[str, tuple[str, tuple[str, ...]]] = {}
    for assertion in assertions:
        if set(assertion) != {"id", "path", "contains"}:
            _fail("password-hashing source assertion fields changed")
        identifier = _text(assertion["id"], "source assertion id")
        path = _text(assertion["path"], f"{identifier} source path")
        fragments = tuple(_string_list(assertion["contains"], f"{identifier} fragments"))
        if identifier in documented:
            _fail(f"duplicate password-hashing source assertion: {identifier}")
        documented[identifier] = (path, fragments)
    if documented != EXPECTED_SOURCE_ASSERTIONS:
        _fail("password-hashing source assertion inventory changed")
    for identifier, (relative_path, _) in documented.items():
        source = _safe_path(relative_path, project_root=project_root).read_text(encoding="utf-8")
        validate_source_contract(identifier, source)


def _validate_gate_wiring(project_root: Path) -> None:
    powershell_gate = (project_root / "scripts/check.ps1").read_text(encoding="utf-8")
    shell_gate = (project_root / "scripts/check.sh").read_text(encoding="utf-8")
    if "scripts\\check_password_hashing_policy.py" not in powershell_gate:
        _fail("password-hashing checker is missing from the PowerShell gate")
    if "scripts/check_password_hashing_policy.py" not in shell_gate:
        _fail("password-hashing checker is missing from the shell gate")


def validate_password_hashing_policy(
    policy: dict[str, Any], *, project_root: Path = PROJECT_ROOT, today: date | None = None
) -> None:
    expected_fields = {
        "schema_version",
        "policy_id",
        "asvs_requirement",
        "last_reviewed",
        "next_review_due",
        "production_profile",
        "consumers",
        "operation_inventory",
        "test_only_exception",
        "upgrade_requirements",
        "source_assertions",
        "summary",
    }
    if set(policy) != expected_fields:
        _fail("password-hashing policy fields changed")
    if (
        policy["schema_version"] != 1
        or policy["policy_id"] != "household-budget-password-hashing-v1"
    ):
        _fail("unsupported password-hashing policy identity")
    if policy["asvs_requirement"] != "v5.0.0-11.4.2":
        _fail("password-hashing ASVS requirement changed")

    reviewed = date.fromisoformat(_text(policy["last_reviewed"], "last_reviewed"))
    due = date.fromisoformat(_text(policy["next_review_due"], "next_review_due"))
    if due <= reviewed or (due - reviewed).days > 90:
        _fail("password-hashing review cadence exceeds 90 days")
    if (today or date.today()) > due:
        _fail("password-hashing policy review is overdue")

    expected_profile = {
        "class": "django.contrib.auth.hashers.PBKDF2PasswordHasher",
        "algorithm": "pbkdf2_sha256",
        "pseudorandom_function": "HMAC-SHA-256",
        "iterations": 1_000_000,
        "salt_entropy_bits": 128,
        "django_version": "5.2.17",
    }
    profile = policy.get("production_profile")
    if not isinstance(profile, dict) or set(profile) != {
        *expected_profile,
        "selection",
        "performance_review",
    }:
        _fail("production password-hashing profile fields changed")
    if {key: profile[key] for key in expected_profile} != expected_profile:
        _fail("production password-hashing profile changed")
    _text(profile["selection"], "production profile selection")
    _text(profile["performance_review"], "production performance review")

    _validate_runtime_primitive()
    _validate_settings(project_root)
    _validate_consumers(policy, project_root)
    _validate_operations(policy, project_root)

    if policy.get("test_only_exception") != EXPECTED_TEST_EXCEPTION:
        _fail("test-only password hasher exception changed")
    for evidence in EXPECTED_TEST_EXCEPTION["evidence"]:
        _safe_path(evidence, project_root=project_root)
    if set(_string_list(policy.get("upgrade_requirements"), "upgrade requirements")) != (
        EXPECTED_UPGRADE_REQUIREMENTS
    ):
        _fail("password-hashing upgrade requirements changed")
    _validate_source_assertions(policy, project_root)
    _validate_gate_wiring(project_root)

    expected_summary = {
        "consumers": len(EXPECTED_CONSUMER_IDS),
        "operation_files": len(EXPECTED_OPERATION_INVENTORY),
        "operations": sum(sum(counts.values()) for counts in EXPECTED_OPERATION_INVENTORY.values()),
        "source_assertions": len(EXPECTED_SOURCE_ASSERTIONS),
        "production_hashers": 1,
        "test_only_hashers": 1,
    }
    if policy.get("summary") != expected_summary:
        _fail("password-hashing policy summary is stale")


def main() -> int:
    try:
        policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        if not isinstance(policy, dict):
            _fail("password-hashing policy must be a JSON object")
        validate_password_hashing_policy(policy)
    except (OSError, SyntaxError, TypeError, ValueError, json.JSONDecodeError) as error:
        print(f"password-hashing policy check failed: {error}", file=sys.stderr)
        return 1
    print(
        "Password-hashing policy passed: "
        f"{len(EXPECTED_OPERATION_INVENTORY)} files, "
        f"{sum(sum(counts.values()) for counts in EXPECTED_OPERATION_INVENTORY.values())} "
        "credential operations."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
