"""Validate approved hash functions and bounded compatibility exceptions."""

from __future__ import annotations

import ast
import json
import re
import sys
from collections import Counter
from datetime import date
from pathlib import Path
from typing import Any, NoReturn

import django
from django.contrib.auth.hashers import PBKDF2PasswordHasher
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.signing import Signer, TimestampSigner

PROJECT_ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = PROJECT_ROOT / "docs" / "hash-function-policy.json"
SCRIPT_PATH = "scripts/check_hash_function_policy.py"
PYTHON_ROOTS = (
    "audit",
    "budgets",
    "config",
    "core",
    "debts",
    "deploy",
    "goals",
    "households",
    "identity",
    "imports",
    "ledger",
    "notifications",
    "periods",
    "reserves",
    "schedules",
    "scripts",
    "spending",
)

EXPECTED_PYTHON_OPERATIONS = {
    "audit/checkpoints.py": Counter({"hmac.new:sha256": 1}),
    "audit/services.py": Counter({"hashlib.sha256": 1}),
    "budgets/views.py": Counter(
        {"django.signing.dumps:sha256": 1, "django.signing.loads:sha256": 1}
    ),
    "debts/services/mortgages.py": Counter({"hashlib.sha256": 1}),
    "deploy/pentest/authenticate-sessions.py": Counter({"hmac.new:sha1": 1}),
    "deploy/pentest/run-csv-security.py": Counter({"hashlib.sha256": 1}),
    "deploy/pentest/run-session-security.py": Counter({"hmac.new:sha1": 1}),
    "goals/services.py": Counter({"hashlib.sha256": 2}),
    "identity/management/commands/build_breached_password_corpus.py": Counter(
        {"hashlib.sha1": 1, "hashlib.sha256": 2}
    ),
    "identity/password_validation.py": Counter({"hashlib.sha1": 1, "hashlib.sha256": 1}),
    "identity/services/mfa.py": Counter({"hashlib.sha256": 1, "hmac.new:sha1": 1}),
    "identity/services/sessions.py": Counter({"django.salted_hmac:sha256": 1}),
    "identity/services/throttling.py": Counter({"hmac.new:sha256": 1}),
    "imports/services/batches.py": Counter({"hashlib.sha256": 1}),
    "imports/services/parsing.py": Counter({"hashlib.sha256": 1}),
    "notifications/services.py": Counter({"hashlib.sha256": 1}),
    "periods/services/boundaries.py": Counter({"hashlib.sha256": 1}),
    "periods/services/generation.py": Counter({"hashlib.sha256": 1}),
    "schedules/services/sources.py": Counter({"hashlib.sha256": 1}),
    "scripts/build_asvs_inventory.py": Counter({"hashlib.sha256": 2}),
    "scripts/build_sbom.py": Counter({"hashlib.sha256": 1}),
    "scripts/check_release_evidence.py": Counter({"hashlib.sha256": 1}),
    "scripts/generate-postgres-tls.py": Counter({"openssl:sha256": 3}),
    "scripts/secret_scan.py": Counter({"hashlib.sha256": 1}),
}
EXPECTED_NON_PYTHON_OPERATIONS = {
    "browser-tests/support.mjs": Counter({"node.createHmac:sha1": 1}),
    "deploy/backup/backup.sh": Counter({"sha256sum:sha256": 1}),
}
EXPECTED_APPROVED_FUNCTIONS = {
    "sha256": ("SHA-256", 256),
    "sha512": ("SHA-512", 512),
}
EXPECTED_MANAGED_PROFILE_IDS = {
    "django-framework",
    "fernet-v1",
    "npm-lock-integrity",
    "operating-system-randomness",
    "restic-repository",
    "tailscale-wireguard",
}
EXPECTED_COMPATIBILITY_OPERATIONS = {
    "rfc6238-totp-sha1": {
        "browser-tests/support.mjs": Counter({"node.createHmac:sha1": 1}),
        "deploy/pentest/authenticate-sessions.py": Counter({"hmac.new:sha1": 1}),
        "deploy/pentest/run-session-security.py": Counter({"hmac.new:sha1": 1}),
        "identity/services/mfa.py": Counter({"hmac.new:sha1": 1}),
    },
    "offline-password-blocklist-sha1": {
        "identity/management/commands/build_breached_password_corpus.py": Counter(
            {"hashlib.sha1": 1}
        ),
        "identity/password_validation.py": Counter({"hashlib.sha1": 1}),
    },
}
EXPECTED_TEST_EXCEPTION = {
    "id": "django-md5-password-hasher",
    "algorithm": "MD5",
    "settings": "config.settings.test",
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
        "tests/test_hash_function_policy.py",
        "tests/test_production_settings.py",
    ],
}
EXPECTED_SOURCE_ASSERTIONS = {
    "backup-integrity": (
        "deploy/backup/backup.sh",
        ("sha256sum",),
    ),
    "certificate-signatures": (
        "scripts/generate-postgres-tls.py",
        ('"-sha256"',),
    ),
    "cryptographic-inventory": (
        "docs/cryptographic-inventory.json",
        (
            '"id": "sha256"',
            '"security_status": "approved"',
            '"id": "totp-hmac-sha1"',
            '"id": "password-blocklist-sha1"',
        ),
    ),
    "dependency-lock": (
        "requirements-prod.lock",
        ("Django==5.2.17", "cryptography==50.0.0"),
    ),
    "image-source-integrity": (
        "deploy/backup/Dockerfile",
        ("ADD --checksum=sha256:${RESTIC_SHA256}",),
    ),
    "npm-integrity": (
        "scripts/build_sbom.py",
        ('integrity.startswith("sha512-")',),
    ),
    "password-hashing": (
        "docs/password-hashing-policy.json",
        ('"algorithm": "pbkdf2_sha256"', '"pseudorandom_function": "HMAC-SHA-256"'),
    ),
    "test-only-md5": (
        "config/settings/test.py",
        ('PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]',),
    ),
    "totp-compatibility": (
        "identity/services/mfa.py",
        ("hashlib.sha1",),
    ),
}
EXPECTED_UPGRADE_REQUIREMENTS = {
    "review and approve every new hash function or use case before source adoption",
    "update the cryptographic inventory, this policy, tests, and both quality gates together",
    "retain SHA-1 only while the exact compatibility protocol or corpus format requires it",
    "treat a dependency change that alters a managed hash default as a security-policy change",
    "capture release evidence for provider-managed profiles without recording secret material",
}
_JS_HASH_CALL = re.compile(
    r"\b(?P<function>createHash|createHmac)\(\s*[\"'](?P<algorithm>[A-Za-z0-9_-]+)[\"']"
)
_JS_HASH_INVOCATION = re.compile(r"\b(?:createHash|createHmac)\s*\(")
_JS_WEB_CRYPTO_INVOCATION = re.compile(r"\b(?:crypto\.)?subtle\.(?:digest|sign|deriveBits)\s*\(")
_SHELL_HASH_COMMAND = re.compile(
    r"\b(?P<command>md5sum|sha1sum|sha224sum|sha256sum|sha384sum|sha512sum)\b"
)
_OPENSSL_HASH_FLAG = re.compile(r"^-sha(?P<bits>1|224|256|384|512)$")
_ALGORITHM_NORMALIZATION = {
    "md5": "md5",
    "sha1": "sha1",
    "sha-1": "sha1",
    "sha224": "sha224",
    "sha-224": "sha224",
    "sha256": "sha256",
    "sha-256": "sha256",
    "sha384": "sha384",
    "sha-384": "sha384",
    "sha512": "sha512",
    "sha-512": "sha512",
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
        _fail(f"hash-function evidence must be relative: {relative_path}")
    path = (project_root / relative_path).resolve()
    try:
        path.relative_to(project_root.resolve())
    except ValueError:
        _fail(f"hash-function evidence escapes project root: {relative_path}")
    if not path.exists():
        _fail(f"missing hash-function evidence: {relative_path}")
    return path


def _normalized_algorithm(value: str, *, context: str) -> str:
    try:
        return _ALGORITHM_NORMALIZATION[value.lower()]
    except KeyError:
        _fail(f"unapproved hash algorithm {value!r} in {context}")


def _keyword(call: ast.Call, name: str) -> ast.expr | None:
    return next((item.value for item in call.keywords if item.arg == name), None)


def _constant_string(node: ast.expr | None, *, context: str) -> str:
    if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
        _fail(f"hash algorithm must be a literal string in {context}")
    return node.value


def _hmac_algorithm(call: ast.Call, *, context: str) -> str:
    digest_node = call.args[2] if len(call.args) >= 3 else _keyword(call, "digestmod")
    if (
        isinstance(digest_node, ast.Attribute)
        and isinstance(digest_node.value, ast.Name)
        and digest_node.value.id == "hashlib"
    ):
        algorithm = _normalized_algorithm(digest_node.attr, context=context)
        if algorithm not in {"sha1", "sha256"}:
            _fail(f"unapproved HMAC hash algorithm {algorithm!r} in {context}")
        return algorithm
    if isinstance(digest_node, ast.Constant) and isinstance(digest_node.value, str):
        algorithm = _normalized_algorithm(digest_node.value, context=context)
        if algorithm not in {"sha1", "sha256"}:
            _fail(f"unapproved HMAC hash algorithm {algorithm!r} in {context}")
        return algorithm
    _fail(f"HMAC digest must be an explicit hashlib function in {context}")


def scan_python_hash_operations(source: str, relative_path: str) -> Counter[str]:
    """Return selected hash operations while rejecting dynamic or unknown algorithms."""

    tree = ast.parse(source, filename=relative_path)
    operations: Counter[str] = Counter()
    parents = {
        id(child): parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for imported in node.names:
                if imported.name in {"hashlib", "hmac"} and imported.asname:
                    _fail(f"aliased hash import in {relative_path}:{node.lineno}")
                if imported.name == "django.core.signing":
                    _fail(f"unreviewed Django signing import in {relative_path}:{node.lineno}")
        elif isinstance(node, ast.ImportFrom):
            if node.module in {"hashlib", "hmac"}:
                _fail(f"direct hash-function import in {relative_path}:{node.lineno}")
            if node.module == "django.core.signing":
                _fail(f"direct Django signing import in {relative_path}:{node.lineno}")
            if node.module == "django.core" and any(
                imported.name == "signing" and imported.asname for imported in node.names
            ):
                _fail(f"aliased Django signing import in {relative_path}:{node.lineno}")
            if node.module == "django.utils.crypto" and any(
                imported.name == "salted_hmac" and imported.asname for imported in node.names
            ):
                _fail(f"aliased Django HMAC import in {relative_path}:{node.lineno}")
            if (
                node.module
                and node.module.startswith("cryptography.hazmat.primitives")
                and any(
                    imported.name == "hashes" or node.module.endswith(".hashes")
                    for imported in node.names
                )
            ):
                _fail(f"unreviewed cryptography hash import in {relative_path}:{node.lineno}")

        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "hashlib"
        ):
            if node.attr not in {"sha1", "sha256"}:
                _fail(
                    f"unapproved hashlib attribute {node.attr!r} in {relative_path}:{node.lineno}"
                )
            parent = parents.get(id(node))
            if not isinstance(parent, ast.Call):
                _fail(f"indirect hashlib function reference in {relative_path}:{node.lineno}")
            is_direct_call = parent.func is node
            is_hmac_digest = (
                isinstance(parent.func, ast.Attribute)
                and isinstance(parent.func.value, ast.Name)
                and parent.func.value.id == "hmac"
                and parent.func.attr == "new"
            )
            if not (is_direct_call or is_hmac_digest):
                _fail(f"indirect hashlib function reference in {relative_path}:{node.lineno}")

        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "hmac"
        ):
            parent = parents.get(id(node))
            if not isinstance(parent, ast.Call) or parent.func is not node:
                _fail(f"indirect HMAC function reference in {relative_path}:{node.lineno}")

        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            match = _OPENSSL_HASH_FLAG.fullmatch(node.value.lower())
            if match:
                algorithm = _normalized_algorithm(
                    f"sha{match.group('bits')}", context=f"{relative_path}:{node.lineno}"
                )
                if algorithm != "sha256":
                    _fail(f"unapproved OpenSSL hash flag in {relative_path}:{node.lineno}")
                operations[f"openssl:{algorithm}"] += 1

        if not isinstance(node, ast.Call):
            continue
        context = f"{relative_path}:{node.lineno}"
        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "hashlib"
        ):
            algorithm = _normalized_algorithm(node.func.attr, context=context)
            if algorithm == "sha1":
                used_for_security = _keyword(node, "usedforsecurity")
                if not (
                    isinstance(used_for_security, ast.Constant) and used_for_security.value is False
                ):
                    _fail(f"direct SHA-1 lacks usedforsecurity=False in {context}")
            operations[f"hashlib.{algorithm}"] += 1
        elif (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "hmac"
        ):
            if node.func.attr != "new":
                if node.func.attr != "compare_digest":
                    _fail(f"unreviewed HMAC API in {context}")
                continue
            algorithm = _hmac_algorithm(node, context=context)
            operations[f"hmac.new:{algorithm}"] += 1
        elif (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "signing"
        ):
            if node.func.attr not in {"dumps", "loads"}:
                _fail(f"unreviewed Django signing API in {context}")
            operations[f"django.signing.{node.func.attr}:sha256"] += 1
        elif isinstance(node.func, ast.Name) and node.func.id == "salted_hmac":
            algorithm = _normalized_algorithm(
                _constant_string(_keyword(node, "algorithm"), context=context), context=context
            )
            if algorithm != "sha256":
                _fail(f"Django salted_hmac must use SHA-256 in {context}")
            operations[f"django.salted_hmac:{algorithm}"] += 1
    return operations


def discover_python_hash_operations(
    project_root: Path = PROJECT_ROOT,
) -> dict[str, Counter[str]]:
    discovered: dict[str, Counter[str]] = {}
    for root_name in PYTHON_ROOTS:
        root = project_root / root_name
        if not root.exists():
            continue
        for path in sorted(root.rglob("*.py")):
            relative = path.relative_to(project_root).as_posix()
            if relative == SCRIPT_PATH or "/migrations/" in f"/{relative}":
                continue
            operations = scan_python_hash_operations(path.read_text(encoding="utf-8"), relative)
            if operations:
                discovered[relative] = operations
    return discovered


def scan_non_python_hash_operations(source: str, relative_path: str) -> Counter[str]:
    operations: Counter[str] = Counter()
    javascript_calls = list(_JS_HASH_CALL.finditer(source))
    if len(javascript_calls) != len(_JS_HASH_INVOCATION.findall(source)):
        _fail(f"dynamic JavaScript hash selection in {relative_path}")
    if _JS_WEB_CRYPTO_INVOCATION.search(source):
        _fail(f"unreviewed Web Crypto hash selection in {relative_path}")
    for match in javascript_calls:
        algorithm = _normalized_algorithm(match.group("algorithm"), context=relative_path)
        if algorithm not in {"sha1", "sha256", "sha512"}:
            _fail(f"unapproved JavaScript hash algorithm {algorithm!r} in {relative_path}")
        operations[f"node.{match.group('function')}:{algorithm}"] += 1
    for match in _SHELL_HASH_COMMAND.finditer(source):
        command = match.group("command")
        algorithm = _normalized_algorithm(command.removesuffix("sum"), context=relative_path)
        if algorithm not in {"sha256", "sha512"}:
            _fail(f"unapproved shell hash algorithm {algorithm!r} in {relative_path}")
        operations[f"{command}:{algorithm}"] += 1
    return operations


def discover_non_python_hash_operations(
    project_root: Path = PROJECT_ROOT,
) -> dict[str, Counter[str]]:
    discovered: dict[str, Counter[str]] = {}
    suffixes = {".js", ".mjs", ".cjs", ".ts", ".html", ".sh", ".ps1"}
    paths = {
        path
        for root_name in (*PYTHON_ROOTS, "browser-tests")
        for path in (project_root / root_name).rglob("*")
        if path.is_file() and path.suffix in suffixes
    }
    paths.update(path for path in project_root.iterdir() if path.suffix in suffixes)
    for path in sorted(paths):
        relative = path.relative_to(project_root).as_posix()
        operations = scan_non_python_hash_operations(path.read_text(encoding="utf-8"), relative)
        if operations:
            discovered[relative] = operations
    return discovered


def _operation_inventory(records: Any, *, label: str) -> dict[str, Counter[str]]:
    if not isinstance(records, list) or any(not isinstance(item, dict) for item in records):
        _fail(f"{label} must contain objects")
    documented: dict[str, Counter[str]] = {}
    for record in records:
        if set(record) != {"operations", "path", "purpose", "status"}:
            _fail(f"{label} fields changed")
        path = _text(record["path"], f"{label} path")
        _text(record["purpose"], f"{path} purpose")
        if record["status"] not in {"approved", "compatibility_only", "mixed_reviewed"}:
            _fail(f"invalid hash operation status for {path}")
        raw_operations = record["operations"]
        if not isinstance(raw_operations, dict) or not raw_operations:
            _fail(f"hash operations are invalid for {path}")
        operations: Counter[str] = Counter()
        for operation, count in raw_operations.items():
            operation = _text(operation, f"{path} operation")
            if not isinstance(count, int) or isinstance(count, bool) or count < 1:
                _fail(f"hash operation count is invalid for {path}")
            operations[operation] += count
        if path in documented:
            _fail(f"duplicate hash operation path: {path}")
        documented[path] = operations
    return documented


def _validate_operation_inventories(policy: dict[str, Any], project_root: Path) -> None:
    python_inventory = _operation_inventory(
        policy.get("python_operation_inventory"), label="python_operation_inventory"
    )
    non_python_inventory = _operation_inventory(
        policy.get("non_python_operation_inventory"), label="non_python_operation_inventory"
    )
    if python_inventory != EXPECTED_PYTHON_OPERATIONS:
        _fail("documented Python hash-operation inventory changed")
    if non_python_inventory != EXPECTED_NON_PYTHON_OPERATIONS:
        _fail("documented non-Python hash-operation inventory changed")
    discovered_python = discover_python_hash_operations(project_root)
    if discovered_python != EXPECTED_PYTHON_OPERATIONS:
        _fail(
            "Python hash-operation inventory changed "
            f"(expected={EXPECTED_PYTHON_OPERATIONS}, discovered={discovered_python})"
        )
    discovered_non_python = discover_non_python_hash_operations(project_root)
    if discovered_non_python != EXPECTED_NON_PYTHON_OPERATIONS:
        _fail(
            "non-Python hash-operation inventory changed "
            f"(expected={EXPECTED_NON_PYTHON_OPERATIONS}, discovered={discovered_non_python})"
        )


def _validate_approved_functions(policy: dict[str, Any], project_root: Path) -> None:
    records = policy.get("approved_hash_functions")
    if not isinstance(records, list) or any(not isinstance(item, dict) for item in records):
        _fail("approved_hash_functions must contain objects")
    documented: dict[str, tuple[str, int]] = {}
    for record in records:
        if set(record) != {
            "digest_bits",
            "evidence",
            "id",
            "name",
            "permitted_uses",
            "prohibited_uses",
            "status",
        }:
            _fail("approved hash-function fields changed")
        identifier = _text(record["id"], "approved hash-function id")
        if record["status"] != "approved":
            _fail(f"approved hash function {identifier} has an invalid status")
        name = _text(record["name"], f"{identifier} name")
        digest_bits = record["digest_bits"]
        if not isinstance(digest_bits, int) or isinstance(digest_bits, bool) or digest_bits < 256:
            _fail(f"approved hash function {identifier} is below 256 bits")
        for field in ("permitted_uses", "prohibited_uses", "evidence"):
            values = _string_list(record[field], f"{identifier} {field}")
            if field == "evidence":
                for evidence in values:
                    _safe_path(evidence, project_root=project_root)
        if identifier in documented:
            _fail(f"duplicate approved hash function: {identifier}")
        documented[identifier] = (name, digest_bits)
    if documented != EXPECTED_APPROVED_FUNCTIONS:
        _fail("approved hash-function inventory changed")


def _validate_compatibility_exceptions(policy: dict[str, Any], project_root: Path) -> None:
    records = policy.get("compatibility_exceptions")
    if not isinstance(records, list) or any(not isinstance(item, dict) for item in records):
        _fail("compatibility_exceptions must contain objects")
    documented: dict[str, dict[str, Counter[str]]] = {}
    for record in records:
        if set(record) != {
            "algorithm",
            "evidence",
            "id",
            "operations",
            "protocol_or_format",
            "restrictions",
            "status",
        }:
            _fail("compatibility-exception fields changed")
        identifier = _text(record["id"], "compatibility exception id")
        if identifier in documented:
            _fail(f"duplicate compatibility exception: {identifier}")
        if record["algorithm"] != "SHA-1" or record["status"] != "compatibility_only":
            _fail(f"compatibility exception {identifier} must remain bounded SHA-1")
        _text(record["protocol_or_format"], f"{identifier} protocol_or_format")
        _string_list(record["restrictions"], f"{identifier} restrictions")
        for evidence in _string_list(record["evidence"], f"{identifier} evidence"):
            _safe_path(evidence, project_root=project_root)
        operations = _operation_inventory(record["operations"], label=f"{identifier} operations")
        documented[identifier] = operations
    if documented != EXPECTED_COMPATIBILITY_OPERATIONS:
        _fail("SHA-1 compatibility exception inventory changed")


def _validate_managed_profiles(policy: dict[str, Any], project_root: Path) -> None:
    records = policy.get("managed_profiles")
    if not isinstance(records, list) or any(not isinstance(item, dict) for item in records):
        _fail("managed_profiles must contain objects")
    identifiers: set[str] = set()
    for record in records:
        if set(record) != {
            "evidence",
            "hash_functions",
            "id",
            "owner",
            "restrictions",
            "status",
        }:
            _fail("managed hash-profile fields changed")
        identifier = _text(record["id"], "managed profile id")
        if identifier in identifiers:
            _fail(f"duplicate managed hash profile: {identifier}")
        identifiers.add(identifier)
        _text(record["owner"], f"{identifier} owner")
        if record["status"] not in {"approved", "provider_managed"}:
            _fail(f"managed hash profile {identifier} has an invalid status")
        _string_list(record["hash_functions"], f"{identifier} hash_functions")
        _string_list(record["restrictions"], f"{identifier} restrictions")
        for evidence in _string_list(record["evidence"], f"{identifier} evidence"):
            _safe_path(evidence, project_root=project_root)
    if identifiers != EXPECTED_MANAGED_PROFILE_IDS:
        _fail("managed hash-profile inventory changed")


def _validate_runtime_defaults() -> None:
    signer = Signer(key="hash-policy-check", fallback_keys=[])
    timestamp_signer = TimestampSigner(key="hash-policy-check", fallback_keys=[])
    password_token = PasswordResetTokenGenerator()
    password_hasher = PBKDF2PasswordHasher()
    actual = {
        "django_version": django.get_version(),
        "signer": signer.algorithm,
        "timestamp_signer": timestamp_signer.algorithm,
        "password_token": password_token.algorithm,
        "password_prf": password_hasher.digest().name,
    }
    expected = {
        "django_version": "5.2.17",
        "signer": "sha256",
        "timestamp_signer": "sha256",
        "password_token": "sha256",  # pragma: allowlist secret
        "password_prf": "sha256",  # pragma: allowlist secret
    }
    if actual != expected:
        _fail(f"managed Django hash defaults changed: {actual}")


def _validate_source_assertions(policy: dict[str, Any], project_root: Path) -> None:
    records = policy.get("source_assertions")
    if not isinstance(records, list) or any(not isinstance(item, dict) for item in records):
        _fail("source_assertions must contain objects")
    documented: dict[str, tuple[str, tuple[str, ...]]] = {}
    for record in records:
        if set(record) != {"contains", "id", "path"}:
            _fail("hash source-assertion fields changed")
        identifier = _text(record["id"], "source assertion id")
        path = _text(record["path"], f"{identifier} path")
        fragments = tuple(_string_list(record["contains"], f"{identifier} contains"))
        if identifier in documented:
            _fail(f"duplicate hash source assertion: {identifier}")
        documented[identifier] = (path, fragments)
    if documented != EXPECTED_SOURCE_ASSERTIONS:
        _fail("hash source-assertion inventory changed")
    for identifier, (relative_path, fragments) in documented.items():
        source = _safe_path(relative_path, project_root=project_root).read_text(encoding="utf-8")
        missing = [fragment for fragment in fragments if fragment not in source]
        if missing:
            _fail(f"hash source contract changed for {identifier}: {missing}")


def _validate_gate_wiring(project_root: Path) -> None:
    powershell_gate = (project_root / "scripts/check.ps1").read_text(encoding="utf-8")
    shell_gate = (project_root / "scripts/check.sh").read_text(encoding="utf-8")
    if "scripts\\check_hash_function_policy.py" not in powershell_gate:
        _fail("hash-function checker is missing from the PowerShell gate")
    if "scripts/check_hash_function_policy.py" not in shell_gate:
        _fail("hash-function checker is missing from the shell gate")


def validate_hash_function_policy(
    policy: dict[str, Any], *, project_root: Path = PROJECT_ROOT, today: date | None = None
) -> None:
    expected_fields = {
        "approved_hash_functions",
        "asvs_requirement",
        "compatibility_exceptions",
        "last_reviewed",
        "managed_profiles",
        "next_review_due",
        "non_python_operation_inventory",
        "policy_id",
        "python_operation_inventory",
        "schema_version",
        "source_assertions",
        "summary",
        "test_only_exception",
        "upgrade_requirements",
    }
    if set(policy) != expected_fields:
        _fail("hash-function policy fields changed")
    if policy["schema_version"] != 1 or policy["policy_id"] != "household-budget-hashes-v1":
        _fail("unsupported hash-function policy identity")
    if policy["asvs_requirement"] != "v5.0.0-11.4.1":
        _fail("hash-function ASVS requirement changed")

    reviewed = date.fromisoformat(_text(policy["last_reviewed"], "last_reviewed"))
    due = date.fromisoformat(_text(policy["next_review_due"], "next_review_due"))
    if due <= reviewed or (due - reviewed).days > 90:
        _fail("hash-function review cadence exceeds 90 days")
    if (today or date.today()) > due:
        _fail("hash-function policy review is overdue")

    _validate_approved_functions(policy, project_root)
    _validate_managed_profiles(policy, project_root)
    _validate_compatibility_exceptions(policy, project_root)
    if policy.get("test_only_exception") != EXPECTED_TEST_EXCEPTION:
        _fail("test-only MD5 exception changed")
    for evidence in EXPECTED_TEST_EXCEPTION["evidence"]:
        _safe_path(evidence, project_root=project_root)
    if set(_string_list(policy.get("upgrade_requirements"), "upgrade_requirements")) != (
        EXPECTED_UPGRADE_REQUIREMENTS
    ):
        _fail("hash-function upgrade requirements changed")
    _validate_operation_inventories(policy, project_root)
    _validate_source_assertions(policy, project_root)
    _validate_runtime_defaults()
    _validate_gate_wiring(project_root)

    python_count = sum(
        sum(operations.values()) for operations in EXPECTED_PYTHON_OPERATIONS.values()
    )
    non_python_count = sum(
        sum(operations.values()) for operations in EXPECTED_NON_PYTHON_OPERATIONS.values()
    )
    compatibility_count = sum(
        sum(sum(operations.values()) for operations in exception.values())
        for exception in EXPECTED_COMPATIBILITY_OPERATIONS.values()
    )
    expected_summary = {
        "approved_hash_functions": len(EXPECTED_APPROVED_FUNCTIONS),
        "managed_profiles": len(EXPECTED_MANAGED_PROFILE_IDS),
        "operation_files": len(EXPECTED_PYTHON_OPERATIONS) + len(EXPECTED_NON_PYTHON_OPERATIONS),
        "operations": python_count + non_python_count,
        "compatibility_exceptions": len(EXPECTED_COMPATIBILITY_OPERATIONS),
        "compatibility_operations": compatibility_count,
        "test_only_exceptions": 1,
        "source_assertions": len(EXPECTED_SOURCE_ASSERTIONS),
    }
    if policy.get("summary") != expected_summary:
        _fail("hash-function policy summary does not match its inventory")


def main() -> int:
    try:
        policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        validate_hash_function_policy(policy)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"Hash-function policy validation failed: {error}", file=sys.stderr)
        return 1
    print(
        "Hash-function policy passed: "
        f"{policy['summary']['operation_files']} files, "
        f"{policy['summary']['operations']} operations, "
        f"{policy['summary']['compatibility_operations']} bounded SHA-1 compatibility operations."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
