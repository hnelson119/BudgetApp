"""Validate the maintained cryptographic inventory without reading live secret material."""

from __future__ import annotations

import json
import re
import sys
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import django
from django.contrib.auth.hashers import PBKDF2PasswordHasher

PROJECT_ROOT = Path(__file__).resolve().parents[1]
INVENTORY_PATH = PROJECT_ROOT / "docs" / "cryptographic-inventory.json"

EXPECTED_KEY_IDS = {
    "audit-checkpoint-signing-key",
    "django-signing-key",
    "gunicorn-server-ca-private-key",
    "gunicorn-server-private-key",
    "mfa-encryption-key",
    "nginx-client-ca-private-key",
    "nginx-client-private-key",
    "postgres-client-ca-private-key",
    "postgres-client-private-keys",
    "postgres-internal-ca-private-key",
    "postgres-server-private-key",
    "restic-master-keys",
    "restic-repository-password",
    "ssh-administrator-keys",
    "tailscale-node-transport-keys",
    "tailscale-serve-tls-private-key",
    "user-totp-seeds",
}
EXPECTED_ALGORITHM_IDS = {
    "django-pbkdf2-hmac-sha256",
    "fernet-v1",
    "hmac-sha256",
    "internal-web-mtls",
    "os-csprng",
    "password-blocklist-sha1",
    "postgres-internal-tls",
    "restic-aes256-ctr-poly1305-aes",
    "restic-scrypt",
    "sha256",
    "ssh-approved-suite",
    "tailscale-wireguard-suite",
    "test-md5-password-hasher",
    "tls12-tls13",
    "totp-hmac-sha1",
}
EXPECTED_CERTIFICATE_IDS = {
    "browser-public-trust-roots",
    "gunicorn-server-ca-certificate",
    "gunicorn-server-certificate",
    "nginx-client-ca-certificate",
    "nginx-client-certificate",
    "postgres-internal-ca-certificate",
    "postgres-client-ca-certificate",
    "postgres-role-client-certificates",
    "postgres-server-certificate",
    "tailscale-serve-leaf-certificate",
}
EXPECTED_ABSENCE_IDS = {
    "reusable-tailscale-auth-keys",
}
EXPECTED_UPDATE_TRIGGERS = {
    "application or infrastructure cryptography changes",
    "a key, certificate, trust boundary, or secret consumer changes",
    "a pinned cryptographic dependency or managed provider changes",
    "every release candidate",
    "a security finding or incident affects cryptographic material",
}
EXPECTED_LIFECYCLE_PHASES = [
    "generation",
    "protected distribution",
    "activation",
    "rotation",
    "suspension or revocation",
    "retirement",
    "destruction",
]
EXPECTED_TRUST_ENTITY_DEFINITION = (
    "One independently authorized runtime, provider, person, or device permitted to perform "
    "cryptographic operations with secret or private key material. Purpose-specific processes "
    "inside one hardened application boundary are one trust entity; public keys and certificates "
    "are not secret holders, and sealed recovery custody or file provisioning alone does not "
    "authorize cryptographic use."
)
EXPECTED_KEY_MANAGEMENT_CONTROLS = {
    (
        "Generate independent purpose-specific material with an approved CSPRNG or approved "
        "managed provider."
    ),
    (
        "Distribute material only through protected files, provider state, or direct enrollment; "
        "never through source control, logs, command lines, or ordinary environment values."
    ),
    (
        "Activate material only after its identifier, purpose, consumers, storage, algorithm, "
        "and recovery boundary are recorded in this inventory."
    ),
    (
        "Do not authorize more than two trust entities to use one shared secret or more than one "
        "active trust entity to use one private key."
    ),
    (
        "Keep recovery and retired verification copies sealed and inactive; mounting or "
        "unsealing one is a separately authorized maintenance event."
    ),
    (
        "Rotate on the documented schedule, ownership or consumer change, suspected exposure, "
        "algorithm or parameter deprecation, or provider incident."
    ),
    (
        "Revoke or suspend affected consumers before replacement when exposure is suspected, "
        "and prove retired access fails before service resumes."
    ),
    (
        "Destroy retired material when its documented retention purpose ends; retain only keys "
        "explicitly required for historical verification or disaster recovery."
    ),
}
KEY_FIELDS = {
    "algorithms",
    "boundary",
    "consumers",
    "evidence",
    "excluded_data",
    "generation",
    "id",
    "material_type",
    "name",
    "owner",
    "permitted_uses",
    "prohibited_uses",
    "protected_data",
    "retirement",
    "rotation",
    "state",
    "storage",
}
ALGORITHM_FIELDS = {
    "consumers",
    "evidence",
    "id",
    "name",
    "parameters",
    "permitted_uses",
    "prohibited_uses",
    "scope",
    "security_status",
}
CERTIFICATE_FIELDS = {
    "algorithms",
    "boundary",
    "evidence",
    "id",
    "issuer",
    "name",
    "owner",
    "key_residency",
    "prohibited_uses",
    "renewal",
    "state",
    "subject",
    "validation",
}
ABSENCE_FIELDS = {
    "current_state",
    "evidence",
    "id",
    "related_asvs",
    "required_action",
}
TEXT_KEY_FIELDS = KEY_FIELDS - {
    "algorithms",
    "consumers",
    "evidence",
    "excluded_data",
    "permitted_uses",
    "prohibited_uses",
    "protected_data",
}
TEXT_ALGORITHM_FIELDS = ALGORITHM_FIELDS - {
    "consumers",
    "evidence",
    "permitted_uses",
    "prohibited_uses",
}
TEXT_CERTIFICATE_FIELDS = CERTIFICATE_FIELDS - {
    "algorithms",
    "evidence",
    "prohibited_uses",
}
TEXT_ABSENCE_FIELDS = ABSENCE_FIELDS - {"evidence", "related_asvs"}
ALLOWED_KEY_STATES = {"active", "deployment_managed", "provider_managed"}
ALLOWED_BOUNDARIES = {"application", "deployment", "provider"}
ALLOWED_SECURITY_STATUSES = {
    "approved",
    "compatibility_only",
    "deployment_managed",
    "provider_managed",
    "test_only",
}
NON_KEY_ALGORITHMS = {
    "django-pbkdf2-hmac-sha256",
    "password-blocklist-sha1",
    "test-md5-password-hasher",
}
_ASVS_ID = re.compile(r"^v5\.0\.0-([1-9]|1[0-7])\.[1-9][0-9]*\.[1-9][0-9]*$")
_EXACT_TAILSCALE_HOST = re.compile(
    r"\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\."
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.ts\.net\b"
)
_BANNED_FIELDS = {
    "certificate_pem",
    "material_value",
    "password",
    "private_key",
    "secret",
    "token",
    "value",
}
_PEM_MARKERS = (
    "BEGIN " + "PRIVATE" + " KEY",
    "BEGIN RSA " + "PRIVATE" + " KEY",
    "BEGIN EC " + "PRIVATE" + " KEY",
)


def _fail(message: str) -> None:
    raise ValueError(message)


def _parse_date(value: Any, *, field: str) -> date:
    if not isinstance(value, str):
        _fail(f"{field} must be an ISO date")
    try:
        parsed = date.fromisoformat(value)
    except ValueError:
        _fail(f"{field} must be an ISO date")
    if parsed.isoformat() != value:
        _fail(f"{field} must be an ISO date")
    return parsed


def _validate_text(value: Any, *, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        _fail(f"{field} must be non-empty text")


def _validate_string_list(value: Any, *, field: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or not all(isinstance(item, str) and item.strip() for item in value)
    ):
        _fail(f"{field} must be a non-empty string list")
    if len(value) != len(set(value)):
        _fail(f"{field} contains duplicate values")
    return value


def _validate_evidence(value: Any, *, item: str) -> None:
    paths = _validate_string_list(value, field=f"{item}.evidence")
    for path in paths:
        if path.startswith("https://"):
            continue
        if path.startswith("http://"):
            _fail(f"{item} references non-HTTPS evidence {path!r}")
        relative_path = path.split("#", maxsplit=1)[0]
        candidate = (PROJECT_ROOT / relative_path).resolve()
        if PROJECT_ROOT not in candidate.parents and candidate != PROJECT_ROOT:
            _fail(f"{item} references evidence outside the project")
        if not candidate.exists():
            _fail(f"{item} references missing evidence {path!r}")


def _validate_no_embedded_material(value: Any, *, path: tuple[str, ...] = ()) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key.casefold() in _BANNED_FIELDS:
                _fail(f"inventory uses prohibited material field {'.'.join((*path, key))}")
            _validate_no_embedded_material(child, path=(*path, key))
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            _validate_no_embedded_material(child, path=(*path, str(index)))
        return
    if isinstance(value, str):
        if any(marker in value for marker in _PEM_MARKERS):
            _fail(f"inventory contains private-key material at {'.'.join(path)}")
        if _EXACT_TAILSCALE_HOST.search(value):
            _fail(f"inventory contains an exact private hostname at {'.'.join(path)}")


def _validate_record_set(
    value: Any,
    *,
    collection: str,
    expected_ids: set[str],
    expected_fields: set[str],
    text_fields: set[str],
    list_fields: set[str],
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    if not isinstance(value, list):
        _fail(f"{collection} must be a list")
    records: list[dict[str, Any]] = []
    by_id: dict[str, dict[str, Any]] = {}
    for raw_record in value:
        if not isinstance(raw_record, dict):
            _fail(f"{collection} entries must be objects")
        record_id = raw_record.get("id")
        if not isinstance(record_id, str):
            _fail(f"{collection} entry has an invalid id")
        if record_id in by_id:
            _fail(f"{collection} contains duplicate id {record_id!r}")
        if set(raw_record) != expected_fields:
            _fail(f"{collection} {record_id!r} has an incomplete or unexpected schema")
        for field in text_fields:
            _validate_text(raw_record[field], field=f"{collection}.{record_id}.{field}")
        for field in list_fields:
            _validate_string_list(raw_record[field], field=f"{collection}.{record_id}.{field}")
        _validate_evidence(raw_record["evidence"], item=f"{collection}.{record_id}")
        records.append(raw_record)
        by_id[record_id] = raw_record
    if set(by_id) != expected_ids:
        _fail(f"{collection} identifiers are incomplete")
    return records, by_id


def _validate_dependency_contract(algorithms: dict[str, dict[str, Any]]) -> None:
    expected_django = django.get_version()
    hasher = PBKDF2PasswordHasher()
    parameters = algorithms["django-pbkdf2-hmac-sha256"]["parameters"]
    if (
        f"Django {expected_django} PBKDF2PasswordHasher" not in parameters
        or f"{hasher.iterations:,} iterations" not in parameters
        or hasher.algorithm != "pbkdf2_sha256"
    ):
        _fail("production PBKDF2 inventory does not match the installed Django dependency")

    project = (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    if f'"Django=={expected_django}"' not in project:
        _fail("installed Django version is not exactly pinned in pyproject.toml")
    if '"cryptography==50.0.0"' not in project:
        _fail("the inventoried cryptography dependency is not pinned to 50.0.0")

    backup_image = (PROJECT_ROOT / "deploy" / "backup" / "Dockerfile").read_text(encoding="utf-8")
    if "ARG RESTIC_VERSION=0.19.1" not in backup_image:
        _fail("the inventoried Restic version is not pinned to 0.19.1")

    test_settings = (PROJECT_ROOT / "config" / "settings" / "test.py").read_text(encoding="utf-8")
    if 'PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]' not in test_settings:
        _fail("the inventoried test-only MD5 exception no longer matches test settings")

    compose = (PROJECT_ROOT / "compose.yaml").read_text(encoding="utf-8")
    gunicorn = (PROJECT_ROOT / "config/gunicorn.py").read_text(encoding="utf-8")
    nginx = (PROJECT_ROOT / "deploy/network/nginx.conf").read_text(encoding="utf-8")
    postgres_startup = (PROJECT_ROOT / "deploy/postgres/start-tls.sh").read_text(encoding="utf-8")
    postgres_hba = (PROJECT_ROOT / "deploy/postgres/pg_hba.conf").read_text(encoding="utf-8")
    if (
        "PGSSLMODE: verify-full" not in compose
        or "PGSSLCERT:" not in compose
        or "PGSSLKEY:" not in compose
        or "postgres_client_ca_certificate" not in compose
        or "postgres_server_private_key" not in compose
        or "ssl_min_protocol_version=TLSv1.2" not in postgres_startup
        or "ssl_max_protocol_version=TLSv1.3" not in postgres_startup
        or "hostssl all all all cert map=budget_service" not in postgres_hba
        or "hostnossl all all all reject" not in postgres_hba
    ):
        _fail("the inventoried PostgreSQL TLS policy no longer matches deployment source")

    if (
        "gunicorn_client_ca_certificate" not in compose
        or "gunicorn_server_private_key" not in compose
        or "nginx_client_certificate" not in compose
        or 'bind = "0.0.0.0:8443"' not in gunicorn
        or "cert_reqs = ssl.CERT_REQUIRED" not in gunicorn
        or "context.minimum_version = ssl.TLSVersion.TLSv1_2" not in gunicorn
        or "context.maximum_version = ssl.TLSVersion.TLSv1_3" not in gunicorn
        or "proxy_pass https://web:8443;" not in nginx
        or "proxy_ssl_name web;" not in nginx
        or "proxy_ssl_verify on;" not in nginx
        or "proxy_ssl_protocols TLSv1.2 TLSv1.3;" not in nginx
        or "proxy_ssl_certificate /run/secrets/nginx_client_certificate;" not in nginx
        or "proxy_ssl_trusted_certificate /run/secrets/gunicorn_ca_certificate;" not in nginx
        or "default http;" not in nginx
        or "~^https$ https;" not in nginx
        or "proxy_set_header X-Forwarded-Proto $upstream_forwarded_proto;" not in nginx
    ):
        _fail("the inventoried internal web mutual-TLS policy no longer matches deployment source")


def validate_inventory(data: Any, *, today: date | None = None) -> None:
    if not isinstance(data, dict):
        _fail("cryptographic inventory must be a JSON object")
    expected_top_level = {
        "algorithms",
        "certificates",
        "cryptographic_keys",
        "inventory_updated",
        "key_management_policy",
        "known_absences",
        "review",
        "schema_version",
        "scope",
        "summary",
    }
    if set(data) != expected_top_level:
        _fail("cryptographic inventory top-level schema is incomplete or unexpected")
    if data["schema_version"] != 1:
        _fail("unsupported cryptographic inventory schema version")

    review = data["review"]
    if not isinstance(review, dict) or set(review) != {
        "cadence_days",
        "next_review_due",
        "owner",
        "procedure",
        "update_triggers",
    }:
        _fail("cryptographic inventory review policy is incomplete")
    if (
        review["owner"] != "release owner"
        or review["procedure"] != "docs/CRYPTOGRAPHIC_INVENTORY.md"
    ):
        _fail("cryptographic inventory review ownership or procedure changed unexpectedly")
    if review["cadence_days"] != 90:
        _fail("cryptographic inventory review cadence must remain 90 days")
    triggers = _validate_string_list(review["update_triggers"], field="review.update_triggers")
    if set(triggers) != EXPECTED_UPDATE_TRIGGERS:
        _fail("cryptographic inventory update triggers are incomplete")

    updated = _parse_date(data["inventory_updated"], field="inventory_updated")
    due = _parse_date(review["next_review_due"], field="review.next_review_due")
    if due != updated + timedelta(days=review["cadence_days"]):
        _fail("next cryptographic inventory review is not exactly one cadence after the update")
    current_date = date.today() if today is None else today
    if updated > current_date:
        _fail("cryptographic inventory update date is in the future")
    if current_date > due:
        _fail("cryptographic inventory review is overdue")

    policy = data["key_management_policy"]
    if not isinstance(policy, dict) or set(policy) != {
        "lifecycle_phases",
        "offline_recovery_is_inactive",
        "owner",
        "private_key_max_active_trust_entities",
        "required_controls",
        "shared_secret_max_trust_entities",
        "standard",
        "trust_entity_definition",
    }:
        _fail("cryptographic key-management policy is incomplete")
    if (
        policy["standard"] != "NIST SP 800-57 Part 1 Revision 5"
        or policy["owner"] != "release owner"
    ):
        _fail("cryptographic key-management authority or standard changed unexpectedly")
    if policy["trust_entity_definition"] != EXPECTED_TRUST_ENTITY_DEFINITION:
        _fail("cryptographic trust-entity boundary changed unexpectedly")
    if (
        policy["shared_secret_max_trust_entities"] != 2
        or policy["private_key_max_active_trust_entities"] != 1
        or policy["offline_recovery_is_inactive"] is not True
    ):
        _fail("cryptographic key-sharing limits have been weakened")
    lifecycle_phases = _validate_string_list(
        policy["lifecycle_phases"], field="key_management_policy.lifecycle_phases"
    )
    if lifecycle_phases != EXPECTED_LIFECYCLE_PHASES:
        _fail("cryptographic key lifecycle is incomplete or out of order")
    controls = _validate_string_list(
        policy["required_controls"], field="key_management_policy.required_controls"
    )
    if set(controls) != EXPECTED_KEY_MANAGEMENT_CONTROLS:
        _fail("cryptographic key-management controls are incomplete")

    scope = data["scope"]
    if not isinstance(scope, dict) or set(scope) != {"excluded", "included"}:
        _fail("cryptographic inventory scope is incomplete")
    _validate_string_list(scope["included"], field="scope.included")
    _validate_string_list(scope["excluded"], field="scope.excluded")

    keys, keys_by_id = _validate_record_set(
        data["cryptographic_keys"],
        collection="cryptographic_keys",
        expected_ids=EXPECTED_KEY_IDS,
        expected_fields=KEY_FIELDS,
        text_fields=TEXT_KEY_FIELDS,
        list_fields=KEY_FIELDS - TEXT_KEY_FIELDS,
    )
    algorithms, algorithms_by_id = _validate_record_set(
        data["algorithms"],
        collection="algorithms",
        expected_ids=EXPECTED_ALGORITHM_IDS,
        expected_fields=ALGORITHM_FIELDS,
        text_fields=TEXT_ALGORITHM_FIELDS,
        list_fields=ALGORITHM_FIELDS - TEXT_ALGORITHM_FIELDS,
    )
    certificates, _ = _validate_record_set(
        data["certificates"],
        collection="certificates",
        expected_ids=EXPECTED_CERTIFICATE_IDS,
        expected_fields=CERTIFICATE_FIELDS,
        text_fields=TEXT_CERTIFICATE_FIELDS,
        list_fields=CERTIFICATE_FIELDS - TEXT_CERTIFICATE_FIELDS,
    )
    absences, _ = _validate_record_set(
        data["known_absences"],
        collection="known_absences",
        expected_ids=EXPECTED_ABSENCE_IDS,
        expected_fields=ABSENCE_FIELDS,
        text_fields=TEXT_ABSENCE_FIELDS,
        list_fields=ABSENCE_FIELDS - TEXT_ABSENCE_FIELDS,
    )

    for record in keys:
        if record["state"] not in ALLOWED_KEY_STATES:
            _fail(f"cryptographic key {record['id']!r} has an invalid state")
        if record["boundary"] not in ALLOWED_BOUNDARIES:
            _fail(f"cryptographic key {record['id']!r} has an invalid boundary")
    for record in algorithms:
        if record["security_status"] not in ALLOWED_SECURITY_STATUSES:
            _fail(f"algorithm {record['id']!r} has an invalid security status")
    for record in certificates:
        if record["state"] not in ALLOWED_KEY_STATES:
            _fail(f"certificate {record['id']!r} has an invalid state")
        if record["boundary"] not in ALLOWED_BOUNDARIES:
            _fail(f"certificate {record['id']!r} has an invalid boundary")
    for record in absences:
        if not all(_ASVS_ID.fullmatch(item) for item in record["related_asvs"]):
            _fail(f"known absence {record['id']!r} has an invalid ASVS identifier")

    referenced_algorithms: set[str] = set()
    for record in (*keys, *certificates):
        unknown = set(record["algorithms"]) - set(algorithms_by_id)
        if unknown:
            _fail(f"{record['id']!r} references unknown algorithms {sorted(unknown)}")
        referenced_algorithms.update(record["algorithms"])
    if referenced_algorithms | NON_KEY_ALGORITHMS != EXPECTED_ALGORITHM_IDS:
        _fail("algorithm inventory contains an unreferenced cryptographic profile")

    if algorithms_by_id["totp-hmac-sha1"]["security_status"] != "compatibility_only":
        _fail("TOTP SHA-1 must remain compatibility-only")
    if algorithms_by_id["password-blocklist-sha1"]["security_status"] != "compatibility_only":
        _fail("password-blocklist SHA-1 must remain compatibility-only")
    if algorithms_by_id["test-md5-password-hasher"]["security_status"] != "test_only":
        _fail("MD5 password hashing must remain test-only")
    if keys_by_id["django-signing-key"]["algorithms"] != ["hmac-sha256"]:
        _fail("Django signing key has acquired an unexpected algorithm or purpose")

    expected_summary = {
        "cryptographic_keys": len(keys),
        "algorithms": len(algorithms),
        "certificates": len(certificates),
        "known_absences": len(absences),
    }
    if data["summary"] != expected_summary:
        _fail("cryptographic inventory summary does not match its records")

    _validate_dependency_contract(algorithms_by_id)
    _validate_no_embedded_material(data)


def main() -> int:
    try:
        data = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))
        validate_inventory(data)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"Cryptographic inventory validation failed: {error}", file=sys.stderr)
        return 1
    print(
        "Cryptographic inventory is structurally complete "
        f"({len(EXPECTED_KEY_IDS)} keys, {len(EXPECTED_ALGORITHM_IDS)} algorithms, "
        f"{len(EXPECTED_CERTIFICATE_IDS)} certificates)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
