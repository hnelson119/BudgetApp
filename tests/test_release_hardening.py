from __future__ import annotations

import copy
import json
import subprocess
import sys
from datetime import date, timedelta
from pathlib import Path

import pytest
from django.conf import settings

from scripts.build_asvs_inventory import (
    IMPLEMENTED_ASSESSMENT_OVERRIDES,
    IMPLEMENTED_EVIDENCE_OVERRIDES,
    IMPLEMENTED_REQUIREMENTS,
    MAPPING_UPDATED,
    NOT_STARTED,
    PARTIAL_ASSESSMENT_OVERRIDES,
    PARTIAL_EVIDENCE_OVERRIDES,
)
from scripts.build_sbom import TRUSTED_REPOSITORIES, build_sbom
from scripts.check_adversarial_test_evidence import (
    EXPECTED_CATEGORIES,
    EXPECTED_SCENARIOS,
)
from scripts.check_adversarial_test_evidence import (
    validate_matrix as validate_adversarial_matrix,
)
from scripts.check_adversarial_test_evidence import validate_run as validate_adversarial_run
from scripts.check_cryptographic_inventory import (
    EXPECTED_ABSENCE_IDS,
    EXPECTED_ALGORITHM_IDS,
    EXPECTED_CERTIFICATE_IDS,
    EXPECTED_KEY_IDS,
)
from scripts.check_cryptographic_inventory import (
    validate_inventory as validate_cryptographic_inventory,
)
from scripts.check_device_test_evidence import validate_matrix, validate_run
from scripts.check_logging_inventory import (
    EXPECTED_EVENT_GROUP_IDS as EXPECTED_LOG_EVENT_GROUP_IDS,
)
from scripts.check_logging_inventory import EXPECTED_GAP_IDS as EXPECTED_LOG_GAP_IDS
from scripts.check_logging_inventory import (
    EXPECTED_LAYER_IDS,
    _validate_base_logging_config,
    _validate_production_logging_config,
)
from scripts.check_logging_inventory import validate_inventory as validate_logging_inventory
from scripts.check_release_evidence import validate_asvs_inventory
from scripts.check_sbom import validate_sbom
from scripts.secret_scan import _is_approved_hash_only_file, _is_approved_public_fingerprint

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_cryptographic_inventory_is_complete_and_current() -> None:
    completed = subprocess.run(
        [sys.executable, "scripts/check_cryptographic_inventory.py"],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert "17 keys, 15 algorithms, 10 certificates" in completed.stdout
    inventory = json.loads(
        (PROJECT_ROOT / "docs/cryptographic-inventory.json").read_text(encoding="utf-8")
    )
    assert {item["id"] for item in inventory["cryptographic_keys"]} == EXPECTED_KEY_IDS
    assert {item["id"] for item in inventory["algorithms"]} == EXPECTED_ALGORITHM_IDS
    assert {item["id"] for item in inventory["certificates"]} == EXPECTED_CERTIFICATE_IDS
    assert {item["id"] for item in inventory["known_absences"]} == EXPECTED_ABSENCE_IDS
    algorithms = {item["id"]: item for item in inventory["algorithms"]}
    assert algorithms["totp-hmac-sha1"]["security_status"] == "compatibility_only"
    assert algorithms["password-blocklist-sha1"]["security_status"] == "compatibility_only"
    assert algorithms["test-md5-password-hasher"]["security_status"] == "test_only"
    policy = inventory["key_management_policy"]
    assert policy["standard"] == "NIST SP 800-57 Part 1 Revision 5"
    assert policy["shared_secret_max_trust_entities"] == 2
    assert policy["private_key_max_active_trust_entities"] == 1
    assert policy["offline_recovery_is_inactive"] is True
    password_kdf_policy = inventory["password_derived_key_policy"]
    assert password_kdf_policy["approved_profiles"] == ["restic-scrypt"]


def test_cryptographic_inventory_rejects_tampering_and_stale_reviews() -> None:
    inventory = json.loads(
        (PROJECT_ROOT / "docs/cryptographic-inventory.json").read_text(encoding="utf-8")
    )

    duplicate_key = copy.deepcopy(inventory)
    duplicate_key["cryptographic_keys"].append(duplicate_key["cryptographic_keys"][0])
    with pytest.raises(ValueError, match="duplicate id"):
        validate_cryptographic_inventory(duplicate_key, today=date(2026, 9, 6))

    missing_prohibition = copy.deepcopy(inventory)
    missing_prohibition["cryptographic_keys"][0]["prohibited_uses"] = []
    with pytest.raises(ValueError, match="non-empty string list"):
        validate_cryptographic_inventory(missing_prohibition, today=date(2026, 9, 6))

    missing_evidence = copy.deepcopy(inventory)
    missing_evidence["algorithms"][0]["evidence"] = ["docs/does-not-exist.md"]
    with pytest.raises(ValueError, match="missing evidence"):
        validate_cryptographic_inventory(missing_evidence, today=date(2026, 9, 6))

    embedded_private_key = copy.deepcopy(inventory)
    embedded_private_key["cryptographic_keys"][0]["storage"] = "BEGIN " + "PRIVATE" + " KEY"
    with pytest.raises(ValueError, match="private-key material"):
        validate_cryptographic_inventory(embedded_private_key, today=date(2026, 9, 6))

    exact_hostname = copy.deepcopy(inventory)
    exact_hostname["certificates"][0]["subject"] = "budget.private-tail.ts.net"
    with pytest.raises(ValueError, match="exact private hostname"):
        validate_cryptographic_inventory(exact_hostname, today=date(2026, 9, 6))

    unknown_algorithm = copy.deepcopy(inventory)
    unknown_algorithm["cryptographic_keys"][0]["algorithms"] = ["unknown-profile"]
    with pytest.raises(ValueError, match="unknown algorithms"):
        validate_cryptographic_inventory(unknown_algorithm, today=date(2026, 9, 6))

    overshared_secret = copy.deepcopy(inventory)
    overshared_secret["key_management_policy"]["shared_secret_max_trust_entities"] = 3
    with pytest.raises(ValueError, match="key-sharing limits"):
        validate_cryptographic_inventory(overshared_secret, today=date(2026, 9, 6))

    incomplete_lifecycle = copy.deepcopy(inventory)
    incomplete_lifecycle["key_management_policy"]["lifecycle_phases"].remove("destruction")
    with pytest.raises(ValueError, match="lifecycle is incomplete"):
        validate_cryptographic_inventory(incomplete_lifecycle, today=date(2026, 9, 6))

    missing_compromise_control = copy.deepcopy(inventory)
    missing_compromise_control["key_management_policy"]["required_controls"].pop()
    with pytest.raises(ValueError, match="controls are incomplete"):
        validate_cryptographic_inventory(missing_compromise_control, today=date(2026, 9, 6))

    unapproved_password_kdf = copy.deepcopy(inventory)
    unapproved_password_kdf["password_derived_key_policy"]["approved_profiles"] = ["pbkdf2"]
    with pytest.raises(ValueError, match="profiles differ"):
        validate_cryptographic_inventory(unapproved_password_kdf, today=date(2026, 9, 6))

    missing_password_kdf_control = copy.deepcopy(inventory)
    missing_password_kdf_control["password_derived_key_policy"]["required_controls"].pop()
    with pytest.raises(ValueError, match="key controls are incomplete"):
        validate_cryptographic_inventory(missing_password_kdf_control, today=date(2026, 9, 6))

    private_browser_ca = copy.deepcopy(inventory)
    browser_roots = next(
        item
        for item in private_browser_ca["certificates"]
        if item["id"] == "browser-public-trust-roots"
    )
    browser_roots["prohibited_uses"].remove("self-signed production certificates")
    with pytest.raises(ValueError, match="public certificate trust boundary"):
        validate_cryptographic_inventory(private_browser_ca, today=date(2026, 9, 6))

    with pytest.raises(ValueError, match="review is overdue"):
        validate_cryptographic_inventory(inventory, today=date(2026, 12, 6))


def test_logging_inventory_is_complete_and_source_derived() -> None:
    completed = subprocess.run(
        [sys.executable, "scripts/check_logging_inventory.py"],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert "14 layers, 5 event groups" in completed.stdout
    inventory = json.loads(
        (PROJECT_ROOT / "docs/logging-inventory.json").read_text(encoding="utf-8")
    )
    assert {item["id"] for item in inventory["layers"]} == EXPECTED_LAYER_IDS
    assert {item["id"] for item in inventory["event_groups"]} == EXPECTED_LOG_EVENT_GROUP_IDS
    assert {item["id"] for item in inventory["known_gaps"]} == EXPECTED_LOG_GAP_IDS
    assert inventory["summary"] == {
        "layers": 14,
        "event_groups": 5,
        "event_entries": 182,
        "known_gaps": 2,
    }
    groups = {item["id"]: item for item in inventory["event_groups"]}
    assert len(groups["django-operational-events"]["events"]) == 2
    assert len(groups["django-security-events"]["events"]) == 56
    assert len(groups["security-archive-events"]["events"]) == 6
    assert len(groups["protected-audit-actions"]["events"]) == 83
    assert len(groups["maintenance-events"]["events"]) == 35


def test_logging_inventory_rejects_tampering_and_stale_reviews() -> None:
    inventory = json.loads(
        (PROJECT_ROOT / "docs/logging-inventory.json").read_text(encoding="utf-8")
    )
    reviewed_on = date.fromisoformat(inventory["inventory_updated"])
    overdue_on = date.fromisoformat(inventory["review"]["next_review_due"]) + timedelta(days=1)

    duplicate_layer = copy.deepcopy(inventory)
    duplicate_layer["layers"].append(duplicate_layer["layers"][0])
    with pytest.raises(ValueError, match="duplicate id"):
        validate_logging_inventory(duplicate_layer, today=reviewed_on)

    missing_retention = copy.deepcopy(inventory)
    missing_retention["layers"][0]["retention"] = ""
    with pytest.raises(ValueError, match="retention must be non-empty text"):
        validate_logging_inventory(missing_retention, today=reviewed_on)

    missing_evidence = copy.deepcopy(inventory)
    missing_evidence["layers"][0]["evidence"] = ["docs/does-not-exist.md"]
    with pytest.raises(ValueError, match="missing evidence"):
        validate_logging_inventory(missing_evidence, today=reviewed_on)

    unknown_group = copy.deepcopy(inventory)
    unknown_group["layers"][0]["event_groups"] = ["unknown-events"]
    with pytest.raises(ValueError, match="unknown event groups"):
        validate_logging_inventory(unknown_group, today=reviewed_on)

    changed_source_event = copy.deepcopy(inventory)
    changed_source_event["event_groups"][0]["events"][0] = "http.request.changed"
    with pytest.raises(ValueError, match="does not match source literals"):
        validate_logging_inventory(changed_source_event, today=reviewed_on)

    embedded_private_key = copy.deepcopy(inventory)
    embedded_private_key["layers"][0]["destination"] = "BEGIN " + "PRIVATE" + " KEY"
    with pytest.raises(ValueError, match="private-key material"):
        validate_logging_inventory(embedded_private_key, today=reviewed_on)

    exact_hostname = copy.deepcopy(inventory)
    exact_hostname["layers"][0]["destination"] = "budget.private-tail.ts.net"
    with pytest.raises(ValueError, match="exact private hostname"):
        validate_logging_inventory(exact_hostname, today=reviewed_on)

    with pytest.raises(ValueError, match="review is overdue"):
        validate_logging_inventory(inventory, today=overdue_on)


def test_logging_inventory_rejects_undocumented_django_destinations() -> None:
    base_source = (PROJECT_ROOT / "config/settings/base.py").read_text(encoding="utf-8")
    production_source = (PROJECT_ROOT / "config/settings/production.py").read_text(encoding="utf-8")

    _validate_base_logging_config(base_source)
    _validate_production_logging_config(production_source)

    file_sink = base_source.replace(
        '"class": "logging.StreamHandler"',
        '"class": "logging.FileHandler"',
        1,
    )
    with pytest.raises(ValueError, match="undocumented destination"):
        _validate_base_logging_config(file_sink)

    changed_archive = production_source.replace(
        '"socket_path": "/run/security-log/security.sock"',
        '"socket_path": "/tmp/undocumented.sock"',
    )
    with pytest.raises(ValueError, match="archive destination changed"):
        _validate_production_logging_config(changed_archive)

    extra_handler = (
        production_source + '\nLOGGING["handlers"]["undocumented"] = {"class": "custom.Handler"}\n'
    )
    with pytest.raises(ValueError, match="logging mutations changed"):
        _validate_production_logging_config(extra_handler)


def test_sbom_is_complete_and_source_derived() -> None:
    completed = subprocess.run(
        [sys.executable, "scripts/check_sbom.py"],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert "83 components" in completed.stdout
    sbom = json.loads((PROJECT_ROOT / "docs/sbom.cdx.json").read_text(encoding="utf-8"))
    assert sbom == build_sbom()
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.6"
    assert len(sbom["components"]) == 83
    assert {component["type"] for component in sbom["components"]} == {
        "application",
        "container",
        "library",
    }
    repositories = {
        property_["value"]
        for component in sbom["components"]
        for property_ in component["properties"]
        if property_["name"] == "budget:source-repository"
    }
    assert repositories == TRUSTED_REPOSITORIES


def test_sbom_rejects_catalog_tampering() -> None:
    sbom = json.loads((PROJECT_ROOT / "docs/sbom.cdx.json").read_text(encoding="utf-8"))
    tampered = copy.deepcopy(sbom)
    tampered["components"][0]["version"] = "mutable"

    with pytest.raises(ValueError, match="is stale"):
        validate_sbom(tampered)


def test_release_evidence_inventory_is_complete_and_validated() -> None:
    completed = subprocess.run(
        [sys.executable, "scripts/check_release_evidence.py"],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert "structurally complete" in completed.stdout

    evidence = json.loads((PROJECT_ROOT / "docs/release-evidence.json").read_text(encoding="utf-8"))
    inventory = json.loads(
        (PROJECT_ROOT / "docs/asvs-5.0.0-level2-evidence.json").read_text(encoding="utf-8")
    )
    assert inventory["requirement_count"] == 253
    assert {item["chapter_id"] for item in inventory["requirements"]} == {
        f"V{number}" for number in range(1, 18)
    }
    assert inventory["summary"] == {
        "applicability": {"applicable": 174, "not_applicable": 79},
        "status": {
            "implemented": 162,
            "not_applicable": 79,
            "partial": 12,
        },
    }
    requirements = {item["id"]: item for item in inventory["requirements"]}
    assert requirements["v5.0.0-9.1.1"]["status"] == "not_applicable"
    assert requirements["v5.0.0-10.4.1"]["status"] == "not_applicable"
    assert requirements["v5.0.0-17.3.2"]["status"] == "not_applicable"
    assert requirements["v5.0.0-3.7.2"]["status"] == "implemented"
    assert requirements["v5.0.0-3.7.1"]["status"] == "implemented"
    assert requirements["v5.0.0-3.4.2"]["status"] == "implemented"
    assert requirements["v5.0.0-5.1.1"]["status"] == "implemented"
    assert requirements["v5.0.0-2.1.1"]["status"] == "implemented"
    assert requirements["v5.0.0-2.1.2"]["status"] == "implemented"
    assert requirements["v5.0.0-2.1.3"]["status"] == "implemented"
    assert requirements["v5.0.0-2.3.2"]["status"] == "partial"
    assert requirements["v5.0.0-4.2.1"]["status"] == "implemented"
    assert requirements["v5.0.0-12.2.2"]["status"] == "implemented"
    assert requirements["v5.0.0-4.1.2"]["status"] == "implemented"
    assert requirements["v5.0.0-4.1.3"]["status"] == "implemented"
    assert requirements["v5.0.0-12.3.1"]["status"] == "partial"
    assert requirements["v5.0.0-12.1.3"]["status"] == "implemented"
    assert requirements["v5.0.0-12.3.3"]["status"] == "implemented"
    assert requirements["v5.0.0-12.3.4"]["status"] == "implemented"
    assert requirements["v5.0.0-13.4.3"]["status"] == "implemented"
    assert requirements["v5.0.0-13.4.4"]["status"] == "implemented"
    assert requirements["v5.0.0-13.4.5"]["status"] == "implemented"
    assert requirements["v5.0.0-14.3.1"]["status"] == "implemented"
    assert requirements["v5.0.0-16.4.3"]["status"] == "implemented"
    assert requirements["v5.0.0-6.1.2"]["status"] == "implemented"
    assert requirements["v5.0.0-6.2.11"]["status"] == "implemented"
    assert requirements["v5.0.0-6.2.12"]["status"] == "implemented"
    assert requirements["v5.0.0-6.4.3"]["status"] == "implemented"
    assert requirements["v5.0.0-6.4.4"]["status"] == "implemented"
    assert requirements["v5.0.0-7.4.5"]["status"] == "implemented"
    assert requirements["v5.0.0-7.1.1"]["status"] == "implemented"
    assert requirements["v5.0.0-7.1.2"]["status"] == "implemented"
    assert requirements["v5.0.0-7.4.2"]["status"] == "implemented"
    assert requirements["v5.0.0-7.5.1"]["status"] == "implemented"
    assert requirements["v5.0.0-8.1.1"]["status"] == "implemented"
    assert requirements["v5.0.0-8.1.2"]["status"] == "implemented"
    assert requirements["v5.0.0-11.1.1"]["status"] == "implemented"
    assert requirements["v5.0.0-11.1.2"]["status"] == "implemented"
    assert requirements["v5.0.0-11.4.1"]["status"] == "implemented"
    assert requirements["v5.0.0-11.4.3"]["status"] == "implemented"
    assert requirements["v5.0.0-11.4.4"]["status"] == "implemented"
    assert requirements["v5.0.0-13.2.4"]["status"] == "implemented"
    assert requirements["v5.0.0-13.2.1"]["status"] == "implemented"
    assert requirements["v5.0.0-13.2.5"]["status"] == "implemented"
    assert requirements["v5.0.0-15.1.2"]["status"] == "implemented"
    assert requirements["v5.0.0-15.3.6"]["status"] == "implemented"
    assert requirements["v5.0.0-16.1.1"]["status"] == "implemented"
    assert requirements["v5.0.0-16.3.3"]["status"] == "implemented"
    assert requirements["v5.0.0-16.4.2"]["status"] == "implemented"
    assert requirements["v5.0.0-16.5.2"]["status"] == "implemented"
    assert {item["id"] for item in evidence["security_tests"]} == set(range(1, 25))
    assert {item["id"] for item in evidence["release_gates"]} == set(range(1, 13))
    assert not any(
        item["status"] == "verified"
        for collection in (
            inventory["requirements"],
            evidence["security_tests"],
            evidence["release_gates"],
        )
        for item in collection
    )


def test_asvs_builder_preserves_completed_m10_overrides() -> None:
    completed_m10 = {
        "V1.1.1",
        "V1.2.3",
        "V1.2.5",
        "V1.2.9",
        "V1.3.3",
        "V1.3.7",
        "V1.3.10",
        "V1.4.1",
        "V1.4.2",
        "V1.4.3",
        "V2.1.1",
        "V2.1.2",
        "V2.1.3",
        "V3.7.2",
        "V3.7.1",
        "V3.4.2",
        "V5.1.1",
        "V4.1.2",
        "V4.1.3",
        "V4.2.1",
        "V6.1.2",
        "V6.2.2",
        "V6.2.3",
        "V6.2.11",
        "V6.2.12",
        "V6.4.3",
        "V6.4.4",
        "V7.1.1",
        "V7.1.2",
        "V7.4.2",
        "V7.4.5",
        "V7.5.1",
        "V7.5.2",
        "V8.1.1",
        "V8.1.2",
        "V11.1.1",
        "V11.1.2",
        "V11.4.1",
        "V11.4.2",
        "V11.4.3",
        "V11.4.4",
        "V12.1.3",
        "V12.2.2",
        "V12.3.3",
        "V12.3.4",
        "V13.1.1",
        "V13.2.1",
        "V13.2.4",
        "V13.2.5",
        "V13.4.3",
        "V13.4.4",
        "V13.4.5",
        "V14.1.1",
        "V14.1.2",
        "V14.3.1",
        "V15.1.2",
        "V15.1.3",
        "V15.3.6",
        "V16.1.1",
        "V16.2.3",
        "V16.3.2",
        "V16.3.3",
        "V16.4.2",
        "V16.4.3",
        "V16.5.2",
    }

    assert MAPPING_UPDATED == "2026-09-25"
    assert not NOT_STARTED
    assert completed_m10 <= IMPLEMENTED_REQUIREMENTS
    assert set(IMPLEMENTED_ASSESSMENT_OVERRIDES) == completed_m10
    assert set(IMPLEMENTED_EVIDENCE_OVERRIDES) == completed_m10
    inventory = json.loads(
        (PROJECT_ROOT / "docs/asvs-5.0.0-level2-evidence.json").read_text(encoding="utf-8")
    )
    requirements = {item["source_id"]: item for item in inventory["requirements"]}
    for source_id in completed_m10:
        assert requirements[source_id]["assessment"] == IMPLEMENTED_ASSESSMENT_OVERRIDES[source_id]
        assert requirements[source_id]["evidence"] == IMPLEMENTED_EVIDENCE_OVERRIDES[source_id]
    assert set(PARTIAL_ASSESSMENT_OVERRIDES) == {"V12.3.1", "V12.3.2"}
    assert set(PARTIAL_EVIDENCE_OVERRIDES) == set(PARTIAL_ASSESSMENT_OVERRIDES)
    for source_id in PARTIAL_ASSESSMENT_OVERRIDES:
        assert requirements[source_id]["status"] == "partial"
        assert requirements[source_id]["assessment"] == PARTIAL_ASSESSMENT_OVERRIDES[source_id]
        assert requirements[source_id]["evidence"] == PARTIAL_EVIDENCE_OVERRIDES[source_id]


def test_session_security_policy_matches_enforced_timeouts() -> None:
    policy = (PROJECT_ROOT / "docs/SESSION_SECURITY.md").read_text(encoding="utf-8")

    assert settings.SESSION_IDLE_TIMEOUT_SECONDS == 60 * 60
    assert settings.SESSION_ABSOLUTE_TIMEOUT_SECONDS == 60 * 60 * 12
    assert settings.SESSION_COOKIE_AGE == settings.SESSION_ABSOLUTE_TIMEOUT_SECONDS
    assert settings.SESSION_ACTIVITY_UPDATE_SECONDS == 60
    assert settings.RECENT_AUTH_TIMEOUT_SECONDS == 10 * 60
    assert settings.MAX_CONCURRENT_SESSIONS == 5
    assert settings.MIDDLEWARE.index("identity.middleware.ConcurrentSessionLimitMiddleware") < (
        settings.MIDDLEWARE.index("django.contrib.sessions.middleware.SessionMiddleware")
    )
    assert all(
        statement in policy
        for statement in (
            "1 hour",
            "12 hours",
            "24 hours",
            "10 minutes",
            "| Concurrent sessions | 5 |",
            "oldest authenticated session is revoked deterministically",
            "does not extend this limit",
            "SESSION_EXPIRE_AT_BROWSER_CLOSE",
            "https://pages.nist.gov/800-63-4/sp800-63b/aal/#aal2reauth",
        )
    )


def test_redirect_policy_matches_the_response_and_production_boundaries() -> None:
    policy = (PROJECT_ROOT / "docs/REDIRECT_SECURITY.md").read_text(encoding="utf-8")
    production = (PROJECT_ROOT / "config/settings/production.py").read_text(encoding="utf-8")

    assert settings.EXTERNAL_REDIRECT_ALLOWED_HOSTS == ()
    assert settings.MIDDLEWARE.index("core.middleware.ActorContextMiddleware") < (
        settings.MIDDLEWARE.index("core.middleware.RedirectHostBoundaryMiddleware")
    )
    assert all(
        statement in policy
        for statement in (
            "exact authority",
            "explicit HTTPS URL",
            "external allowlist to remain empty",
            "without a `Location` header",
        )
    )
    assert "Production does not permit external redirect destinations." in production


def test_asvs_inventory_rejects_catalog_and_disposition_tampering() -> None:
    inventory = json.loads(
        (PROJECT_ROOT / "docs/asvs-5.0.0-level2-evidence.json").read_text(encoding="utf-8")
    )

    changed_requirement = copy.deepcopy(inventory)
    changed_requirement["requirements"][0]["description"] += " altered"
    with pytest.raises(ValueError, match="declared catalog fingerprint"):
        validate_asvs_inventory(changed_requirement)

    missing_reason = copy.deepcopy(inventory)
    excluded = next(
        item for item in missing_reason["requirements"] if item["status"] == "not_applicable"
    )
    del excluded["reason"]
    with pytest.raises(ValueError, match="not applicable without a reason"):
        validate_asvs_inventory(missing_reason)

    overstated_exclusion = copy.deepcopy(inventory)
    applicable = next(
        item for item in overstated_exclusion["requirements"] if item["status"] == "partial"
    )
    applicable["status"] = "not_applicable"
    with pytest.raises(ValueError, match="applicable but has N/A status"):
        validate_asvs_inventory(overstated_exclusion)


def test_secret_scan_only_exempts_exact_public_asvs_fingerprints() -> None:
    source_sha256 = "".join(
        (
            "8201b20eec2908c3",  # pragma: allowlist secret
            "380ac600c91c8ba7",  # pragma: allowlist secret
            "46346fbb80885936",  # pragma: allowlist secret
            "6abb232027532311",  # pragma: allowlist secret
        )
    )
    line = f'    "source_sha256": "{source_sha256}",'

    assert _is_approved_public_fingerprint("docs/release-evidence.json", line)
    assert _is_approved_public_fingerprint("docs\\release-evidence.json", line)
    assert not _is_approved_public_fingerprint("docs/other.json", line)
    assert not _is_approved_public_fingerprint(
        "docs/release-evidence.json",
        f'    "source_sha256": "{source_sha256[:-1]}0",',
    )


def test_secret_scan_only_exempts_hash_fields_in_the_generated_sbom() -> None:
    digest_line = f'    "content": "{"a" * 64}",'
    revision_line = f'    "version": "{"b" * 40}",'

    assert _is_approved_public_fingerprint("docs/sbom.cdx.json", digest_line)
    assert _is_approved_public_fingerprint("docs\\sbom.cdx.json", revision_line)
    assert not _is_approved_public_fingerprint("docs/other.json", digest_line)
    assert not _is_approved_public_fingerprint("docs/sbom.cdx.json", f'    "token": "{"a" * 64}",')
    assert not _is_approved_public_fingerprint(
        "docs/sbom.cdx.json", f'    "content": "{"a" * 63}",'
    )


def test_secret_scan_only_exempts_the_exact_reviewed_hash_corpus() -> None:
    corpus = (PROJECT_ROOT / "identity/data/breached-passwords-v1.txt").read_bytes()

    assert _is_approved_hash_only_file("identity/data/breached-passwords-v1.txt", corpus)
    assert _is_approved_hash_only_file("identity\\data\\breached-passwords-v1.txt", corpus)
    assert not _is_approved_hash_only_file("identity/data/other.txt", corpus)
    assert not _is_approved_hash_only_file(
        "identity/data/breached-passwords-v1.txt",
        corpus + b"0",
    )


def test_raw_security_reports_are_ignored_and_documented_as_sensitive() -> None:
    gitignore = (PROJECT_ROOT / ".gitignore").read_text(encoding="utf-8")
    runbook = (PROJECT_ROOT / "docs/RELEASE_HARDENING.md").read_text(encoding="utf-8")

    assert "security-reports/" in gitignore
    assert "Do not commit raw ZAP sessions" in runbook
    assert "real household data" in runbook


def test_device_and_accessibility_evidence_matrix_is_complete_and_pending() -> None:
    completed = subprocess.run(
        [sys.executable, "scripts/check_device_test_evidence.py"],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert "structurally complete (0 run records)" in completed.stdout
    matrix = json.loads((PROJECT_ROOT / "docs/device-test-matrix.json").read_text(encoding="utf-8"))
    assert matrix["release_candidate"] is None
    assert {target["id"] for target in matrix["targets"]} >= {
        "desktop-edge-current",
        "desktop-firefox-current",
        "mobile-iphone-safari-current",
        "mobile-ipad-firefox-current",
        "mobile-android-chrome-current",
        "mobile-android-firefox-current",
        "screenreader-narrator-edge-current",
        "screenreader-voiceover-safari-current",
        "screenreader-talkback-chrome-current",
    }
    assert not list((PROJECT_ROOT / "docs/device-test-runs").glob("*.json"))


def test_device_run_validation_rejects_unprotected_or_overstated_evidence() -> None:
    matrix = json.loads((PROJECT_ROOT / "docs/device-test-matrix.json").read_text(encoding="utf-8"))
    scenarios, targets = validate_matrix(matrix)
    run_id = "2026-08-24-keyboard-edge-current-aaaaaaa"
    valid_run = {
        "schema_version": 1,
        "run_id": run_id,
        "target_id": "keyboard-edge-current",
        "purpose": "development_baseline",
        "tested_at": "2026-08-24",
        "candidate_commit": "a" * 40,
        "tester_role": "release owner",
        "browser_version": "151.0.0.0",
        "platform_version": "Windows test environment",
        "synthetic_data_only": True,
        "overall_status": "passed",
        "scenario_results": [{"id": "KEYBOARD-01", "status": "passed", "notes": "No finding."}],
        "supersedes": None,
    }

    validate_run(
        valid_run,
        filename=f"{run_id}.json",
        matrix=matrix,
        scenarios=scenarios,
        targets=targets,
    )
    with pytest.raises(ValueError, match="synthetic_data_only"):
        validate_run(
            valid_run | {"synthetic_data_only": False},
            filename=f"{run_id}.json",
            matrix=matrix,
            scenarios=scenarios,
            targets=targets,
        )
    with pytest.raises(ValueError, match="does not match the matrix release candidate"):
        validate_run(
            valid_run | {"purpose": "release_candidate"},
            filename=f"{run_id}.json",
            matrix=matrix,
            scenarios=scenarios,
            targets=targets,
        )


def test_adversarial_evidence_matrix_is_complete_and_pending() -> None:
    completed = subprocess.run(
        [sys.executable, "scripts/check_adversarial_test_evidence.py"],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert "structurally complete (0 run records)" in completed.stdout
    assert "Release-candidate coverage: 0/3 required targets." in completed.stdout
    matrix = json.loads(
        (PROJECT_ROOT / "docs/adversarial-test-matrix.json").read_text(encoding="utf-8")
    )
    assert matrix["release_candidate"] is None
    assert set(matrix["categories"]) == EXPECTED_CATEGORIES
    assert {scenario["id"] for scenario in matrix["scenarios"]} == set(EXPECTED_SCENARIOS)
    assert len(matrix["scenarios"]) == 28
    targets = {target["id"]: target for target in matrix["targets"]}
    assert targets["linux-vm-private-ingress"]["execution_phase"] == "release_only"
    assert not list((PROJECT_ROOT / "docs/adversarial-test-runs").glob("*.json"))

    required = subprocess.run(
        [sys.executable, "scripts/check_adversarial_test_evidence.py", "--require-complete"],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert required.returncode == 1
    assert "release_candidate must be selected" in required.stderr


def test_adversarial_matrix_rejects_coverage_tampering() -> None:
    matrix = json.loads(
        (PROJECT_ROOT / "docs/adversarial-test-matrix.json").read_text(encoding="utf-8")
    )

    missing_scenario = copy.deepcopy(matrix)
    missing_scenario["scenarios"].pop()
    with pytest.raises(ValueError, match="scenarios are incomplete"):
        validate_adversarial_matrix(missing_scenario)

    weakened_mapping = copy.deepcopy(matrix)
    scenario = next(item for item in weakened_mapping["scenarios"] if item["id"] == "AUTHZ-01")
    scenario["security_test_ids"] = [23]
    with pytest.raises(ValueError, match="incomplete security-test coverage"):
        validate_adversarial_matrix(weakened_mapping)

    relabeled_target = copy.deepcopy(matrix)
    scenario = next(item for item in relabeled_target["scenarios"] if item["id"] == "NET-01")
    scenario["target_id"] = "synthetic-app"
    with pytest.raises(ValueError, match="invalid target"):
        validate_adversarial_matrix(relabeled_target)


def test_adversarial_run_rejects_unprotected_or_overstated_evidence() -> None:
    matrix = json.loads(
        (PROJECT_ROOT / "docs/adversarial-test-matrix.json").read_text(encoding="utf-8")
    )
    scenarios, targets = validate_adversarial_matrix(matrix)
    run_id = "2026-08-27-synthetic-postgresql-aaaaaaa"
    valid_run = {
        "schema_version": 1,
        "run_id": run_id,
        "target_id": "synthetic-postgresql",
        "purpose": "development_baseline",
        "tested_at": "2026-08-27",
        "candidate_commit": "a" * 40,
        "tester_role": "release owner",
        "environment_summary": "Disposable PostgreSQL synthetic-data target",
        "synthetic_data_only": True,
        "overall_status": "passed",
        "scenario_results": [
            {"id": scenario_id, "status": "passed", "notes": "No finding.", "finding_ids": []}
            for scenario_id in ("AUDIT-01", "AUDIT-02", "AUDIT-03", "AUDIT-04")
        ],
        "supersedes": None,
    }
    validation_arguments = {
        "filename": f"{run_id}.json",
        "matrix": matrix,
        "scenarios": scenarios,
        "targets": targets,
        "known_finding_ids": {"M10-F001"},
    }

    validate_adversarial_run(valid_run, **validation_arguments)
    with pytest.raises(ValueError, match="synthetic_data_only"):
        validate_adversarial_run(valid_run | {"synthetic_data_only": False}, **validation_arguments)
    with pytest.raises(ValueError, match="restricted environment or credential detail"):
        validate_adversarial_run(
            valid_run | {"environment_summary": "Disposable target at 192.0.2.10"},
            **validation_arguments,
        )
    with pytest.raises(ValueError, match="does not match the matrix release candidate"):
        validate_adversarial_run(
            valid_run | {"purpose": "release_candidate"}, **validation_arguments
        )

    failed_without_finding = copy.deepcopy(valid_run)
    failed_without_finding["overall_status"] = "failed"
    failed_without_finding["scenario_results"][0]["status"] = "failed"
    with pytest.raises(ValueError, match="must reference a finding"):
        validate_adversarial_run(failed_without_finding, **validation_arguments)

    unknown_finding = copy.deepcopy(failed_without_finding)
    unknown_finding["scenario_results"][0]["finding_ids"] = ["M10-F999"]
    with pytest.raises(ValueError, match="references unknown findings"):
        validate_adversarial_run(unknown_finding, **validation_arguments)

    incomplete = copy.deepcopy(valid_run)
    incomplete["scenario_results"].pop()
    with pytest.raises(ValueError, match="does not contain every scenario"):
        validate_adversarial_run(incomplete, **validation_arguments)
