"""Build the pinned OWASP ASVS 5.0.0 Level 2 application mapping.

This command intentionally requires a caller-supplied copy of OWASP's tagged flat JSON. It never
downloads a moving upstream artifact, and it refuses any input whose SHA-256 does not match the
official v5.0.0 release asset.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = PROJECT_ROOT / "docs" / "asvs-5.0.0-level2-evidence.json"
ASVS_VERSION = "5.0.0"
ASVS_SOURCE_URL = (
    "https://raw.githubusercontent.com/OWASP/ASVS/v5.0.0/5.0/docs_en/"
    "OWASP_Application_Security_Verification_Standard_5.0.0_en.flat.json"
)
ASVS_SOURCE_SHA256 = "".join(
    (
        "8201b20eec2908c3",  # pragma: allowlist secret
        "380ac600c91c8ba7",  # pragma: allowlist secret
        "46346fbb80885936",  # pragma: allowlist secret
        "6abb232027532311",  # pragma: allowlist secret
    )
)
ASVS_SOURCE_GIT_BLOB = "".join(
    (
        "f7ae2926598c4648",  # pragma: allowlist secret
        "ff7614a6968e4c8f",  # pragma: allowlist secret
        "d89524bd",
    )
)
MAPPING_UPDATED = "2026-08-24"

CHAPTER_EVIDENCE: dict[str, list[str]] = {
    "V1": ["core/", "imports/services/", "tests/test_csv_imports.py", "scripts/check.ps1"],
    "V2": ["CALCULATION_RULES.md", "budgets/services/", "ledger/services/", "tests/"],
    "V3": [
        "config/settings/production.py",
        "core/middleware.py",
        "browser-tests/security-accessibility.spec.mjs",
        "tests/test_logging.py",
    ],
    "V4": ["config/settings/production.py", "core/middleware.py", "tests/test_web_foundation.py"],
    "V5": ["SECURITY_PLAN.md", "imports/services/", "spending/services/exports.py", "tests/"],
    "V6": [
        "identity/",
        "config/settings/base.py",
        "tests/test_authentication.py",
        "tests/test_mfa.py",
    ],
    "V7": [
        "identity/services/sessions.py",
        "identity/middleware.py",
        "tests/test_authentication.py",
    ],
    "V8": ["households/services/", "tests/test_web_foundation.py", "tests/"],
    "V9": ["PRODUCT_SPEC.md", "SECURITY_PLAN.md"],
    "V10": ["PRODUCT_SPEC.md", "SECURITY_PLAN.md"],
    "V11": [
        "SECURITY_PLAN.md",
        "identity/services/mfa.py",
        "audit/checkpoints.py",
        "tests/test_mfa.py",
        "tests/test_checkpoints.py",
    ],
    "V12": [
        "SECURITY_PLAN.md",
        "config/settings/production.py",
        "compose.yaml",
        "tests/test_production_settings.py",
    ],
    "V13": [
        "SECURITY_PLAN.md",
        "Dockerfile",
        "compose.yaml",
        "tests/test_deployment_config.py",
    ],
    "V14": [
        "SECURITY_PLAN.md",
        "core/middleware.py",
        "core/logging.py",
        "tests/test_logging.py",
    ],
    "V15": [
        "SECURITY_PLAN.md",
        "requirements-prod.lock",
        ".github/workflows/quality.yml",
        "tests/test_deployment_config.py",
    ],
    "V16": [
        "SECURITY_PLAN.md",
        "core/logging.py",
        "core/errors.py",
        "audit/services.py",
        "tests/test_logging.py",
    ],
    "V17": ["PRODUCT_SPEC.md", "SECURITY_PLAN.md"],
}

SECTION_EVIDENCE: dict[str, list[str]] = {
    "V3.3": ["config/settings/production.py", "tests/test_production_settings.py"],
    "V3.4": ["core/middleware.py", "config/settings/production.py", "tests/test_logging.py"],
    "V3.5": ["config/settings/base.py", "tests/test_web_foundation.py", "tests/"],
    "V5.2": ["imports/services/parsing.py", "tests/test_csv_imports.py"],
    "V5.3": ["imports/services/", "tests/test_csv_imports.py", "Dockerfile"],
    "V5.4": ["spending/services/exports.py", "audit/exports.py", "tests/test_csv_exports.py"],
    "V6.2": [
        "config/settings/base.py",
        "identity/management/commands/bootstrap_household.py",
        "tests/test_identity_commands.py",
    ],
    "V6.3": [
        "identity/services/throttling.py",
        "identity/middleware.py",
        "tests/test_authentication.py",
    ],
    "V6.4": [
        "identity/management/commands/reset_user_mfa.py",
        "identity/services/sessions.py",
        "tests/test_identity_commands.py",
    ],
    "V6.5": ["identity/services/mfa.py", "tests/test_mfa.py"],
    "V7.2": ["identity/services/sessions.py", "tests/test_authentication.py"],
    "V7.3": [
        "config/settings/base.py",
        "identity/services/sessions.py",
        "tests/test_authentication.py",
    ],
    "V7.4": ["identity/services/sessions.py", "identity/views.py", "tests/test_authentication.py"],
    "V7.5": ["identity/services/sessions.py", "identity/views.py", "tests/test_authentication.py"],
    "V8.2": ["households/services/access.py", "tests/"],
    "V8.3": ["households/services/access.py", "tests/"],
    "V8.4": ["households/services/access.py", "tests/"],
    "V11.3": ["identity/services/mfa.py", "audit/checkpoints.py", "tests/test_mfa.py"],
    "V11.4": ["config/settings/base.py", "identity/services/mfa.py", "audit/services.py", "tests/"],
    "V11.5": ["identity/services/mfa.py", "identity/services/sessions.py", "tests/test_mfa.py"],
    "V12.2": ["config/settings/production.py", "tests/test_production_settings.py"],
    "V12.3": ["compose.yaml", "docs/ASVS_LEVEL2_MAPPING.md"],
    "V13.2": [
        "compose.yaml",
        "deploy/postgres/bootstrap-roles.sh",
        "tests/test_deployment_config.py",
    ],
    "V13.3": ["compose.yaml", "config/settings/environment.py", "tests/test_environment.py"],
    "V13.4": ["Dockerfile", ".dockerignore", "tests/test_deployment_config.py"],
    "V14.3": [
        "core/middleware.py",
        "core/static/core/app.js",
        "browser-tests/security-accessibility.spec.mjs",
    ],
    "V15.1": ["SECURITY_PLAN.md", "requirements-prod.lock", "docs/ASVS_LEVEL2_MAPPING.md"],
    "V15.2": ["Dockerfile", ".github/workflows/quality.yml", "tests/test_deployment_config.py"],
    "V15.3": ["core/forms.py", "households/services/access.py", "tests/"],
    "V16.2": ["core/logging.py", "tests/test_logging.py"],
    "V16.3": ["core/logging.py", "identity/views.py", "tests/test_logging.py"],
    "V16.4": ["core/logging.py", "audit/services.py", "docs/ASVS_LEVEL2_MAPPING.md"],
    "V16.5": ["core/errors.py", "core/middleware.py", "tests/test_logging.py"],
}

EXCLUDED_SECTIONS: dict[str, str] = {
    "V4.3": "The application has no GraphQL endpoint or GraphQL data layer.",
    "V4.4": "The application has no WebSocket endpoint or WebSocket session mechanism.",
    "V6.6": (
        "The application has no SMS, email-code, PSTN, or other out-of-band "
        "authentication mechanism."
    ),
    "V6.8": (
        "The application does not authenticate users through an external or federated identity "
        "provider."
    ),
    "V7.6": "The application has no federated sign-in or federated session lifecycle.",
    "V9.1": (
        "The application uses server-side Django reference sessions and does not issue or accept "
        "self-contained tokens."
    ),
    "V9.2": (
        "The application uses server-side Django reference sessions and does not issue or accept "
        "self-contained tokens."
    ),
    "V10.1": "The application has no OAuth or OpenID Connect role or integration.",
    "V10.2": "The application has no OAuth or OpenID Connect role or integration.",
    "V10.3": "The application has no OAuth or OpenID Connect role or integration.",
    "V10.4": "The application has no OAuth or OpenID Connect role or integration.",
    "V10.5": "The application has no OAuth or OpenID Connect role or integration.",
    "V10.6": "The application has no OAuth or OpenID Connect role or integration.",
    "V10.7": "The application has no OAuth or OpenID Connect role or integration.",
    "V17.1": "The application has no WebRTC or TURN service.",
    "V17.2": "The application has no WebRTC media service.",
    "V17.3": "The application has no WebRTC signaling service.",
}

EXCLUDED_REQUIREMENTS: dict[str, str] = {
    "V1.2.6": "The application does not construct or submit LDAP queries.",
    "V1.2.7": "The application does not construct or submit XPath queries.",
    "V1.2.8": "The application does not process LaTeX.",
    "V1.3.1": "The application has no rich-text or user-supplied HTML authoring feature.",
    "V1.3.4": "The application does not accept user-supplied SVG content.",
    "V1.3.5": (
        "The application does not accept user-authored Markdown, CSS, XSL, BBCode, or another "
        "scriptable markup language."
    ),
    "V1.3.6": (
        "The application has no user-controlled server-side request destination or outbound "
        "URL-fetch feature."
    ),
    "V1.3.8": "The Python application does not use JNDI.",
    "V1.3.9": "The application does not use memcache.",
    "V1.3.11": "The initial release does not send user-controlled content to SMTP or IMAP systems.",
    "V1.5.1": "The application does not accept or parse XML from an untrusted source.",
    "V3.5.2": (
        "The application uses server-validated CSRF tokens and does not rely on CORS preflight as "
        "its request-forgery control."
    ),
    "V3.5.4": (
        "The initial release is a single same-origin web application and has no separate "
        "application origin to isolate."
    ),
    "V3.5.5": "The application does not use the browser postMessage interface.",
    "V5.2.3": "The CSV import feature does not accept compressed files or archives.",
    "V5.4.3": (
        "The application does not redistribute or serve files obtained from untrusted sources; "
        "uploaded CSV content is parsed and discarded."
    ),
    "V6.1.3": "The application has one documented local password-then-TOTP authentication pathway.",
    "V6.3.4": "The application has one documented local password-then-TOTP authentication pathway.",
    "V6.4.1": (
        "Provisioning uses administrator-entered user passwords and does not generate initial "
        "passwords or activation codes."
    ),
    "V7.1.3": "The application has no federated identity or SSO session ecosystem.",
    "V12.1.3": (
        "The application does not use mTLS certificate identity for authentication or "
        "authorization."
    ),
    "V15.3.2": "The application backend does not currently call user-selected or external URLs.",
}

NOT_STARTED: dict[str, str] = {
    "V4.2.1": (
        "A production reverse-proxy and Gunicorn request-smuggling compatibility test has not "
        "been completed."
    ),
    "V6.1.2": "A product-specific prohibited-password word list has not been documented.",
    "V6.2.2": "The application does not yet provide a user password-change flow.",
    "V6.2.3": "The missing password-change flow cannot yet require the current and new password.",
    "V6.2.11": "A product-specific prohibited-password word list is not yet enforced.",
    "V6.2.12": (
        "Passwords are checked against Django's common-password list, not a maintained "
        "breached-password corpus."
    ),
    "V6.4.3": (
        "A documented forgotten-password recovery process that preserves MFA strength has not "
        "been implemented."
    ),
    "V7.4.5": (
        "There is no dedicated administrator operation to terminate an arbitrary user's sessions "
        "without also resetting MFA."
    ),
    "V7.5.2": "Users can terminate all sessions but cannot yet review individual active sessions.",
    "V11.1.2": (
        "A complete cryptographic key, algorithm, and certificate inventory has not been produced."
    ),
    "V12.3.1": (
        "The application-to-PostgreSQL connection is isolated on an internal Docker network but "
        "is not encrypted with TLS."
    ),
    "V12.3.3": (
        "Internal HTTP/service connections have not been comprehensively inventoried and forced "
        "to encrypted transports."
    ),
    "V12.3.4": (
        "No internal service certificate trust policy is implemented because internal service "
        "TLS is not yet configured."
    ),
    "V13.2.1": (
        "Backend database authentication still uses long-lived, file-mounted passwords rather "
        "than short-term or certificate credentials."
    ),
    "V13.2.4": "The deployment has no explicit outbound network allowlist.",
    "V13.2.5": "The web container has no explicit application-server egress allowlist.",
    "V15.1.2": (
        "Locked dependency inventories exist, but a generated and retained SBOM is not yet part "
        "of the release gate."
    ),
    "V16.1.1": (
        "A complete layer-by-layer logging inventory, access model, and retention schedule has "
        "not been documented."
    ),
    "V16.4.3": (
        "Operational security logs remain in Docker's local log store and are not transmitted to "
        "a logically separate system."
    ),
}

IMPLEMENTED_REQUIREMENTS = {
    "V1.1.2",
    "V1.2.1",
    "V1.2.2",
    "V1.2.4",
    "V1.3.2",
    "V1.5.2",
    "V2.2.1",
    "V2.2.2",
    "V2.2.3",
    "V2.3.1",
    "V2.3.3",
    "V2.3.4",
    "V3.2.1",
    "V3.2.2",
    "V3.3.1",
    "V3.3.2",
    "V3.3.3",
    "V3.3.4",
    "V3.4.1",
    "V3.4.3",
    "V3.4.4",
    "V3.4.5",
    "V3.4.6",
    "V3.5.1",
    "V3.5.3",
    "V4.1.1",
    "V5.2.1",
    "V5.2.2",
    "V5.3.1",
    "V5.3.2",
    "V5.4.1",
    "V5.4.2",
    "V6.1.1",
    "V6.2.1",
    "V6.2.4",
    "V6.2.5",
    "V6.2.6",
    "V6.2.7",
    "V6.2.8",
    "V6.2.9",
    "V6.2.10",
    "V6.3.1",
    "V6.3.2",
    "V6.3.3",
    "V6.4.2",
    "V6.5.1",
    "V6.5.2",
    "V6.5.3",
    "V6.5.4",
    "V6.5.5",
    "V7.2.1",
    "V7.2.2",
    "V7.2.3",
    "V7.2.4",
    "V7.3.1",
    "V7.3.2",
    "V7.4.1",
    "V7.4.3",
    "V7.4.4",
    "V8.2.1",
    "V8.2.2",
    "V8.2.3",
    "V8.3.1",
    "V8.4.1",
    "V11.2.1",
    "V11.3.1",
    "V11.3.2",
    "V11.3.3",
    "V11.5.1",
    "V12.2.1",
    "V13.2.2",
    "V13.2.3",
    "V13.3.1",
    "V13.3.2",
    "V13.4.1",
    "V13.4.2",
    "V14.2.1",
    "V14.2.2",
    "V14.2.3",
    "V14.3.2",
    "V14.3.3",
    "V15.1.1",
    "V15.2.1",
    "V15.2.3",
    "V15.3.1",
    "V15.3.3",
    "V15.3.5",
    "V15.3.7",
    "V16.2.1",
    "V16.2.2",
    "V16.2.4",
    "V16.2.5",
    "V16.3.1",
    "V16.3.4",
    "V16.4.1",
    "V16.5.1",
    "V16.5.3",
}


def _catalog_sha256(requirements: list[dict[str, Any]]) -> str:
    catalog = [
        {
            "id": item["id"],
            "source_id": item["source_id"],
            "chapter_id": item["chapter_id"],
            "chapter_name": item["chapter_name"],
            "section_id": item["section_id"],
            "section_name": item["section_name"],
            "level": item["level"],
            "description": item["description"],
        }
        for item in requirements
    ]
    payload = json.dumps(catalog, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


def _exclusion_reason(source_id: str, section_id: str) -> str | None:
    return EXCLUDED_REQUIREMENTS.get(source_id, EXCLUDED_SECTIONS.get(section_id))


def _evidence(chapter_id: str, section_id: str) -> list[str]:
    return SECTION_EVIDENCE.get(section_id, CHAPTER_EVIDENCE[chapter_id])


def _validate_policy(source_requirements: list[dict[str, Any]]) -> None:
    source_ids = {str(item["req_id"]) for item in source_requirements}
    source_sections = {str(item["section_id"]) for item in source_requirements}
    policy_ids = set(EXCLUDED_REQUIREMENTS) | set(NOT_STARTED) | IMPLEMENTED_REQUIREMENTS
    unknown_ids = policy_ids - source_ids
    if unknown_ids:
        raise ValueError(f"mapping policy references unknown ASVS IDs: {sorted(unknown_ids)}")
    unknown_sections = (set(EXCLUDED_SECTIONS) | set(SECTION_EVIDENCE)) - source_sections
    if unknown_sections:
        raise ValueError(
            f"mapping policy references unknown ASVS sections: {sorted(unknown_sections)}"
        )

    excluded_ids = {
        str(item["req_id"])
        for item in source_requirements
        if _exclusion_reason(str(item["req_id"]), str(item["section_id"]))
    }
    overlap = excluded_ids & (set(NOT_STARTED) | IMPLEMENTED_REQUIREMENTS)
    if overlap:
        raise ValueError(f"excluded ASVS requirements also have active statuses: {sorted(overlap)}")
    active_overlap = set(NOT_STARTED) & IMPLEMENTED_REQUIREMENTS
    if active_overlap:
        raise ValueError(
            f"ASVS requirements are both implemented and not started: {sorted(active_overlap)}"
        )


def build_inventory(source_path: Path) -> dict[str, Any]:
    source_bytes = source_path.read_bytes()
    observed_sha256 = hashlib.sha256(source_bytes).hexdigest()
    if observed_sha256 != ASVS_SOURCE_SHA256:
        raise ValueError(
            f"ASVS source SHA-256 mismatch: expected {ASVS_SOURCE_SHA256}, got {observed_sha256}"
        )

    source = json.loads(source_bytes)
    source_requirements = source.get("requirements")
    if not isinstance(source_requirements, list):
        raise ValueError("ASVS flat JSON does not contain a requirements list")
    _validate_policy(source_requirements)

    requirements: list[dict[str, Any]] = []
    for raw in source_requirements:
        level = int(raw["L"])
        if level > 2:
            continue
        source_id = str(raw["req_id"])
        section_id = str(raw["section_id"])
        chapter_id = str(raw["chapter_id"])
        reason = _exclusion_reason(source_id, section_id)
        if reason:
            applicability = "not_applicable"
            status = "not_applicable"
            assessment = reason
        elif source_id in NOT_STARTED:
            applicability = "applicable"
            status = "not_started"
            assessment = NOT_STARTED[source_id]
        elif source_id in IMPLEMENTED_REQUIREMENTS:
            applicability = "applicable"
            status = "implemented"
            assessment = (
                "The mapped control has repeatable implementation evidence; a dated "
                "release-candidate run is still required before verification."
            )
        else:
            applicability = "applicable"
            status = "partial"
            assessment = (
                "Relevant controls or documentation exist, but the exact Level 2 requirement "
                "remains incomplete or has not been fully exercised at its release boundary."
            )

        item: dict[str, Any] = {
            "id": f"v{ASVS_VERSION}-{source_id.removeprefix('V')}",
            "source_id": source_id,
            "chapter_id": chapter_id,
            "chapter_name": str(raw["chapter_name"]),
            "section_id": section_id,
            "section_name": str(raw["section_name"]),
            "level": level,
            "description": str(raw["req_description"]),
            "applicability": applicability,
            "status": status,
            "assessment": assessment,
            "evidence": _evidence(chapter_id, section_id),
        }
        if reason:
            item["reason"] = reason
        requirements.append(item)

    status_counts = Counter(item["status"] for item in requirements)
    applicability_counts = Counter(item["applicability"] for item in requirements)
    return {
        "schema_version": 1,
        "mapping_updated": MAPPING_UPDATED,
        "release_candidate": None,
        "target_level": 2,
        "source": {
            "version": ASVS_VERSION,
            "tag": "v5.0.0",
            "url": ASVS_SOURCE_URL,
            "sha256": ASVS_SOURCE_SHA256,
            "git_blob": ASVS_SOURCE_GIT_BLOB,
            "license": "Creative Commons Attribution-ShareAlike 4.0 International",
        },
        "requirement_count": len(requirements),
        "catalog_sha256": _catalog_sha256(requirements),
        "summary": {
            "applicability": dict(sorted(applicability_counts.items())),
            "status": dict(sorted(status_counts.items())),
        },
        "requirements": requirements,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path, help="Downloaded official v5.0.0 flat JSON")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    inventory = build_inventory(args.source)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(inventory, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(
        f"Wrote {inventory['requirement_count']} ASVS requirements to {args.output} "
        f"(catalog {inventory['catalog_sha256']})."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
