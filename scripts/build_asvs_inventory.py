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
MAPPING_UPDATED = "2026-09-13"

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
    "V15.3.2": "The application backend does not currently call user-selected or external URLs.",
}

NOT_STARTED: dict[str, str] = {}

IMPLEMENTED_REQUIREMENTS = {
    "V1.1.1",
    "V1.1.2",
    "V1.2.1",
    "V1.2.2",
    "V1.2.3",
    "V1.2.4",
    "V1.2.5",
    "V1.2.9",
    "V1.3.2",
    "V1.3.3",
    "V1.3.7",
    "V1.3.10",
    "V1.4.1",
    "V1.4.2",
    "V1.4.3",
    "V1.5.2",
    "V2.1.1",
    "V2.1.2",
    "V2.1.3",
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
    "V3.4.2",
    "V3.4.3",
    "V3.4.4",
    "V3.4.5",
    "V3.4.6",
    "V3.5.1",
    "V3.5.3",
    "V3.7.1",
    "V3.7.2",
    "V4.1.1",
    "V4.1.2",
    "V4.1.3",
    "V4.2.1",
    "V5.1.1",
    "V5.2.1",
    "V5.2.2",
    "V5.3.1",
    "V5.3.2",
    "V5.4.1",
    "V5.4.2",
    "V6.1.1",
    "V6.1.2",
    "V6.2.1",
    "V6.2.2",
    "V6.2.3",
    "V6.2.4",
    "V6.2.5",
    "V6.2.6",
    "V6.2.7",
    "V6.2.8",
    "V6.2.9",
    "V6.2.10",
    "V6.2.11",
    "V6.2.12",
    "V6.3.1",
    "V6.3.2",
    "V6.3.3",
    "V6.4.2",
    "V6.4.3",
    "V6.5.1",
    "V6.5.2",
    "V6.5.3",
    "V6.5.4",
    "V6.5.5",
    "V7.1.1",
    "V7.1.2",
    "V7.2.1",
    "V7.2.2",
    "V7.2.3",
    "V7.2.4",
    "V7.3.1",
    "V7.3.2",
    "V7.4.1",
    "V7.4.2",
    "V7.4.3",
    "V7.4.4",
    "V7.4.5",
    "V7.5.2",
    "V8.1.1",
    "V8.1.2",
    "V8.2.1",
    "V8.2.2",
    "V8.2.3",
    "V8.3.1",
    "V8.4.1",
    "V11.1.2",
    "V11.2.1",
    "V11.3.1",
    "V11.3.2",
    "V11.3.3",
    "V11.5.1",
    "V12.1.3",
    "V12.2.1",
    "V12.3.3",
    "V12.3.4",
    "V13.1.1",
    "V13.2.1",
    "V13.2.2",
    "V13.2.3",
    "V13.2.4",
    "V13.2.5",
    "V13.3.1",
    "V13.3.2",
    "V13.4.1",
    "V13.4.2",
    "V13.4.3",
    "V13.4.4",
    "V13.4.5",
    "V14.1.1",
    "V14.1.2",
    "V14.2.1",
    "V14.2.2",
    "V14.2.3",
    "V14.3.1",
    "V14.3.2",
    "V14.3.3",
    "V15.1.1",
    "V15.1.2",
    "V15.1.3",
    "V15.2.1",
    "V15.2.3",
    "V15.3.1",
    "V15.3.3",
    "V15.3.5",
    "V15.3.6",
    "V15.3.7",
    "V16.1.1",
    "V16.2.1",
    "V16.2.2",
    "V16.2.3",
    "V16.2.4",
    "V16.2.5",
    "V16.3.1",
    "V16.3.2",
    "V16.3.4",
    "V16.4.1",
    "V16.4.3",
    "V16.5.1",
    "V16.5.3",
}

IMPLEMENTED_ASSESSMENT_OVERRIDES: dict[str, str] = {
    "V1.1.1": (
        "Django owns the single percent/form decoding pass before validation, and application code "
        "contains no second unquote, query, or HTML-entity decoder. A fail-closed AST inventory "
        "pins all 16 strict text, JSON, and purpose-specific Base32 operations across seven files, "
        "rejects permissive or dynamic encodings and general input decoders, and detects nested "
        "deserialization. Each documented boundary validates the canonical result before business "
        "processing, persistence, or security use."
    ),
    "V1.2.3": (
        "Django templates retain automatic contextual HTML escaping, and production JavaScript "
        "uses DOM construction and textContent instead of parsing dynamic HTML. A fail-closed "
        "inventory rejects disabled or bypassed template escaping, inline scripts, HTML-parsing "
        "and code-execution sinks, custom trusted-HTML APIs, manual script or JSON media bodies, "
        "and custom JsonResponse encoders. The two fixed operational JSON endpoints use Django's "
        "default JsonResponse encoder, while CSP permits scripts only from the same origin."
    ),
    "V1.2.5": (
        "The production Python runtime has a zero-child-process boundary: application, settings, "
        "migration, management-command, and entry-point code imports and invokes no shell or "
        "process-launch API. A fail-closed AST inventory rejects subprocess and equivalent "
        "modules, OS exec/spawn/system APIs, asyncio process creation, dynamic module loading, "
        "and dynamic lookup of OS or asyncio APIs, including renamed imports."
    ),
    "V1.2.9": (
        "A fail-closed AST inventory requires every Python and Django regular-expression call to "
        "use a non-empty literal pattern, except for the one reviewed password-validator pattern. "
        "That construction applies re.escape independently to every configured alternative before "
        "placing the single escaped fragment in fixed anchored syntax; module aliasing, direct "
        "symbol imports, new dynamic patterns, and unescaped interpolation are rejected."
    ),
    "V1.3.3": (
        "A maintained inventory defines the exact treatment for 11 dangerous context families. "
        "The aggregate fail-closed checker scans all 218 production Python files, including "
        "migrations, and pins all 25 raw SQL calls to literal text: three application cursor "
        "calls and 22 fixed schema-editor migration calls. It requires nine specialized context "
        "checkers in both quality gates and exact source contracts for CSV formula encoding, "
        "redirect and notification URLs, checkpoint filenames, disabled production email, and "
        "structured-log redaction."
    ),
    "V1.3.7": (
        "All production render and template-loader calls select existing templates with fixed "
        "literal names, and every template extends or includes an existing literal dependency. "
        "A fail-closed source inventory rejects runtime template construction, dynamic or missing "
        "template names, mixed literal/dynamic fallback lists, dynamic inheritance or includes, "
        "and aliases of the reviewed Django selection APIs."
    ),
    "V1.3.10": (
        "Format grammars are code-owned literals. A fail-closed AST inventory rejects dynamic "
        "str.format receivers, format specifications, f-string specifications, HTML formatting "
        "grammars, datetime output grammars, runtime string templates, log message templates, and "
        "percent-format expressions. The one iterated CSV date parser is constrained to an exact "
        "literal format allowlist, and all 11 percent operators are pinned arithmetic modulo."
    ),
    "V1.4.1": (
        "Application-owned Python and JavaScript use managed strings, bytes, objects, and buffers "
        "without pointer arithmetic or manual allocation. A fail-closed scan rejects application "
        "native source, unsafe memory and FFI modules, unreviewed buffer views, native-size struct "
        "formats, and JavaScript raw-memory or WebAssembly APIs. The sole memoryview and two "
        "explicit big-endian TOTP conversions are pinned and bounds-checked."
    ),
    "V1.4.2": (
        "Python integer arithmetic cannot wrap, financial code cannot convert through binary "
        "float, and fixed-width TOTP operations are explicitly bounded. The model registry pins "
        "38 DecimalFields to reviewed money or rate shapes and 37 non-automatic IntegerFields to "
        "bounded big or positive types; forms, services, models, and database constraints enforce "
        "finiteness, scale, sign, rate, amount, calendar, upload, and projection limits."
    ),
    "V1.4.3": (
        "Managed runtimes reclaim application allocations without dangling pointers. The checker "
        "pins all low-level descriptor operations to six reviewed files, requires every fdopen, "
        "Unix socket, and named temporary file to use a context manager, and rejects new unsafe "
        "allocation interfaces. Each raw descriptor site has explicit failure and finally cleanup "
        "or transfers ownership to a context-managed file."
    ),
    "V2.1.1": (
        "The maintained input-validation policy inventories all 49 form classes across eight "
        "production form modules and defines ten structure-rule families for authentication, "
        "MFA, financial values, text, calendar recurrence, identifiers, scoped references, CSV, "
        "enumerated controls, and local action targets. A fail-closed checker detects form, "
        "evidence, policy, review-date, and source-contract drift."
    ),
    "V2.1.2": (
        "Ten documented contextual rule groups define household ownership, recurrence, goal, "
        "debt, mortgage, balanced-ledger, reversal and reconciliation, CSV staging, MFA session, "
        "and audit-chain consistency. The policy requires authoritative checks in transactional "
        "services and database constraints rather than relying on browser or scalar validation."
    ),
    "V2.1.3": (
        "Eleven business-limit groups document exact money and rate shapes, upload resources, "
        "recurrence and projection horizons, authentication and MFA time windows, blocklist "
        "bounds, notification windows, and pagination. Thirteen source assertions pin the current "
        "values and fail the normal gates on drift; exhaustive business-rule enforcement remains "
        "separately partial under V2.3.2."
    ),
    "V3.4.2": (
        "The private application deliberately grants no cross-origin reads. An outer same-origin "
        "response boundary removes every CORS permission field and Timing-Allow-Origin, sets "
        "Cross-Origin-Resource-Policy to same-origin, and encloses the hardened static-file layer; "
        "WhiteNoise's independent wildcard-origin default remains disabled."
    ),
    "V3.7.1": (
        "The production client is limited to reviewed browser-native formats and dependency-free "
        "runtime JavaScript. A fail-closed inventory rejects legacy plug-in elements, APIs, media "
        "types, executable artifacts, references, and unreviewed asset types; CSP independently "
        "blocks object execution and current Chromium, Firefox, and WebKit engines exercise the "
        "client in pull-request CI."
    ),
    "V3.7.2": (
        "A final response boundary rejects malformed, downgraded, and unapproved external redirect "
        "locations. External redirects require an exact HTTPS authority allowlist entry, and the "
        "private production profile requires that allowlist to remain empty."
    ),
    "V4.1.2": (
        "A hardened pre-redirect boundary classifies reserved documentation and monitoring paths "
        "as non-browser endpoints. Missing or ambiguous trusted proxy schemes receive an empty "
        "400 response without Location, while a representative browser page retains its exact "
        "canonical HTTPS redirect; the production-derived runtime probe exercises both paths."
    ),
    "V4.1.3": (
        "Tailscale Serve overwrites the sole trusted scheme header at the HTTPS edge, while the "
        "loopback-only nginx relay replaces it with a canonical value and clears every other "
        "forwarding header before the mutually authenticated Gunicorn boundary. Configuration "
        "tests and a dated deployed spoofing probe enforce the complete intermediary chain."
    ),
    "V4.2.1": (
        "The production-derived nginx and Gunicorn boundary accepts three valid HTTP/1.1 message "
        "forms and must reject six ambiguous or malformed framing forms with exactly one error "
        "response and a closed connection. Browser-facing Tailscale HTTP/2 or HTTP/3 validation "
        "remains a dated release-candidate check."
    ),
    "V5.1.1": (
        "The documented upload inventory permits only bounded UTF-8 .csv transaction statements, "
        "defines the extension, advertised media type, raw and unpacked-size treatment, row, "
        "column, and cell limits, and records fail-closed rejection, staging, cleanup, preview, "
        "and formula-safe generated-download behavior."
    ),
    "V6.1.2": (
        "The exact product and system identifiers plus normalized separator, leetspeak, prefix, "
        "suffix, and short-numeric permutations are documented; release-candidate verification "
        "remains pending."
    ),
    "V6.2.2": (
        "A recent-authentication-protected self-service flow changes the password, rotates the "
        "surviving session, revokes other sessions, and creates protected audit evidence."
    ),
    "V6.2.3": (
        "The password-change form and transactional view require both the accepted current "
        "password and a separately validated new password after recent password-plus-MFA "
        "verification."
    ),
    "V6.2.11": (
        "ContextSpecificPasswordValidator enforces the documented normalized product and system "
        "identifier permutations through every Django-validated new or changed password path; "
        "release-candidate verification remains pending."
    ),
    "V6.2.12": (
        "New and changed passwords are compared locally with a packaged, integrity-checked, "
        "freshness-bounded hash-only breached-password corpus; hardened settings fail closed and "
        "no candidate-derived value leaves the process. Release-candidate verification remains "
        "pending."
    ),
    "V6.4.3": (
        "Public password recovery requires a confirmed TOTP or unused single-use recovery code, "
        "returns a generic rate-limited result, never authenticates the requester, revokes every "
        "prior session, and requires fresh MFA after the replacement password."
    ),
    "V7.4.5": (
        "A guarded trusted-console operation terminates one arbitrary account's sessions or every "
        "account's sessions independently of credential reset, with explicit confirmation, "
        "server-side version rotation, stored-session deletion, redacted security logging, and "
        "protected household audit events. Dated release-candidate replay verification remains "
        "pending."
    ),
    "V7.5.2": (
        "Users can review their current-version server-side sessions and, after recent "
        "authentication, terminate an individual session or all sessions through non-reversible "
        "action references."
    ),
    "V7.1.1": (
        "The session policy documents and justifies the enforced one-hour inactivity and "
        "twelve-hour overall limits against the current NIST SP 800-63B AAL2 recommendation, "
        "including the stricter overall boundary, browser-only persistence, termination behavior, "
        "and change-control requirements."
    ),
    "V7.1.2": (
        "The documented five-session account limit is enforced after a new authenticated session "
        "is saved. Per-account database locking serializes enforcement, the new "
        "login is preserved, "
        "and the oldest current-version session is revoked with cleanup on its next request."
    ),
    "V7.4.2": (
        "User lifecycle hooks synchronously delete every authenticated and pending-MFA session "
        "when an existing account is disabled or deleted. Queryset deletion is covered, and a "
        "displaced browser receives secure client-state cleanup on its next request."
    ),
    "V8.1.1": (
        "The deny-by-default authorization policy defines four consumer states and eleven "
        "function and record rule groups using active membership, selected household, recipient, "
        "lifecycle, classification, recent-authentication, integrity, and purpose attributes. "
        "Its fail-closed route registry classifies all 70 named routes across nine namespaces and "
        "verifies authentication and sensitive-function guards from source."
    ),
    "V8.1.2": (
        "Ten field-level rule groups define readable, client-writable, and service-managed fields "
        "for credentials, identity, membership, finances, immutable accounting and revisions, "
        "imports, recipient notifications, audit history, system metadata, and exports. Forms and "
        "serializers are explicit allowlists; ownership, hashes, counters, links, revisions, and "
        "integrity metadata remain service-controlled."
    ),
    "V11.1.2": (
        "The machine-validated inventory covers application, deployment, provider-managed, and "
        "test-only key, algorithm, and certificate boundaries; it defines permitted and "
        "prohibited uses, protected and excluded data, rotation, retirement, review cadence, and "
        "known absences without claiming release verification."
    ),
    "V12.1.3": (
        "PostgreSQL validates every production client certificate against a dedicated client CA "
        "and maps its exact certificate CN to one configured database role. The runtime proof "
        "confirms the web client DN and rejects a web certificate attempting the audit role."
    ),
    "V12.3.3": (
        "The only internal HTTP service hop uses mutually authenticated TLS 1.2 or TLS 1.3: "
        "nginx validates the DNS-constrained web server against a dedicated CA, Gunicorn trusts "
        "only the separate nginx client CA, and neither side exposes a plaintext listener."
    ),
    "V12.3.4": (
        "PostgreSQL and the nginx-to-Gunicorn hop use separate purpose-bound offline server and "
        "client CAs. Each TLS client trusts only its intended internal server CA and exact DNS "
        "name; each server trusts only its intended client CA."
    ),
    "V13.1.1": (
        "A machine-readable and human-reviewed inventory documents all 10 runtime, management, "
        "and maintenance communication paths plus six external host/build dependencies. It "
        "records purpose, destination, transport, protection, data class, phase, and evidence, "
        "and explicitly records no user-supplied external destination. A fail-closed runtime scan "
        "rejects network clients beyond two Unix-datagram-only logging files, while production "
        "settings disable SMTP and retain exact database, proxy, service-network, and redirect "
        "allowlists."
    ),
    "V13.2.1": (
        "Every production database client uses a unique purpose-bound certificate identity mapped "
        "to its least-privilege role. PostgreSQL accepts no password-authenticated TCP path, and "
        "bootstrapping plus the runtime proof require all production login roles to have no "
        "password verifier."
    ),
    "V13.2.4": (
        "The production Compose model fixes the exact service catalog and network attachments, "
        "rejects network-bypass settings, keeps the application and maintenance workloads on "
        "internal networks or no network, and defines no external application destination. The "
        "TLS-only loopback relay retains the non-internal network required for its host publish "
        "but its running nginx configuration is restricted to the single authenticated internal "
        "web upstream. "
        "Release-candidate verification remains pending."
    ),
    "V13.2.5": (
        "The Django server is restricted to its internal database destination and cannot connect "
        "to an external TCP endpoint, while nginx has exactly one static internal proxy "
        "destination, https://web:8443, with exact server trust and a purpose-bound client "
        "identity. The production-derived runtime probe checks both "
        "paths without claiming release-candidate verification."
    ),
    "V13.4.3": (
        "The production nginx relay explicitly disables autoindex, has no root or alias directive, "
        "and is validated from the running production-derived configuration so it cannot expose "
        "a filesystem directory listing."
    ),
    "V13.4.4": (
        "The production nginx relay rejects TRACE with 405 before proxying. The production-derived "
        "runtime probe sends TRACE with a canary header and requires one 405 response without "
        "reflecting that request content."
    ),
    "V13.4.5": (
        "The hardened application reserves documentation and monitoring route namespaces and "
        "exposes only the exact minimal liveness endpoint. The production-derived runtime probe "
        "requires the existing database-readiness route and representative documentation, metrics, "
        "schema, debug, and actuator paths to return empty hardened 404 responses."
    ),
    "V14.1.1": (
        "A machine-readable classification identifies all sensitive data created or processed by "
        "the application across 45 Django models and 10 non-model data surfaces. Every model is "
        "assigned exactly once at the highest protection needed by any field, and encoded, hashed, "
        "masked, encrypted, compressed, or pseudonymous derivatives explicitly inherit their "
        "source classification. The documented deployment and privacy context has mandatory "
        "jurisdiction, integration, provider, regulated-use, and release reassessment triggers."
    ),
    "V14.1.2": (
        "Four ordered protection levels define requirements for transport and at-rest encryption, "
        "database-volume encryption, integrity, retention, logging, log access, authorization, "
        "privacy, confidentiality, encoding, disposal, backups, and client storage. Fifteen "
        "dataset records apply concrete lifecycle rules and evidence, while the checker pins the "
        "model registry and implemented cookie, TLS, no-store, browser-cleanup, import-scrubbing, "
        "export, and encrypted-backup boundaries. Dated database-volume and full control "
        "verification remains separately tracked under V14.2.4."
    ),
    "V14.3.1": (
        "Every secure server-side session termination response directs the browser to clear "
        "cache, cookies, and origin storage. Logout forms also synchronously clear Web Storage, "
        "begin Cache Storage and IndexedDB removal, and replace the authenticated DOM "
        "independently of the network response; the browser lifecycle test exercises both paths."
    ),
    "V15.1.2": (
        "The deterministic CycloneDX inventory derives all production, development, build, test, "
        "and CI components from exact locks, digest-pinned images, checksummed source, Go pins, "
        "and immutable actions, enforces the approved repository set, and is complemented by "
        "90-day image-resolved SBOM artifacts for all three release images without claiming "
        "release-candidate verification."
    ),
    "V15.1.3": (
        "The maintained resource-demand policy identifies seven expensive interactive and "
        "operator workflow families, their fixed input, result, horizon, process, and concurrency "
        "bounds, and their failure and retry behavior. Five explicit ingress and application "
        "timeouts preserve worker-before-proxy failure ordering. A fail-closed checker pins 12 "
        "source contracts and the two-worker deployment envelope. Representative load evidence "
        "and CPU or memory quotas remain separately tracked under V15.2.2."
    ),
    "V15.3.6": (
        "The dependency-free production JavaScript uses Map and Set for runtime-selected keys and "
        "membership. Its fail-closed client inventory rejects prototype names, object/reflection "
        "mutation APIs, dynamic bracket access, and inherited-property iteration across every "
        "reviewed JavaScript file and inline-script-capable template."
    ),
    "V16.1.1": (
        "The machine-validated inventory covers every application, web, relay, database, "
        "container, host, provider, browser, security-test, and CI layer with source-derived event "
        "catalogs, formats, destinations, uses, readers, retention, sensitive-data rules, "
        "integrity limits, and explicit separate-destination gaps without claiming release "
        "verification."
    ),
    "V16.2.3": (
        "A fail-closed source validator pins the exact Django console, null, and separate Unix "
        "datagram archive handlers; their logger routes; and every literal application logger "
        "name. It rejects additional settings mutations plus file, network, mail, syslog, queue, "
        "dynamic, and third-party telemetry sinks, while the existing deployment checks pin the "
        "documented Docker, Gunicorn, nginx, and collector destinations."
    ),
    "V16.3.2": (
        "Every explicit 403 response and every authenticated, resolved identifier-bearing 404 "
        "used to conceal object scope emits one warning-level authorization.denied security event. "
        "The record contains only method, resolved route, status, error reference, and bound "
        "pseudonymous context; it excludes paths, queries, route arguments, object identifiers, "
        "and exception text, and expected permission or not-found outcomes are not labeled "
        "unhandled."
    ),
    "V16.4.3": (
        "Production Django security records are sent over a permission-restricted Unix datagram "
        "socket to a distinct networkless collector. The application has only a read-only socket "
        "mount and cannot access the collector-only archive volume. The collector independently "
        "validates and redacts records, persists them with restrictive modes, creates a "
        "warning-or-higher alert stream, and emits fixed safe transport or validation failures. "
        "Release-candidate retention, review, and escalation observations remain pending."
    ),
}

IMPLEMENTED_EVIDENCE_OVERRIDES: dict[str, list[str]] = {
    "V1.1.1": [
        "docs/CANONICAL_INPUT_DECODING.md",
        "docs/DATA_CLASSIFICATION.md",
        "scripts/check_canonical_decoding.py",
        "scripts/check.ps1",
        "scripts/check.sh",
        "tests/test_canonical_decoding.py",
        "imports/services/parsing.py",
        "core/security_log_collector.py",
        "identity/services/mfa.py",
        "identity/password_validation.py",
        "audit/management/commands/verify_audit_checkpoint.py",
        "tests/test_csv_imports.py",
        "tests/test_security_log_archive.py",
        "tests/test_password_policy.py",
    ],
    "V2.1.1": [
        "docs/INPUT_VALIDATION_POLICY.md",
        "docs/input-validation-policy.json",
        "scripts/check_input_validation_policy.py",
        "scripts/check.ps1",
        "scripts/check.sh",
        "tests/test_input_validation_policy.py",
        "identity/forms.py",
        "imports/forms.py",
    ],
    "V2.1.2": [
        "docs/INPUT_VALIDATION_POLICY.md",
        "docs/input-validation-policy.json",
        "scripts/check_input_validation_policy.py",
        "tests/test_input_validation_policy.py",
        "households/services/access.py",
        "ledger/services/entries.py",
        "schedules/recurrence.py",
    ],
    "V2.1.3": [
        "docs/INPUT_VALIDATION_POLICY.md",
        "docs/input-validation-policy.json",
        "scripts/check_input_validation_policy.py",
        "scripts/check.ps1",
        "scripts/check.sh",
        "tests/test_input_validation_policy.py",
        "config/settings/base.py",
        "debts/services/projections.py",
    ],
    "V1.2.3": [
        "docs/OUTPUT_ENCODING_POLICY.md",
        "scripts/check_output_encoding.py",
        "scripts/check.ps1",
        "scripts/check.sh",
        "core/views.py",
        "core/static/core/app.js",
        "core/middleware.py",
        "tests/test_output_encoding.py",
        "tests/test_logging.py",
        "tests/test_release_hardening.py",
    ],
    "V1.2.5": [
        "docs/OS_COMMAND_SAFETY.md",
        "scripts/check_os_command_safety.py",
        "scripts/check.ps1",
        "scripts/check.sh",
        "compose.yaml",
        "Dockerfile",
        "tests/test_os_command_safety.py",
        "tests/test_release_hardening.py",
    ],
    "V1.2.9": [
        "docs/REGULAR_EXPRESSION_SAFETY.md",
        "scripts/check_regex_safety.py",
        "scripts/check.ps1",
        "scripts/check.sh",
        "identity/password_validation.py",
        "tests/test_regex_safety.py",
        "tests/test_password_policy.py",
        "tests/test_release_hardening.py",
    ],
    "V1.3.3": [
        "docs/CONTEXT_SANITIZATION.md",
        "docs/context-sanitization.json",
        "scripts/check_context_sanitization.py",
        "scripts/check.ps1",
        "scripts/check.sh",
        "spending/services/exports.py",
        "core/middleware.py",
        "notifications/models.py",
        "audit/checkpoints.py",
        "tests/test_context_sanitization.py",
        "tests/test_release_hardening.py",
    ],
    "V1.3.7": [
        "docs/TEMPLATE_INJECTION_POLICY.md",
        "scripts/check_template_safety.py",
        "scripts/check.ps1",
        "scripts/check.sh",
        "core/templates/core/app_base.html",
        "core/views.py",
        "identity/views.py",
        "budgets/views.py",
        "tests/test_template_safety.py",
        "tests/test_release_hardening.py",
    ],
    "V1.3.10": [
        "docs/FORMAT_STRING_SAFETY.md",
        "scripts/check_format_string_safety.py",
        "scripts/check.ps1",
        "scripts/check.sh",
        "imports/services/batches.py",
        "core/logging.py",
        "tests/test_format_string_safety.py",
        "tests/test_release_hardening.py",
    ],
    "V1.4.1": [
        "docs/MANAGED_RUNTIME_SAFETY.md",
        "scripts/check_managed_runtime_safety.py",
        "scripts/check.ps1",
        "scripts/check.sh",
        "core/security_log_collector.py",
        "identity/services/mfa.py",
        "core/static/core/app.js",
        "docs/SBOM.md",
        "tests/test_managed_runtime_safety.py",
        "tests/test_release_hardening.py",
    ],
    "V1.4.2": [
        "docs/MANAGED_RUNTIME_SAFETY.md",
        "scripts/check_managed_runtime_safety.py",
        "budgets/forms.py",
        "debts/forms.py",
        "debts/services/projections.py",
        "imports/services/batches.py",
        "ledger/models.py",
        "identity/services/mfa.py",
        "tests/test_managed_runtime_safety.py",
        "tests/test_debt_projections.py",
        "tests/test_release_hardening.py",
    ],
    "V1.4.3": [
        "docs/MANAGED_RUNTIME_SAFETY.md",
        "scripts/check_managed_runtime_safety.py",
        "core/security_log_collector.py",
        "core/logging.py",
        "core/pentest_fixture.py",
        "audit/checkpoints.py",
        "identity/password_validation.py",
        "identity/management/commands/build_breached_password_corpus.py",
        "tests/test_managed_runtime_safety.py",
        "tests/test_release_hardening.py",
    ],
    "V3.4.2": [
        "docs/CROSS_ORIGIN_SECURITY.md",
        "docs/SECURITY_FINDINGS.md",
        "config/settings/base.py",
        "config/settings/hardened.py",
        "config/settings/production.py",
        "core/middleware.py",
        "tests/test_logging.py",
        "tests/test_production_settings.py",
        "tests/test_release_hardening.py",
    ],
    "V3.7.1": [
        "docs/CLIENT_TECHNOLOGY_POLICY.md",
        "scripts/check_client_technologies.py",
        "scripts/check.ps1",
        "scripts/check.sh",
        "core/middleware.py",
        "core/static/core/app.js",
        "Dockerfile.browser-tests",
        "package-lock.json",
        "playwright.config.mjs",
        ".github/workflows/browser.yml",
        "tests/test_client_technologies.py",
        "tests/test_release_hardening.py",
    ],
    "V3.7.2": [
        "docs/REDIRECT_SECURITY.md",
        "config/settings/base.py",
        "config/settings/production.py",
        "core/middleware.py",
        "identity/views.py",
        "notifications/models.py",
        "tests/test_authentication.py",
        "tests/test_production_settings.py",
        "tests/test_release_hardening.py",
    ],
    "V4.1.2": [
        "core/middleware.py",
        "config/settings/production.py",
        "deploy/network/run-production-boundary.py",
        "scripts/run-network-boundary.sh",
        "tests/test_logging.py",
        "tests/test_network_boundary.py",
        "tests/test_production_settings.py",
        "docs/PRIVATE_INGRESS.md",
    ],
    "V4.1.3": [
        "config/settings/hardened.py",
        "core/middleware.py",
        "deploy/network/nginx.conf",
        "deploy/network/run-production-boundary.py",
        "deploy/network/verify-private-ingress.py",
        "scripts/verify-private-ingress.sh",
        "tests/test_network_boundary.py",
        "tests/test_production_settings.py",
        "docs/PRIVATE_INGRESS.md",
    ],
    "V4.2.1": [
        "deploy/network/nginx.conf",
        "deploy/network/run-production-boundary.py",
        "scripts/run-network-boundary.sh",
        ".github/workflows/http-framing.yml",
        "tests/test_network_boundary.py",
        "docs/PRIVATE_INGRESS.md",
    ],
    "V5.1.1": [
        "docs/FILE_HANDLING_POLICY.md",
        "config/settings/base.py",
        "imports/forms.py",
        "imports/services/parsing.py",
        "imports/services/batches.py",
        "imports/templates/imports/import_preview.html",
        "spending/services/exports.py",
        "audit/exports.py",
        "tests/test_csv_imports.py",
        "tests/test_csv_exports.py",
        "tests/test_audit_ui.py",
        "tests/test_release_hardening.py",
    ],
    "V6.1.2": [
        "docs/PASSWORD_BLOCKLIST.md",
        "config/settings/base.py",
        "identity/password_validation.py",
        "tests/test_password_policy.py",
    ],
    "V6.2.2": ["identity/forms.py", "identity/views.py", "tests/test_account_security.py"],
    "V6.2.3": ["identity/forms.py", "identity/views.py", "tests/test_account_security.py"],
    "V6.2.11": [
        "config/settings/base.py",
        "identity/password_validation.py",
        "identity/forms.py",
        "identity/management/commands/bootstrap_household.py",
        "identity/management/commands/reset_user_password.py",
        "tests/test_password_policy.py",
    ],
    "V6.2.12": [
        "config/settings/base.py",
        "config/settings/hardened.py",
        "identity/password_validation.py",
        "identity/data/breached-passwords-v1.txt",
        "identity/management/commands/build_breached_password_corpus.py",
        "docs/PASSWORD_BLOCKLIST.md",
        "tests/test_password_policy.py",
    ],
    "V6.4.3": [
        "identity/forms.py",
        "identity/services/mfa.py",
        "identity/services/recovery.py",
        "identity/views.py",
        "deploy/pentest/run-session-security.py",
        "tests/test_password_recovery.py",
    ],
    "V7.4.5": [
        "identity/services/sessions.py",
        "identity/management/commands/revoke_user_sessions.py",
        "deploy/pentest/run-session-security.py",
        "scripts/run-session-security.sh",
        "tests/test_identity_commands.py",
        "tests/test_pentest_harness.py",
        "docs/INCIDENT_RESPONSE.md",
        "docs/ADVERSARIAL_TESTING.md#sess-03",
        "docs/SECURITY_FINDINGS.md#M10-F023",
    ],
    "V7.5.2": [
        "identity/services/sessions.py",
        "identity/views.py",
        "deploy/pentest/run-session-security.py",
        "tests/test_account_security.py",
    ],
    "V7.1.1": [
        "docs/SESSION_SECURITY.md",
        "config/settings/base.py",
        "config/settings/hardened.py",
        "identity/services/sessions.py",
        "identity/middleware.py",
        "tests/test_authentication.py",
        "tests/test_release_hardening.py",
    ],
    "V7.1.2": [
        "docs/SESSION_SECURITY.md",
        "config/settings/base.py",
        "identity/services/sessions.py",
        "identity/middleware.py",
        "tests/test_account_security.py",
        "tests/test_release_hardening.py",
    ],
    "V7.4.2": [
        "docs/SESSION_SECURITY.md",
        "identity/apps.py",
        "identity/signals.py",
        "identity/services/sessions.py",
        "identity/middleware.py",
        "tests/test_authentication.py",
        "tests/test_release_hardening.py",
    ],
    "V8.1.1": [
        "docs/AUTHORIZATION_POLICY.md",
        "docs/authorization-policy.json",
        "scripts/check_authorization_policy.py",
        "scripts/check.ps1",
        "scripts/check.sh",
        "tests/test_authorization_policy.py",
        "households/services/access.py",
        "core/middleware.py",
    ],
    "V8.1.2": [
        "docs/AUTHORIZATION_POLICY.md",
        "docs/authorization-policy.json",
        "scripts/check_authorization_policy.py",
        "tests/test_authorization_policy.py",
        "identity/models.py",
        "notifications/services.py",
        "ledger/models.py",
        "audit/models.py",
    ],
    "V11.1.2": [
        "docs/cryptographic-inventory.json",
        "docs/CRYPTOGRAPHIC_INVENTORY.md",
        "scripts/check_cryptographic_inventory.py",
        "tests/test_release_hardening.py",
    ],
    "V12.1.3": [
        "scripts/generate-postgres-tls.py",
        "compose.yaml",
        "deploy/postgres/start-tls.sh",
        "deploy/postgres/pg_hba.conf",
        "deploy/network/run-production-boundary.py",
        "tests/test_network_boundary.py",
        "docs/POSTGRES_TLS.md",
    ],
    "V12.3.3": [
        "compose.yaml",
        "config/gunicorn.py",
        "deploy/network/nginx.conf",
        "deploy/network/run-production-boundary.py",
        "scripts/generate-postgres-tls.py",
        "tests/test_deployment_config.py",
        "tests/test_network_boundary.py",
        "tests/test_postgres_tls.py",
        "docs/PRIVATE_INGRESS.md",
        "docs/cryptographic-inventory.json",
    ],
    "V12.3.4": [
        "compose.yaml",
        "config/gunicorn.py",
        "deploy/network/nginx.conf",
        "deploy/network/run-production-boundary.py",
        "deploy/postgres/start-tls.sh",
        "scripts/generate-postgres-tls.py",
        "tests/test_network_boundary.py",
        "tests/test_postgres_tls.py",
        "docs/PRIVATE_INGRESS.md",
        "docs/POSTGRES_TLS.md",
        "docs/cryptographic-inventory.json",
    ],
    "V13.1.1": [
        "docs/COMMUNICATION_INVENTORY.md",
        "docs/communication-inventory.json",
        "scripts/check_communication_inventory.py",
        "scripts/check.ps1",
        "scripts/check.sh",
        "compose.yaml",
        "config/settings/hardened.py",
        "config/settings/production.py",
        "deploy/network/nginx.conf",
        "tests/test_communication_inventory.py",
        "tests/test_production_settings.py",
        "tests/test_network_boundary.py",
        "tests/test_release_hardening.py",
    ],
    "V13.2.1": [
        "scripts/generate-postgres-tls.py",
        "compose.yaml",
        "config/settings/hardened.py",
        "deploy/postgres/bootstrap-roles.sh",
        "deploy/postgres/pg_hba.conf",
        "deploy/network/run-production-boundary.py",
        "tests/test_deployment_config.py",
        "tests/test_network_boundary.py",
        "docs/POSTGRES_TLS.md",
    ],
    "V13.2.4": [
        "compose.yaml",
        "deploy/network/run-production-boundary.py",
        "scripts/run-network-boundary.sh",
        "tests/test_network_boundary.py",
        "docs/PRIVATE_INGRESS.md",
    ],
    "V13.2.5": [
        "compose.yaml",
        "deploy/network/nginx.conf",
        "deploy/network/run-production-boundary.py",
        "tests/test_network_boundary.py",
        "docs/PRIVATE_INGRESS.md",
    ],
    "V13.4.3": [
        "deploy/network/nginx.conf",
        "deploy/network/run-production-boundary.py",
        "scripts/run-network-boundary.sh",
        "tests/test_network_boundary.py",
        "docs/PRIVATE_INGRESS.md",
    ],
    "V13.4.4": [
        "deploy/network/nginx.conf",
        "deploy/network/run-production-boundary.py",
        "scripts/run-network-boundary.sh",
        "tests/test_network_boundary.py",
        "docs/PRIVATE_INGRESS.md",
    ],
    "V13.4.5": [
        "core/middleware.py",
        "config/settings/hardened.py",
        "deploy/network/run-production-boundary.py",
        "scripts/run-network-boundary.sh",
        "tests/test_logging.py",
        "tests/test_network_boundary.py",
        "tests/test_production_settings.py",
        "docs/PRIVATE_INGRESS.md",
    ],
    "V14.1.1": [
        "docs/DATA_CLASSIFICATION.md",
        "docs/data-classification.json",
        "scripts/check_data_classification.py",
        "scripts/check.ps1",
        "scripts/check.sh",
        "tests/test_data_classification.py",
        "config/settings/base.py",
        "config/settings/hardened.py",
        "core/middleware.py",
        "identity/middleware.py",
        "imports/services/batches.py",
        "docs/COMMUNICATION_INVENTORY.md",
        "docs/LOGGING_INVENTORY.md",
        "docs/CRYPTOGRAPHIC_INVENTORY.md",
    ],
    "V14.1.2": [
        "docs/DATA_CLASSIFICATION.md",
        "docs/data-classification.json",
        "scripts/check_data_classification.py",
        "scripts/check.ps1",
        "scripts/check.sh",
        "tests/test_data_classification.py",
        "config/settings/base.py",
        "config/settings/hardened.py",
        "core/middleware.py",
        "identity/middleware.py",
        "core/static/core/app.js",
        "imports/services/batches.py",
        "spending/views.py",
        "audit/views.py",
        "docs/BACKUP_AND_RESTORE.md",
    ],
    "V14.3.1": [
        "identity/services/sessions.py",
        "identity/middleware.py",
        "identity/views.py",
        "core/static/core/app.js",
        "core/templates/core/app_base.html",
        "identity/templates/identity/mfa_enroll.html",
        "browser-tests/session-lifecycle.spec.mjs",
        "tests/test_authentication.py",
        "tests/test_browser_harness.py",
    ],
    "V15.1.2": [
        "docs/sbom.cdx.json",
        "docs/SBOM.md",
        "scripts/build_sbom.py",
        "scripts/check_sbom.py",
        ".github/workflows/quality.yml",
        "tests/test_release_hardening.py",
    ],
    "V15.1.3": [
        "docs/RESOURCE_DEMAND_POLICY.md",
        "docs/resource-demand-policy.json",
        "scripts/check_resource_demand_policy.py",
        "scripts/check_input_validation_policy.py",
        "scripts/check.ps1",
        "scripts/check.sh",
        "config/gunicorn.py",
        "deploy/network/nginx.conf",
        "compose.yaml",
        "tests/test_resource_demand_policy.py",
        "tests/test_deployment_config.py",
        "tests/test_release_hardening.py",
    ],
    "V15.3.6": [
        "docs/JAVASCRIPT_OBJECT_SAFETY.md",
        "docs/CLIENT_TECHNOLOGY_POLICY.md",
        "core/static/core/app.js",
        "scripts/check_client_technologies.py",
        "scripts/check.ps1",
        "scripts/check.sh",
        "tests/test_client_technologies.py",
        "tests/test_release_hardening.py",
        ".github/workflows/quality.yml",
    ],
    "V16.1.1": [
        "docs/logging-inventory.json",
        "docs/LOGGING_INVENTORY.md",
        "scripts/check_logging_inventory.py",
        "tests/test_release_hardening.py",
    ],
    "V16.2.3": [
        "docs/logging-inventory.json",
        "docs/LOGGING_INVENTORY.md",
        "config/settings/base.py",
        "config/settings/production.py",
        "core/logging.py",
        "scripts/check_logging_inventory.py",
        "compose.yaml",
        "Dockerfile",
        "deploy/network/nginx.conf",
        "tests/test_release_hardening.py",
    ],
    "V16.3.2": [
        "core/middleware.py",
        "core/logging.py",
        "config/settings/base.py",
        "docs/LOGGING_INVENTORY.md",
        "docs/logging-inventory.json",
        "tests/urls.py",
        "tests/test_logging.py",
        "tests/test_release_hardening.py",
    ],
    "V16.4.3": [
        "core/logging.py",
        "core/security_log_collector.py",
        "config/settings/production.py",
        "compose.yaml",
        "deploy/network/run-production-boundary.py",
        "docs/logging-inventory.json",
        "docs/LOGGING_INVENTORY.md",
        "scripts/check_logging_inventory.py",
        "tests/test_security_log_archive.py",
        "tests/test_network_boundary.py",
    ],
}

PARTIAL_ASSESSMENT_OVERRIDES: dict[str, str] = {
    "V12.3.1": (
        "Every application-managed production TCP connection now requires TLS 1.2 or TLS 1.3 "
        "without a plaintext fallback. Dated verification of browser-facing Tailscale HTTPS and "
        "key-only administrative SSH on the release VM remains pending."
    ),
    "V12.3.2": (
        "Production libpq clients and nginx validate their internal server certificates against "
        "purpose-specific CAs and exact DNS names before sending application data. Dated browser "
        "trust-store verification against the release Tailscale hostname remains pending."
    ),
}

PARTIAL_EVIDENCE_OVERRIDES: dict[str, list[str]] = {
    source_id: [
        "compose.yaml",
        "config/settings/hardened.py",
        "deploy/postgres/start-tls.sh",
        "deploy/postgres/pg_hba.conf",
        "config/gunicorn.py",
        "deploy/network/nginx.conf",
        "deploy/network/run-production-boundary.py",
        "scripts/generate-postgres-tls.py",
        "tests/test_deployment_config.py",
        "tests/test_network_boundary.py",
        "docs/POSTGRES_TLS.md",
        "docs/cryptographic-inventory.json",
    ]
    for source_id in PARTIAL_ASSESSMENT_OVERRIDES
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
    if set(IMPLEMENTED_ASSESSMENT_OVERRIDES) != set(IMPLEMENTED_EVIDENCE_OVERRIDES):
        raise ValueError("implemented ASVS assessment and evidence overrides disagree")
    unknown_overrides = set(IMPLEMENTED_ASSESSMENT_OVERRIDES) - IMPLEMENTED_REQUIREMENTS
    if unknown_overrides:
        raise ValueError(
            f"implemented ASVS overrides reference inactive IDs: {sorted(unknown_overrides)}"
        )
    if set(PARTIAL_ASSESSMENT_OVERRIDES) != set(PARTIAL_EVIDENCE_OVERRIDES):
        raise ValueError("partial ASVS assessment and evidence overrides disagree")
    invalid_partial_overrides = set(PARTIAL_ASSESSMENT_OVERRIDES) & (
        excluded_ids | set(NOT_STARTED) | IMPLEMENTED_REQUIREMENTS
    )
    if invalid_partial_overrides:
        raise ValueError(
            f"partial ASVS overrides reference non-partial IDs: {sorted(invalid_partial_overrides)}"
        )
    unknown_partial_overrides = set(PARTIAL_ASSESSMENT_OVERRIDES) - source_ids
    if unknown_partial_overrides:
        raise ValueError(
            f"partial ASVS overrides reference unknown IDs: {sorted(unknown_partial_overrides)}"
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
            assessment = IMPLEMENTED_ASSESSMENT_OVERRIDES.get(
                source_id,
                "The mapped control has repeatable implementation evidence; a dated "
                "release-candidate run is still required before verification.",
            )
        else:
            applicability = "applicable"
            status = "partial"
            assessment = PARTIAL_ASSESSMENT_OVERRIDES.get(
                source_id,
                "Relevant controls or documentation exist, but the exact Level 2 requirement "
                "remains incomplete or has not been fully exercised at its release boundary.",
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
            "evidence": IMPLEMENTED_EVIDENCE_OVERRIDES.get(
                source_id,
                PARTIAL_EVIDENCE_OVERRIDES.get(source_id, _evidence(chapter_id, section_id)),
            ),
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
