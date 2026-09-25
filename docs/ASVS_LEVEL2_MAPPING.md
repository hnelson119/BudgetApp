# OWASP ASVS 5.0.0 Level 2 mapping

Status: requirement-level applicability complete; release verification pending  
Last updated: 2026-09-25

## Scope and source integrity

The application targets OWASP Application Security Verification Standard (ASVS) 5.0.0 Level 2
where applicable. The machine-readable mapping is
`docs/asvs-5.0.0-level2-evidence.json`. It contains every Level 1 and Level 2 requirement from the
official `v5.0.0` tagged English flat JSON and uses OWASP's recommended version-qualified
identifiers, such as `v5.0.0-1.2.5`.

The source artifact is pinned to:

- Tag: `v5.0.0`
- Git blob: `f7ae2926598c4648ff7614a6968e4c8fd89524bd`
- SHA-256: `8201b20eec2908c3380ac600c91c8ba746346fbb808859366abb232027532311`
- License: Creative Commons Attribution-ShareAlike 4.0 International

The local validator recomputes a fingerprint over the exact requirement IDs, levels, chapter and
section names, and descriptions. It also validates every application status, reason, and evidence
path. Editing the source digest stored in the JSON is not sufficient to bypass this check because
the expected digest and catalog fingerprint are pinned in the validator.

## Current disposition

The 253 Level 1 and Level 2 requirements currently resolve as follows:

| Disposition | Count | Meaning |
| --- | ---: | --- |
| Applicable | 174 | The requirement applies to the initial private-hosted product. |
| Not applicable | 79 | The associated feature or protocol is absent and a requirement-level reason is recorded. |
| Implemented | 165 | A control and repeatable implementation evidence exist; release-candidate verification is pending. |
| Partial | 9 | Some relevant control or documentation exists, but the exact requirement remains incomplete or not fully exercised. |
| Verified | 0 | No dated release-candidate ASVS pass is claimed yet. |

`implemented` is not a release pass. Only a dated `verified` result with sanitized evidence, or a
justified `not_applicable` result, satisfies the final release review.

## Most concrete incomplete controls

These are the clearest implementation or operational work items exposed by the mapping. The 9
partial items also remain release blockers until their exact requirement boundary is completed and
verified.

### Encoding and expression safety

The canonical input-decoding boundary implements `v5.0.0-1.1.1`. Django owns the single percent
and form-decoding pass before application validation, and runtime code contains no second unquote,
query-string, or HTML-entity decoder. A fail-closed AST inventory pins all 16 strict text, JSON, and
purpose-specific Base32 operations across seven files; rejects permissive, dynamic, and general
input decoders; and detects nested deserialization. Each documented input validates its canonical
result before persistence, business processing, or security use. See
`docs/CANONICAL_INPUT_DECODING.md`.

The managed-runtime boundary implements `v5.0.0-1.4.1`, `v5.0.0-1.4.2`, and
`v5.0.0-1.4.3`. Application Python and JavaScript use managed memory with no native source, FFI,
pointer, or raw client-memory APIs. Python integers cannot wrap, financial values use bounded
`Decimal` fields and reject binary-float conversion, and the two fixed-width TOTP conversions have
literal big-endian sizes. The checker pins the sole managed buffer, 38 decimal and 37 integer
fields, six low-level descriptor files, and every context-managed socket and temporary file. See
`docs/MANAGED_RUNTIME_SAFETY.md`.

The maintained input-validation policy implements `v5.0.0-2.1.1`, `v5.0.0-2.1.2`, and
`v5.0.0-2.1.3`. It inventories all 49 form classes across eight production form modules, defines
ten structure-rule families and ten cross-field or contextual rule groups, and records eleven
business-limit groups. Thirteen exact source assertions pin money and rate shapes, household and
balanced-ledger checks, upload caps, recurrence and projection horizons, authentication and MFA
windows, blocklist bounds, notification limits, and pagination. New form classes, changed limits,
missing evidence, stale review dates, and catalog drift fail the normal gates. The broader
exhaustive enforcement review in `v5.0.0-2.3.2` remains partial, and release-candidate verification
remains pending. See `docs/INPUT_VALIDATION_POLICY.md` and
`docs/input-validation-policy.json`.

The dangerous-context boundary implements `v5.0.0-1.3.3`. It defines the exact treatment for 11
context families and scans all 218 production Python files, including migrations, for raw SQL.
All 25 calls are pinned to literal text: three application cursor calls and 22 fixed schema-editor
migration calls. The aggregate checker also requires nine specialized context checks in both
quality gates and pins source contracts for CSV formula encoding, redirect and notification URLs,
checkpoint filenames, disabled production email, and structured-log redaction. See
`docs/CONTEXT_SANITIZATION.md` and `docs/context-sanitization.json`.

The JavaScript and JSON output-encoding boundary implements `v5.0.0-1.2.3`. Django templates keep
contextual auto-escaping enabled, CSP permits only same-origin external scripts, and the production
client inserts dynamic text with DOM APIs and `textContent`. A fail-closed inventory rejects
escaping bypasses, inline scripts, HTML-parsing and code-execution sinks, custom trusted-HTML APIs,
manual script or JSON media bodies, and custom `JsonResponse` encoders. The two fixed operational
JSON endpoints use Django's default encoder. See `docs/OUTPUT_ENCODING_POLICY.md`.

The operating-system command boundary implements `v5.0.0-1.2.5`. The production Python runtime
does not launch child processes. A fail-closed inventory covers application and configuration code,
migrations, management commands, and the runtime entry point, rejecting shell/process modules,
OS exec/spawn/system calls, asynchronous process creation, dynamic module loading, and renamed or
dynamically selected process APIs. See `docs/OS_COMMAND_SAFETY.md`.

The template-selection boundary implements `v5.0.0-1.3.7`. All production renderer and loader calls
use literal names that resolve to files in the reviewed template inventory, and all template
inheritance and includes name literal existing dependencies. Runtime template construction,
dynamic or missing names, mixed fallback lists, dynamic dependencies, and aliases of reviewed
selection APIs fail the local and CI gates. See `docs/TEMPLATE_INJECTION_POLICY.md`.

The format-string boundary implements `v5.0.0-1.3.10`. Formatting and structured-log grammars are
code-owned literals; the CSV date parser selects only from an exact literal allowlist. Dynamic
format receivers and specifications, dynamic f-string and datetime grammars, runtime string
templates, unreviewed percent expressions, and renamed helpers fail closed. All 11 production
percent operators are pinned numeric modulo operations. See `docs/FORMAT_STRING_SAFETY.md`.

The regular-expression boundary implements `v5.0.0-1.2.9`. A fail-closed AST inventory requires
literal Python and Django patterns throughout the production application. The sole runtime-built
pattern normalizes configured product identifiers and applies `re.escape` independently to every
alternative before inserting that one fragment into fixed anchored password-validator syntax.
Module aliasing, direct symbol imports, other dynamic patterns, and unescaped interpolation fail the
local and CI gates. See `docs/REGULAR_EXPRESSION_SAFETY.md`.

### Authentication and session lifecycle

The product-specific prohibited-word documentation and enforcement (`v5.0.0-6.1.2` and
`v5.0.0-6.2.11`) and maintained offline breached-password check (`v5.0.0-6.2.12`) are implemented.
Their local, privacy-preserving trust boundary and update procedure are in
`docs/PASSWORD_BLOCKLIST.md`; release-candidate verification remains pending.

Lost-factor identity proofing now implements `v5.0.0-6.4.4`. Initial enrollment follows direct
trusted-console provisioning for the two known household members. Emergency MFA reset requires a
different member to directly confirm the affected person in person or from an already approved
Tailscale device, plus an explicit console attestation; weaker email, phone, security-question, and
profile-fact fallbacks are prohibited. Without the attestation the command changes nothing. A
successful reset removes the seed and recovery codes, revokes all sessions, and requires fresh
enrollment. See `docs/INCIDENT_RESPONSE.md`; release-candidate rehearsal remains pending.

The dedicated trusted-console session-revocation operation (`v5.0.0-7.4.5`) can terminate one
arbitrary account or every account independently of credential reset. It requires explicit scope
confirmation and a bounded reason, rotates server-side versions, removes matching stored sessions,
and records protected household audit events. Release-candidate verification remains pending.

The enforced session timeouts and their risk rationale now implement `v5.0.0-7.1.1`. The
one-hour inactivity limit matches the current NIST AAL2 recommendation; the twelve-hour overall
limit is deliberately tighter than its 24-hour recommendation for consolidated private financial
data. Exact settings, reauthentication behavior, browser persistence, and change control are in
`docs/SESSION_SECURITY.md`.

Concurrent-session behavior now implements `v5.0.0-7.1.2`. Each account may have five unexpired,
current-version authenticated sessions. A sixth full login succeeds and atomically revokes the
oldest session while preserving the new one; the displaced browser is cleaned up on its next
request, and users retain individual and all-device revocation controls.

Account lifecycle termination now implements `v5.0.0-7.4.2`. Disabling or deleting an account
synchronously removes its authenticated and pending-MFA session records, including queryset
deletion. A displaced browser is redirected to full login and receives secure client-state cleanup
on its next request.

Sensitive-account reauthentication now implements `v5.0.0-7.5.1`. Password, email, account
authority, MFA, and recovery mutations are confined to boundaries that require the current
password, fresh password-plus-MFA proof, a confirmed recovery factor, or trusted-console authority
that revokes existing sessions. Confirmed MFA enrollment cannot be restarted from the browser, and
the product does not use phone numbers for authentication or recovery. The exact inventory and
proof requirements are in `docs/SESSION_SECURITY.md`; release-candidate verification remains
pending.

Redirect handling now implements `v5.0.0-3.7.2`. A response boundary permits same-authority
redirects and only exact, explicitly allowlisted HTTPS external authorities. The private production
profile requires that external allowlist to remain empty, so an unexpected external `Location`
becomes a non-cacheable HTTP 400 response.

Session termination now implements `v5.0.0-14.3.1`: every secure server-driven termination response
requests browser cache, cookie, and origin-storage removal, while logout forms independently scrub
Web Storage, Cache Storage, IndexedDB, and the authenticated DOM before a server response is
available. The dedicated browser lifecycle test covers successful and unavailable-response paths.

The supported-client policy implements `v5.0.0-3.7.1`: production uses reviewed browser-native
formats and dependency-free runtime JavaScript. A fail-closed inventory rejects legacy plug-in
elements, APIs, media types, executable artifacts and references, symlinks, oversized text assets,
or unreviewed file types from every production template and static root. CSP independently blocks
object execution, and the pull-request matrix exercises Chromium, Firefox, and WebKit.

The same-origin response boundary implements `v5.0.0-3.4.2`: this private application grants no
cross-origin reads, strips every CORS permission and timing-origin response field, and fixes
`Cross-Origin-Resource-Policy` to `same-origin`. The boundary encloses WhiteNoise in hardened
deployments, whose independent wildcard-origin default also remains disabled following the retested
`M10-F002` finding.

### Sensitive-data classification

The deny-by-default authorization policy implements `v5.0.0-8.1.1` and `v5.0.0-8.1.2`. Four
consumer states distinguish anonymous, pending-MFA, active household member, and separately trusted
administrator authority. Eleven function and record rule groups and ten field rule groups define
decisions from membership, selected household, recipient, lifecycle, account classification,
recent authentication, integrity, and purpose. A fail-closed registry classifies all 70 named
routes across nine namespaces, verifies every member login guard and all five recent-auth checks,
and pins recipient, household, export, and denial-logging contracts. See
`docs/AUTHORIZATION_POLICY.md` and `docs/authorization-policy.json`.

The model-anchored data inventory implements `v5.0.0-14.1.1` and `v5.0.0-14.1.2`. It assigns all
45 stored Django models exactly once and covers 10 additional request, browser, export, secret,
backup, log, reference, operational, release, and static-asset surfaces. Four ordered protection
levels define encryption, database storage, integrity, retention, logging, log access, authorization,
privacy, confidentiality, encoding, disposal, backup, and client-storage requirements. Encoded,
hashed, masked, compressed, encrypted, and pseudonymous forms inherit their source classification.
The checker rejects new unclassified models and drift in the implemented boundaries. Dated host
volume-encryption and end-to-end protection verification remains honestly partial under
`v5.0.0-14.2.4`. See `docs/DATA_CLASSIFICATION.md` and `docs/data-classification.json`.

### HTTP and backend communication

The complete communication inventory implements `v5.0.0-13.1.1`. Ten runtime, management, and
maintenance flows and six host/build external dependencies record their exact purpose, destination,
transport, protections, data, phase, and evidence. The initial release accepts no user-provided
external destination, hardened settings disable unused SMTP, and a fail-closed scan permits runtime
socket use only for the two fixed Unix-datagram logging endpoints. See
`docs/COMMUNICATION_INVENTORY.md` and `docs/communication-inventory.json`.

The hardened pre-redirect boundary implements `v5.0.0-4.1.2`: browser-facing pages retain their
canonical HTTP-to-HTTPS redirect, but liveness and every reserved documentation or monitoring path
return an empty `400` with no `Location` when the trusted HTTPS signal is absent or ambiguous. The
production-derived probe exercises both outcomes so an accidentally plaintext service client is
not hidden behind a successful redirect.

The intermediary chain implements `v5.0.0-4.1.3`: Tailscale Serve overwrites the trusted scheme
header at its HTTPS edge, nginx accepts only the exact lowercase secure value, replaces the value
sent to Gunicorn, and clears every other forwarding field. The production-derived configuration
probe enforces those exact directives. A dated VM release check sends spoofed values for all six
forwarding fields through the private HTTPS hostname and requires the secure liveness response with
no redirect or reflected canary.

The production-derived request-boundary harness implements `v5.0.0-4.2.1` for the nginx-to-Gunicorn
HTTP/1.1 boundary. It accepts three valid body encodings and requires six ambiguous or malformed
forms to produce exactly one rejection followed by connection closure; a trailing harmless request
acts as a smuggling canary. The dedicated read-only CI workflow runs the actual production images.
Tailscale Serve's browser-facing HTTP/2 or HTTP/3 message-length behavior remains an explicit dated
release-candidate check rather than a claimed verification. See `docs/PRIVATE_INGRESS.md`.

The same production-derived boundary implements the outbound allowlists in `v5.0.0-13.2.4` and
`v5.0.0-13.2.5`. Compose fixes the exact service catalog and network attachments, rejects network
bypasses, and leaves the Django and maintenance workloads with no external route. The Django
server's only configured backend is `db:5432`. The relay retains the non-internal network needed for
its loopback host publish, but receives only its dedicated Gunicorn server CA and nginx client
identity. The live nginx configuration must contain exactly one static destination,
`https://web:8443`, and exact CA/hostname/client-certificate controls. The probe proves the required
internal connections, denied Django external TCP egress, and running relay destination.
Release-candidate verification remains pending.

The relay also implements `v5.0.0-13.4.3` and `v5.0.0-13.4.4`: its production configuration
explicitly disables directory indexing, contains no filesystem `root` or `alias`, and rejects
HTTP TRACE with `405` before proxying. The runtime probe validates the effective nginx
configuration and requires a canary-bearing TRACE request to be rejected without reflection.

The hardened application implements `v5.0.0-13.4.5` by reserving documentation and monitoring
route namespaces and exposing only the exact, intentionally minimal `/health/live/` response. The
database-readiness route remains useful in non-production development but is blocked at the
production application boundary. The production-derived probe requires that route and
representative metrics, documentation, schema, debug, and actuator paths to return empty hardened
`404` responses.

- `v5.0.0-12.1.3` and `v5.0.0-13.2.1` are implemented: every production PostgreSQL client uses a
  unique client certificate from a separate CA, its exact CN maps only to the intended role, no
  password-authenticated production path exists, and login roles have no password verifiers. The
  production-derived proof confirms the live client DN and rejects missing-certificate and
  wrong-role attempts.
- `v5.0.0-12.3.3` and `v5.0.0-12.3.4` are implemented: the only internal HTTP hop requires mutually
  authenticated TLS 1.2 or TLS 1.3. Nginx verifies the dedicated Gunicorn server CA and exact `web`
  identity; Gunicorn trusts only the separate nginx client CA, and production exposes no plaintext
  application listener. PostgreSQL retains its independently purpose-separated mutual-TLS trust.
- `v5.0.0-12.3.1` and `v5.0.0-12.3.2` remain partial only at the release boundary: all
  application-managed production TCP paths now encrypt and validate peer identity without fallback,
  while dated browser-facing Tailscale certificate/trust and key-only SSH observations still require
  the real VM and approved devices.

### File handling

The complete upload inventory implements `v5.0.0-5.1.1`. The only accepted upload is a bounded
UTF-8 `.csv` transaction statement; its extension, advertised media type, 5 MiB byte ceiling,
archive exclusion, structural limits, rejection behavior, staging lifetime, and generated-download
safety are defined in `docs/FILE_HANDLING_POLICY.md`. Invalid content is closed and rejected before
staging, original uploads are never redistributed, and freshly generated exports neutralize
spreadsheet-formula prefixes.

### Cryptography, supply chain, and logging

The production JavaScript object-safety boundary implements `v5.0.0-15.3.6`. Runtime-selected keys
use `Map`, membership uses `Set`, and a fail-closed inventory rejects prototype names,
object/reflection mutation APIs, dynamic bracket-property access, and inherited-property iteration
from every reviewed JavaScript file and script-capable template. See
`docs/JAVASCRIPT_OBJECT_SAFETY.md`.

The machine-validated key-management policy implements `v5.0.0-11.1.1` against NIST SP 800-57
Part 1 Revision 5. It pins the full lifecycle, limits shared secrets to two trust entities and
private keys to one active trust entity, treats offline copies as sealed and inactive, and requires
revocation, replacement, retired-access proof, retention, and destruction controls. The same key,
algorithm, and certificate inventory implements `v5.0.0-11.1.2` with explicit permitted/prohibited
uses, protected/excluded data, rotation, retirement, provider boundaries, test-only exceptions,
review cadence, and known absences. See
`docs/CRYPTOGRAPHIC_INVENTORY.md`; release-candidate verification remains pending.

The approved hash-function boundary implements `v5.0.0-11.4.1`. A fail-closed scanner inventories
all 35 direct hash and signing operations across 26 Python, JavaScript, and shell files, rejects
dynamic or unapproved selections, and verifies the pinned Django SHA-256 signing, token, and PBKDF2
defaults. SHA-1 is limited to six exact compatibility operations for RFC 6238 TOTP and the local
breached-password corpus; MD5 remains test-only. See `docs/HASH_FUNCTION_POLICY.md` and
`docs/hash-function-policy.json`. The same inventory implements `v5.0.0-11.4.3`: every signature,
data-authentication, and data-integrity use selects SHA-256 or SHA-512 with at least 256 output
bits. The six SHA-1 operations are confined to TOTP and offline corpus compatibility and are
explicitly prohibited from signatures, collision resistance, and data integrity.

The password-to-key boundary implements `v5.0.0-11.4.4`. Restic 0.19.1's approved scrypt profile
is the sole production path from a password to secret key material; each authenticated repository
key file stores a unique random salt and explicit `N`, `r`, and `p` work parameters that application
code cannot override. Unlocking remains isolated to bounded maintenance jobs, and guarded rotation
requires replacement access, repository integrity, retired-credential rejection, and acceptable
release-host performance before promotion. Dated performance evidence remains pending verification.

The password-storage boundary implements `v5.0.0-11.4.2`. Production explicitly selects Django
5.2.17's salted PBKDF2-HMAC-SHA-256 hasher with 1,000,000 iterations and a 128-bit salt-entropy
target. Its fail-closed checker verifies the installed primitive and dependency, pins production
and test settings, inventories all 14 credential hash/check operations across six production files,
and rejects direct password-field writes or unreviewed hasher imports. The fast MD5 hasher remains
confined to synthetic unit tests. See `docs/PASSWORD_HASHING_POLICY.md` and
`docs/password-hashing-policy.json`; release-host performance verification remains pending.

The deterministic CycloneDX source/build inventory implements `v5.0.0-15.1.2` for all 83 current
third-party production, development, build, test, and CI inputs. Its validator derives exact
components and approved repositories from locks, digest-pinned images, checksummed sources, Go
module pins, and immutable actions. CI separately generates and retains image-resolved SBOMs for
all three release images. See `docs/SBOM.md`; exact release-candidate preservation and review remain
pending.

The maintained resource-demand policy implements `v5.0.0-15.1.3`. It identifies seven expensive
interactive and operator workflow families, five explicit response-time boundaries, and the exact
input, result, horizon, process, and concurrency limits used to protect availability. Its
fail-closed checker pins twelve source contracts and preserves the ordering in which a silent
application worker fails before ingress abandons it. All long-running and one-shot Compose services
have explicit CPU, memory, and PID ceilings, which implements `v5.0.0-15.2.2`; representative
release-host load verification remains pending. See
`docs/RESOURCE_DEMAND_POLICY.md` and `docs/resource-demand-policy.json`.

The maintained logging inventory implements `v5.0.0-16.1.1` across all 14 current stack layers,
its fail-closed destination validator implements `v5.0.0-16.2.3`, authorization-denial logging
implements `v5.0.0-16.3.2`, and the separate security archive implements `v5.0.0-16.4.2` and
`v5.0.0-16.4.3`. The
validator pins the exact application handlers and logger routes, rejects unreviewed local or remote
sinks, and retains the exact Docker, Gunicorn, nginx, and collector boundaries. Every explicit 403
and every authenticated identifier-bearing 404 that conceals object scope produces a warning-level
event with only the method, resolved route, status, error reference, and pseudonymous context.
Production sends redacted security JSON through a permission-restricted Unix socket to a distinct
networkless collector; Django cannot mount or read its archive volume. The collector validates and
redacts again, writes restrictive append-only records, creates minimized warning-or-higher alerts,
and exposes safe delivery and validation failures. The validator derives 182 stable event entries,
verifies every Compose logging and collector isolation policy, and enforces evidence and review
cadence. See
`docs/LOGGING_INVENTORY.md`; release-candidate delivery, retention, alert review, escalation, and
live host/provider verification remain pending. Archive files are owned regular files opened with
append and no-follow semantics, forced to mode 0600, and fsynced after complete records; only the
networkless collector mounts their volume. Invalid CSV lifecycle forms and rejected expense,
income, card-payment, card-refund, transaction-reversal, goal-management, budget-configuration,
occurrence-management, reserve-allocation, fixed-expense schedule, general debt-management,
mortgage-management, financial-account setup, and notification-preference submissions produce
minimized warning events. Together with authorization-denial events and authentication/recovery
events that retain only explicit anti-automation outcomes, this implements the documented
`v5.0.0-16.3.3` repository boundary. Dated release-candidate archive observation remains pending
before verification.

The external-resource failure boundary implements `v5.0.0-16.5.2` for all ten inventoried runtime
and management flows. PostgreSQL loss yields a sanitized no-store readiness `503` while liveness
remains independent, ordinary request errors retain the generic boundary, and transactions roll
back without an insecure transport or authentication fallback. Security-log delivery has a 250 ms
bound and fixed redacted stderr fallback. Other ingress, backup, checkpoint, and host-control
failures close or fail nonzero without weakening trust. See `docs/COMMUNICATION_INVENTORY.md`;
dated release-candidate outage observation remains pending before verification.

## Applicability policy

An item is excluded only when its triggering feature or protocol does not exist in the initial
product. Examples include LDAP/XPath/LaTeX parsing, GraphQL, WebSockets, external identity
providers, OAuth/OIDC, self-contained authentication tokens, and WebRTC. Every exclusion records a
specific reason.

A control is not excluded merely because the application is private, small, or currently lacks the
infrastructure to meet it. Live Tailscale, SSH, browser trust, and device-boundary observations
therefore stay applicable release gaps even though internal service TLS is implemented.
Future OAuth, public hosting, external identity, WebSocket, bank-sync, email, or file-processing
features require re-evaluating the associated exclusions before merge.

## Updating and validating the mapping

The checked-in mapping is the review artifact. To reproduce its official catalog from a downloaded
copy of the pinned upstream JSON, first verify the SHA-256 above, then run:

```powershell
.\.venv\Scripts\python.exe scripts\build_asvs_inventory.py <path-to-pinned-flat-json>
.\.venv\Scripts\python.exe scripts\check_release_evidence.py
```

The builder rejects any input other than the exact pinned source. Its policy tables establish the
current baseline and intentionally do not claim release verification. Review the resulting diff;
do not regenerate over dated release evidence without first preserving the evidence and assessment
changes.

When changing an item's disposition:

1. Confirm the exact version-qualified requirement text.
2. Record the narrowest accurate applicability decision.
3. Link implementation, test, or tracking evidence that exists in the repository.
4. Use `implemented` only when a repeatable control and test exist.
5. Use `verified` only for a dated release-candidate run and record `last_verified` plus sanitized
   evidence.
6. Re-run the evidence validator and the full quality gate.

