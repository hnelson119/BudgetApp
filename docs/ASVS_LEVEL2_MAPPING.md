# OWASP ASVS 5.0.0 Level 2 mapping

Status: requirement-level applicability complete; release verification pending  
Last updated: 2026-09-09

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
| Implemented | 122 | A control and repeatable implementation evidence exist; release-candidate verification is pending. |
| Partial | 52 | Some relevant control or documentation exists, but the exact requirement remains incomplete or not fully exercised. |
| Verified | 0 | No dated release-candidate ASVS pass is claimed yet. |

`implemented` is not a release pass. Only a dated `verified` result with sanitized evidence, or a
justified `not_applicable` result, satisfies the final release review.

## Most concrete incomplete controls

These are the clearest implementation or operational work items exposed by the mapping. The 52
partial items also remain release blockers until their exact requirement boundary is completed and
verified.

### Authentication and session lifecycle

The product-specific prohibited-word documentation and enforcement (`v5.0.0-6.1.2` and
`v5.0.0-6.2.11`) and maintained offline breached-password check (`v5.0.0-6.2.12`) are implemented.
Their local, privacy-preserving trust boundary and update procedure are in
`docs/PASSWORD_BLOCKLIST.md`; release-candidate verification remains pending.

The dedicated trusted-console session-revocation operation (`v5.0.0-7.4.5`) can terminate one
arbitrary account or every account independently of credential reset. It requires explicit scope
confirmation and a bounded reason, rotates server-side versions, removes matching stored sessions,
and records protected household audit events. Release-candidate verification remains pending.

The enforced session timeouts and their risk rationale now implement `v5.0.0-7.1.1`. The
one-hour inactivity limit matches the current NIST AAL2 recommendation; the twelve-hour overall
limit is deliberately tighter than its 24-hour recommendation for consolidated private financial
data. Exact settings, reauthentication behavior, browser persistence, and change control are in
`docs/SESSION_SECURITY.md`.

Session termination now implements `v5.0.0-14.3.1`: every secure server-driven termination response
requests browser cache, cookie, and origin-storage removal, while logout forms independently scrub
Web Storage, Cache Storage, IndexedDB, and the authenticated DOM before a server response is
available. The dedicated browser lifecycle test covers successful and unavailable-response paths.

### HTTP and backend communication

The hardened pre-redirect boundary implements `v5.0.0-4.1.2`: browser-facing pages retain their
canonical HTTP-to-HTTPS redirect, but liveness and every reserved documentation or monitoring path
return an empty `400` with no `Location` when the trusted HTTPS signal is absent or ambiguous. The
production-derived probe exercises both outcomes so an accidentally plaintext service client is
not hidden behind a successful redirect.

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

### Cryptography, supply chain, and logging

The machine-validated key, algorithm, and certificate inventory implements `v5.0.0-11.1.2` with
explicit permitted/prohibited uses, protected/excluded data, rotation, retirement, provider
boundaries, test-only exceptions, review cadence, and known absences. See
`docs/CRYPTOGRAPHIC_INVENTORY.md`; release-candidate verification remains pending.

The deterministic CycloneDX source/build inventory implements `v5.0.0-15.1.2` for all 83 current
third-party production, development, build, test, and CI inputs. Its validator derives exact
components and approved repositories from locks, digest-pinned images, checksummed sources, Go
module pins, and immutable actions. CI separately generates and retains image-resolved SBOMs for
all three release images. See `docs/SBOM.md`; exact release-candidate preservation and review remain
pending.

The maintained logging inventory implements `v5.0.0-16.1.1` across all 14 current stack layers and
the separate security archive implements `v5.0.0-16.4.3`. Production sends redacted security JSON
through a permission-restricted Unix socket to a distinct networkless collector; Django cannot
mount or read its archive volume. The collector validates and redacts again, writes restrictive
append-only records, creates minimized warning-or-higher alerts, and exposes safe delivery and
validation failures. The validator derives 149 stable event entries, verifies every Compose logging
and collector isolation policy, and enforces evidence and review cadence. See
`docs/LOGGING_INVENTORY.md`; release-candidate delivery, retention, alert review, escalation, and
live host/provider verification remain pending.

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

