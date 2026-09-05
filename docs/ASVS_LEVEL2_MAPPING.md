# OWASP ASVS 5.0.0 Level 2 mapping

Status: requirement-level applicability complete; release verification pending  
Last updated: 2026-09-05

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
| Applicable | 173 | The requirement applies to the initial private-hosted product. |
| Not applicable | 80 | The associated feature or protocol is absent and a requirement-level reason is recorded. |
| Implemented | 109 | A control and repeatable implementation evidence exist; release-candidate verification is pending. |
| Partial | 57 | Some relevant control or documentation exists, but the exact requirement remains incomplete or not fully exercised. |
| Not started | 7 | The control is absent or its required verification has not been designed. |
| Verified | 0 | No dated release-candidate ASVS pass is claimed yet. |

`implemented` is not a release pass. Only a dated `verified` result with sanitized evidence, or a
justified `not_applicable` result, satisfies the final release review.

## Not-started controls

These are the clearest implementation or operational work items exposed by the mapping. The 57
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

### HTTP and backend communication

The production-derived request-boundary harness implements `v5.0.0-4.2.1` for the nginx-to-Gunicorn
HTTP/1.1 boundary. It accepts three valid body encodings and requires six ambiguous or malformed
forms to produce exactly one rejection followed by connection closure; a trailing harmless request
acts as a smuggling canary. The dedicated read-only CI workflow runs the actual production images.
Tailscale Serve's browser-facing HTTP/2 or HTTP/3 message-length behavior remains an explicit dated
release-candidate check rather than a claimed verification. See `docs/PRIVATE_INGRESS.md`.

- `v5.0.0-12.3.1`, `v5.0.0-12.3.3`, `v5.0.0-12.3.4`: inventory and encrypt internal service
  communication, including application-to-PostgreSQL traffic, with an explicit certificate trust
  policy.
- `v5.0.0-13.2.1`: replace long-lived backend passwords with short-lived or certificate-based
  service authentication where the chosen private-hosting stack can support it.
- `v5.0.0-13.2.4`, `v5.0.0-13.2.5`: enforce deployment- and application-layer outbound allowlists.

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

The maintained logging inventory implements `v5.0.0-16.1.1` across all 13 current stack layers. It
documents events, formats, destinations, uses, access controls, retention, sensitive-data rules,
integrity/availability properties, and limitations. Its validator derives 143 stable event entries
from application and maintenance source, verifies every production Compose logging policy, and
enforces evidence and review cadence. See `docs/LOGGING_INVENTORY.md`; release-candidate and live
host/provider verification remain pending.

- `v5.0.0-16.4.3`: transmit security logs to a logically separate protected destination.

## Applicability policy

An item is excluded only when its triggering feature or protocol does not exist in the initial
product. Examples include LDAP/XPath/LaTeX parsing, GraphQL, WebSockets, external identity
providers, OAuth/OIDC, self-contained authentication tokens, and WebRTC. Every exclusion records a
specific reason.

A control is not excluded merely because the application is private, small, or currently lacks the
infrastructure to meet it. Internal TLS, short-lived service authentication, egress restrictions,
separate log storage and administrator session revocation therefore remain applicable gaps.
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

