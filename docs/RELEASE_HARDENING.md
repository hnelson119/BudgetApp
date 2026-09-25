# Release hardening and evidence

Status: Milestone 10 baseline in progress  
Last updated: 2026-09-20

## Purpose

Milestone 10 turns the existing security controls into a repeatable release decision. The
machine-readable inventories track all 253 OWASP ASVS 5.0.0 Level 1/2 requirements, the 24 required
security tests in `SECURITY_PLAN.md`, and the 12 release gates in `IMPLEMENTATION_PLAN.md`. A control
is not a release pass merely because code or a unit test exists.

The ASVS review is pinned by upstream tag, source SHA-256, Git blob, and a locally enforced catalog
fingerprint. Requirement-level applicability and evidence are recorded in
`docs/asvs-5.0.0-level2-evidence.json`; the review rationale and current gap summary are in
`docs/ASVS_LEVEL2_MAPPING.md`. The mapping currently contains 174 applicable requirements and 79
requirement-level feature exclusions. None is marked release-verified.

## Evidence states

- `not_started`: no release verification has been performed.
- `partial`: some relevant controls or tests exist, but the requirement is incomplete.
- `implemented`: a repeatable control and test exist; release-candidate execution is still pending.
- `verified`: a dated release-candidate run passed and a sanitized evidence reference is recorded.
- `not_applicable`: the product does not contain the relevant feature and records why.

Only `verified` and justified `not_applicable` items satisfy a final release review. The inventory
validator rejects missing identifiers, unknown states, duplicate entries, unreasoned exclusions,
and undated verified claims.

## Automated baseline

Run the normal local gate:

```powershell
.\scripts\check.ps1
```

This includes Django checks, migration drift, Ruff, mypy, secret scanning, evidence-ledger
validation, Bandit, the complete test suite, line coverage, and branch coverage. Dependency audit
remains an explicit network-backed command:

```powershell
.\.venv\Scripts\python.exe -m pip_audit --requirement requirements-dev.lock --cache-dir .pip-audit-cache --no-deps --disable-pip --strict
```

GitHub Actions independently builds the production image without runtime secrets, builds the
minimal ingress relay from its immutable upstream base while applying current Alpine fixes, and
builds the encrypted backup/restore image from its checksummed Restic source and immutable builder.
It runs the official Trivy container pinned to an immutable digest against all three resulting
images. Using a pinned scanner preserves the repository's GitHub-owned-actions-only policy. Any
known high or critical operating-system, Python-package, or embedded Go vulnerability fails the
image job. The existing dependency, source, configuration, and secret checks remain separate so one
scanner cannot silently replace another.

The same image job generates CycloneDX inventories from the three built images and uploads them as
a commit-bound artifact retained for 90 days. The deterministic checked-in CycloneDX inventory
covers 83 locked or pinned production, development, build, test, and CI inputs and is rebuilt by the
normal quality gate. See `docs/SBOM.md` for trusted repositories, diff review, candidate artifact
preservation, and failure rules.

The image and application scans identified and remediated `M10-F001`, `M10-F002`, `M10-F006`, and
the relay-image finding `M10-F018`, and the backup-image finding `M10-F021`; their sanitized findings and clean retests are recorded in
`docs/SECURITY_FINDINGS.md`. The synthetic ZAP baseline also records the scoped test-transport
acceptance `M10-F003`. These results are baseline evidence, not a future release pass: every
candidate must rebuild and repeat the applicable scans against then-current vulnerability data and
code.

## Evidence handling

Do not commit raw ZAP sessions, attack payloads, cookies, TOTP material, passwords, internal
hostnames, database dumps, or detailed scanner reports. Local tool output belongs under the ignored
`security-reports/` directory or in an encrypted assessment location outside the repository. Commit
only sanitized summaries, finding identifiers, affected release, severity, remediation, and retest
status.

Every finding uses these states: `open`, `accepted`, `remediated`, or `retested`. Critical and high
findings cannot be accepted for the initial release. Medium acceptance requires a reason, owner, and
deadline. A retest must reproduce the original request boundary and confirm the fix without using
real household data.

## Execution order

1. Keep the completed ASVS 5.0.0 requirement mapping current as features and evidence change.
2. Select the candidate and complete all three machine-validated manual adversarial target records
   in `docs/ADVERSARIAL_TESTING.md`; the Linux VM network target cannot be substituted with loopback.
3. Repeat the implemented Chromium, Firefox, and WebKit suite against the release candidate.
4. Repeat the isolated synthetic PostgreSQL penetration-test profile in `docs/PENTESTING.md`.
5. Run its unauthenticated ZAP passive/active automation, then authenticated automation for both
   synthetic users; review and disposition every report alert.
6. Remediate and retest findings.
7. Run restore/checkpoint, lost-device, credential-rotation, upgrade, and rollback rehearsals.
8. Mark a gate verified only after retaining dated, sanitized evidence.

## Current baseline gaps

- The complete ASVS mapping resolves 253 Level 1/2 requirements: 164 implemented, 10 partial, 79
  justified feature exclusions, and zero verified. Internal HTTP service TLS, purpose-specific
  trust, directory-listing prevention, TRACE rejection, operational-endpoint minimization, and
  non-browser plaintext rejection, and authenticated client-state cleanup are implemented; live
  release-boundary verification remains
  pending. See
  `docs/ASVS_LEVEL2_MAPPING.md` for exact version-qualified identifiers.
- The maintained cryptographic inventory now covers 17 key classes, 15 algorithm profiles, 10
  certificate classes, and 1 intentional absence across application, deployment, provider, and
  test-only boundaries. Its validator enforces purpose separation, protected/excluded data,
  evidence, dependency contracts, no embedded material/private hostname, and a 90-day review
  cadence. PostgreSQL now uses separate offline server/client CAs, a DNS-constrained server
  identity, unique purpose-bound client identities, exact certificate-to-role mapping, and
  plaintext/password rejection. Nginx and Gunicorn now use distinct offline server/client CAs, an
  exact `web` server identity, one nginx client identity, TLS 1.2/1.3, and no plaintext production
  listener. Live certificate/Tailscale/SSH observations remain open release work;
  implementation of the inventory is not release verification.
- Production password storage now explicitly selects Django 5.2.17's salted
  PBKDF2-HMAC-SHA-256 hasher at 1,000,000 iterations. A fail-closed policy pins the installed
  primitive, its settings and dependency, and all 14 current credential operations while rejecting
  direct password-field writes. The release host still needs a dated synthetic performance check.
- The approved hash-function policy inventories 35 direct operations across 26 source files and
  fails closed on new, dynamic, or unapproved selections. SHA-256 is the application default,
  SHA-512 is approved for npm artifact integrity, six SHA-1 operations are bounded to TOTP and the
  offline breached-password corpus, and MD5 remains isolated to synthetic unit tests.
- The resource-demand inventory documents seven expensive workflow families, five explicit
  response-time boundaries, and twelve pinned implementation contracts. The application-worker
  timeout is explicit and remains shorter than the ingress upstream-read timeout. Four long-running
  services now have pinned CPU and memory ceilings; representative maximum-load measurements and
  one-shot maintenance ceilings remain release work under `v5.0.0-15.2.2`.
- The maintained logging inventory now covers all 14 current stack layers and 182 source-derived
  operational, security, protected-audit, and maintenance event entries. It records formats,
  destinations, uses, readers, retention, redaction, integrity/availability properties, and known
  limitations; its validator also enforces bounded Docker logging, the networkless collector and
  read-only application socket boundary, and a 90-day review cadence. The collector independently
  validates/redacts records, writes to its collector-only archive, creates minimized alerts, and
  emits safe delivery/rejection diagnostics. Rejected CSV, core financial mutation, goal,
  budget-configuration, occurrence-management, reserve-allocation, fixed-expense schedule, and
  general debt-management, mortgage-management, financial-account setup, and notification-
  preference submissions now emit minimized fixed events without submitted financial or form
  values. Live delivery, retention, alert review, escalation, and host/provider observations remain
  pending; implementation is not release verification.
- The maintained CycloneDX inventory now derives 83 third-party components from exact locks,
  digest-pinned images, checksummed source, Go pins, and immutable workflow actions, and restricts
  them to six approved repository services. CI additionally retains image-resolved SBOMs for all
  three release images for 90 days. The exact candidate artifacts still require release-owner
  preservation and review; inventory implementation is not release verification.
- Context-specific prohibited words and a freshness-bounded offline breached-password corpus are
  now enforced on Django-validated password creation and changes. The packaged hash-only corpus,
  strict startup validation, no-network boundary, provenance, and reviewed update/rollback process
  are documented in `docs/PASSWORD_BLOCKLIST.md`. This is implementation evidence, not a dated
  release-candidate verification.
- Django administration now requires application MFA proof and recent full authentication rather
  than accepting password-only login or account enrollment state. Internal authentication state is
  read-only in the user editor. `M10-F024` records the regression tests; deployment must revoke all
  old sessions before reopening traffic, as described in `docs/SESSION_SECURITY.md`. The admin fix
  does not itself perform a production revocation or close the broader release-verification gap.
- A guarded trusted-console operation now revokes either one arbitrary account's sessions or every
  account's sessions without requiring a credential reset. It requires explicit confirmation and a
  reason, rotates server-side session versions, removes stored authenticated and pending-MFA
  sessions transactionally, emits a redacted security event, and writes protected household audit
  events. The production-derived disposable PostgreSQL harness proves both scopes reject replay and
  now rebuilds every one-off image after finding and remediating `M10-F023`. This implements the
  administrator operation; release-candidate replay testing remains pending.
- A production-derived disposable probe now verifies the exact Compose service/network allowlist,
  application and database internal-only routes, the relay's single mutually authenticated TLS upstream, the exact
  proxy-header contract, runtime least privilege, blocked Django egress, and local secret
  non-leakage. Its dedicated CI job also drives three valid and six ambiguous or malformed HTTP/1.1
  message boundaries through the production nginx/Gunicorn images; ambiguity must yield exactly one
  rejection and connection closure. The separate private-ingress runbook provides a least-privilege
  grants template, guarded VM preflight, and bounded HTTP/2/3 length-mismatch procedure. Actual
  Tailscale identity, HTTP/2/3 receiver behavior, certificate, firewall, approved/unapproved-device,
  and authenticated-cookie observations still require the Linux VM and cannot be marked verified
  from the disposable run.
- The disposable ZAP baseline completed for unauthenticated traffic and both MFA-authenticated
  synthetic users with no High/Critical alert. Its internal plain-HTTP transport remains a scoped,
  time-bound Medium acceptance until the real VM TLS boundary is verified.
- The disposable Chromium, Firefox, and WebKit baseline passed after remediating the two
  cross-browser findings recorded in `docs/SECURITY_FINDINGS.md`. Release-candidate repetition and
  branded/real-device mobile passes remain pending. Their exact browser, device, keyboard,
  screen-reader, and zoom targets now have a machine-validated sanitized evidence procedure; no
  target is counted before a dated manual run against the selected candidate.
- Browser-driven DOM-XSS coverage passed across every automated engine/viewport. The 28-scenario
  authorization, session, CSV, financial-logic, audit-tampering, and network catalog now has fixed
  WSTG/local-test mappings, sanitized append-only run records, finding references, candidate
  binding, and a completeness gate. The disposable application fixture now provides two verified
  household boundaries, three MFA users, and protected UUID references for representative object
  types without treating fixture readiness as test execution. The matrix remains at 0 of 3 required
  targets because no manual run has been performed; the private-ingress target additionally
  requires the Linux VM.
- A disposable production-path encrypted backup/restore and signed-checkpoint rehearsal now passes,
  rotates the Restic repository key before restoring the earlier snapshot, and records remediation
  of `M10-F020` and `M10-F021`; it is repeatable development evidence. A separate guarded rehearsal passes the
  versioned MFA re-encryption and lost-device password/MFA/session recovery path with protected
  audit events. The disposable production-path upgrade/rollback rehearsal also passes: it backs up
  before an additive candidate migration, proves the previous application can use the compatible
  forward schema, and proves clean recovery by starting the baseline application on a separate
  restored database where candidate schema is absent. The real off-VM release-candidate restore,
  timed recovery observation, Tailscale device revocation, full host credential rotation, and
  clean-VM upgrade/rollback validation with two preserved release artifacts remain pending.
- No complete release-candidate penetration-test pass is claimed yet.
