# Security finding register

This register contains sanitized summaries only. Raw scanner output, attack traces, credentials,
cookies, internal hostnames, and reusable payloads must remain in the ignored `security-reports/`
directory or an encrypted assessment location outside the repository.

## M10-F001 — Stale release base image

- Severity: Critical
- State: Retested
- Detected: 2026-08-24
- Owner: release owner
- Affected baseline: pre-M10 `python:3.12-slim` release image
- Detection: Trivy 0.70.0 image vulnerability and secret scan with a current vulnerability database
- Evidence summary: the Debian runtime contained 3 critical and 50 high operating-system findings;
  installed Python packages reported no high or critical findings, and no embedded secret finding
  was reported.
- Root cause: the immutable Debian base digest preserved packages with newly disclosed findings.
- Remediation: replaced it with the current official `python:3.12-alpine` image pinned to digest
  `sha256:d09d15e60962ca365d1cd544a48773bac9d33f2fb1b00f2aa0deec78ade7dc31`, retained the
  non-root numeric account, read-only filesystem, dropped capabilities, and no-new-privileges
  controls, and added a blocking CI scan using the official Trivy container pinned by digest.
- Retest: the rebuilt complete application image reported zero high/critical Alpine or Python
  package findings and no embedded-secret finding. PostgreSQL migrations, the least-privilege
  notification worker, and the web readiness endpoint then passed on the replacement runtime.
- Exceptions or suppressions: none.
- Follow-up: every release candidate must rebuild and pass the blocking image scan because a pinned
  digest does not remain vulnerability-free over time.

## M10-F002 — Permissive CORS header on public static assets

- Severity: Medium
- State: Retested
- Detected: 2026-08-24
- Owner: release owner
- Affected baseline: the initial M10 synthetic ZAP run
- Detection: ZAP rule 10098 reported `Access-Control-Allow-Origin: *` on the two public,
  fingerprinted application CSS and JavaScript assets. No application page, authenticated response,
  API response, or user data was affected.
- Root cause: WhiteNoise enables cross-origin reads for public static files by default.
- Remediation: set `WHITENOISE_ALLOW_ALL_ORIGINS = False` in the production-derived settings. This
  deployment serves assets from the same origin and does not require cross-origin CDN access.
- Retest: the unauthenticated and both MFA-authenticated scans completed without rule 10098 or any
  other cross-domain alert.
- Exceptions or suppressions: none. The alert was fixed rather than hidden from the report.

## M10-F003 — Plain HTTP in the isolated scanner transport

- Severity: Medium
- State: Accepted
- Detected: 2026-08-24
- Affected environment: the disposable internal-only synthetic pentest network
- Detection: ZAP reported `HTTP Only Site` for the synthetic login page.
- Reason: ZAP and the production-derived app communicate over a private Docker network during this
  one-run test. The pentest settings are guarded by the exact environment, database host, database
  name, and synthetic-data opt-in; they alone disable HTTPS redirect, HSTS, and secure cookies.
  Production settings retain HTTPS redirect, secure `__Host-` cookies, and HSTS.
- Owner: release owner
- Deadline: verify the real VM ingress, certificate, redirect, HSTS, and secure-cookie boundary
  before release-candidate approval and no later than 2026-09-30.
- Acceptance boundary: this exception applies only to the disposable scanner transport. Plain HTTP
  is not accepted for a deployed instance.

## M10-F004 — Nonportable native date-control defaults

- Severity: Low
- State: Retested
- Detected: 2026-08-24
- Owner: release owner
- Affected baseline: initial Chromium, Firefox, and WebKit workflow run
- Detection: every engine retained the manual-expense form instead of accepting the write because
  Django's locale-formatted initial date was not a valid HTML `date` control value.
- Remediation: introduced shared ISO-date and minute-precision time widgets and applied them to all
  audit, budget, debt, goal, and spending native date/time controls.
- Retest: portable widget unit tests and the manual-expense workflow passed in all seven automated
  browser projects.
- Security impact: none observed; validation rejected the incomplete submission and no partial
  ledger write occurred.

## M10-F005 — Font-dependent narrow summary-card overflow

- Severity: Low
- State: Retested
- Detected: 2026-08-24
- Owner: release owner
- Affected baseline: Firefox narrow dashboard and WebKit iPhone Goals view
- Detection: engine-specific font metrics forced two summary cards 7–12 pixels beyond the
  390-pixel viewport.
- Remediation: changed the narrow two-column tracks to shrink-safe `minmax(0, 1fr)` sizing and
  allowed summary text to wrap without expanding its grid item.
- Retest: dashboard, Spending, Debts, and Goals had no horizontal document overflow across every
  desktop, narrow, phone, and iPad project.
- Security impact: none; this was a responsive usability defect.

## M10-F006 — Stale OpenSSL packages in pinned Alpine base

- Severity: High
- State: Retested
- Detected: 2026-08-27
- Owner: release owner
- Affected baseline: commit `b230396` release image in PR #22
- Detection: the blocking Trivy 0.70.0 release-image job used a current vulnerability database and
  identified `CVE-2026-14456` in both `libcrypto3` and `libssl3`.
- Evidence summary: the pinned official Python Alpine image contained OpenSSL `3.5.7-r0`; Alpine's
  official 3.24 repository provided the fixed `3.5.8-r0`. No High/Critical Python-package finding
  or embedded-secret finding was reported.
- Root cause: the immutable base digest had not yet been rebuilt after Alpine published the fixed
  OpenSSL packages. Pinning an image prevents an unexpected base change but cannot keep its
  installed operating-system packages vulnerability-free.
- Remediation: retained the reviewed immutable Python base digest and added a no-cache Alpine
  package upgrade during the release build so current security fixes are applied before the
  unprivileged application user and application layers are created.
- Retest: the complete image rebuilt with OpenSSL `3.5.8-r0`; the same immutable Trivy command and
  a current vulnerability database reported zero High/Critical Alpine or Python-package findings
  and no embedded-secret finding. The application quality gate also passed after the change.
- Exceptions or suppressions: none; the finding is not ignored or severity-downgraded.

## M10-F007 — Anonymous state retained across the password trust boundary

- Severity: Low
- State: Retested
- Detected: 2026-08-28
- Owner: release owner
- Affected baseline: initial disposable `SESS-02` session-fixation probe
- Detection: a controlled server-side marker in a cloned anonymous session survived password
  acceptance and MFA completion even though the session identifier rotated at both transitions.
- Security impact: no reusable identifier fixation or authorization bypass was observed, and the
  application does not expose a client-controlled arbitrary-session-data facility. Retaining
  unrelated anonymous values across a trust transition was nevertheless unnecessary and could
  make a future session-backed feature inherit stale untrusted state.
- Remediation: password acceptance now flushes the anonymous session before writing the three
  pending-MFA fields. Final authentication and recent authentication continue to rotate the new
  identifier.
- Retest: unit coverage proved the old key and marker are absent after password acceptance; the
  disposable HTTP probe then passed pre-authentication, pending-MFA, final-authentication, and
  recent-authentication rotations without preserving the marker.
- Exceptions or suppressions: none.

## M10-F008 — Authentication cookie outlived a normal browser session

- Severity: Medium
- State: Retested
- Detected: 2026-08-28
- Owner: release owner
- Affected baseline: initial disposable `SESS-05` cookie-lifetime probe
- Detection: pending-MFA and authenticated session helpers set explicit time-based expiry values,
  causing a persistent browser cookie despite the production browser-close policy. Server-side
  five-minute pending, one-hour idle, and twelve-hour absolute checks still limited reuse.
- Remediation: both helpers now issue browser-session-only cookies. The existing server-side
  timestamps remain authoritative for pending, idle, and absolute expiry, and database cleanup
  retains its global session age.
- Retest: unit tests, real HTTP cookie-jar checks, and the Chromium/Firefox/WebKit Playwright matrix
  confirmed browser-session-only expiry. The final lifecycle project also proved sign-out removes
  the cookie, back navigation does not reveal the protected audit page, and a fresh context starts
  unauthenticated.
- Exceptions or suppressions: none.

## M10-F009 — Unfinished CSV staging retained raw cells indefinitely

- Severity: Medium
- State: Retested
- Detected: 2026-08-31
- Owner: release owner
- Affected baseline: pre-CSV-security adversarial slice
- Detection: lifecycle review for `CSV-04` found that commit and explicit abandonment scrubbed raw
  cells, but an uploaded or previewed batch left unfinished by both members had no automatic expiry.
- Security impact: the complete upload file was never persisted and row, column, cell, and byte
  limits applied, but bounded statement cells could remain in PostgreSQL longer than needed. That
  unnecessarily increased the confidentiality impact of a later database compromise or overly
  broad administrative access.
- Remediation: added a configurable 24-hour staging limit and an hourly least-privilege maintenance
  service. It locks and rechecks eligible uploaded/previewed batches, scrubs all raw mappings, marks
  the batch abandoned, and appends an actorless protected audit event. The job receives only the
  normal runtime database identity and application secrets; it receives no administrator,
  migration, backup, or checkpoint-signing credential.
- Retest: unit tests proved uploaded and previewed expiry, recent-batch preservation, idempotent
  reruns, raw-cell deletion, protected audit creation, configuration bounds, and the management
  command. The disposable `CSV-04` HTTP/PostgreSQL probe then expired one 25-hour batch, preserved
  one recent batch, observed no retained media file, verified audit-chain integrity, and removed
  every synthetic container, volume, and network.
- Exceptions or suppressions: none.

## M10-F010 — Financial form races could overwrite or duplicate accepted changes

- Severity: Medium
- State: Retested
- Detected: 2026-08-31
- Owner: release owner
- Affected baseline: initial `FIN-05` concurrency and replay review
- Detection: variable-budget edits carried no version of the row displayed to the member, so a
  stale form could silently replace a newer amount. Manual goal contributions derived their
  ledger idempotency key from a per-request identifier, so resubmitting the same browser form could
  create a second accepted contribution.
- Security impact: either household member could unintentionally erase the other's concurrent
  budget edit or duplicate a goal allocation during retry. Household authorization and protected
  audit append still applied, but they did not prevent or reconcile the duplicate financial effect.
- Remediation: variable-budget create forms now carry a signed category-version snapshot captured
  when the form is rendered, and edit forms carry the displayed row version; both reject stale
  writes inside the locked transaction. Goal forms now carry a stable random submission token; the
  service hashes its goal-scoped value into the existing ledger idempotency boundary while retaining
  request identifiers for trace correlation.
- Retest: focused tests proved one accepted budget edit, one visible stale-form rejection, and one
  audit event; a repeated goal form produced one contribution, one journal entry, and one audit
  event. The disposable PostgreSQL probe then passed controlled two-member budget, spending,
  payment, goal, and period-move races with exactly one consistent accepted effect.
- Exceptions or suppressions: none.

## M10-F011 — Nullable joins broke PostgreSQL locks for financial corrections

- Severity: Medium
- State: Retested
- Detected: 2026-08-31
- Owner: release owner
- Affected baseline: initial `FIN-01` and `FIN-04` PostgreSQL runs
- Detection: expense refund, journal reversal, and mortgage extra-principal services combined
  `SELECT FOR UPDATE` with eager joins to nullable category or pay-period rows. PostgreSQL rejects
  a row lock on the nullable side of an outer join, although the SQLite unit-test backend accepts
  the query shape.
- Security impact: valid corrections failed safely and rolled back rather than corrupting balances,
  but members could not complete the affected refund, reversal, or mortgage-planning operation on
  the production database engine.
- Remediation: each service now locks only its authoritative financial row, then resolves related
  household, category, source, and period data separately through the model relationships. Atomic
  authorization, validation, ledger effects, and protected audit append remain unchanged.
- Retest: the card regression covered a purchase, mixed payment, partial and full refunds, and
  payment reversal with zero final cash, liability, refundable, and reserve balances. Mortgage
  service tests passed, and fresh PostgreSQL runs completed all `FIN-01` and `FIN-04` invariants.
- Exceptions or suppressions: none.

## M10-F012 — Financial probe could reuse an older helper image

- Severity: Low
- State: Retested
- Detected: 2026-08-31
- Owner: release owner
- Affected baseline: initial financial-logic runner
- Detection: the base synthetic application was rebuilt, but the later one-off financial probe
  used Compose `run` without `--build`. A helper image left by an earlier attempt could therefore
  execute older application modules and make the evidence disagree with the reviewed tree.
- Security impact: no application or household data was exposed. The defect reduced confidence in
  test evidence and could produce either stale failures or stale passes after a code change.
- Remediation: both Windows/WSL and Linux runners now rebuild the guarded probe service immediately
  before execution. Static harness tests require the fixed project, exact guard, fresh-volume
  cleanup, and the `run --build` invocation.
- Retest: the helper image rebuilt from the current tree and all five financial families passed;
  cleanup removed every disposable container, volume, and network.
- Exceptions or suppressions: none.

## M10-F013 — Restore verifier trusted a mutable audit head without replaying the chain

- Severity: High
- State: Retested
- Detected: 2026-08-31
- Owner: release owner
- Affected baseline: pre-`AUDIT-02` and `AUDIT-04` restore-verification review
- Detection: the signed external checkpoint verifier authenticated the checkpoint document and
  compared it with `AuditHead`, but it did not replay every event hash. A privileged mutation that
  left the mutable head unchanged could therefore pass the documented restore check. The command
  also selected the household from the supplied document rather than requiring the operator's
  expected household, and the signature envelope's key ID was not covered by the version-1 body or
  compared with the configured rotation ID.
- Security impact: PostgreSQL's runtime role still could not perform the mutation, and changing the
  protected records required the administrative audit owner. After such a compromise or an
  incorrect restore selection, however, the documented checkpoint command could report success
  for modified history or the wrong household and weaken the intended independent evidence
  boundary.
- Remediation: checkpoint version 2 signs the algorithm and key ID inside the canonical body. The
  verifier now requires an operator-supplied household UUID, checks the signed key ID against the
  configured key ID, replays the complete event chain, and compares the replayed count and head
  with both the protected database head and signed checkpoint. Failed database checkpoint records
  also remove the just-written external file so an unrecorded artifact is not mistaken for a
  completed checkpoint.
- Retest: unit tests rejected modified key metadata, an unexpected configured key ID, a foreign
  expected household, a tampered event chain, and a simulated database-record failure. Fresh
  PostgreSQL `AUDIT-02` probes detected field mutation, removal, reordering, and a forged link with
  both verifiers. `AUDIT-04` rejected a foreign checkpoint, unexpected and modified key metadata,
  a modified body, a stale checkpoint, and internally valid chains restored behind or ahead, then
  accepted the exactly restored chain and matching checkpoint.
- Exceptions or suppressions: version-1 documents remain cryptographically readable for recovery.
  Their envelope key ID is not part of the signed body, so the management command additionally
  requires it to match the trusted configured ID. New checkpoints are version 2.

## M10-F014 — Internal-only application networks could not provide the loopback upstream

- Severity: Medium
- State: Retested
- Detected: 2026-09-01
- Owner: release owner
- Affected baseline: initial production-derived `NET-03` through `NET-06` run
- Detection: the production Compose model attached the Django service only to Docker networks marked
  `internal` while also declaring a loopback host publish. This Docker engine accepted the model but
  created no host port binding, so the planned Tailscale Serve upstream could not reach Gunicorn.
- Security impact: no data or service was exposed; the application was unavailable through its
  intended ingress. Simply making the Django frontend network non-internal would have restored the
  port while also restoring general application-container egress, weakening the SSRF and
  compromise-containment boundary.
- Remediation: a dedicated relay built from an immutable official nginx base now owns the only
  non-internal network and the only `127.0.0.1:8000` publish. The relay has no secrets, application
  database access, or access logs;
  runs as numeric UID/GID 101 with no capabilities, no-new-privileges, a read-only root filesystem,
  and bounded no-exec temporary storage; and can proxy only to the Django service over the internal
  frontend network. Django and PostgreSQL remain exclusively on internal networks. CI now scans the
  pinned relay image independently from the application image.
- Retest: a minimal Docker reproduction confirmed the engine behavior, then the real production
  Compose stack proved the relay port was loopback-only, the web and database published no port,
  the relay could reach only the web upstream, and the web could reach PostgreSQL but not an
  external test endpoint. Runtime inspection confirmed both containers retained their documented
  identities and hardening controls.
- Exceptions or suppressions: the relay can initiate traffic through its non-internal network by
  Docker design. It receives no credentials or household data at rest, has one fixed internal
  upstream, strips client forwarding identities, and is separately pinned, scanned, and hardened.

## M10-F015 — Host allowlist enforcement was lazy on host-agnostic routes

- Severity: Medium
- State: Retested
- Detected: 2026-09-01
- Owner: release owner
- Affected baseline: initial production-derived `NET-05` HTTP probe
- Detection: Django validates `ALLOWED_HOSTS` when code resolves `request.get_host()`, not as an
  unconditional first step. The liveness route did not resolve the host and therefore returned its
  safe 200 response to an alternate `Host` header instead of the expected generic 400.
- Security impact: the observed response contained only static health state, and the alternate host
  could not alter HTTPS redirects or generated links. However, relying on every current and future
  route to resolve the host made an explicit production trust boundary inconsistent and could
  enable host-header behavior to reappear as views changed.
- Remediation: the outer proxy middleware first canonicalizes the one trusted scheme header and
  strips all other forwarding authority. A dedicated host-boundary middleware immediately behind
  Django's security middleware then resolves and validates the host for every request, returning an
  empty generic 400 before routing when it is not the one configured Tailscale hostname.
- Retest: unit tests cover approved and alternate hosts on the health path. The production-derived
  relay run confirmed alternate `Host`, `Forwarded`, `X-Forwarded-Host`, and
  `X-Forwarded-Port` values cannot change a response or redirect, ambiguous scheme values cannot
  assert HTTPS, approved HTTPS retains exact HSTS, and safe 400/404 responses contain no traceback,
  attacker host, or reusable secret.
- Exceptions or suppressions: none.

## M10-F016 — Linux file-backed secrets were unreadable to non-root service identities

- Severity: Medium
- State: Retested
- Detected: 2026-09-01
- Owner: release owner
- Affected baseline: first direct Linux `NET-06` run
- Detection: Docker Compose file-backed secrets preserved the host files' Linux ownership and mode.
  Mode-0600 files owned by the deployment user were readable through Docker Desktop's Windows bind
  behavior but failed with `Permission denied` when the PostgreSQL bootstrap ran as its non-root
  Linux identity.
- Security impact: no secret was disclosed and startup failed closed. Broadening the files to 0444,
  running application/maintenance services as root, or sharing one user identity would have made
  the deployment start while weakening the least-privilege and host-secret boundary.
- Remediation: production uses one dedicated, non-root numeric secret-reader GID with no human
  members. The root-owned secret directory remains mode 0700 and each root-owned secret file is
  mode 0440. Compose grants the supplemental GID only to the nine secret-bearing services, while
  each service still mounts only its explicitly allowed files. The relay receives neither the GID
  nor a secret mount. The deployment environment stores only the non-sensitive numeric GID.
- Retest: the direct Linux runner created 0700/0440 temporary sources owned by one user/group,
  rendered all Compose profiles, verified every source path and reader-group assignment, completed
  role bootstrap and migrations under the intended identities, and confirmed the running web
  process received only its three read-only secret files. The Windows runner remains green without
  treating its filesystem behavior as Linux evidence.
- Exceptions or suppressions: none.

## M10-F017 — OneDrive reparse metadata could prevent the Linux boundary harness from building

- Severity: Low
- State: Retested
- Detected: 2026-09-01
- Owner: release owner
- Affected baseline: first direct WSL execution of the network-boundary runner
- Detection: BuildKit attempted to inspect extended attributes on an ignored OneDrive pytest-cache
  reparse point before applying `.dockerignore` and failed with access denied. Deleting or traversing
  the cloud reparse point from the security runner was not safe.
- Security impact: no application state or secret was affected. The failure prevented Linux-specific
  secret-permission evidence and could encourage an operator to delete ambiguous filesystem objects
  or move unreviewed files into a build context.
- Remediation: the Linux runner asks Git for the tracked and non-ignored file list using NUL-delimited
  names, archives only those explicit files into its guarded temporary directory, and points every
  Compose build at that directory. Ignored `.env` files, caches, reports, local credentials, and
  repository metadata cannot enter the staged context. The runner deletes the file list, archive,
  context, and all other temporary state on exit.
- Retest: the WSL run built both application helper images from the staged context, completed all
  production-derived checks, and removed the temporary context without reading or deleting the
  OneDrive cache reparse points.
- Exceptions or suppressions: none.

## M10-F018 — Pinned upstream relay image contained fixed High Alpine vulnerabilities

- Severity: High
- State: Retested
- Detected: 2026-09-01
- Owner: release owner
- Affected baseline: first PR #30 ingress-relay image scan
- Detection: the pinned official nginx 1.30.4 Alpine image contained `libcrypto3` and `libssl3`
  3.5.7-r0 affected by `CVE-2026-14456`, plus `libexpat` 2.8.2-r0 affected by
  `CVE-2026-66046` and `CVE-2026-76641`. Alpine had already published fixed OpenSSL 3.5.8-r0 and
  Expat 2.8.4-r0 packages. The new independent relay-image gate failed on all four High results.
- Security impact: the relay does not enable QUIC or parse XML in its configured path, which reduced
  the direct reachability of the reported denial-of-service conditions. The vulnerable libraries
  were nevertheless present in the release artifact, and the release policy does not accept a
  known fixed High image finding based only on feature reachability.
- Remediation: the repository now builds a minimal relay image from the immutable official nginx
  base, applies `apk upgrade --no-cache`, and pins runtime to UID/GID 101. Compose deploys that built
  artifact, and CI scans it separately from the application image so an upstream base that has not
  yet been republished cannot bypass available Alpine security fixes.
- Retest: the guarded Linux production-boundary run rebuilt the relay, visibly upgraded OpenSSL to
  3.5.8-r0 and Expat to 2.8.4-r0, passed all 81 runtime controls, and cleaned up. The exact immutable
  Trivy 0.70.0 command used by CI then reported zero High/Critical vulnerabilities and no secret
  finding for the upgraded local relay image.
- Exceptions or suppressions: none.

## M10-F019 — Production-only identity validation blocked the disposable browser stack

- Severity: Low
- State: Retested
- Detected: 2026-09-01
- Owner: release owner
- Affected baseline: first two PR #30 browser-matrix runs
- Detection: the new production environment and exact Tailscale-host validation ran while
  `config.settings.pentest` imported `config.settings.production`. The disposable stack correctly
  failed closed during migration, before any browser test could run. Its runner then removed the
  failed one-shot container without first printing the service log, which made the CI exception
  unnecessarily difficult to recover.
- Security impact: production enforcement remained intact and required checks blocked the merge;
  there was no production bypass or lost financial data. The failure temporarily removed browser
  regression evidence and exposed insufficient diagnostics in the synthetic test harness.
- Remediation: shared deployment controls now live in a guarded hardened-settings module that can be
  loaded only through the production or pentest settings modules. Production retains its exact
  environment, hostname, and HTTPS-origin validation; pentest retains its independent synthetic-data,
  database-host, and database-name guards. Both browser runners now print only the bounded synthetic
  service logs when startup fails, before removing the disposable project.
- Retest: 49 focused settings, pentest-harness, and browser-harness tests passed. The local disposable
  stack then migrated, seeded, and completed all applicable checks across Chromium, Firefox, and
  WebKit desktop and mobile profiles plus session lifecycle, followed by complete volume/network
  cleanup.
- Exceptions or suppressions: none.

## M10-F020 — Backup role could not read the complete protected database

- Severity: High
- State: Retested
- Detected: 2026-09-01
- Owner: release owner
- Affected baseline: first automated production-path backup and restore rehearsal
- Detection: the production `pg_dump` stream failed first on the protected audit schema and then on
  public sequence state. The `budget_backup` login was intentionally `NOINHERIT`, but bootstrap had
  relied on membership in PostgreSQL's broad `pg_read_all_data` role. The membership therefore did
  not provide the intended access, and the explicit grants covered tables but not future sequences.
- Security impact: every attempted backup failed closed before the success marker was written, so
  the freshness alert could detect the outage and no plaintext dump was retained. A deployment left
  in that state would nevertheless have no usable recovery point, creating an unacceptable loss-of-
  availability and data-recovery risk.
- Remediation: the ineffective broad role membership was removed. Bootstrap now grants the backup
  login only `CONNECT`, schema `USAGE`, and current-and-future read access to tables and sequences in
  `public` and `budget_audit`. Restore bootstrap also reapplies the protected schema, table, and
  function ACLs that `pg_restore --no-privileges` intentionally omits.
- Retest: the real backup script streamed the complete PostgreSQL database into a new encrypted
  Restic repository, completed `restic check`, restored into a fixed disposable target, reapplied
  least-privilege roles, and verified all 26 cross-household fixture references plus both complete
  audit chains and their signed checkpoints. Live-target and existing-target attempts both failed
  without changing data.
- Exceptions or suppressions: none.

## M10-F021 — Backup image contained vulnerable embedded Go components

- Severity: High
- State: Retested
- Detected: 2026-09-01
- Owner: release owner
- Affected baseline: first independent backup/restore image scan
- Detection: the immutable Trivy gate found a Critical result and multiple High results in the
  inherited, unused `gosu` helper and in dependencies embedded in the official Restic 0.19.1 binary.
  Updating Alpine packages alone correctly left those statically compiled components unchanged.
- Security impact: `gosu` was unreachable because the image clears the inherited entrypoint and
  starts directly as UID 70. The Restic binary handles attacker-relevant repository data and is part
  of the recovery trust boundary, so known fixed High findings could not be accepted based on the
  private/local repository topology.
- Remediation: the image now uses a minimal immutable Alpine runtime with only the PostgreSQL 17
  client, eliminating `gosu`. It reproducibly builds the checksummed Restic 0.19.1 release source in
  an immutable Go 1.26.6 builder while pinning the affected Go modules to fixed versions. The runtime
  retains UID/GID 70 with a nonexistent home and `nologin`; CI builds and scans this third release
  artifact independently from the application and ingress relay.
- Retest: the rebuilt image completed the entire encrypted backup and restore rehearsal. The exact
  immutable Trivy 0.70.0 command used by CI then reported zero High/Critical vulnerability and zero
  secret findings for both the Alpine runtime and Restic binary.
- Exceptions or suppressions: none.

## M10-F022 — Refreshed scanner database found a newly fixed gRPC-Go vulnerability

- Severity: High
- State: Retested
- Detected: 2026-09-01
- Owner: release owner
- Affected baseline: credential-rotation pull-request image scan
- Detection: the immutable Trivy gate refreshed its vulnerability database and found
  `CVE-2026-84304` in `google.golang.org/grpc` 1.82.1 embedded in the reproducibly built Restic
  binary. The scanner identified 1.83.1 as the first fixed version; the current signed upstream
  module release is 1.83.2.
- Security impact: the vulnerable package is statically embedded in the backup/recovery trust
  boundary. Even though the affected behavior may not be reachable through BudgetApp's current
  Restic usage, carrying a known fixed High result would weaken the release image and recovery path.
- Remediation: the checksummed Restic 0.19.1 source build now pins `google.golang.org/grpc` 1.83.2.
  No scanner exception, version suppression, or topology-based acceptance was added.
- Retest: the full encrypted backup, key-rotation, pre-rotation snapshot restore, fixture, audit-chain,
  and signed-checkpoint rehearsal passed with the rebuilt image. The immutable High/Critical Trivy
  gate then passed for the exact pull-request revision.
- Exceptions or suppressions: none.

## M10-F023 — Session rehearsal could reuse stale one-off images

- Severity: Low
- State: Retested
- Detected: 2026-09-04
- Owner: release owner
- Affected baseline: administrator session-revocation rehearsal
- Detection: the current session probe script was mounted into a one-off image retained from an
  earlier run. The script imported the new administrator revocation service, but the stale image's
  application package did not contain it, so the guarded rehearsal failed closed before probing.
- Security impact: no application or household data was exposed. The defect reduced confidence in
  session evidence because fixture, authentication, or probe code could disagree with the reviewed
  source tree.
- Remediation: the Windows/WSL and Linux session runners now use Compose `run --build` for the
  fixture verifier, password-and-TOTP initializer, and bounded session probe. Static regression
  tests require each fresh-build invocation along with the fixed project and cleanup guards.
- Retest: every one-off image rebuilt from the current tree; `SESS-01` through `SESS-05` passed with
  30 identity/throttle, 4 trust-transition, 29 account/revocation, 8 timeout/concurrency, and 6
  cookie/cache checks. Cleanup removed every disposable container, volume, and network.
- Exceptions or suppressions: none.

## M10-F024 — Password-only administration bypassed per-session MFA

- Severity: High
- State: Remediated
- Detected: 2026-09-14
- Owner: release owner
- Affected baseline: Django administration login and sensitive user editing
- Detection: the default admin login accepted a staff password while middleware checked only
  completed account enrollment, not whether that browser session had passed MFA. Administration
  also lacked the application's recent-authentication guard.
- Security impact: a compromised staff password could establish administration access without the
  second factor; stale administrative sessions could modify sensitive account attributes. The user
  editor also exposed internal session versions and authentication timestamps as editable fields.
- Remediation: a custom admin site redirects login to application authentication and requires
  explicit current-session MFA proof plus recent full authentication for every protected view.
  Only successful MFA sign-in or password-plus-MFA reauthentication grants proof. Internal
  authentication state is read-only in the user editor; ordinary staff/model permissions and CSRF
  checks remain enforced.
- Automated retest: `tests/test_admin_security.py` covers password-only GET/POST attempts, pending
  MFA, legacy sessions, failed and successful reauthentication, stale sensitive edits, non-staff
  denial, read-only authentication fields, and retained CSRF protection using synthetic accounts.
- Deployment requirement: revoke every pre-upgrade authenticated and pending-MFA session before
  reopening traffic. The command and evidence requirements are in `docs/SESSION_SECURITY.md`.
  No live revocation or release-candidate retest is claimed; keep this finding out of the release
  pass until those steps are recorded.
- Exceptions or suppressions: none.

## M10-F025 — Authentication outcome flags were omitted from archived security records

- Severity: Low
- State: Remediated
- Detected: 2026-09-18
- Owner: release owner
- Affected baseline: structured Django security logging for login, MFA, reauthentication, and password recovery
- Detection: producers attached `rate_limited` and `accepted` outcome booleans, but the JSON formatter's
  allowlist omitted them before delivery to the independent security archive.
- Security impact: authentication failure events still reached the archive, but an operator could not
  distinguish active throttling from an ordinary failed attempt or accepted from rejected password
  recovery by those documented outcome fields. No credential or account identifier was exposed.
- Remediation: the formatter now preserves only those two typed booleans, and the collector rejects
  non-boolean substitutes. The inventory documents their minimized purpose and restricted audience.
- Automated retest: `tests/test_logging.py` exercises a throttled login and formatter-to-collector
  preservation; `tests/test_security_log_archive.py` rejects string, number, and null substitutes.
- Release boundary: verify archive delivery, alert review, and retention on the selected VM with
  synthetic accounts. The repository tests are not a live release-candidate pass.
- Exceptions or suppressions: none.

## M10-F026 — Rejected financial mutations lacked security-stream events

- Severity: Low
- State: Remediated
- Detected: 2026-09-19
- Owner: release owner
- Affected baseline: expense, income, card-payment, card-refund, and transaction-reversal views
- Detection: invalid financial forms and service-level business-rule rejections returned safe
  responses and operational request records, but did not create distinct security-archive events.
- Security impact: financial invariants remained enforced and no unauthorized write was observed,
  but repeated attempts to bypass those controls were harder to distinguish during security review.
- Remediation: each rejected workflow now emits exactly one fixed warning event with only the HTTP
  method, request error reference, and pseudonymous bound context. Amounts, descriptions, notes,
  reasons, object references, form errors, and submitted values are excluded.
- Automated retest: `tests/test_spending_ui.py` covers all five invalid-form boundaries, confirms
  fixed event ordering and levels, verifies request correlation and canary exclusion, and separately
  exercises service-level idempotency and business-rule rejections across all five workflows.
- Release boundary: ASVS `v5.0.0-16.3.3` remains partial until the complete documented event review
  and live archive delivery, retention, alert-review, and escalation checks are performed.
- Exceptions or suppressions: none.

## M10-F027 — Rejected goal mutations lacked security-stream events

- Severity: Low
- State: Remediated
- Detected: 2026-09-19
- Owner: release owner
- Affected baseline: goal creation, revision, status, contribution, reserve-allocation, and
  priority-allocation views
- Detection: invalid goal forms and service-level business-rule rejections returned safe responses
  and operational request records, but did not create distinct security-archive events.
- Security impact: goal and reserve invariants remained enforced and no unauthorized write was
  observed, but repeated attempts to bypass those controls were harder to identify during review.
- Remediation: each rejected workflow now emits exactly one fixed warning event with only the HTTP
  method, request error reference, and pseudonymous bound context. Goal names, amounts, dates,
  statuses, notes, reasons, account, goal, or period references, preview fingerprints, form errors,
  validation messages, and submitted values are excluded.
- Automated retest: `tests/test_goal_ui.py` covers all six invalid-form and service-level rejection
  boundaries, verifies fixed ordering and warning levels, request correlation, canary exclusion,
  and exactly one event for an idempotency replay.
- Release boundary: ASVS `v5.0.0-16.3.3` remains partial until the complete documented event review
  and live archive delivery, retention, alert-review, and escalation checks are performed.
- Exceptions or suppressions: none.

## M10-F028 — Rejected budget-configuration mutations lacked security-stream events

- Severity: Low
- State: Remediated
- Detected: 2026-09-19
- Owner: release owner
- Affected baseline: variable-budget creation, editing, deletion, and category-creation views
- Detection: invalid configuration forms, stale-version conflicts, and service-level rejections
  returned safe responses but did not create distinct security-archive events.
- Security impact: budget invariants and optimistic concurrency remained enforced, but repeated
  attempts to bypass those controls were harder to identify during security review.
- Remediation: each rejected workflow now emits exactly one fixed warning event with only the HTTP
  method, request error reference, and pseudonymous bound context. Planned amounts, category names,
  notes, reasons, object references, version tokens, form errors, validation messages, and submitted
  values are excluded.
- Automated retest: `tests/test_budget_dashboard.py` covers all four invalid-form and service-level
  rejection boundaries, fixed event order, request correlation, canary exclusion, confirmation
  rejection, and safe stale-version handling.
- Release boundary: ASVS `v5.0.0-16.3.3` remains partial until the complete documented event review
  and live archive delivery, retention, alert-review, and escalation checks are performed.
- Exceptions or suppressions: none.

## M10-F029 — Rejected occurrence mutations lacked security-stream events

- Severity: Low
- State: Remediated
- Detected: 2026-09-19
- Owner: release owner
- Affected baseline: occurrence edit, move, cancel, and reconciliation views
- Detection: invalid occurrence forms and service-level rejections returned safe responses but did
  not create distinct security-archive events.
- Security impact: occurrence and reconciliation invariants remained enforced and no unauthorized
  write was observed, but repeated attempts to bypass those controls were harder to identify.
- Remediation: each rejected workflow now emits exactly one fixed warning event with only the HTTP
  method, request error reference, and pseudonymous bound context. Planned and actual amounts,
  reasons, scopes, occurrence, period, and journal-entry references, form errors, validation
  messages, and submitted values are excluded.
- Automated retest: `tests/test_budget_dashboard.py` covers all four invalid-form and service-level
  rejection boundaries, fixed event order, request correlation, and canary exclusion.
- Release boundary: ASVS `v5.0.0-16.3.3` remains partial until the complete documented event review
  and live archive delivery, retention, alert-review, and escalation checks are performed.
- Exceptions or suppressions: none.

## 2026-09-02 synthetic upgrade and rollback baseline

- The fixed disposable rehearsal wrote independently signed audit checkpoints and created an
  encrypted production-script backup before applying a test-only additive candidate migration.
  The candidate schema, healthy candidate application, complete synthetic fixture, and unchanged
  audit chains all verified afterward.
- The baseline application then became healthy against the explicitly compatible forward schema
  without reversing a migration. The clean-database path restored the pre-upgrade snapshot to a
  separately named target, refused to overwrite that target, reapplied least-privilege grants, and
  proved the candidate migration record and marker table were absent.
- The restored multi-household fixture and signed audit checkpoints matched, and the baseline
  application became healthy against the restored database. The bounded schema verifier used the
  existing read-only backup role; no administrator credential was added to an application image.
- Development runs exposed and corrected three harness-only fail-closed integration gaps: the new
  restored database was initially absent from the exact settings allowlist, one verifier invocation
  and the rollback service omitted the matching restore-context signal, and the verifier initially
  used a role that could not read metadata restored without ownership. Regression assertions now
  cover each boundary. No production application vulnerability was identified.
- The final upgrade/rollback run and the original encrypted restore/key-rotation rehearsal passed
  and removed all generated credentials, database state, checkpoints, repository packs, containers,
  networks, volumes, and Linux-native temporary build context on exit.
- This is supporting development evidence from one source tree and a test-only migration, not
  release-gate 10 completion. The real Linux VM exercise must use a clean snapshot, two preserved
  release artifacts, private TLS, the off-VM repository, approved-device login, observed recovery
  time, and a sanitized release-evidence record.

## 2026-09-01 synthetic encrypted restore baseline

- The fixed disposable rehearsal completed an encrypted production-script backup, repository
  integrity check, known-plaintext and generated-secret scan, validated Restic key replacement,
  retired-key rejection, post-backup source divergence proof, guarded restore of the pre-rotation
  snapshot using the new key, full fixture verification, complete audit-chain replay, and
  signed-checkpoint comparison for both synthetic households.
- The live database target and a pre-existing restore target were each refused without data changes.
  The run used separate administrator, migration, runtime, backup, and audit logins and removed every
  generated credential, database, checkpoint, repository pack, container, network, volume, and
  Linux-native temporary build context on exit.
- The runs found and drove remediation of `M10-F020`, `M10-F021`, and the later database refresh
  finding `M10-F022`. The final production-path run and independent backup-image scan passed without
  exceptions or suppressions.
- This is supporting development evidence, not the quarterly release record. The real VM exercise
  must still use the selected release candidate, off-VM repository, external checkpoint directory,
  documented operator, observed recovery time, and sanitized release-evidence record.

## 2026-09-01 synthetic lost-device and credential-rotation baseline

- The fixed disposable rehearsal re-encrypted all three synthetic MFA seeds from version 1 to 2 in
  one PostgreSQL transaction, wrote protected rotation events for both household boundaries,
  proved the retired key could decrypt no seed, preserved the known seed exactly, and retained both
  unrelated authenticated sessions during the planned rotation.
- The lost-device path changed the synthetic account password without echo or argument exposure,
  reset MFA and recovery codes, revoked the old server-side session, rejected the old password,
  TOTP, and recovery code, created protected recovery events, required a distinct fresh seed, and
  completed a new password-plus-TOTP login. Both complete audit chains verified afterward.
- The production PostgreSQL administrator-password helper then rotated the disposable database
  role, reconnected with the replacement, and proved the retired password no longer authenticated.
- The run printed only `ROTATE-01`/`RECOVER-01` counts and generic outcomes and removed its generated
  passwords, seeds, codes, sessions, database, containers, volumes, and networks. It found and
  corrected two harness-only orchestration issues before the final pass: re-running a guarded
  one-shot secret generator and omitting the rotated service's synthetic internal hostname.
- This is supporting development evidence, not security test 20 or release-gate 9 completion. The
  real release candidate still requires Tailscale device revocation, Linux-host secret promotion,
  affected-service restart, retired-access checks, two-user observation, and sanitized evidence.

## 2026-09-01 synthetic network-boundary baseline

- The guarded production-derived helper passed the pre-deployment portions of `NET-03` through
  `NET-06`: 5 HTTPS-policy checks, 8 port/network isolation checks, 8 host/header/error checks, and
  81 runtime, identity, mount, secret-source/mode/group, egress, metadata, image-history, and log
  checks on Linux.
- The run built the production application and secretless relay images from immutable bases, created a
  new PostgreSQL volume, bootstrapped the distinct database roles, applied every migration, and
  mounted nine random temporary secrets from a mode-restricted directory outside the repository.
  It printed no secret values, credentials, financial data, database rows, request bodies, or raw
  runtime metadata. Cleanup removed all containers, volumes, networks, and temporary secret files.
- This is supporting development evidence, not a manual scenario result or release-candidate run.
  The real Tailscale identity, certificate, UFW boundary, approved household devices, unapproved
  device, authenticated secure cookies, and real-proxy observations still require the Linux VM.
  The adversarial matrix therefore remains at zero of three completed targets.

## 2026-08-31 synthetic audit-integrity baseline

- The guarded disposable helper passed `AUDIT-01` through `AUDIT-04`: 15 runtime-role boundary
  checks, 9 corruption-detection checks, 7 financial rollback/recovery checks, and 9 signed
  checkpoint/restore checks.
- The run used PostgreSQL, distinct runtime and audit logins, a bounded administrative test role,
  the protected multi-household fixture, ephemeral checkpoint signing material, complete chain
  replay, and the documented checkpoint command. It printed no credentials, identifiers,
  financial values, database rows, checkpoint contents, or raw audit data, and cleanup removed all
  synthetic state.
- This is supporting development evidence, not a manual scenario result or release-candidate run.
  Human restore observation, bounded audit/log review, and the remaining steps for a complete
  target still have to be exercised. The adversarial matrix therefore remains at zero of three
  completed targets.

## 2026-08-31 synthetic financial-logic baseline

- The guarded disposable helper passed `FIN-01` through `FIN-05`: 14 accounting/retry checks, 12
  validation/allocation checks, 15 boundary/history checks, 14 mortgage/projection checks, and 14
  concurrency/replay checks.
- The run used PostgreSQL, the protected synthetic fixture, real password-plus-TOTP sessions for
  both household members, direct domain-service invariants, and controlled real HTTP races. It
  printed no credentials, cookies, identifiers, amounts, request/response bodies, database rows,
  or raw audit data, and cleanup removed all disposable state.
- This is supporting development evidence, not a manual scenario result or release-candidate run.
  UI/history observation, bounded log review, and the remaining steps for a complete target still
  have to be exercised. The adversarial matrix therefore remains at zero of three completed
  targets.

## 2026-08-31 synthetic CSV-security baseline

- The guarded disposable helper passed `CSV-01` through `CSV-04`: 15 malformed/limit checks, 12
  formula-defense checks, 8 duplicate/replay/concurrency checks, and 10 filename/cleanup checks.
- The run used real password-plus-TOTP sessions for both primary household members, real HTTP
  multipart/form and export requests, and PostgreSQL invariants. It printed no credentials,
  cookies, identifiers, filenames, CSV cells, request/response bodies, or database contents.
- This is supporting development evidence, not a manual scenario result or release-candidate run.
  Spreadsheet-client observation, bounded resource/log review, and the remaining scenarios for a
  complete target still have to be exercised. The adversarial matrix therefore remains at zero of
  three completed targets.

## 2026-09-02 synthetic forgotten-password recovery baseline

- The expanded guarded helper passed `SESS-01` through `SESS-05`: 30 bounded identity/throttle
  checks, 4 trust-transition checks, 22 account/revocation checks, 8 timeout/concurrency checks, and
  6 cookie/cache checks. New HTTP observations compared known and unknown recovery responses and
  bounded timing, enforced keyed throttling, completed a real single-use recovery-code reset,
  invalidated two concurrent sessions, and proved the replacement password reached the MFA
  checkpoint without creating authenticated recovery state.
- The helper retained the synthetic recovery factor only in the isolation authentication volume,
  mounted it only into the bounded session probe, printed no credentials, factors, identities,
  submitted values, response bodies, database contents, or timing samples, and removed every
  database and credential/session volume, container, and network afterward.
- The complete local suite passed 448 tests at 91% combined and 83.00% branch coverage. The public
  recovery page then passed the Chromium, Firefox, WebKit, phone, narrow, iPhone, and iPad browser
  matrix: 52 passed, 13 intentionally project-inapplicable skips, and no accessibility or layout
  failures. ASVS `v5.0.0-6.4.3` is now implemented, not release verified.
- This is supporting development evidence, not a completed manual target or release-candidate run.
  A maintained offline breached-password corpus and deployed TLS/`Secure` observations remain
  pending. The adversarial matrix therefore remains at zero of three completed targets.

## 2026-09-02 synthetic account-security baseline

- The expanded guarded helper passed `SESS-01` through `SESS-05`: 18 bounded identity/throttle
  checks, 4 trust-transition checks, 16 account/revocation checks, 8 timeout/concurrency checks, and
  6 cookie/cache checks. New HTTP observations covered keyed non-reversible session references,
  absence of raw session identifiers in the Account Security response, stale reauthentication
  denial, exact individual-session revocation, current-session preservation, current-password
  verification, password-driven session rotation, and concurrent-session invalidation.
- The run used the protected PostgreSQL fixture and real password-plus-TOTP sessions. It printed no
  credentials, cookies, identifiers, submitted values, response bodies, database contents, or
  timing samples, and cleanup removed the database and every credential/session volume, container,
  and network.
- Focused identity, harness, and release-evidence tests passed alongside the runtime rehearsal. The
  Account Security page also passed the 45-test Chromium, Firefox, WebKit, phone, narrow, iPhone,
  and iPad matrix with 13 intentionally project-inapplicable skips and no accessibility or layout
  failures. The ASVS mapping now records password change and active-session review/revocation as
  implemented, not release verified.
- This is supporting development evidence, not a complete manual scenario result or release-
  candidate run. Forgotten-password recovery, a maintained offline breached-password corpus, and
  deployed TLS/`Secure` observations remain pending. The adversarial matrix therefore remains at
  zero of three completed targets.

## 2026-08-28 synthetic session-security baseline

- The guarded disposable helper passed `SESS-01` through `SESS-05`: 18 bounded identity/throttle
  checks, 4 trust-transition checks, 7 revocation checks, 8 timeout/concurrency checks, and 6
  cookie/cache checks. It printed no credentials, cookies, identifiers, submitted values, response
  bodies, database contents, or timing samples, and cleanup removed the database and every
  credential/session volume.
- The expanded browser matrix completed with 45 passed, 13 intentionally project-inapplicable
  skips, and zero failed. The destructive Chromium lifecycle proof ran only after all Chromium,
  Firefox, WebKit, phone, narrow, iPhone, and iPad dependencies completed.
- This was supporting development evidence, not a manual scenario result or release-candidate run.
  At the time of this baseline, self-service password change/forgot-password and individual active-
  session review/revocation were missing; the trusted-console emergency reset was not a user-facing
  replacement. The 2026-09-02 baseline above supersedes the implemented-control portion of that
  gap. Deployed TLS/`Secure` behavior still requires the private Linux VM target.

## 2026-08-24 synthetic browser baseline

- Result after the accessibility extension: 44 passed, 13 intentionally skipped, and zero failed
  in 37.4 seconds. The skipped cases were project-inapplicable keyboard/touch checks and duplicate
  executions of the destructive category-budget deletion proof; every designated execution passed.
- Matrix: Chromium, Firefox, and WebKit desktop; Chromium phone; Firefox narrow; and WebKit iPhone
  and iPad viewports.
- The real password-and-TOTP UI login, HttpOnly/SameSite session cookie, no-store/cache headers,
  CSP, Permissions Policy, X-Frame-Options, local/session storage restrictions, manual expense,
  deletion confirmation, responsive navigation, theme, and no-horizontal-overflow checks passed.
- Reflected query and fragment DOM-XSS probes remained inert in every project. Automated WCAG 2
  A/AA axe checks reported no violation on the dashboard, Debts, or Goals pages in any project.
- The Chromium, Firefox, and WebKit desktop projects passed keyboard skip-navigation, visible-focus,
  logical initial focus, and keyboard theme-activation checks. Phone, narrow Firefox, iPhone, and
  iPad layouts exposed primary navigation targets at least 44 CSS pixels high.
- The test browser received only a scoped mode-restricted copy of Alex's disposable password and
  TOTP seed. It never mounted the full secret/auth volumes. Screenshots, traces, video, and HTML
  reports were disabled; all synthetic state and Docker resources were removed after execution.
- This is a development baseline, not release-candidate or real-device evidence. Branded browser,
  assistive-technology, real iOS/iPadOS/Android, and remaining manual security passes are pending.

## 2026-08-24 synthetic ZAP baseline

- Unauthenticated: 8 spider URLs, 6 alert types, zero Automation Framework errors/warnings, and no
  High or Critical alert.
- MFA-authenticated Alex: protected audit-page probe returned 200; 640 spider URLs, 3 alert types,
  zero Automation Framework errors/warnings, and no High or Critical alert.
- MFA-authenticated Riley: protected audit-page probe returned 200; 774 spider URLs, 3 alert types,
  zero Automation Framework errors/warnings, and no High or Critical alert.
- Remaining informational observations were ZAP's modern-application classification, recognition of
  session-management responses, authentication-request recognition, user-agent fuzzing, and its
  potential user-controllable HTML-attribute heuristic. The active scan raised no server-side XSS
  finding. The separate browser-driven DOM-XSS baseline subsequently passed in every project.
- All test users, passwords, MFA seeds, sessions, database/media contents, containers, networks, and
  named volumes were generated for the run and removed afterward. Raw reports were reviewed locally,
  summarized here, and deleted after the secret scanner confirmed they contained ephemeral session
  material. They are not release evidence.
- This is a development baseline, not a completed release-candidate penetration-test report. Manual
  authorization, business-logic, audit-tampering, CSV, network, and real-device tests remain.
