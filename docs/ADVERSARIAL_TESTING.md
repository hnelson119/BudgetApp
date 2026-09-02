# Manual adversarial testing

Status: procedure and evidence format implemented; no manual run is recorded yet

Last updated: 2026-08-31

## Purpose

This runbook turns the manual coverage in `SECURITY_PLAN.md` section 18 into a fixed, reviewable
release test. The catalog in `docs/adversarial-test-matrix.json` binds every scenario to a target,
the applicable local security-test identifiers, a procedure below, and published OWASP Web Security
Testing Guide (WSTG) identifiers reviewed on the date above. Business-specific audit and budgeting tests also carry the
closest WSTG integrity or workflow identifiers, but their pass conditions come from this project's
security and calculation rules.

Automated unit, browser, and ZAP results can support an investigation; they do not count as this
manual test. A passing record means a tester actually exercised every scenario assigned to that
target against the named commit.

The guarded `scripts/run-authz-csrf.ps1` and `scripts/run-authz-csrf.sh` helpers execute repeatable
real-HTTP and database-invariant checks for `AUTHZ-01` through `AUTHZ-04`. Their sanitized output is
supporting evidence only: it does not create a run record, does not advance the target count, and
does not replace the tester's review of logs, errors, route coverage, or registered findings.

The equally guarded `scripts/run-session-security.ps1` and `scripts/run-session-security.sh`
helpers supply real-HTTP, browser, and controlled server-side boundary observations for implemented
parts of `SESS-01` through `SESS-05`. They have the same supporting-evidence limitation. In
particular, they now exercise the self-service password-change and active-session inventory/revoke
controls plus generic, rate-limited forgotten-password recovery with session revocation and a fresh
MFA requirement. A maintained offline breached-password corpus is still absent. Supporting
logout-all, recovery, and administrative checks must not be reported as a completed manual target.

The guarded `scripts/run-csv-security.ps1` and `scripts/run-csv-security.sh` helper exercises
repeatable real-HTTP and PostgreSQL invariants for `CSV-01` through `CSV-04`, including two-member
concurrency and the staging-expiry boundary. Its sanitized counts are supporting evidence only and
do not replace spreadsheet-client observation, resource/log review, or a complete target record.

## Safety and data boundaries

- Use only disposable synthetic households, credentials, financial records, files, and audit data.
- Never run destructive, high-volume, tampering, or concurrency tests against the household's real
  instance. Database tampering is permitted only in the disposable PostgreSQL target.
- Fix the target commit, target environment, approved test window, request-rate ceiling, and test
  accounts before starting. Do not probe third-party services or hosts.
- Keep raw requests, responses, payloads, scanner sessions, cookies, database output, hostnames,
  addresses, and screenshots under the ignored `security-reports/` directory or in an encrypted
  assessment location outside the repository. Delete ephemeral material after review.
- Record only a concise outcome and registered finding identifiers in Git. Do not include real or
  synthetic secrets, reusable attack strings, internal infrastructure identifiers, or financial
  values in a run record.
- Stop a scenario if it could cross the agreed boundary, affect a non-test system, or exhaust the
  host. Mark it `blocked` and explain the sanitized reason.

## Targets and prerequisites

### Disposable synthetic application

Use the production-derived disposable stack. The fixture must contain two MFA-enabled users in one
synthetic household, a user and records in a second synthetic household, representative budgets,
paycheck-anchored periods, card activity, split mortgage payments, goals, debts, and CSV import
history. The standard harness generates a protected, ephemeral UUID-only fixture manifest and must
pass `python manage.py verify_pentest_fixture` before testing; do not copy the manifest into a run
record. Exercise the real HTTP/browser boundary. Development runs may use an equivalent isolated
local stack; release runs use the selected candidate's production-like profile.

### Protected synthetic PostgreSQL runtime

Use disposable PostgreSQL with the real migration/runtime role split, protected audit schema, and
synthetic audit plus financial rows. Take a disposable snapshot before testing. The tester may use
an administrative test role only to create controlled corruptions and restore the snapshot; the
application runtime role is the subject of the permission test.

### Private Linux VM ingress

This target is release-only. Use the release-like Linux VM, its intended private ingress and TLS
configuration, one approved test device, and one unapproved test device. Do not substitute Docker
loopback for this target: loopback cannot prove Tailscale policy, host firewall behavior, TLS, or
household-device isolation.

## Execution and evidence workflow

1. Confirm the target contains synthetic data only and record the full 40-character commit under
   test. For a release run, set `release_candidate` in `docs/adversarial-test-matrix.json` to that
   commit before adding the evidence record.
2. Exercise every scenario assigned to one target. Preserve raw material only in the restricted
   temporary assessment location.
3. Add every observed security defect to `docs/SECURITY_FINDINGS.md` before referencing its
   identifier from a failed scenario. Do not erase an earlier finding or run after remediation.
4. Add one JSON record to `docs/adversarial-test-runs/`. Use
   `YYYY-MM-DD-target-shortsha.json`; a same-day repeat appends `-r2`, `-r3`, and so on. A replacement
   points `supersedes` to the earlier run, while the earlier file remains intact.
5. Run `python scripts/check_adversarial_test_evidence.py`. This validates structure, exact scenario
   coverage, finding references, derived status, candidate binding, and supersession history.
6. For the final release decision, run
   `python scripts/check_adversarial_test_evidence.py --require-complete`. It fails until each of the
   three targets has one active passing record for the selected release candidate.
7. Review the pull request and machine checks before accepting evidence. Git history plus protected
   branch review provides change detection and accountability; repository administrators can still
   rewrite Git history, so this is not represented as an immutable external evidence store.

Each record contains exactly: `schema_version`, `run_id`, `target_id`, `purpose`, `tested_at`,
`candidate_commit`, `tester_role`, `environment_summary`, `synthetic_data_only`, `overall_status`,
`scenario_results`, and `supersedes`. Each scenario result contains `id`, `status`, one-line
sanitized `notes`, and `finding_ids`. Valid scenario states are `passed`, `failed`, `blocked`, and
`not_run`; the validator derives the overall state and rejects a failed scenario without a finding.

## Authorization procedures

<a id="authz-01"></a>
### AUTHZ-01 — Cross-household direct-object isolation

- From each route or form that accepts an object identifier, replace a first-household identifier
  with the same object type from the second household, including list, detail, edit, delete, export,
  and asynchronous endpoints.
- Repeat using both household roles and identifiers in URL paths, query strings, form fields, and
  any client-supplied relationship fields.
- Pass only if no existence, value, metadata, side effect, or distinguishable error leaks across
  the household boundary and the attempt is safely logged where required.

<a id="authz-02"></a>
### AUTHZ-02 — Role, function, and administrative endpoint enforcement

- Enumerate protected functions from navigation, route definitions, and observed requests, then
  request higher-privilege, hidden, staff, framework-administration, and alternate-method variants
  directly with each synthetic role.
- Try the operation after removing UI controls from the path and by changing the HTTP method where
  the route accepts more than one method.
- Pass only if server-side authorization rejects every disallowed function without exposing an
  administrative interface or performing a partial write.

<a id="authz-03"></a>
### AUTHZ-03 — Mass-assignment and protected-field enforcement

- Add unrendered ownership, household, actor, status, audit, calculated-total, and privilege fields
  to representative create and edit submissions.
- Attempt relationship reassignment to another household and edits to server-derived values.
- Pass only if protected values are ignored or rejected, no cross-household relationship changes,
  and accepted fields remain consistent with server-side calculations.

<a id="authz-04"></a>
### AUTHZ-04 — Cross-site request forgery rejection on state changes

- Inventory every state-changing route for budgets, spending, income, debts, goals, imports,
  identity, notifications, and administrative actions.
- Replay each representative operation with a missing token, an invalid token, a token from another
  session, and an unsafe cross-origin request context.
- Pass only if each attempt fails before a write, does not rotate into an authenticated state, and
  does not weaken the cookie or origin boundary.

## Session and identity procedures

Run the guarded session helper against a fresh disposable stack before the manual review. Retain
only its sanitized scenario/count output with the restricted assessment notes. Complete the
unautomated recovery, deployed TLS, browser-family, active-session-management, logging, and restart
observations below before recording any scenario as passed.

<a id="sess-01"></a>
### SESS-01 — Identity enumeration, throttling, and recovery-safe responses

- Compare status, body, redirects, and practical timing for known and unknown identifiers across
  login, MFA, recovery, invitation, and other identity entry points.
- Exercise the documented low-rate threshold from distinct sessions without attempting service
  exhaustion, then verify the recovery path does not disclose credentials, MFA material, or account
  existence.
- Pass only if responses remain enumeration-resistant, throttling activates as designed, valid
  recovery remains usable, and security logs contain no submitted secret.

<a id="sess-02"></a>
### SESS-02 — Session fixation prevention and identifier rotation

- Capture only the presence and fingerprint of pre-authentication state in restricted evidence,
  authenticate through password and MFA, and compare identifiers after each trust transition.
- Repeat around recent-authentication gates and any identity or MFA change.
- Pass only if attacker-chosen or pre-authentication state cannot become an authenticated session
  and the server rotates identifiers at each required trust transition.

<a id="sess-03"></a>
### SESS-03 — Session replay rejection after revocation events

- Establish two synthetic sessions, preserve a restricted replay copy, then exercise sign-out,
  sign-out-all, password recovery/change, MFA reset, user disablement, and membership removal where
  implemented.
- Replay the prior state against multiple security-sensitive endpoints after each event.
- Pass only if the intended sessions are invalidated server-side, replay cannot regain access, and
  browser history does not reveal authenticated content.

<a id="sess-04"></a>
### SESS-04 — Idle, absolute, and concurrent-session boundaries

- Measure idle and absolute expiration without changing client clocks or client-side fields; probe
  protected pages just before and after each server-side boundary.
- Exercise concurrent sessions from two clients and confirm the documented session policy remains
  visible and enforceable.
- Pass only if expired state is unusable, activity cannot extend an absolute limit, and concurrent
  behavior matches the documented design without exposing another session's data.

<a id="sess-05"></a>
### SESS-05 — Cookie, browser-storage, and authenticated-cache boundaries

- Inspect authentication cookies and browser storage before, during, and after authentication in
  each supported browser family; check paths, domain scope, expiry, `Secure`, `HttpOnly`, and
  `SameSite` behavior at the real TLS boundary.
- Inspect authenticated response cache directives, navigate back after sign-out, and test a normal
  shared-device restart without accepting password-manager storage.
- Pass only if reusable credentials and household data are absent from script-readable storage,
  cookies have the required scope and flags, and cached authenticated content is not recoverable.

## CSV procedures

<a id="csv-01"></a>
### CSV-01 — Oversized, malformed, and unexpected upload rejection

- Submit files just below and above documented size/row limits, invalid encodings, truncated and
  inconsistent rows, missing headers, extra columns, non-CSV content, and safe high-complexity
  samples below the agreed resource ceiling.
- Observe validation, memory/CPU behavior, transaction boundaries, logs, and cleanup.
- Pass only if invalid content is rejected without partial imports, unsafe interpretation, secret
  leakage, persistent temporary files, or disproportionate resource consumption.

<a id="csv-02"></a>
### CSV-02 — Spreadsheet-formula neutralization on import and export

- Import synthetic text beginning with each spreadsheet formula trigger supported by the threat
  model, then export transaction and audit CSVs after completing required reauthentication.
- Review the resulting cells as text without enabling external links, macros, or active content.
- Pass only if imported content is never executed, exports neutralize every dangerous leading
  character, streaming leaves no retained server file, and the audit export records its boundary.

<a id="csv-03"></a>
### CSV-03 — Duplicate-batch and replay idempotency

- Submit an identical file twice, retry during confirmation, refresh/replay a completed submission,
  and attempt a concurrent confirmation using two clients.
- Compare imported rows, ledger effects, batch state, and audit history.
- Pass only if one logical batch produces one set of effects, retries are safely recognized, and no
  duplicate or partial financial write occurs.

<a id="csv-04"></a>
### CSV-04 — Filename, content, and abandoned-upload cleanup boundaries

- Use harmless filenames containing traversal-like segments, alternate separators, misleading
  extensions, long names, and control-character edge cases supported by the client.
- Abandon, reject, and complete imports while observing only the disposable storage boundary.
- Pass only if filenames cannot select a path or executable context, content determines validation,
  and rejected or abandoned data is removed under the documented retention policy. Confirm that an
  unfinished batch older than 24 hours is scrubbed by the maintenance job while a newer batch is
  retained, and that expiry leaves one protected system audit event without raw cells.

## Financial-logic procedures

<a id="fin-01"></a>
### FIN-01 — Credit-card payment, refund, and reserve double-counting resistance

- Build a synthetic period containing card purchases, a payment from cash, partial and full refunds,
  reversals, and a card-payment reserve.
- Reorder entry and reconciliation, move eligible items across adjacent periods, and repeat a safe
  submission retry.
- Pass only if purchases, payment transfers, refunds, cash availability, and debt balance appear
  exactly once in the correct totals and the invariant checks remain satisfied.

<a id="fin-02"></a>
### FIN-02 — Negative, excessive, and unallocated amount handling

- Attempt negative, zero, over-income, over-available, excessive goal/debt, and precision-edge
  allocations through both visible fields and modified requests.
- Leave valid income intentionally unallocated and compare the dashboard, ledger, and goal state.
- Pass only if invalid values are rejected atomically, precision is deterministic, and valid excess
  remains visibly unallocated rather than disappearing or being silently assigned.

<a id="fin-03"></a>
### FIN-03 — Pay-period boundary moves and closed-period corrections

- Use income schedules whose paycheck arrivals define non-calendar-week boundaries, then place and
  move obligations at the instant before, on, and after a boundary.
- Exercise the default due-date assignment, an explicit move, close, correction/reopen workflow,
  and schedule change that affects future periods.
- Pass only if periods remain paycheck-to-paycheck, historical decisions remain auditable, closed
  periods reject unauthorized edits, and future schedule changes do not rewrite history.

<a id="fin-04"></a>
### FIN-04 — Split mortgage schedule and extra-principal correctness

- Configure two monthly mortgage payments whose sum equals the contractual amount, including month
  boundaries, a short month, and pay-period reassignment.
- Record a larger payment with an extra-principal component and compare the budget occurrence, debt
  balance, interest, and payoff projection.
- Pass only if both scheduled parts populate once, the full monthly obligation is represented, and
  the one-off larger payment changes actuals/projections without rewriting the recurring schedule.

<a id="fin-05"></a>
### FIN-05 — Concurrent submission, retry, and replay resistance

- From two clients, submit the same and conflicting budget, spending, debt-payment, goal-allocation,
  and period-move operations at a controlled low rate.
- Include browser retry and stale-form cases while observing transaction, ledger, and audit results.
- Pass only if writes are atomic, uniqueness/idempotency rules prevent duplicate effects, conflicts
  fail visibly, and every accepted financial change has exactly one consistent audit history.

## Audit-integrity procedures

<a id="audit-01"></a>
### AUDIT-01 — Runtime-database credential mutation denial

- In disposable PostgreSQL, connect with exactly the application's runtime database role and try
  update, delete, truncate, ownership, trigger, and protected-schema changes against audit records.
- Confirm normal application writes can still append through the approved database function.
- Pass only if direct mutation and privilege changes are denied by PostgreSQL while legitimate
  append behavior remains available and least-privileged.

<a id="audit-02"></a>
### AUDIT-02 — Mutation, removal, and chain-splice detection

- Snapshot disposable data, then use the administrative test role to create one controlled field
  mutation, removal, reordering/chain splice, and forged-link case at a time.
- Run the application and offline chain verifiers after each corruption, then restore the snapshot.
- Pass only if every corruption fails verification visibly at or before its affected sequence and
  no verifier silently repairs or normalizes the evidence.

<a id="audit-03"></a>
### AUDIT-03 — Financial rollback when protected audit append fails

- In the disposable target, induce a bounded audit-append failure without weakening production
  code, then attempt representative budget, spending, debt, goal, import, and period writes.
- Compare all application, ledger, and audit rows after each transaction.
- Pass only if the financial transaction rolls back completely, the user receives a safe failure,
  and no partial state or secret-bearing diagnostic is left behind.

<a id="audit-04"></a>
### AUDIT-04 — Checkpoint substitution, staleness, and restore-mismatch detection

- Create an external signed checkpoint for disposable data, then separately test a stale checkpoint,
  a checkpoint from another synthetic history, a modified checkpoint, and a backup restored behind
  or ahead of the expected sequence.
- Run the documented checkpoint and restore verification without replacing the trusted key source.
- Pass only if substitution, invalid signatures, rollback, and sequence mismatch fail visibly while
  the matching checkpoint and restored chain verify successfully.

## Network-boundary procedures

Run `scripts/run-network-boundary.ps1` (or the Linux `.sh` equivalent) for the production-derived
pre-deployment controls, then follow `docs/PRIVATE_INGRESS.md` on the real Linux VM. The local probe
is supporting development evidence only. The VM preflight still cannot substitute for the
approved- and unapproved-device observations required by `NET-01` and `NET-02`.

<a id="net-01"></a>
### NET-01 — Unapproved-device reachability denial

- From a test device that is not approved by the private-network policy, attempt name resolution and
  connection only to the documented application address and expected service ports.
- Do not broaden discovery beyond the owned VM and agreed scope.
- Pass only if the device cannot establish an application, proxy, database, SSH, or administrative
  session and the failure does not reveal a bypass route.

<a id="net-02"></a>
### NET-02 — Approved-device least-privilege service reachability

- From each intended approved-user policy role, connect to the budget service and perform narrowly
  scoped discovery against the owned VM's documented port set.
- Verify that device approval alone does not grant shell, database, metrics, container, or proxy
  administration access.
- Pass only if the expected HTTPS budget service is reachable and all non-required services remain
  denied by both private-network policy and host firewall.

<a id="net-03"></a>
### NET-03 — HTTPS redirect, HSTS, TLS, and secure-cookie boundary

- Request the deployment over HTTP before authentication, follow redirects, and inspect TLS,
  certificate identity, HSTS, cookie flags, and authenticated endpoints over the deployed ingress.
- Attempt direct access to upstream/container HTTP from the approved client without crossing scope.
- Pass only if HTTP never serves authenticated content, the public private-network boundary uses the
  approved TLS configuration, cookies remain secure, and the upstream is not client-reachable.

<a id="net-04"></a>
### NET-04 — Database and administrative-port isolation

- From approved and unapproved test devices, attempt connection only to the VM's documented database,
  SSH, metrics, container-engine, and reverse-proxy administrative ports.
- From the application container, confirm only required database connectivity and credentials are
  available.
- Pass only if household clients cannot reach PostgreSQL or administrative services, published ports
  match the allowlist, and the app cannot use migration/owner privileges.

<a id="net-05"></a>
### NET-05 — Host, forwarded-header, cache, and error-leakage resistance

- Send safe alternate `Host` and forwarded-origin/scheme values through the real proxy, request
  malformed routes and validation failures, and inspect redirects, error pages, and cache headers.
- Repeat representative authenticated responses through browser back/refresh behavior.
- Pass only if untrusted headers cannot alter authorization, generated links, redirects, or secure
  scheme decisions; errors expose no internals or secrets; and authenticated data is never cached.

<a id="net-06"></a>
### NET-06 — Runtime privilege and secret-leakage inspection

- Inspect the deployed container user, capabilities, mounts, filesystem mode, environment names,
  process arguments, image history, health output, logs, diagnostics, backup metadata, and temporary
  paths using authorized administrative access.
- Search restricted local output for credential values or household data without copying matches
  into the repository.
- Pass only if containers run with documented least privilege, secrets are not embedded or printed,
  logs and backup metadata contain no reusable credential or financial payload, and sensitive files
  have the intended ownership and mode.

## References

- OWASP Web Security Testing Guide, current index:
  https://owasp.org/www-project-web-security-testing-guide/latest/
- Required local security tests: `SECURITY_PLAN.md#17-required-security-tests`
- Penetration-test scope and exit criteria:
  `SECURITY_PLAN.md#18-penetration-testing-and-adversarial-validation`
- Sanitized finding register: `docs/SECURITY_FINDINGS.md`
- Disposable ZAP harness: `docs/PENTESTING.md`
