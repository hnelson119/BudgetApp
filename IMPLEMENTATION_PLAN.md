# Household Budget Application — Implementation Plan

Status: Milestone 5 implementation, coverage hardening, and local PostgreSQL verification complete; private-ingress deployment verification pending
Last updated: 2026-08-23

## 1. Locked architecture

- Application: Python/Django monolith
- Database: PostgreSQL
- Frontend: server-rendered Django templates with HTMX and small Alpine-style interactions
- Styling: utility CSS with the approved dark/light design tokens
- Charts: lightweight browser charting library
- Dependency management: locked Python and frontend dependencies
- Packaging: Docker Compose
- Private ingress: HTTPS reachable only through Tailscale
- Background operations: scheduled Django management commands/systemd timers initially
- Test stack: Django/pytest-style tests plus Playwright browser coverage
- Production topology: reverse proxy, web application, PostgreSQL, and scheduled backup/integrity job

Exact supported runtime and package versions will be selected at scaffold time, recorded in lock files, and kept within upstream-supported releases.

## 2. Application modules

Suggested Django application boundaries:

- `identity`: users, membership, MFA, recovery, sessions
- `households`: household settings, timezone, categories
- `schedules`: recurrence rules, source revisions, occurrence generation
- `periods`: paycheck anchors, pay periods, closing/reopening
- `ledger`: accounts, journal entries/postings, transfers, reconciliation
- `budgets`: fixed items, variable budgets, overrides, dashboard calculations
- `spending`: manual transactions, category reporting, card-payment reserve
- `imports`: CSV staging, mappings, duplicate detection, commit
- `debts`: loans, APR rules, strategies, mortgage components/installments
- `goals`: contribution plans, priorities, progress, excess allocation
- `reserves`: Household Reserve and Credit-card Payment Reserve ledgers
- `audit`: append-only events, verification, checkpoints, exports
- `notifications`: in-app reminders and security alerts

Business calculations belong in explicit service/domain modules rather than views or templates.

## 3. Delivery milestones

### Milestone 0 — Repository and developer baseline

- Initialize repository structure and branch protections
- Add formatting, linting, type checking, test runner, secret scanning, and dependency scanning
- Add local environment template without real secrets
- Add architecture decision records and contribution/deployment documentation
- Establish database migration policy

Exit criteria: a clean checkout can run formatting and an empty test suite reproducibly.

Progress: the local repository structure, locked dependencies, documentation, migration policy,
quality/security checks, immutable-action CI workflow, and dependency-update configuration are
implemented. The private GitHub remote enforces read-only workflow tokens, GitHub-owned actions,
and full-SHA action pinning. The current free private-repository plan does not provide enforced
branch protection, so short-lived pull requests and passing checks remain an operational rule until
the repository moves to a plan that supports protection for private branches.

### Milestone 1 — Secure private deployment skeleton

- Create minimal Linux/Docker Compose deployment
- Configure private HTTPS and Tailscale-only ingress
- Configure host firewall expectations and non-root containers
- Create separate PostgreSQL runtime, migration, backup, and audit roles
- Add health checks without exposing sensitive data
- Implement encrypted backup and test-restore skeleton

Progress: the encrypted, off-VM Restic backup service and recovery-only restore verifier are
implemented and runtime-tested, with a daily systemd timer template. Private HTTPS/Tailscale
ingress remains deployment-time work for the Linux VM.

Exit criteria: a placeholder authenticated endpoint is reachable from an approved device and not reachable publicly or by an unapproved device.

### Milestone 2 — Identity, household, and audit foundation

- Create the first household and two separate users
- Implement password authentication, MFA, recovery codes, session controls, and logout-all-devices
- Implement equal household membership authorization
- Implement append-only audit writes in the same transaction as domain changes
- Implement hash-chain verification and external checkpoint job
- Add audit history UI foundation

Progress: distinct email/password identities, encrypted TOTP enrollment, hash-only single-use
recovery codes, generic and rate-limited authentication, idle/absolute session expiry,
logout-all-devices, sensitive-action reauthentication, trusted-console two-user provisioning and
emergency recovery, active-household authorization, and a canonical per-household SHA-256 audit
chain, PostgreSQL-owned protected schema and append function, isolated signed-checkpoint job, and
household-scoped read-only audit history are implemented with security tests. A clean PostgreSQL 17
rehearsal confirms runtime append isolation, direct audit-mutation denial, least-privilege role
flags, and signed-checkpoint verification. Private-ingress validation remains for the Linux VM.

Exit criteria: authentication/recovery tests pass; a sample domain mutation and audit event commit or roll back together; tampering fails verification.

### Milestone 3 — Accounts, ledger, and categories

- Add Checking, Savings, Cash, Credit Card, and Other account types
- Add balanced JournalEntry/JournalPosting services
- Add expense, income, transfer, debt-payment, goal, fee, and adjustment transaction builders
- Add manual balance snapshots and reconciliation variance
- Add category management

Progress: household-scoped accounts and categories, application- and PostgreSQL-protected append-only balanced entries/postings, audited
transaction builders, corrections through linked reversals, manual balance snapshots, reconciliation
variance, and net expense/category reporting are implemented. SQLite acceptance tests and a
rollback-only PostgreSQL runtime-role rehearsal confirm that transfers, goal contributions, and card
payments do not become categorized spending; card purchases do, exactly once.

Exit criteria: transfer and card-payment tests prove that spending is not double-counted.

### Milestone 4 — Scheduling and paycheck periods

- Implement the shared recurrence engine
- Implement immutable effective-dated source revisions
- Implement income anchors and paycheck-period generation
- Add weekend/holiday policy and boundary-difference confirmation
- Add occurrence generation, move, override, cancellation, and safe series deletion
- Add period closing, reopening, and reserve-delta corrections

Progress: deterministic structured recurrence rules, immutable effective-dated revisions,
same-day-deduplicated income anchors, half-open paycheck periods, preview-confirmed projection and
boundary changes, one-way occurrence generation, protected one-off changes, series cancellation,
period state transitions, and append-only closing/reserve corrections are implemented. Application
guards and PostgreSQL runtime-role triggers protect revisions and closing history from mutation and
prevent overlapping household periods. Golden, randomized boundary, rollback, authorization,
secret-rejection, and rollback-only PostgreSQL runtime rehearsals pass.

Exit criteria: paycheck-boundary and recurrence golden cases pass, including same-day anchors and schedule changes.

### Milestone 5 — Budget and dashboard vertical slice

- Add fixed expenses and variable category budgets
- Assign items to periods by due date
- Implement planned/actual status and reconciliation
- Implement current-period dashboard, upcoming bills, status, and unallocated excess
- Implement Household Reserve display and explicit allocation
- Implement mobile responsive navigation and light/dark themes

Progress: fixed-expense category metadata and preview-confirmed recurring schedule creation,
period-specific variable category budgets, grouped planned/actual budget rows, explicit
occurrence-to-ledger reconciliation, period-only edit/move/cancellation workflows, current-period
status and cash-flow calculations, upcoming bills, scheduled goal funding, recent transactions,
Household Reserve display/allocation, and previous/next paycheck navigation are implemented. Every
financial mutation is household-scoped and audited. Reconciliation and reserve history are
append-only in the application and protected from runtime-role mutation by PostgreSQL. Golden
calculation, authorization, deletion-confirmation, responsive-render, migration, and rollback-only
PostgreSQL runtime rehearsals pass.

The M5.1 hardening pass added rejection-path coverage for audit checkpoints, household selection,
ledger postings and snapshots, paycheck-boundary changes, period corrections, recurrence
configuration, and occurrence mutations. CI enforces at least 80% combined coverage and 80%
branch-only coverage, excluding migration modules that have dedicated migration and PostgreSQL
rehearsal tests.

Exit criteria: Golden cases A–D, I–N pass and the dashboard matches the approved information hierarchy.

### Milestone 6 — Spending, CSV, and credit cards

- Add manual transaction workflows
- Add Credit-card Payment Reserve
- Add refunds/reversals and debt-settlement allocation
- Implement CSV upload limits, staging, mapping, preview, duplicates, category review, and idempotent commit
- Implement formula-safe CSV exports

Progress: the manual-spending and credit-card reserve slices are implemented. Spending has a
responsive, household-scoped UI for manual expense, one-off income, card-payment entry, basic
financial-account setup, paycheck-period and all-history views, account/type/text filtering,
pagination, household-timezone display, idempotent form submissions, transaction detail with
balanced postings, and confirmed full refunds/reversals. Categorized card purchases now create
append-only payment-reserve entries; card payments consume that reserve first and classify only the
excess as current-income debt payoff. The dashboard, transaction detail, budget summary, and
scheduled-debt reconciliation preserve that separation, including refund/payment-reversal ordering.
Ledger, reserve, and audit history remain append-only in the application and protected by
PostgreSQL runtime-role triggers.
Multiple partial card refunds are now also implemented as append-only expense-refund entries. Each
refund links to the original purchase, cumulative service validation prevents over-refunding, and
the reserve correction releases only cash that remains reserved. Refunds after card settlement and
later payment reversals remain budget-neutral where appropriate. Expense CSV import is now also
implemented with bounded UTF-8 parsing, nonpersistent upload handling, mapping and preview, category-gap
review, cross-file and in-file duplicate fingerprints, household scoping, atomic/idempotent commit,
imported ledger provenance, audit events, and raw-row cleanup. Formula-safe transaction export is
also implemented. It mirrors the current household-scoped pay-period/all-history filters, requires
recent password-plus-MFA verification, verifies audit integrity before generation, streams directly
without a temporary file, preserves Decimal amounts as numeric cells, neutralizes untrusted formula-like
text, and appends an export-scope audit event without retaining the file or transaction contents.

Status: the code-deliverable portions of Milestone 6 are complete and locally verified.

Exit criteria: Golden cases E–G pass; malformed/import security tests pass; repeating an import does not duplicate transactions.

### Milestone 7 — Debts and split mortgage

- Implement debt accounts, APR/compounding models, and statement reconciliation
- Implement minimum-only, snowball, avalanche, and custom payoff strategies
- Implement mortgage principal/interest, escrow, PMI, fees, and extra-principal components
- Implement two monthly mortgage installment rules totaling one obligation
- Sync installment occurrences one way into Budget

Progress: the debt-account and payoff-comparison vertical slice is implemented. Household members
can create and maintain debts, optionally link one liability account, append effective-dated APR,
interest-method, minimum-payment, recurring-extra, due-day, and custom-priority revisions, and
reconcile lender statements without rewriting history. Statement records preserve principal,
interest, fees, escrow, PMI, and extra principal as distinct values; corrections append a linked
replacement while retaining the original. Application service guards and PostgreSQL triggers
protect terms and statements from ordinary mutation or deletion. The shared exact-Decimal engine
compares minimum-only, snowball, avalanche, and custom ordering, supports monthly and actual-day
interest, applies future terms by effective date, and rolls freed scheduled payments beginning in
the next modeled cycle. Responsive, MFA-protected, household-scoped debt screens and confirmation-
gated archiving are covered by integration tests. The split-mortgage persistence, installment
schedule, and one-way Budget synchronization remain in progress.

Exit criteria: Golden case H and debt projection comparison tests pass; escrow never reduces principal.

### Milestone 8 — Goals and automatic allocation

- Implement saving, payoff, and investing goals
- Implement recurring contributions, target dates, priority ordering, and progress
- Keep automatic excess allocation off by default
- Implement explicit and optional automatic Household Reserve allocations

Exit criteria: goal contribution and reserve-allocation tests pass without creating income or categorized spending.

### Milestone 9 — Notifications and complete audit UI

- Add due/overdue, missing paycheck, deficit, milestone, backup, login, and integrity alerts
- Complete protected audit filters, details, verification status, and export
- Audit detailed audit access and exports

Exit criteria: alert and audit-access tests pass; no UI path offers audit mutation or deletion.

### Milestone 10 — Release hardening

- Complete OWASP ASVS review with documented applicability
- Complete security, accessibility, responsive, and supported-browser test matrices
- Run dependency, image, source, and secret scans
- Build a production-like penetration-test environment containing synthetic data
- Run repeatable authenticated and unauthenticated OWASP ZAP automation
- Complete manual authorization, session, CSV, financial business-logic, audit-tampering, and network-boundary tests
- Remediate and retest every critical/high finding and document disposition of lower-severity findings
- Perform quarterly-style restore rehearsal and audit-checkpoint comparison
- Perform lost-device and credential-rotation exercise
- Document upgrades, rollback, backup, restore, and incident response

Exit criteria: every release gate in this plan passes with no unresolved critical defect.

## 4. Browser support and test matrix

### Desktop

- Current and previous major Microsoft Edge
- Current and previous major Google Chrome
- Current and previous major Mozilla Firefox
- Current Safari where macOS testing is available

### Mobile/tablet

- Current Safari on supported iPhone and iPad devices
- Current Firefox on iPhone and iPad
- Current Chrome on Android
- Current Firefox on Android

### Automated coverage

- Chromium engine at desktop and phone/tablet viewports
- Firefox engine at desktop and narrow responsive viewports
- WebKit engine at desktop and iPhone/iPad viewports

At least one manual smoke pass is required on real or hosted iPhone/iPad Safari and Firefox, and Android Chrome and Firefox when those platforms are available. Browser support must not weaken security-cookie, CSRF, CSP, cache, or storage controls.

## 5. Test strategy

### Unit tests

- Recurrence and boundary generation
- Exact Decimal calculations and rounding
- Reserve calculations
- Ledger balancing and transaction builders
- Debt amortization and strategy ordering
- CSV normalization and fingerprints
- Audit canonicalization and hash verification

### Property and boundary tests

- Non-overlapping pay periods across randomized anchor schedules
- Source revisions never rewrite protected occurrence states
- Ledger postings always balance
- Reserve balances equal append-only entry sums
- Mortgage installments equal their configured obligation
- Idempotent import retries produce no duplicate committed transactions

### Integration tests

- Authentication, MFA, recovery, and session revocation
- Household-scoped authorization
- Source-to-occurrence one-way synchronization
- Period close/reopen/reserve delta
- Actual transaction reconciliation
- Audit/domain transactional atomicity
- Backup/restore and audit checkpoint validation

### Browser tests

- Navigation and theme
- Dashboard and budget editing
- Schedule preview and deletion confirmation
- Manual transaction and CSV import
- Debt strategy and goal priority interactions
- Audit filtering/details
- Keyboard accessibility and narrow-screen behavior

### Security tests

The release must pass all requirements in `SECURITY_PLAN.md` section 17.

## 6. Definition of done for each feature

A feature is complete only when:

- Product acceptance criteria are implemented.
- Authorization and household scoping are enforced server-side.
- Material writes generate protected audit events transactionally.
- Unit and integration tests cover success, failure, and edge cases.
- Responsive and keyboard behavior is verified.
- Firefox, Chromium, and WebKit automated coverage remains green where applicable.
- No new critical security, dependency, or secret-scan finding is introduced.
- User-facing help/error text explains destructive or irreversible effects.
- Database migrations are reversible when technically safe or include a documented recovery path.
- Operational, backup, and restore implications are documented.

## 7. Initial infrastructure checklist

### Hyper-V host

- Windows and Hyper-V fully updated
- BitLocker enabled on the VM storage volume and recovery key stored safely
- Secure Boot and host firewall enabled
- Host configured not to sleep when remote availability is required
- Backup destination available outside the VM
- Optional UPS considered for graceful shutdown during power failures

### Linux VM starting profile

- 2 virtual CPUs
- 4 GB RAM
- At least 40 GB dynamically allocated storage with monitored free space
- Supported minimal Linux server installation
- Accurate timezone and time synchronization
- Automatic security updates or documented patch routine
- Tailscale installed with device approval
- Linux firewall default-deny inbound

### Private service setup

- Neutral Tailscale hostname selected
- HTTPS certificate/private endpoint configured
- Only application HTTPS permitted to household devices
- SSH restricted to administrative devices and keys
- PostgreSQL and Docker API not published

### Backup setup

- Daily encrypted database destination selected
- Version history confirmed
- Independent/disconnected backup location selected
- Restore credentials and decryption keys stored separately
- External audit-checkpoint destination selected
- Quarterly restore reminder documented

## 8. Release gates

The first household-data release requires:

1. Product criteria 1–39 passing
2. Security tests in `SECURITY_PLAN.md` passing
3. Golden calculation cases in `CALCULATION_RULES.md` passing
4. No unresolved critical/high vulnerability without explicit documented acceptance
5. Successful Firefox, Chromium, and WebKit browser suites
6. Successful real-device mobile smoke testing where available
7. Successful encrypted backup and clean restore
8. Restored audit chain matching the external checkpoint
9. Lost-device and account-recovery rehearsal
10. Deployment and rollback instructions validated from a clean VM snapshot
11. Completed penetration-test report with no unresolved critical/high finding
12. Successful retest evidence for every remediated penetration-test finding

## 9. Remaining setup-time inputs

These values are configuration data, not unresolved product-design decisions:

- Final application/household display name
- Actual paycheck amounts and anchor schedules
- Mortgage installment dates and component amounts from the lender statement
- Account labels and opening balance snapshots
- Initial debts, APRs, compounding information, and minimums
- Categories, bills, goals, and opening Household Reserve
- VM hostname, backup destinations, and recovery-key storage location

They can be entered during onboarding or deployment and do not block scaffolding the application.
