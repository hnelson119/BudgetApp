# Household Budget App

A private, paycheck-anchored budgeting application for a two-person household.

The application foundation is now runnable. It includes a responsive dark-first
interface, an email-based custom user model, shared households, manual financial
accounts, an append-only double-entry ledger, PostgreSQL-ready production settings,
Docker deployment files, health checks, and tested core money rules.

## Current milestone

The code-deliverable portions of Milestones 0 through 9 are complete and locally verified. The
private GitHub remote, read-only quality workflow, SHA-pinned GitHub-owned action policy, and
Dependabot alerts are active. Enforced branch protection remains unavailable on the current free
private-repository plan, so short-lived pull requests and passing checks remain an operational rule.
Identity, MFA, recovery, household authorization, protected audit history, manual accounts,
categories, database-protected committed ledger history, reversals, balance reconciliation,
structured recurrence, immutable schedule revisions, paycheck-anchored periods, occurrence
overrides, append-only period-closing reserve corrections, fixed-expense schedules, variable
category budgets, planned/actual reconciliation, responsive paycheck-period dashboard, and
explicit Household Reserve allocation are implemented. The local PostgreSQL
rehearsal passes with the dedicated migration identity and least-privilege runtime role, including
database rejection of history tampering, reconciliation mutation, and overlapping periods.
The code-deliverable portions of Milestone 6 are complete. Its manual-spending and credit-card
slices add responsive,
paycheck-period-scoped transaction history; manual expense, one-off income, and card-payment entry;
basic checking, savings, cash, credit-card, and other account setup; duplicate-submit protection;
confirmed full refunds/reversals; and an append-only Credit-card Payment Reserve. Card payments
consume reserved purchase money first and expose only any excess as current-income debt payoff,
preventing double-counted spending. The reserve is separately visible on the dashboard and its
history is protected from runtime-role mutation in PostgreSQL. Append-only partial card refunds are
also implemented, including multiple-refund limits, category/liability corrections, and
refund-aware reserve reallocation. Hardened expense CSV import now provides bounded, nonpersistent
UTF-8 upload parsing, column/sign/date mapping, preview-only staging, category gaps, normalized duplicate detection,
atomic and idempotent confirmation, import provenance, and raw-row cleanup. Staged raw cells are
automatically scrubbed after 24 hours by an hourly least-privilege maintenance
job, even when a member leaves an import unfinished; expiry appends a protected system audit event.
Transaction CSV export now mirrors the selected pay-period or all-history filters, requires recent reauthentication,
verifies audit integrity, streams without temporary files, preserves numeric amounts, neutralizes
spreadsheet-formula text, and records the export scope in protected audit history. Milestone 7 adds
household-scoped debt accounts, immutable effective-dated APR and
payment terms, append-only lender-statement reconciliation and correction, and exact-Decimal
minimum-only, snowball, avalanche, and custom payoff comparisons. Its completed split-mortgage
workflow stores protected effective-dated payment components, enforces exactly two monthly
installments, assigns each installment to the paycheck period containing its due date, and supports
period-only moves, edits, and extra-principal overrides without changing future schedules. Mortgage
projections amortize principal-and-interest and extra principal while keeping escrow, PMI, and fees
out of principal reduction. Milestone 8 adds protected Savings, Debt Payoff, and Investing goals;
paycheck-period-based recurring funding; target dates, priorities, status revisions, progress and
completion projections; actual transfer/debt-payment recording; and preview-confirmed Household
Reserve allocation. Automatic excess eligibility is off by default, and priority batches remain
explicitly confirmed. Reserve-funded goal activity is excluded from current-paycheck actuals to
prevent double counting.
Milestone 9 adds optional per-person in-app alerts for upcoming and overdue bills, missing
paychecks, negative period projections, goal milestones, verified-backup freshness, authenticated
sessions, repeated login failures, and audit-integrity/checkpoint problems. A least-privilege
maintenance container evaluates alerts every 30 minutes without receiving backup or audit signing
secrets. The audit interface now provides household-scoped filters, paginated read-only details,
human-readable before/after differences, current verification/checkpoint status, and streamed
formula-safe CSV export. Detailed audit access and exports append their own protected events;
exports require recent password-plus-MFA verification and fail closed if chain verification fails.
Milestone 10 is now in progress. Its release-hardening baseline adds a machine-validated mapping of
all 253 OWASP ASVS 5.0.0 Level 1/2 requirements, the security-test and release-gate inventories, and
a pinned Trivy container scan that fails CI on high or critical release-image vulnerabilities.
The Account Security screen now supports current-password-verified password changes, opaque
active-session review, recent-authentication-protected individual or all-session revocation, and
protected audit events without retaining session identifiers or submitted passwords. Public
forgotten-password recovery requires an existing authenticator or unused recovery code, returns a
generic result for every submitted identity, revokes all prior sessions, never signs the requester
in, and requires fresh MFA after the replacement password. New and changed passwords also reject
documented application-name permutations and a maintained, hash-only breached-password corpus
without making password-derived network requests. Hardened processes validate the packaged corpus
and its freshness at startup; the provenance and offline update procedure are in
`docs/PASSWORD_BLOCKLIST.md`. A guarded trusted-console operation can independently revoke one
account or every account without resetting credentials; it rotates server-side session versions,
removes stored authenticated and pending-MFA sessions, and writes protected household audit events.
The maintained cryptographic inventory assigns explicit owners, algorithms, consumers, permitted
and prohibited uses, protected and excluded data, rotation, and retirement to application,
deployment, provider-managed, and test-only cryptographic boundaries. Production PostgreSQL now
requires TLS 1.2 or TLS 1.3, exact internal-CA and `db` hostname verification, and hard plaintext TCP
rejection; the still-HTTP nginx-to-Gunicorn hop remains explicitly open. See
`docs/CRYPTOGRAPHIC_INVENTORY.md` and `docs/POSTGRES_TLS.md`.
The maintained logging inventory documents events, formats, destinations, operational uses,
readers, retention, sensitive-data rules, and limitations across all 14 current stack layers. Its
quality-gate validator derives 149 stable event entries from source and verifies bounded Docker
logging plus the separate networkless security-log collector. Django can write only through a
read-only-mounted Unix socket and cannot access the collector-only archive volume; see
`docs/LOGGING_INVENTORY.md`.
The maintained CycloneDX SBOM derives 83 third-party production, development, build, test, and CI
inputs from exact locks and pins, restricts them to six approved repository services, and is checked
for drift on every quality run. CI also retains image-resolved SBOMs for all three release images;
see `docs/SBOM.md`.
See
`docs/RELEASE_HARDENING.md` for the honest current status and evidence-handling rules. The guarded
production-derived network probe and Linux VM runbook are in `docs/PRIVATE_INGRESS.md`; actual
Tailscale HTTPS, firewall/device checks, and provisioning the two real household accounts remain
deployment-time work on the Linux VM before household financial data is entered.
An isolated restore profile now runs the production backup and restore scripts against synthetic
PostgreSQL data, scans encrypted repository storage for known plaintext and generated secrets,
proves stale signed checkpoints fail, and verifies the restored multi-household fixture and complete
audit chains. CI also scans the independently built backup/restore image; the quarterly release-
candidate restore on the real VM remains a required deployment gate.
A separate upgrade profile checkpoints and backs up the baseline, applies a test-only additive
migration with the dedicated migration role, proves candidate and previous-app health on the forward
schema, and restores the pre-upgrade snapshot into a new database for clean rollback verification.

## Local development

Prerequisites: Python 3.12 and Git. PostgreSQL is not required for the fast local
test configuration.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.lock
python -m pip install --no-deps -e .
python manage.py migrate
python manage.py runserver
```

Open `http://127.0.0.1:8000/`. Run all local checks with:

```powershell
.\scripts\check.ps1
```

On Linux or macOS, activate `.venv/bin/activate` and use `./scripts/check.sh`.

### First household provisioning

After migrations, create the household and exactly two individual accounts from a trusted console.
Passwords are prompted without echo and are never accepted as command-line arguments, environment
variables, or configuration values. The same context-specific and offline breached-password policy
used by self-service password changes applies to this command:

```powershell
python manage.py bootstrap_household `
  --household-name "Our Household" `
  --user-email "first@example.com" --display-name "First person" `
  --user-email "second@example.com" --display-name "Second person"
```

Each person is restricted to MFA enrollment at first login. TOTP seeds are encrypted with the
separate `django_mfa_encryption_key` secret; recovery codes are displayed once and only salted
password hashes are retained. The sign-in screen's recovery flow accepts a current authenticator
code or one unused recovery code and never bypasses the next MFA challenge. If an authenticator and
all recovery codes are lost, a VM
administrator can run the interactive `reset_user_mfa <email> --reason "..."` command. That reset
revokes every session, invalidates the old seed and codes, and creates a protected audit event.

### Local Docker verification on Windows

Docker Desktop should use its per-user WSL 2 backend with Linux containers. The bounded command
below creates random temporary credentials outside the checkout, runs the production Compose
boundary, and removes its containers, volumes, networks, and secret directory afterward:

```powershell
.\scripts\run-network-boundary.ps1
```

The production probe does not make the workstation a release target; device approval, Tailscale
Serve, UFW, certificate, and real-client checks still require the Linux VM. Use synthetic data only;
production secrets must be generated independently on that host.

## Private Docker deployment

Copy `.env.example` to `.env` and set the private Tailscale hostname. This file
contains configuration only—never credentials. Create the production secrets
outside the repository on the Linux host:

```bash
cp .env.example .env
sudo groupadd --system household-budget-secrets
secret_gid="$(getent group household-budget-secrets | cut -d: -f3)"
sudo install -d -m 0700 -o root -g "$secret_gid" /etc/household-budget/secrets
for specification in \
  django_secret_key:64 django_mfa_encryption_key:32 \
  audit_checkpoint_signing_key:48 \
  restic_repository_password:48
do
  secret_name="${specification%%:*}"
  byte_count="${specification##*:}"
  sudo install -m 0440 -o root -g "$secret_gid" /dev/null \
    "/etc/household-budget/secrets/$secret_name"
  openssl rand -base64 "$byte_count" | sudo tee \
    "/etc/household-budget/secrets/$secret_name" >/dev/null
done

# Use an actually mounted offline/removable path outside the checkout and production VM storage.
offline_authority_dir=/media/offline-custody/household-budget-postgres-authorities-v1
sudo install -d -m 0700 -o root -g root "$offline_authority_dir"
sudo python3 scripts/generate-postgres-tls.py \
  --authority-directory "$offline_authority_dir" \
  --deployment-directory /etc/household-budget/secrets \
  --secret-group-id "$secret_gid"
```

If the dedicated group already exists, omit `groupadd`. Replace `BUDGET_SECRET_GID` in `.env` with
the numeric value printed by `getent group household-budget-secrets`. Do not add either household
member or the deployment account to this group. The root-owned directory is mode 0700 and each
file is mode 0440; Compose grants only the secret-bearing containers that supplemental numeric GID,
and each service still mounts only its explicitly allowed files.
Immediately unmount and secure the offline authority after generation. Its two private keys must
never remain on the production VM or enter the deployment secret directory. The server and
per-service client leaves, exact
trust model, rotation procedure, and fail-closed validation are documented in
[`docs/POSTGRES_TLS.md`](docs/POSTGRES_TLS.md).

Initialize the least-privilege database roles, apply migrations with the
dedicated migration identity, and then start the runtime services:

```bash
docker compose --profile maintenance run --rm db-bootstrap
docker compose --profile maintenance run --rm migrate
docker compose up --build -d db web ingress
```

The audit migrations move protected records into the separately owned `budget_audit` schema. The
runtime role receives read access plus execution of one append function; it receives no direct
insert, update, delete, truncate, DDL, ownership, or grant authority over audit records.

Create `BUDGET_AUDIT_CHECKPOINT_DIRECTORY` on an already mounted off-VM filesystem, verify the
mount with `findmnt`, and grant the container's fixed UID/GID 10001 access. Never let a missing
mount fall back to the VM disk. After the first household exists, verify every chain and create a
signed checkpoint with:

```bash
docker compose --profile maintenance run --rm integrity
```

The integrity container receives the read-only audit database identity and checkpoint signing key,
but none of the web, migration, administrator, backup, Django, or MFA secrets. The signing-key file
should live on an independently protected or read-only mounted location when practical.

The runtime web process cannot migrate the schema and receives only its own database client
certificate, never another service's private key. Production PostgreSQL login roles have no
password verifiers. The exact service/network catalog is enforced as an outbound
allowlist: application, database, and maintenance workloads stay exclusively on internal Docker
networks (or no network), and the web service's only backend destination is `db:5432`. Every
production database client verifies the dedicated server CA and `db` hostname with libpq
`verify-full`, presents a unique purpose-bound client certificate, and is mapped only to its
least-privilege role. PostgreSQL accepts only certificate-authenticated TLS 1.2 or TLS 1.3 TCP
sessions and rejects plaintext, absent-certificate, wrong-role, and password fallbacks. A separate
secretless, read-only nginx relay is the only service attached to the non-internal ingress network
and the only service bound to loopback port 8000; its running configuration is checked for exactly
one static destination, `web:8000`. Put private Tailscale HTTPS in front of that relay and never
forward the port from the router.

The production-derived boundary runner also sends valid and ambiguous HTTP/1.1 message framing
through the actual nginx/Gunicorn images. Its pull-request workflow requires every ambiguity to
produce exactly one rejection and a closed connection. This does not replace the runbook's bounded
release-candidate check of Tailscale's browser-facing HTTP/2/3 message-length handling.

Follow [`docs/PRIVATE_INGRESS.md`](docs/PRIVATE_INGRESS.md) to apply the least-privilege tailnet
policy, configure Tailscale Serve and UFW, run the VM preflight, and complete the required approved-
and unapproved-device release checks. The runbook deliberately leaves `NET-01` and `NET-02` pending
until they are observed on the real devices and VM.

Encrypted backup creation and safe restore verification are documented in
[`docs/BACKUP_AND_RESTORE.md`](docs/BACKUP_AND_RESTORE.md). The backup destination must be an
existing off-VM mount; it is deliberately unavailable to the web container. The same runbook
documents the independent audit-checkpoint timer and verification expectations.
It also documents the hourly staged-CSV cleanup timer; production deployments must enable it so
unfinished imports cannot retain raw statement cells indefinitely.
Lost-device containment, protected password/MFA recovery, and staged application, database,
Restic, audit, Tailscale, and SSH credential rotation are documented in
[`docs/INCIDENT_RESPONSE.md`](docs/INCIDENT_RESPONSE.md).
Release staging, backward-compatible application rollback, and clean-database recovery are in
[`docs/UPGRADE_AND_ROLLBACK.md`](docs/UPGRADE_AND_ROLLBACK.md).

## Quality commands

```powershell
python -m coverage run -m pytest
python -m coverage report
python scripts/check_branch_coverage.py --fail-under 80
python -m ruff check .
python -m ruff format --check .
python -m mypy audit budgets core debts goals households identity imports ledger notifications periods reserves schedules spending
python manage.py makemigrations --check --dry-run --settings=config.settings.test
python scripts/secret_scan.py
python scripts/check_cryptographic_inventory.py
python scripts/check_logging_inventory.py
python scripts/check_sbom.py
python scripts/check_release_evidence.py
python scripts/check_device_test_evidence.py
python scripts/check_adversarial_test_evidence.py
python -m bandit -c pyproject.toml -r audit budgets config core debts goals households identity imports ledger notifications periods reserves schedules spending
python -m pip_audit --requirement requirements-dev.lock --cache-dir .pip-audit-cache --no-deps --disable-pip --strict
.\scripts\run-browser-tests.ps1
```

Coverage excludes Django migration modules, which are verified separately through migration and
PostgreSQL rehearsal tests. The quality gate requires at least 80% combined coverage and 80%
branch-only coverage.

Production container dependencies are installed from `requirements-prod.lock`.
Regenerate and audit both lock files whenever dependency constraints change.
The Docker-only browser command creates and removes an isolated synthetic environment; see
[`docs/BROWSER_TESTING.md`](docs/BROWSER_TESTING.md) before changing its scope or credentials. The
separate branded-browser, real-device, keyboard, screen-reader, and zoom procedure is in
[`docs/REAL_DEVICE_ACCESSIBILITY_TESTING.md`](docs/REAL_DEVICE_ACCESSIBILITY_TESTING.md); automated
engine results do not satisfy those manual targets.
The separate authorization, session, CSV, financial-logic, audit-integrity, and private-network
manual release procedures are in [`docs/ADVERSARIAL_TESTING.md`](docs/ADVERSARIAL_TESTING.md).
Its evidence validator reports structural readiness without treating an unexecuted scenario as a
pass.

The GitHub workflow in `.github/workflows/quality.yml` uses read-only repository permissions and
immutable commit SHAs for official actions. Dependabot proposes reviewed updates for Python,
Node browser-test packages, workflow actions, and container bases; it does not deploy changes
automatically.

## Build authority

1. [`PRODUCT_SPEC.md`](PRODUCT_SPEC.md) — product behavior and acceptance criteria
2. [`SECURITY_PLAN.md`](SECURITY_PLAN.md) — threat model, controls, and security tests
3. [`DATA_MODEL.md`](DATA_MODEL.md) — entities, relationships, and database invariants
4. [`WORKFLOWS.md`](WORKFLOWS.md) — period, transaction, reserve, import, mortgage, and audit state flows
5. [`CALCULATION_RULES.md`](CALCULATION_RULES.md) — formulas and golden test cases
6. [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md) — architecture, milestones, test matrix, and setup checklist
7. [`design/mockups/`](design/mockups/) — approved visual direction
8. [`docs/adr/`](docs/adr/) — accepted architecture decisions
9. [`docs/MIGRATIONS.md`](docs/MIGRATIONS.md) — database migration policy
10. [`docs/UPGRADE_AND_ROLLBACK.md`](docs/UPGRADE_AND_ROLLBACK.md) — release upgrade and rollback
11. [`docs/PASSWORD_BLOCKLIST.md`](docs/PASSWORD_BLOCKLIST.md) — prohibited identifiers and offline breached-password corpus maintenance
12. [`docs/CRYPTOGRAPHIC_INVENTORY.md`](docs/CRYPTOGRAPHIC_INVENTORY.md) — maintained key, algorithm, certificate, and purpose inventory
13. [`docs/POSTGRES_TLS.md`](docs/POSTGRES_TLS.md) — internal database TLS trust, generation, validation, and rotation
14. [`docs/LOGGING_INVENTORY.md`](docs/LOGGING_INVENTORY.md) — maintained event, destination, access, retention, and sensitive-data inventory
15. [`docs/SBOM.md`](docs/SBOM.md) — maintained CycloneDX inventory, approved repositories, and release retention procedure

Where a mockup's sample figure conflicts with a specification or calculation rule, the written specification and golden calculation cases are authoritative.
