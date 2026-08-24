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
atomic and idempotent confirmation, import provenance, and raw-row cleanup. Transaction CSV export
now mirrors the selected pay-period or all-history filters, requires recent reauthentication,
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
Milestone 10 is now in progress. Its first release-hardening baseline adds a machine-validated
OWASP ASVS 5.0 Level 2, security-test, and release-gate evidence inventory plus a pinned Trivy
container scan that fails CI on high or critical release-image vulnerabilities. See
`docs/RELEASE_HARDENING.md` for the honest current status and evidence-handling rules. Private
Tailscale-only HTTPS, firewall/device checks, and
provisioning the two real household accounts remain deployment-time work on the Linux VM before
household financial data is entered.

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
variables, or configuration values:

```powershell
python manage.py bootstrap_household `
  --household-name "Our Household" `
  --user-email "first@example.com" --display-name "First person" `
  --user-email "second@example.com" --display-name "Second person"
```

Each person is restricted to MFA enrollment at first login. TOTP seeds are encrypted with the
separate `django_mfa_encryption_key` secret; recovery codes are displayed once and only salted
password hashes are retained. If an authenticator and all recovery codes are lost, a VM
administrator can run the interactive `reset_user_mfa <email> --reason "..."` command. That reset
revokes every session, invalidates the old seed and codes, and creates a protected audit event.

### Local Docker verification on Windows

Docker Desktop should use its per-user WSL 2 backend with Linux containers.
Generate local-only credentials, then provide non-secret settings to the current
PowerShell process:

```powershell
.\scripts\create-local-test-secrets.ps1
$env:BUDGET_SECRET_DIR = Join-Path $env:LOCALAPPDATA "HouseholdBudget\test-secrets"
$env:DJANGO_ALLOWED_HOSTS = "localhost,127.0.0.1"
$env:DJANGO_CSRF_TRUSTED_ORIGINS = "https://localhost,https://127.0.0.1"
$env:BUDGET_BACKUP_REPOSITORY = Join-Path $env:LOCALAPPDATA "HouseholdBudget\test-backups"
[IO.Directory]::CreateDirectory($env:BUDGET_BACKUP_REPOSITORY) | Out-Null
docker compose --profile maintenance build
docker compose up -d db
docker compose --profile maintenance run --rm db-bootstrap
docker compose --profile maintenance run --rm migrate
docker compose up -d web
docker compose --profile maintenance run --rm backup
docker compose --profile maintenance run --rm notify
```

The generated directory stays outside the OneDrive workspace. Secret-directory
patterns are also excluded from Git and the Docker build context as defense in
depth. Use synthetic data only; production secrets must be generated
independently on the Linux host.

## Private Docker deployment

Copy `.env.example` to `.env` and set the private Tailscale hostname. This file
contains configuration only—never credentials. Create the production secrets
outside the repository on the Linux host:

```bash
cp .env.example .env
sudo install -d -m 0700 -o "$USER" -g "$USER" /etc/household-budget/secrets
umask 077
openssl rand -base64 64 > /etc/household-budget/secrets/django_secret_key
openssl rand -base64 32 > /etc/household-budget/secrets/django_mfa_encryption_key
openssl rand -base64 48 > /etc/household-budget/secrets/postgres_admin_password
openssl rand -base64 48 > /etc/household-budget/secrets/postgres_runtime_password
openssl rand -base64 48 > /etc/household-budget/secrets/postgres_migration_password
openssl rand -base64 48 > /etc/household-budget/secrets/postgres_backup_password
openssl rand -base64 48 > /etc/household-budget/secrets/postgres_audit_password
openssl rand -base64 48 > /etc/household-budget/secrets/audit_checkpoint_signing_key
openssl rand -base64 48 > /etc/household-budget/secrets/restic_repository_password
```

Initialize the least-privilege database roles, apply migrations with the
dedicated migration identity, and then start the runtime services:

```bash
docker compose --profile maintenance run --rm db-bootstrap
docker compose --profile maintenance run --rm migrate
docker compose up --build -d db web
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

The runtime web process cannot migrate the schema and never receives the
database administrator, migration, backup, or audit passwords. Both the application
and database are on an internal Docker network; only web port 8000 is bound to
loopback. Put private Tailscale HTTPS in front of it and never forward the port
from the router.

Encrypted backup creation and safe restore verification are documented in
[`docs/BACKUP_AND_RESTORE.md`](docs/BACKUP_AND_RESTORE.md). The backup destination must be an
existing off-VM mount; it is deliberately unavailable to the web container. The same runbook
documents the independent audit-checkpoint timer and verification expectations.

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

Where a mockup's sample figure conflicts with a specification or calculation rule, the written specification and golden calculation cases are authoritative.
