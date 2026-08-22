# Household Budget App

A private, paycheck-anchored budgeting application for a two-person household.

The application foundation is now runnable. It includes a responsive dark-first
interface, an email-based custom user model, shared households, PostgreSQL-ready
production settings, Docker deployment files, health checks, and tested core
money rules.

## Current milestone

The local Milestone 0 baseline and the encrypted backup/recovery portion of Milestone 1 are
complete. Remote branch protection becomes enforceable when a private Git host is connected. The
remaining private deployment work is Tailscale-only HTTPS configuration on the Linux VM.
Application work then moves to authentication, household authorization, and the protected audit
foundation before household financial data is entered.

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
openssl rand -base64 48 > /etc/household-budget/secrets/postgres_admin_password
openssl rand -base64 48 > /etc/household-budget/secrets/postgres_runtime_password
openssl rand -base64 48 > /etc/household-budget/secrets/postgres_migration_password
openssl rand -base64 48 > /etc/household-budget/secrets/postgres_backup_password
openssl rand -base64 48 > /etc/household-budget/secrets/postgres_audit_password
openssl rand -base64 48 > /etc/household-budget/secrets/restic_repository_password
```

Initialize the least-privilege database roles, apply migrations with the
dedicated migration identity, and then start the runtime services:

```bash
docker compose --profile maintenance run --rm db-bootstrap
docker compose --profile maintenance run --rm migrate
docker compose up --build -d db web
```

The runtime web process cannot migrate the schema and never receives the
database administrator, migration, backup, or audit passwords. Both the application
and database are on an internal Docker network; only web port 8000 is bound to
loopback. Put private Tailscale HTTPS in front of it and never forward the port
from the router.

Encrypted backup creation and safe restore verification are documented in
[`docs/BACKUP_AND_RESTORE.md`](docs/BACKUP_AND_RESTORE.md). The backup destination must be an
existing off-VM mount; it is deliberately unavailable to the web container.

## Quality commands

```powershell
python -m pytest
python -m ruff check .
python -m ruff format --check .
python -m mypy budgets core debts households identity spending
python manage.py makemigrations --check --dry-run --settings=config.settings.test
python scripts/secret_scan.py
python -m bandit -c pyproject.toml -r audit budgets config core debts goals households identity imports ledger notifications periods reserves schedules spending
python -m pip_audit --requirement requirements-dev.lock --cache-dir .pip-audit-cache --no-deps --disable-pip --strict
```

Production container dependencies are installed from `requirements-prod.lock`.
Regenerate and audit both lock files whenever dependency constraints change.

The GitHub workflow in `.github/workflows/quality.yml` uses read-only repository permissions and
immutable commit SHAs for official actions. Dependabot proposes reviewed updates for Python,
workflow actions, and container bases; it does not deploy changes automatically.

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
