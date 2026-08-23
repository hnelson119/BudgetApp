import importlib
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _walk_mappings(value: Any) -> Iterator[dict[Any, Any]]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk_mappings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_mappings(child)


def test_compose_separates_privileged_database_tasks() -> None:
    compose = yaml.safe_load((PROJECT_ROOT / "compose.yaml").read_text(encoding="utf-8"))
    services = compose["services"]

    assert services["web"]["environment"]["POSTGRES_USER"].endswith("budget_runtime}")
    assert services["migrate"]["environment"]["POSTGRES_USER"].endswith("budget_migration}")
    assert services["db"]["environment"]["POSTGRES_USER"].endswith("budget_admin}")
    audit_user = services["db-bootstrap"]["environment"]["POSTGRES_AUDIT_USER"]
    assert audit_user.endswith("budget_audit}")
    assert "maintenance" in services["migrate"]["profiles"]
    assert "maintenance" in services["db-bootstrap"]["profiles"]
    assert services["backup"]["environment"]["POSTGRES_BACKUP_USER"].endswith("budget_backup}")
    assert services["restore-verify"]["environment"]["POSTGRES_ADMIN_USER"].endswith(
        "budget_admin}"
    )
    assert "maintenance" in services["backup"]["profiles"]
    assert "recovery" in services["restore-verify"]["profiles"]


def test_postgresql_audit_boundary_uses_owned_schema_and_capability_roles() -> None:
    bootstrap = (PROJECT_ROOT / "deploy/postgres/bootstrap-roles.sh").read_text(encoding="utf-8")
    migration = (PROJECT_ROOT / "audit/migrations/0002_postgresql_protected_schema.py").read_text(
        encoding="utf-8"
    )
    service = (PROJECT_ROOT / "audit/services.py").read_text(encoding="utf-8")

    assert "CREATE ROLE budget_audit_owner NOLOGIN" in bootstrap
    assert "CREATE ROLE budget_runtime_access NOLOGIN" in bootstrap
    assert "GRANT budget_audit_owner TO %I" in bootstrap
    assert "REVOKE ALL ON ALL TABLES IN SCHEMA public" in bootstrap
    assert "budget_audit.append_event" in migration
    assert "SECURITY DEFINER" in migration
    assert "SET search_path = pg_catalog, pg_temp" in migration
    assert "BEFORE UPDATE OR DELETE" in migration
    assert "BEFORE TRUNCATE" in migration
    assert "protected audit records cannot be %% by this database role" in migration
    assert "REVOKE ALL ON TABLE budget_audit.audit_auditevent" in migration
    assert "GRANT EXECUTE ON FUNCTION budget_audit.append_event" in migration
    assert "SELECT budget_audit.append_event" in service


def test_parameterless_postgresql_migration_sql_escapes_percent_literals() -> None:
    migration_sql = (
        (
            "audit.migrations.0002_postgresql_protected_schema",
            ("PROTECT_AUDIT_SQL", "UNPROTECT_AUDIT_SQL"),
        ),
        (
            "audit.migrations.0004_postgresql_protect_checkpoints",
            ("PROTECT_CHECKPOINT_SQL", "UNPROTECT_CHECKPOINT_SQL"),
        ),
        (
            "ledger.migrations.0002_postgresql_protect_history",
            ("PROTECT_LEDGER_HISTORY_SQL", "UNPROTECT_LEDGER_HISTORY_SQL"),
        ),
        (
            "periods.migrations.0002_postgresql_period_guards",
            ("PROTECT_PERIOD_SQL", "UNPROTECT_PERIOD_SQL"),
        ),
        (
            "schedules.migrations.0002_postgresql_protect_revisions",
            ("PROTECT_SOURCE_REVISIONS_SQL", "UNPROTECT_SOURCE_REVISIONS_SQL"),
        ),
        (
            "reserves.migrations.0002_postgresql_protect_entries",
            ("PROTECT_RESERVE_ENTRIES_SQL", "UNPROTECT_RESERVE_ENTRIES_SQL"),
        ),
        (
            "reserves.migrations.0004_cardpaymentreserveentry",
            ("PROTECT_CARD_RESERVE_SQL", "UNPROTECT_CARD_RESERVE_SQL"),
        ),
        (
            "budgets.migrations.0002_postgresql_protect_reconciliations",
            ("PROTECT_RECONCILIATIONS_SQL", "UNPROTECT_RECONCILIATIONS_SQL"),
        ),
    )

    for module_name, attribute_names in migration_sql:
        module = importlib.import_module(module_name)
        for attribute_name in attribute_names:
            sql = getattr(module, attribute_name)
            assert re.search(r"(?<!%)%(?!%)", sql) is None


def test_postgresql_committed_ledger_history_has_database_mutation_guards() -> None:
    migration = (PROJECT_ROOT / "ledger/migrations/0002_postgresql_protect_history.py").read_text(
        encoding="utf-8"
    )

    assert "ledger_journalentry" in migration
    assert "ledger_journalposting" in migration
    assert "ledger_balancesnapshot" in migration
    assert migration.count("BEFORE UPDATE OR DELETE") == 3
    assert migration.count("BEFORE TRUNCATE") == 3
    assert "committed ledger records cannot be %%" in migration


def test_postgresql_schedule_and_period_history_has_database_guards() -> None:
    period_migration = (
        PROJECT_ROOT / "periods/migrations/0002_postgresql_period_guards.py"
    ).read_text(encoding="utf-8")
    schedule_migration = (
        PROJECT_ROOT / "schedules/migrations/0002_postgresql_protect_revisions.py"
    ).read_text(encoding="utf-8")
    reserve_migration = (
        PROJECT_ROOT / "reserves/migrations/0002_postgresql_protect_entries.py"
    ).read_text(encoding="utf-8")
    reconciliation_migration = (
        PROJECT_ROOT / "budgets/migrations/0002_postgresql_protect_reconciliations.py"
    ).read_text(encoding="utf-8")
    card_reserve_migration = (
        PROJECT_ROOT / "reserves/migrations/0004_cardpaymentreserveentry.py"
    ).read_text(encoding="utf-8")

    assert "pg_advisory_xact_lock" in period_migration
    assert "pay periods for one household cannot overlap" in period_migration
    assert "BEFORE UPDATE OR DELETE" in period_migration
    assert "BEFORE TRUNCATE" in period_migration
    assert "source revisions cannot be %%" in schedule_migration
    assert "reserve entries cannot be %%" in reserve_migration
    assert "budget reconciliations cannot be %%" in reconciliation_migration
    assert "budgets_occurrencereconciliation" in reconciliation_migration
    assert "reserves_cardpaymentreserveentry" in card_reserve_migration
    for migration in (
        schedule_migration,
        reserve_migration,
        reconciliation_migration,
        card_reserve_migration,
    ):
        assert "BEFORE UPDATE OR DELETE" in migration
        assert "BEFORE TRUNCATE" in migration


def test_compose_hardens_runtime_and_keeps_secrets_out_of_environment() -> None:
    compose = yaml.safe_load((PROJECT_ROOT / "compose.yaml").read_text(encoding="utf-8"))
    web = compose["services"]["web"]

    assert web["read_only"] is True
    assert web["cap_drop"] == ["ALL"]
    assert web["ports"] == ["127.0.0.1:8000:8000"]
    assert compose["networks"]["backend"]["internal"] is True
    assert set(web["networks"]) == {"frontend", "backend"}
    assert compose["services"]["db"]["networks"] == ["backend"]
    assert not any(part in web["command"] for part in ("migrate", "collectstatic"))

    forbidden_keys = {
        "AUDIT_CHECKPOINT_SIGNING_KEY",
        "DJANGO_SECRET_KEY",
        "DJANGO_MFA_ENCRYPTION_KEY",
        "POSTGRES_PASSWORD",
    }
    for mapping in _walk_mappings(compose):
        assert forbidden_keys.isdisjoint(mapping)

    for configuration in compose["secrets"].values():
        assert set(configuration) == {"file"}


def test_backup_credentials_and_repository_are_isolated_from_web() -> None:
    compose = yaml.safe_load((PROJECT_ROOT / "compose.yaml").read_text(encoding="utf-8"))
    services = compose["services"]
    web = services["web"]
    backup = services["backup"]
    restore = services["restore-verify"]
    integrity = services["integrity"]

    assert set(web["secrets"]) == {
        "django_secret_key",
        "django_mfa_encryption_key",
        "postgres_runtime_password",
    }
    assert "postgres_backup_password" not in web["secrets"]
    assert "restic_repository_password" not in web["secrets"]
    assert all("repository" not in str(volume) for volume in web["volumes"])

    assert set(backup["secrets"]) == {
        "postgres_backup_password",
        "restic_repository_password",
    }
    assert set(restore["secrets"]) == {
        "postgres_admin_password",
        "restic_repository_password",
    }
    assert backup["read_only"] is True
    assert restore["read_only"] is True
    assert backup["environment"]["RESTIC_CACHE_DIR"] == "/tmp/restic-cache"
    assert restore["environment"]["RESTIC_CACHE_DIR"] == "/tmp/restic-cache"
    assert backup["cap_drop"] == ["ALL"]
    assert restore["cap_drop"] == ["ALL"]
    assert backup["volumes"][0]["bind"]["create_host_path"] is False
    assert restore["volumes"][0]["read_only"] is True
    assert restore["volumes"][0]["bind"]["create_host_path"] is False
    assert set(integrity["secrets"]) == {
        "postgres_audit_password",
        "audit_checkpoint_signing_key",
    }
    assert integrity["networks"] == ["backend"]
    assert integrity["volumes"][0]["bind"]["create_host_path"] is False
    assert "audit_checkpoint_signing_key" not in web["secrets"]


def test_backup_streams_into_encrypted_repository_and_restore_refuses_live_target() -> None:
    backup_script = (PROJECT_ROOT / "deploy/backup/backup.sh").read_text(encoding="utf-8")
    restore_script = (PROJECT_ROOT / "deploy/backup/restore-verify.sh").read_text(encoding="utf-8")
    backup_dockerfile = (PROJECT_ROOT / "deploy/backup/Dockerfile").read_text(encoding="utf-8")

    assert "pg_dump" in backup_script
    assert "--stdin" in backup_script
    assert "restic check" in backup_script
    assert "--keep-daily" in backup_script
    assert "PGPASSWORD" not in backup_script
    assert "RESTIC_PASSWORD=" not in backup_script
    assert "RESTIC_PASSWORD_FILE" in backup_script
    assert "RESTIC_SHA256=" in backup_dockerfile
    assert "ADD --checksum=sha256:" in backup_dockerfile

    assert 'if [ "$RESTORE_TARGET_DB" = "$POSTGRES_DB" ]' in restore_script
    assert "restore_target_refused" in restore_script
    assert "restore_target_exists" in restore_script
    assert "--single-transaction" in restore_script
    assert "--no-owner" in restore_script


def test_container_does_not_enable_raw_access_logging() -> None:
    dockerfile = (PROJECT_ROOT / "Dockerfile").read_text(encoding="utf-8")
    dockerignore = set((PROJECT_ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines())

    assert "USER budget" in dockerfile
    assert "useradd --uid 10001" in dockerfile
    assert "python:3.12-slim@sha256:" in dockerfile
    assert "--access-logfile" not in dockerfile
    assert {".env*", "secrets", "local-test-secrets"}.issubset(dockerignore)


def test_database_images_are_pinned_by_digest() -> None:
    compose = yaml.safe_load((PROJECT_ROOT / "compose.yaml").read_text(encoding="utf-8"))

    for service_name in ("db", "db-bootstrap"):
        image = compose["services"][service_name]["image"]
        assert image.startswith("postgres:17-alpine@sha256:")


def test_daily_backup_timer_uses_the_isolated_compose_service() -> None:
    service = (PROJECT_ROOT / "deploy/systemd/household-budget-backup.service").read_text(
        encoding="utf-8"
    )
    timer = (PROJECT_ROOT / "deploy/systemd/household-budget-backup.timer").read_text(
        encoding="utf-8"
    )

    assert "EnvironmentFile=/etc/household-budget/household-budget.env" in service
    assert "docker compose --profile maintenance run --rm backup" in service
    assert "UMask=0077" in service
    assert "OnCalendar=*-*-* 03:15:00" in timer
    assert "Persistent=true" in timer
    assert "RandomizedDelaySec=30m" in timer

    integrity_service = (
        PROJECT_ROOT / "deploy/systemd/household-budget-integrity.service"
    ).read_text(encoding="utf-8")
    integrity_timer = (PROJECT_ROOT / "deploy/systemd/household-budget-integrity.timer").read_text(
        encoding="utf-8"
    )
    assert "docker compose --profile maintenance run --rm integrity" in integrity_service
    assert "UMask=0077" in integrity_service
    assert "OnCalendar=*-*-* 02:45:00" in integrity_timer
    assert "Persistent=true" in integrity_timer


def test_ci_uses_read_only_permissions_and_immutable_official_actions() -> None:
    workflow = (PROJECT_ROOT / ".github/workflows/quality.yml").read_text(encoding="utf-8")

    assert "pull_request_target" not in workflow
    assert "permissions:\n  contents: read" in workflow
    assert "persist-credentials: false" in workflow
    assert "pip_audit --requirement requirements-dev.lock" in workflow
    assert "--cache-dir .pip-audit-cache --no-deps --disable-pip --strict" in workflow
    assert "docker compose --profile maintenance --profile recovery config --quiet" in workflow

    action_references = re.findall(r"uses: ([^\s#]+)", workflow)
    assert {reference.split("@")[0] for reference in action_references} == {
        "actions/checkout",
        "actions/setup-python",
    }
    assert all(re.fullmatch(r"[^@]+@[0-9a-f]{40}", reference) for reference in action_references)


def test_linux_entrypoints_are_forced_to_lf_in_git() -> None:
    attributes = (PROJECT_ROOT / ".gitattributes").read_text(encoding="utf-8")

    assert "*.sh text eol=lf" in attributes
    assert "Dockerfile* text eol=lf" in attributes
    assert "*.yml text eol=lf" in attributes


def test_pytest_temporary_files_stay_inside_the_checkout() -> None:
    pyproject = (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    gitignore = (PROJECT_ROOT / ".gitignore").read_text(encoding="utf-8")
    secret_scan = (PROJECT_ROOT / "scripts/secret_scan.py").read_text(encoding="utf-8")

    assert "--basetemp=.pytest-tmp" in pyproject
    assert ".pytest-tmp/" in gitignore
    assert "\\.pytest-tmp" in secret_scan
