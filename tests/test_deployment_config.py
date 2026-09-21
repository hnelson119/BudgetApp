import importlib
import re
import ssl
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
    assert "maintenance" in services["notify"]["profiles"]
    assert services["notify"]["environment"]["POSTGRES_USER"].endswith("budget_runtime}")
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
    card_refund_migration_path = next((PROJECT_ROOT / "reserves/migrations").glob("0005_*.py"))
    card_refund_migration = card_refund_migration_path.read_text(encoding="utf-8")

    assert "pg_advisory_xact_lock" in period_migration
    assert "pay periods for one household cannot overlap" in period_migration
    assert "BEFORE UPDATE OR DELETE" in period_migration
    assert "BEFORE TRUNCATE" in period_migration
    assert "source revisions cannot be %%" in schedule_migration
    assert "reserve entries cannot be %%" in reserve_migration
    assert "budget reconciliations cannot be %%" in reconciliation_migration
    assert "budgets_occurrencereconciliation" in reconciliation_migration
    assert "reserves_cardpaymentreserveentry" in card_reserve_migration
    assert "backfill_purchase_refund_amount" in card_refund_migration
    assert "purchase_refund_amount" in card_refund_migration
    assert "migrations.RunPython(backfill_purchase_refund_amount" in card_refund_migration
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
    assert web["user"] == "10001:10001"
    assert web["group_add"] == ["${BUDGET_SECRET_GID:-10002}"]
    assert web["pids_limit"] == 128
    assert (web["cpus"], web["mem_limit"]) == (1.0, "1g")
    assert web["cap_drop"] == ["ALL"]
    assert "ports" not in web
    assert compose["networks"]["backend"]["internal"] is True
    assert compose["networks"]["frontend"]["internal"] is True
    assert compose["networks"]["ingress"] is None
    assert set(web["networks"]) == {"frontend", "backend"}
    assert compose["services"]["db"]["networks"] == ["backend"]
    assert (compose["services"]["db"]["cpus"], compose["services"]["db"]["mem_limit"]) == (
        2.0,
        "2g",
    )
    assert not any(part in web["command"] for part in ("migrate", "collectstatic"))

    ingress = compose["services"]["ingress"]
    assert ingress["build"] == {
        "context": "${BUDGET_BUILD_CONTEXT:-.}",
        "dockerfile": "deploy/network/Dockerfile",
    }
    assert ingress["ports"] == ["127.0.0.1:8000:8000"]
    assert ingress["networks"] == ["ingress", "frontend"]
    assert ingress["user"] == "101:101"
    assert ingress["read_only"] is True
    assert ingress["cap_drop"] == ["ALL"]
    assert ingress["pids_limit"] == 64
    assert (ingress["cpus"], ingress["mem_limit"]) == (0.5, "256m")
    assert set(ingress["secrets"]) == {
        "gunicorn_ca_certificate",
        "nginx_client_certificate",
        "nginx_client_private_key",
    }
    assert ingress["group_add"] == ["${BUDGET_SECRET_GID:-10002}"]
    assert set(web["secrets"]) >= {
        "gunicorn_client_ca_certificate",
        "gunicorn_server_certificate",
        "gunicorn_server_private_key",
    }
    assert web["command"][:4] == [
        "gunicorn",
        "--config",
        "python:config.gunicorn",
        "config.wsgi:application",
    ]

    gunicorn_configuration = importlib.import_module("config.gunicorn")
    assert gunicorn_configuration.bind == "0.0.0.0:8443"
    assert gunicorn_configuration.cert_reqs == ssl.CERT_REQUIRED
    assert gunicorn_configuration.ca_certs == "/run/secrets/gunicorn_client_ca_certificate"
    assert gunicorn_configuration.timeout == 30
    assert gunicorn_configuration.graceful_timeout == 30

    class Context:
        minimum_version: ssl.TLSVersion | None = None
        maximum_version: ssl.TLSVersion | None = None

    context = gunicorn_configuration.ssl_context(None, Context)
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2
    assert context.maximum_version == ssl.TLSVersion.TLSv1_3

    security_log = compose["services"]["security-log"]
    assert security_log["network_mode"] == "none"
    assert security_log["user"] == "10003:10003"
    assert security_log["read_only"] is True
    assert security_log["cap_drop"] == ["ALL"]
    assert security_log["pids_limit"] == 32
    assert (security_log["cpus"], security_log["mem_limit"]) == (0.5, "256m")
    assert "secrets" not in security_log
    assert "environment" not in security_log
    assert {volume.split(":")[0] for volume in security_log["volumes"]} == {
        "security_log_socket",
        "security_log_archive",
    }
    assert set(compose["volumes"]) >= {"security_log_socket", "security_log_archive"}
    socket_mount = next(volume for volume in web["volumes"] if isinstance(volume, dict))
    assert socket_mount == {
        "type": "volume",
        "source": "security_log_socket",
        "target": "/run/security-log",
        "read_only": True,
    }
    assert "security-log" in web["depends_on"]

    relay_dockerfile = (PROJECT_ROOT / "deploy/network/Dockerfile").read_text(encoding="utf-8")
    assert "FROM nginx:1.30.4-alpine@sha256:" in relay_dockerfile
    assert "RUN apk upgrade --no-cache" in relay_dockerfile
    assert "USER 101:101" in relay_dockerfile

    application_dockerfile = (PROJECT_ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "adduser -u 10003" in application_dockerfile
    assert "chmod 0711 /run/security-log" in application_dockerfile
    assert "chmod 0700 /var/lib/security-log" in application_dockerfile

    secret_services = {
        "db",
        "db-bootstrap",
        "migrate",
        "mfa-key-rotate",
        "backup",
        "restic-key-rotate",
        "integrity",
        "notify",
        "import-cleanup",
        "restore-verify",
        "web",
    }
    for service_name in secret_services:
        service = compose["services"][service_name]
        assert service["group_add"] == ["${BUDGET_SECRET_GID:-10002}"]
        assert service["secrets"]

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

    environment_example = (PROJECT_ROOT / ".env.example").read_text(encoding="utf-8")
    assert "BUDGET_SECRET_GID=10002" in environment_example
    assert "DJANGO_MFA_ENCRYPTION_KEY_VERSION=1" in environment_example

    rotation = compose["services"]["mfa-key-rotate"]
    assert rotation["profiles"] == ["maintenance"]
    assert rotation["networks"] == ["backend"]
    assert rotation["command"][2] == "rotate_mfa_encryption_key"
    assert set(rotation["secrets"]) == {
        "django_secret_key",
        "django_mfa_encryption_key",
        "django_mfa_encryption_key_next",
        "postgres_ca_certificate",
        "postgres_mfa_key_rotate_client_certificate",
        "postgres_mfa_key_rotate_client_private_key",
    }
    assert rotation["environment"]["DJANGO_MFA_ENCRYPTION_KEY_NEXT_FILE"] == (
        "/run/secrets/django_mfa_encryption_key_next"
    )

    assert "db-admin-key-rotate" not in compose["services"]
    assert not any("postgres" in name and "password" in name for name in compose["secrets"])


def test_backup_credentials_and_repository_are_isolated_from_web() -> None:
    compose = yaml.safe_load((PROJECT_ROOT / "compose.yaml").read_text(encoding="utf-8"))
    services = compose["services"]
    web = services["web"]
    backup = services["backup"]
    restore = services["restore-verify"]
    rotation = services["restic-key-rotate"]
    integrity = services["integrity"]

    assert set(web["secrets"]) == {
        "django_secret_key",
        "django_mfa_encryption_key",
        "gunicorn_client_ca_certificate",
        "gunicorn_server_certificate",
        "gunicorn_server_private_key",
        "postgres_ca_certificate",
        "postgres_web_client_certificate",
        "postgres_web_client_private_key",
    }
    assert "postgres_backup_password" not in web["secrets"]
    assert "restic_repository_password" not in web["secrets"]
    assert all("repository" not in str(volume) for volume in web["volumes"])

    assert set(backup["secrets"]) == {
        "postgres_ca_certificate",
        "postgres_backup_client_certificate",
        "postgres_backup_client_private_key",
        "restic_repository_password",
    }
    assert set(restore["secrets"]) == {
        "postgres_ca_certificate",
        "postgres_restore_verify_client_certificate",
        "postgres_restore_verify_client_private_key",
        "restic_repository_password",
    }
    assert set(rotation["secrets"]) == {
        "restic_repository_password",
        "restic_repository_password_next",
    }
    assert rotation["network_mode"] == "none"
    assert rotation["volumes"][0]["bind"]["create_host_path"] is False
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
        "postgres_ca_certificate",
        "postgres_integrity_client_certificate",
        "postgres_integrity_client_private_key",
        "audit_checkpoint_signing_key",
    }
    assert integrity["networks"] == ["backend"]
    assert integrity["volumes"][0]["bind"]["create_host_path"] is False
    assert "audit_checkpoint_signing_key" not in web["secrets"]
    notify = services["notify"]
    assert set(notify["secrets"]) == {
        "django_secret_key",
        "django_mfa_encryption_key",
        "postgres_ca_certificate",
        "postgres_notify_client_certificate",
        "postgres_notify_client_private_key",
    }
    assert notify["read_only"] is True
    assert notify["networks"] == ["backend"]
    assert notify["volumes"][0]["read_only"] is True
    assert notify["volumes"][0]["bind"]["create_host_path"] is False


def test_production_postgres_requires_exact_internal_ca_and_rejects_plaintext_tcp() -> None:
    compose = yaml.safe_load((PROJECT_ROOT / "compose.yaml").read_text(encoding="utf-8"))
    services = compose["services"]
    database = services["db"]
    clients = {
        "backup",
        "db-bootstrap",
        "import-cleanup",
        "integrity",
        "mfa-key-rotate",
        "migrate",
        "notify",
        "restore-verify",
        "web",
    }

    assert database["entrypoint"] == ["/bin/sh", "/usr/local/bin/start-postgres-tls.sh"]
    assert set(database["secrets"]) == {
        "postgres_client_ca_certificate",
        "postgres_server_certificate",
        "postgres_server_private_key",
    }
    assert set(database["tmpfs"]) == {
        "/run/postgresql-tls:rw,noexec,nosuid,nodev,size=1m,mode=0700"
    }
    assert {
        "./deploy/postgres/start-tls.sh:/usr/local/bin/start-postgres-tls.sh:ro",
        "./deploy/postgres/pg_hba.conf:/etc/postgresql/pg_hba.conf:ro",
    }.issubset(database["volumes"])
    for service_name in clients:
        service = services[service_name]
        assert service["environment"]["PGSSLMODE"] == "verify-full"
        assert service["environment"]["PGSSLROOTCERT"] == ("/run/secrets/postgres_ca_certificate")
        assert service["environment"]["PGSSLCERT"].startswith("/run/secrets/postgres_")
        assert service["environment"]["PGSSLKEY"].startswith("/run/secrets/postgres_")
        assert "postgres_ca_certificate" in service["secrets"]
        assert (
            service["environment"]["PGSSLCERT"].removeprefix("/run/secrets/") in service["secrets"]
        )
        assert (
            service["environment"]["PGSSLKEY"].removeprefix("/run/secrets/") in service["secrets"]
        )

    policy = (PROJECT_ROOT / "deploy/postgres/pg_hba.conf").read_text(encoding="utf-8")
    rules = [
        line.strip()
        for line in policy.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    assert rules == [
        "local all all trust",
        "hostssl all all all cert map=budget_service",
        "hostnossl all all all reject",
    ]
    wrapper = (PROJECT_ROOT / "deploy/postgres/start-tls.sh").read_text(encoding="utf-8")
    assert "ssl=on" in wrapper
    assert "ssl_min_protocol_version=TLSv1.2" in wrapper
    assert "ssl_ca_file=" in wrapper
    assert "ident_file=" in wrapper
    assert "hba_file=/etc/postgresql/pg_hba.conf" in wrapper


def test_backup_streams_into_encrypted_repository_and_restore_refuses_live_target() -> None:
    backup_script = (PROJECT_ROOT / "deploy/backup/backup.sh").read_text(encoding="utf-8")
    restore_script = (PROJECT_ROOT / "deploy/backup/restore-verify.sh").read_text(encoding="utf-8")
    backup_dockerfile = (PROJECT_ROOT / "deploy/backup/Dockerfile").read_text(encoding="utf-8")

    assert "pg_dump" in backup_script
    assert "--stdin" in backup_script
    assert "restic check" in backup_script
    assert "--keep-daily" in backup_script
    assert "PGPASSWORD" not in backup_script
    assert "PGPASSFILE" not in backup_script
    assert "PGPASSFILE" not in restore_script
    assert "RESTIC_PASSWORD=" not in backup_script
    assert "RESTIC_PASSWORD_FILE" in backup_script
    assert ".last-success" in backup_script
    assert "release=%s" in backup_script
    assert "RESTIC_SHA256=" in backup_dockerfile
    assert "ADD --checksum=sha256:" in backup_dockerfile
    assert "apk upgrade --no-cache" in backup_dockerfile
    assert "golang:1.26.6-alpine3.24@sha256:" in backup_dockerfile
    assert "alpine:3.24.1@sha256:" in backup_dockerfile
    assert "postgresql17-client" in backup_dockerfile
    assert "/nonexistent:/sbin/nologin" in backup_dockerfile
    assert 'test "$(id -u postgres)" = "70"' in backup_dockerfile
    assert "golang.org/x/crypto@v0.55.0" in backup_dockerfile
    assert "golang.org/x/net@v0.58.0" in backup_dockerfile
    assert "golang.org/x/text@v0.41.0" in backup_dockerfile
    assert "google.golang.org/grpc@v1.83.2" in backup_dockerfile
    assert "COPY --from=restic-builder /out/restic" in backup_dockerfile

    assert 'if [ "$RESTORE_TARGET_DB" = "$POSTGRES_DB" ]' in restore_script
    assert "restore_target_refused" in restore_script
    assert "restore_target_exists" in restore_script
    assert "--single-transaction" in restore_script
    assert "--no-owner" in restore_script

    bootstrap = (PROJECT_ROOT / "deploy/postgres/bootstrap-roles.sh").read_text(encoding="utf-8")
    admin_rotation = (PROJECT_ROOT / "deploy/postgres/rotate-admin-password.sh").read_text(
        encoding="utf-8"
    )
    assert "GRANT USAGE ON SCHEMA budget_audit TO %I" in bootstrap
    assert "GRANT SELECT ON ALL TABLES IN SCHEMA budget_audit TO %I" in bootstrap
    assert "IN SCHEMA budget_audit GRANT SELECT ON TABLES TO %I" in bootstrap
    assert "IN SCHEMA public GRANT SELECT ON TABLES TO %I" in bootstrap
    assert bootstrap.count("GRANT USAGE, SELECT ON SEQUENCES TO %I") == 3
    assert "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA budget_audit TO %I" in bootstrap
    assert "REVOKE ALL ON SCHEMA budget_audit FROM PUBLIC" in bootstrap
    assert "REVOKE ALL ON ALL TABLES IN SCHEMA budget_audit" in bootstrap
    assert "tablename IN ('audit_auditevent', 'audit_audithead', 'audit_auditcheckpoint')" in (
        bootstrap
    )
    assert "TO budget_runtime_access, budget_audit_reader'" in bootstrap
    assert "REVOKE ALL ON ALL FUNCTIONS IN SCHEMA budget_audit" in bootstrap
    assert "TO budget_runtime_access'" in bootstrap
    assert "TO budget_audit_reader'" in bootstrap
    assert bootstrap.count("REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC") == 2
    assert "BUDGET_NEW_DATABASE_PASSWORD" in admin_rotation
    assert "ALTER ROLE %I PASSWORD %L" in admin_rotation
    assert "--no-password" in admin_rotation
    assert "PGPASSWORD=" in admin_rotation
    assert '--command "SELECT 1"' in admin_rotation
    assert "retired credential still authenticates" in admin_rotation
    assert "GRANT pg_read_all_data" not in bootstrap
    assert "PASSWORD NULL" in bootstrap
    assert "rolpassword IS NOT NULL" in bootstrap
    assert "PGPASSWORD" not in bootstrap


def test_container_does_not_enable_raw_access_logging() -> None:
    dockerfile = (PROJECT_ROOT / "Dockerfile").read_text(encoding="utf-8")
    dockerignore = set((PROJECT_ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines())

    assert "USER budget" in dockerfile
    assert "adduser -u 10001" in dockerfile
    assert "python:3.12-alpine@sha256:" in dockerfile
    assert "apk upgrade --no-cache" in dockerfile
    assert "--access-logfile" not in dockerfile
    assert {".env*", "secrets", "local-test-secrets"}.issubset(dockerignore)

    relay_configuration = (PROJECT_ROOT / "deploy/network/nginx.conf").read_text(encoding="utf-8")
    assert "access_log off" in relay_configuration
    assert "proxy_pass https://web:8443" in relay_configuration
    assert "proxy_ssl_verify on" in relay_configuration
    assert "proxy_ssl_name web" in relay_configuration
    assert "proxy_ssl_certificate /run/secrets/nginx_client_certificate" in relay_configuration
    assert "default http;" in relay_configuration
    assert "~^https$ https;" in relay_configuration
    assert "proxy_set_header X-Forwarded-Proto $upstream_forwarded_proto" in relay_configuration
    assert 'proxy_set_header X-Forwarded-For ""' in relay_configuration


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

    notification_service = (
        PROJECT_ROOT / "deploy/systemd/household-budget-notifications.service"
    ).read_text(encoding="utf-8")
    notification_timer = (
        PROJECT_ROOT / "deploy/systemd/household-budget-notifications.timer"
    ).read_text(encoding="utf-8")
    assert "docker compose --profile maintenance run --rm notify" in notification_service
    assert "UMask=0077" in notification_service
    assert "OnUnitActiveSec=30m" in notification_timer
    assert "Persistent=true" in notification_timer

    import_cleanup_service = (
        PROJECT_ROOT / "deploy/systemd/household-budget-import-cleanup.service"
    ).read_text(encoding="utf-8")
    import_cleanup_timer = (
        PROJECT_ROOT / "deploy/systemd/household-budget-import-cleanup.timer"
    ).read_text(encoding="utf-8")
    assert "docker compose --profile maintenance run --rm import-cleanup" in import_cleanup_service
    assert "UMask=0077" in import_cleanup_service
    assert "OnUnitActiveSec=1h" in import_cleanup_timer
    assert "Persistent=true" in import_cleanup_timer
    assert "RandomizedDelaySec=5m" in import_cleanup_timer


def test_import_cleanup_uses_the_runtime_database_identity() -> None:
    compose = yaml.safe_load((PROJECT_ROOT / "compose.yaml").read_text(encoding="utf-8"))
    cleanup = compose["services"]["import-cleanup"]

    assert cleanup["profiles"] == ["maintenance"]
    assert cleanup["command"] == ["python", "manage.py", "cleanup_stale_imports"]
    assert cleanup["environment"]["POSTGRES_USER"] == ("${POSTGRES_RUNTIME_USER:-budget_runtime}")
    assert cleanup["read_only"] is True
    assert cleanup["cap_drop"] == ["ALL"]
    assert cleanup["networks"] == ["backend"]


def test_ci_uses_read_only_permissions_and_immutable_official_actions() -> None:
    workflow = (PROJECT_ROOT / ".github/workflows/quality.yml").read_text(encoding="utf-8")

    assert "pull_request_target" not in workflow
    assert "permissions:\n  contents: read" in workflow
    assert "persist-credentials: false" in workflow
    assert "pip_audit --requirement requirements-dev.lock" in workflow
    assert "--cache-dir .pip-audit-cache --no-deps --disable-pip --strict" in workflow
    assert "docker compose --profile maintenance --profile recovery config --quiet" in workflow
    assert "docker build --tag household-budget:${{ github.sha }} ." in workflow
    assert "docker build --file deploy/network/Dockerfile" in workflow
    assert "household-budget-ingress:${{ github.sha }}" in workflow
    assert "docker build --file deploy/backup/Dockerfile" in workflow
    assert "household-budget-backup:${{ github.sha }}" in workflow
    assert "aquasec/trivy:0.70.0@sha256:" in workflow
    assert "image --scanners vuln,secret --severity HIGH,CRITICAL --exit-code 1" in workflow
    assert "--volume /var/run/docker.sock:/var/run/docker.sock" in workflow
    assert "image --format cyclonedx --output" in workflow
    assert "name: release-image-sboms-${{ github.sha }}" in workflow
    assert "retention-days: 90" in workflow

    action_references = re.findall(r"uses: ([^\s#]+)", workflow)
    assert {reference.split("@")[0] for reference in action_references} == {
        "actions/checkout",
        "actions/setup-python",
        "actions/upload-artifact",
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
