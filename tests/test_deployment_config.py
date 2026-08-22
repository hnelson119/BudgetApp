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

    forbidden_keys = {"DJANGO_SECRET_KEY", "POSTGRES_PASSWORD"}
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

    assert set(web["secrets"]) == {"django_secret_key", "postgres_runtime_password"}
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
