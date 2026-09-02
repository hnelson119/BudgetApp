from __future__ import annotations

import re
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _read(path: str) -> str:
    return (PROJECT_ROOT / path).read_text(encoding="utf-8")


def test_upgrade_services_are_isolated_and_use_separate_database_roles() -> None:
    services = yaml.safe_load(_read("compose.pentest.yaml"))["services"]
    migration = services["pentest-upgrade-migrate"]
    candidate = services["pentest-upgrade-candidate-web"]
    rollback = services["pentest-upgrade-rollback-web"]
    verifier = services["pentest-upgrade-verify"]

    for service in (migration, candidate, rollback, verifier):
        assert service["profiles"] == ["upgrade"]
        assert service["read_only"] is True
        assert service["cap_drop"] == ["ALL"]
        assert service["security_opt"] == ["no-new-privileges:true"]
        assert "ports" not in service

    assert migration["environment"]["POSTGRES_USER"] == "budget_migration"
    assert verifier["environment"]["POSTGRES_USER"] == "budget_backup"
    assert verifier["environment"]["POSTGRES_PASSWORD_FILE"].endswith("postgres_backup_password")
    assert candidate["environment"]["POSTGRES_USER"] == "budget_runtime"
    assert rollback["environment"]["POSTGRES_USER"] == "budget_runtime"
    assert candidate["environment"]["POSTGRES_DB"] == "household_budget_pentest"
    assert rollback["environment"]["POSTGRES_DB"] == (
        "household_budget_pentest_restore_upgrade_rollback"
    )
    assert rollback["environment"]["PENTEST_RESTORE_EXPECTATION"] == ("upgrade-restored-match")
    migration_mount = (
        "./deploy/pentest/upgrade_probe_migration.py:"
        "/app/notifications/migrations/0002_upgrade_rehearsal_marker.py:ro"
    )
    assert migration_mount in migration["volumes"]
    assert migration_mount in candidate["volumes"]
    assert migration_mount not in rollback["volumes"]
    assert verifier["environment"]["PENTEST_UPGRADE_PROBE_GUARD"] == (
        "yes-i-understand-upgrade-probes-use-only-disposable-data"
    )


def test_upgrade_probe_is_additive_bounded_and_not_a_production_migration() -> None:
    migration = _read("deploy/pentest/upgrade_probe_migration.py")
    verifier = _read("deploy/pentest/verify-upgrade-rollback.py")

    assert not (PROJECT_ROOT / "notifications/migrations/0002_upgrade_rehearsal_marker.py").exists()
    assert "CREATE TABLE public.pentest_upgrade_rehearsal_marker" in migration
    assert "REVOKE ALL" in migration
    assert "GRANT SELECT" in migration
    assert "DROP TABLE IF EXISTS" in migration
    assert "PENTEST_UPGRADE_PROBE_GUARD" in verifier
    assert 'database.get("HOST") == "pentest-db"' in verifier
    assert '_current_role() == "budget_backup"' in verifier
    assert "candidate-source" in verifier
    assert "restored-baseline" in verifier
    assert "UPGRADE-01" in verifier and "ROLLBACK-01" in verifier
    assert "print(row" not in verifier


def test_pentest_settings_allow_only_the_named_upgrade_rollback_database() -> None:
    settings = _read("config/settings/pentest.py")

    expected_guard = '"upgrade-restored-match": "household_budget_pentest_restore_upgrade_rollback"'
    assert expected_guard in settings
    assert "restored_database_by_expectation.get(" in settings


def test_upgrade_runner_backs_up_before_migration_and_restores_to_a_new_target() -> None:
    powershell = _read("scripts/run-upgrade-rehearsal.ps1")
    shell = _read("scripts/run-upgrade-rehearsal.sh")

    for runner in (powershell, shell):
        assert "budgetapp-upgrade-rehearsal" in runner
        assert "--profile" in runner and "upgrade" in runner
        assert "pentest-upgrade-migrate" in runner
        assert "pentest-upgrade-candidate-web" in runner
        assert "pentest-upgrade-rollback-web" in runner
        assert "pentest-upgrade-verify" in runner
        assert "write_audit_checkpoints" in runner
        assert "pentest-backup" in runner
        assert "verify-encrypted-repository.sh" in runner
        assert "household_budget_pentest_restore_upgrade_rollback" in runner
        assert "upgrade-restored-match" in runner
        restored_schema_check = re.compile(
            r"PENTEST_RESTORE_EXPECTATION=upgrade-restored-match[\s\\`]+"
            r"(?:-e )?PENTEST_UPGRADE_EXPECTATION=restored-baseline"
        )
        assert restored_schema_check.search(runner)
        expected_restic_password_file = (
            "RESTIC_PASSWORD_FILE="
            "/run/secrets/restic_repository_password"  # pragma: allowlist secret
        )
        assert expected_restic_password_file in runner
        assert runner.index("pentest-backup") < runner.index("pentest-upgrade-migrate")
        assert "migrate notifications 0001" not in runner
        assert "down" in runner and "--volumes" in runner and "--remove-orphans" in runner
        assert "--no-build" in runner
    assert "PENTEST_BUILD_CONTEXT" in shell
    assert "/tmp/budgetapp-upgrade-rehearsal." in shell
    assert "trap cleanup" in shell
    assert "finally" in powershell


def test_upgrade_rehearsal_ci_is_read_only_and_pinned() -> None:
    workflow = _read(".github/workflows/upgrade-rehearsal.yml")

    assert re.search(r"^  pull_request:$", workflow, re.MULTILINE)
    assert re.search(r"^  workflow_dispatch:$", workflow, re.MULTILINE)
    assert "pull_request_target" not in workflow
    assert re.search(r"^permissions:\n  contents: read$", workflow, re.MULTILINE)
    assert re.search(r"actions/checkout@[0-9a-f]{40}", workflow)
    assert "persist-credentials: false" in workflow
    assert "sh scripts/run-upgrade-rehearsal.sh" in workflow
