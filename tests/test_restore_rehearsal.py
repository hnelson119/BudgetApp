from __future__ import annotations

import re
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _read(path: str) -> str:
    return (PROJECT_ROOT / path).read_text(encoding="utf-8")


def test_restore_rehearsal_uses_production_backup_paths_and_disposable_storage() -> None:
    compose = yaml.safe_load(_read("compose.pentest.yaml"))
    services = compose["services"]
    storage = services["pentest-restore-storage-init"]
    backup = services["pentest-backup"]
    rotation = services["pentest-restic-key-rotate"]
    restore = services["pentest-restore-verify"]

    assert "pentest_backup_repository" in compose["volumes"]
    assert storage["profiles"] == ["restore", "upgrade"]
    assert storage["network_mode"] == "none"
    assert storage["read_only"] is True
    assert storage["cap_drop"] == ["ALL"]
    assert storage["cap_add"] == ["CHOWN"]
    assert "pentest_backup_repository:/repository" in storage["volumes"]

    for service in (backup, restore):
        assert service["profiles"] == ["restore", "upgrade"]
        assert service["build"]["dockerfile"] == "deploy/backup/Dockerfile"
        assert service["networks"] == ["pentest_backend"]
        assert service["read_only"] is True
        assert service["user"] == "postgres"
        assert service["cap_drop"] == ["ALL"]
        assert service["security_opt"] == ["no-new-privileges:true"]
        assert "pentest_secrets:/run/secrets:ro" in service["volumes"]
        assert "ports" not in service
    assert "pentest_backup_repository:/repository" in backup["volumes"]
    assert "pentest_backup_repository:/repository:ro" in restore["volumes"]
    assert backup["command"] == ["/usr/local/bin/backup.sh"]
    assert restore["command"] == ["/usr/local/bin/restore-verify.sh"]
    assert rotation["command"] == ["/usr/local/bin/rotate-restic-key.sh"]
    assert rotation["profiles"] == ["restore"]
    assert rotation["network_mode"] == "none"
    assert rotation["read_only"] is True
    assert rotation["user"] == "postgres"
    assert "pentest_secrets:/run/secrets:ro" in rotation["volumes"]
    assert "pentest_backup_repository:/repository" in rotation["volumes"]
    assert rotation["environment"]["RESTIC_NEW_PASSWORD_FILE"].endswith(
        "restic_repository_password_next"
    )
    assert restore["environment"]["RESTIC_PASSWORD_FILE"].endswith(
        "restic_repository_password_next"
    )
    assert backup["environment"]["APP_RELEASE"] == (
        "${PENTEST_BACKUP_RELEASE:-pentest-restore-rehearsal}"
    )
    assert backup["environment"]["PENTEST_EXPECTED_BACKUP_RELEASE"] == (
        "${PENTEST_BACKUP_RELEASE:-pentest-restore-rehearsal}"
    )
    assert restore["environment"]["RESTORE_TARGET_DB"] == (
        "household_budget_pentest_restore_rehearsal"
    )
    assert all(
        "pentest_backup_repository" not in volume
        for volume in services["pentest-web"].get("volumes", [])
    )


def test_restore_rehearsal_separates_runtime_advance_from_audit_verification() -> None:
    services = yaml.safe_load(_read("compose.pentest.yaml"))["services"]
    advance = services["pentest-restore-source-advance"]
    audit = services["pentest-restore-audit"]

    assert advance["environment"]["POSTGRES_USER"] == "budget_runtime"
    assert advance["environment"]["DJANGO_SETTINGS_MODULE"] == "config.settings.pentest"
    assert "pentest_fixture:/run/pentest-fixture:ro" in advance["volumes"]
    assert all("pentest_checkpoints" not in volume for volume in advance["volumes"])
    assert audit["environment"]["POSTGRES_USER"] == "budget_audit"
    assert audit["environment"]["DJANGO_SETTINGS_MODULE"] == "config.settings.integrity"
    assert audit["environment"]["PENTEST_RESTORE_EXPECTATION"] == "source-diverged"
    assert "pentest_checkpoints:/run/pentest-checkpoints" in audit["volumes"]
    assert all("pentest_backup_repository" not in volume for volume in audit["volumes"])
    assert advance["profiles"] == ["restore"]
    assert audit["profiles"] == ["restore", "upgrade"]
    for service in (advance, audit):
        assert service["networks"] == ["pentest_backend"]
        assert service["read_only"] is True
        assert service["cap_drop"] == ["ALL"]
        assert service["security_opt"] == ["no-new-privileges:true"]
        assert service["environment"]["PENTEST_RESTORE_PROBE_GUARD"] == (
            "yes-i-understand-restore-probes-mutate-disposable-data"
        )


def test_restore_probes_are_bounded_and_emit_only_sanitized_outcomes() -> None:
    storage = _read("deploy/pentest/prepare-restore-storage.py")
    advance = _read("deploy/pentest/advance-restore-source.py")
    verify = _read("deploy/pentest/verify-restored-backup.py")
    encrypted = _read("deploy/pentest/verify-encrypted-repository.sh")
    generator = _read("deploy/pentest/generate-secrets.py")

    assert "any(REPOSITORY.iterdir())" in storage
    assert "os.chown(REPOSITORY, POSTGRES_UID, POSTGRES_GID)" in storage
    assert storage.index("os.chmod(REPOSITORY, 0o700)") < storage.index("os.chown(REPOSITORY")
    assert "PENTEST_RESTORE_PROBE_GUARD" in advance
    assert 'database.get("NAME") == _EXPECTED_DATABASE' in advance
    assert '_current_role() == "budget_runtime"' in advance
    assert "verify_household_chain(household).valid" in advance
    assert "source-diverged" in verify and "restored-match" in verify
    assert "source-match" in verify and "upgrade-restored-match" in verify
    assert '_current_role() == "budget_audit"' in verify
    assert "verify_audit_checkpoint" in verify
    assert "django_migrations" not in verify
    assert "does not match the database audit head" in verify
    assert "set(checkpoints) != set(households.values())" in verify
    assert "Synthetic Household" in encrypted
    assert "PENTEST_EXPECTED_BACKUP_RELEASE" in encrypted
    assert "for secret_file in /run/secrets/*" in encrypted
    assert "grep -a -F -r -q" in encrypted
    assert '"restic_repository_password"' in generator
    assert '"restic_repository_password_next"' in generator
    assert "print(household" not in advance + verify
    assert "print(manifest" not in advance + verify


def test_restore_runner_refuses_live_and_existing_targets_and_always_cleans_up() -> None:
    powershell = _read("scripts/run-restore-rehearsal.ps1")
    shell = _read("scripts/run-restore-rehearsal.sh")

    for runner in (powershell, shell):
        assert "budgetapp-restore-rehearsal" in runner
        assert "--profile" in runner and "restore" in runner
        assert "down" in runner and "--volumes" in runner and "--remove-orphans" in runner
        assert "pentest-fixture-verify" in runner
        assert "pentest-restore-storage-init" in runner
        assert "write_audit_checkpoints" in runner
        assert "pentest-backup" in runner
        assert "verify-encrypted-repository.sh" in runner
        assert "pentest-restic-key-rotate" in runner
        assert "pentest-restore-source-advance" in runner
        assert "household_budget_pentest_restore_rehearsal" in runner
        assert "household_budget_pentest" in runner
        assert "pentest-db-bootstrap" in runner
        assert "PENTEST_RESTORE_EXPECTATION=restored-match" in runner
        assert runner.count("pentest-fixture-verify") >= 3
        assert runner.count("pentest-restore-verify") >= 3
        assert "pentest-restore-source-advance" in runner
        assert "pentest-restore-audit" in runner
        assert "--no-build" in runner
    assert "PENTEST_BUILD_CONTEXT" in shell
    assert "git -C" in shell and "ls-files" in shell
    assert "--exclude-standard" in shell
    assert "/tmp/budgetapp-restore-rehearsal." in shell
    assert "trap cleanup" in shell
    assert "finally" in powershell


def test_restore_rehearsal_ci_is_read_only_and_pinned() -> None:
    workflow = _read(".github/workflows/restore-rehearsal.yml")

    assert re.search(r"^  pull_request:$", workflow, re.MULTILINE)
    assert re.search(r"^  workflow_dispatch:$", workflow, re.MULTILINE)
    assert "pull_request_target" not in workflow
    assert re.search(r"^permissions:\n  contents: read$", workflow, re.MULTILINE)
    assert re.search(r"actions/checkout@[0-9a-f]{40}", workflow)
    assert "persist-credentials: false" in workflow
    assert "sh scripts/run-restore-rehearsal.sh" in workflow
