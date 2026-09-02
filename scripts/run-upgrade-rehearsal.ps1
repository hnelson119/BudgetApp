[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    $wslProjectRoot = (& wsl.exe wslpath -a $projectRoot).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $wslProjectRoot) {
        throw "Docker is not on the Windows path and the project path could not be mapped into WSL."
    }
    if ($wslProjectRoot.Contains("'")) {
        throw "The WSL project path cannot contain an apostrophe."
    }
    & wsl.exe sh -lc "cd '$wslProjectRoot' && sh ./scripts/run-upgrade-rehearsal.sh"
    exit $LASTEXITCODE
}

$composeFile = Join-Path $projectRoot "compose.pentest.yaml"
$projectName = "budgetapp-upgrade-rehearsal"
$rollbackTarget = "household_budget_pentest_restore_upgrade_rollback"
$composePrefix = @(
    "compose", "-p", $projectName, "-f", $composeFile, "--profile", "upgrade"
)
$previousBackupRelease = $env:PENTEST_BACKUP_RELEASE
$env:PENTEST_BACKUP_RELEASE = "pentest-upgrade-baseline"

& docker @composePrefix down --volumes --remove-orphans
if ($LASTEXITCODE -ne 0) {
    throw "Unable to clear the fixed disposable upgrade-rehearsal project."
}

try {
    & docker @composePrefix build `
        pentest-migrate `
        pentest-seed `
        pentest-web `
        pentest-fixture-verify `
        pentest-backup `
        pentest-restore-verify `
        pentest-restore-audit `
        pentest-upgrade-migrate `
        pentest-upgrade-candidate-web `
        pentest-upgrade-rollback-web `
        pentest-upgrade-verify
    if ($LASTEXITCODE -ne 0) { throw "The disposable upgrade images failed to build." }

    & docker @composePrefix up --no-build --wait pentest-web
    if ($LASTEXITCODE -ne 0) { throw "The baseline application failed to start." }
    & docker @composePrefix run --rm --no-deps pentest-fixture-verify
    if ($LASTEXITCODE -ne 0) { throw "The baseline fixture verification failed." }
    & docker @composePrefix run --rm --no-deps pentest-restore-storage-init
    if ($LASTEXITCODE -ne 0) { throw "The rollback repository could not be initialized." }
    & docker @composePrefix run --rm --no-deps pentest-restore-audit `
        python manage.py write_audit_checkpoints
    if ($LASTEXITCODE -ne 0) { throw "The pre-upgrade checkpoints could not be written." }
    & docker @composePrefix run --rm --no-deps pentest-backup
    if ($LASTEXITCODE -ne 0) { throw "The pre-upgrade encrypted backup failed." }
    & docker @composePrefix run --rm --no-deps pentest-backup `
        /bin/sh /opt/pentest/verify-encrypted-repository.sh
    if ($LASTEXITCODE -ne 0) { throw "The encrypted rollback repository check failed." }

    & docker @composePrefix stop pentest-web
    if ($LASTEXITCODE -ne 0) { throw "The baseline application could not be stopped." }
    & docker @composePrefix run --rm --no-deps pentest-upgrade-migrate
    if ($LASTEXITCODE -ne 0) { throw "The candidate migration failed." }
    & docker @composePrefix run --rm --no-deps pentest-upgrade-verify
    if ($LASTEXITCODE -ne 0) { throw "The candidate schema verification failed." }
    & docker @composePrefix up --no-build --wait --no-deps pentest-upgrade-candidate-web
    if ($LASTEXITCODE -ne 0) { throw "The candidate application failed to become healthy." }
    & docker @composePrefix run --rm --no-deps pentest-fixture-verify
    if ($LASTEXITCODE -ne 0) { throw "The candidate fixture verification failed." }
    & docker @composePrefix run --rm --no-deps `
        -e PENTEST_RESTORE_EXPECTATION=source-match pentest-restore-audit
    if ($LASTEXITCODE -ne 0) { throw "The candidate audit chains changed unexpectedly." }

    & docker @composePrefix stop pentest-upgrade-candidate-web
    if ($LASTEXITCODE -ne 0) { throw "The candidate application could not be stopped." }
    & docker @composePrefix up --no-build --wait --no-deps pentest-web
    if ($LASTEXITCODE -ne 0) { throw "The baseline app could not use the additive schema." }
    & docker @composePrefix run --rm --no-deps pentest-fixture-verify
    if ($LASTEXITCODE -ne 0) { throw "The app-only rollback fixture verification failed." }
    & docker @composePrefix run --rm --no-deps pentest-upgrade-verify
    if ($LASTEXITCODE -ne 0) { throw "The app-only rollback changed candidate schema state." }
    & docker @composePrefix stop pentest-web
    if ($LASTEXITCODE -ne 0) { throw "The app-only rollback service could not be stopped." }

    & docker @composePrefix run --rm --no-deps `
        -e RESTIC_PASSWORD_FILE=/run/secrets/restic_repository_password `
        -e RESTORE_TARGET_DB=$rollbackTarget `
        pentest-restore-verify
    if ($LASTEXITCODE -ne 0) { throw "The pre-upgrade snapshot could not be restored." }
    & docker @composePrefix run --rm --no-deps `
        -e RESTIC_PASSWORD_FILE=/run/secrets/restic_repository_password `
        -e RESTORE_TARGET_DB=$rollbackTarget `
        pentest-restore-verify
    if ($LASTEXITCODE -eq 0) {
        throw "The upgrade rehearsal unexpectedly overwrote its rollback database."
    }

    & docker @composePrefix run --rm --no-deps `
        -e POSTGRES_DB=$rollbackTarget pentest-db-bootstrap
    if ($LASTEXITCODE -ne 0) { throw "Rollback database roles could not be reapplied." }
    & docker @composePrefix run --rm --no-deps `
        -e POSTGRES_DB=$rollbackTarget `
        -e PENTEST_RESTORE_EXPECTATION=upgrade-restored-match `
        pentest-fixture-verify
    if ($LASTEXITCODE -ne 0) { throw "The rollback fixture verification failed." }
    & docker @composePrefix run --rm --no-deps `
        -e POSTGRES_DB=$rollbackTarget `
        -e PENTEST_RESTORE_EXPECTATION=upgrade-restored-match `
        pentest-restore-audit
    if ($LASTEXITCODE -ne 0) { throw "The rollback audit checkpoint verification failed." }
    & docker @composePrefix run --rm --no-deps `
        -e POSTGRES_DB=$rollbackTarget `
        -e PENTEST_RESTORE_EXPECTATION=upgrade-restored-match `
        -e PENTEST_UPGRADE_EXPECTATION=restored-baseline `
        pentest-upgrade-verify
    if ($LASTEXITCODE -ne 0) { throw "The restored baseline schema verification failed." }
    & docker @composePrefix up --no-build --wait --no-deps pentest-upgrade-rollback-web
    if ($LASTEXITCODE -ne 0) { throw "The restored baseline application failed to become healthy." }
    & docker @composePrefix run --rm --no-deps `
        -e POSTGRES_DB=$rollbackTarget `
        -e PENTEST_RESTORE_EXPECTATION=upgrade-restored-match `
        pentest-fixture-verify
    if ($LASTEXITCODE -ne 0) { throw "The live rollback fixture verification failed." }
}
finally {
    & docker @composePrefix down --volumes --remove-orphans
    if ($LASTEXITCODE -ne 0) {
        Write-Error "The fixed disposable upgrade-rehearsal project could not be fully removed."
    }
    $env:PENTEST_BACKUP_RELEASE = $previousBackupRelease
}

Write-Host "Disposable forward-upgrade and clean-database rollback rehearsal completed."
