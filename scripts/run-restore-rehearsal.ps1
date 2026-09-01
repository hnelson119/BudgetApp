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
    & wsl.exe sh -lc "cd '$wslProjectRoot' && sh ./scripts/run-restore-rehearsal.sh"
    exit $LASTEXITCODE
}

$composeFile = Join-Path $projectRoot "compose.pentest.yaml"
$projectName = "budgetapp-restore-rehearsal"
$restoreTarget = "household_budget_pentest_restore_rehearsal"
$composePrefix = @(
    "compose", "-p", $projectName, "-f", $composeFile, "--profile", "restore"
)

& docker @composePrefix down --volumes --remove-orphans
if ($LASTEXITCODE -ne 0) {
    throw "Unable to clear the fixed disposable restore-rehearsal project."
}

try {
    & docker @composePrefix build `
        pentest-migrate `
        pentest-seed `
        pentest-web `
        pentest-fixture-verify `
        pentest-backup `
        pentest-restore-verify `
        pentest-restore-source-advance `
        pentest-restore-audit
    if ($LASTEXITCODE -ne 0) {
        throw "The disposable restore-rehearsal images failed to build."
    }
    & docker @composePrefix up --no-build --wait pentest-web
    if ($LASTEXITCODE -ne 0) {
        throw "The disposable restore-rehearsal application failed to start."
    }
    & docker @composePrefix run --rm --no-deps pentest-fixture-verify
    if ($LASTEXITCODE -ne 0) {
        throw "The disposable multi-household fixture verification failed."
    }
    & docker @composePrefix run --rm --no-deps pentest-restore-storage-init
    if ($LASTEXITCODE -ne 0) {
        throw "The disposable encrypted repository could not be initialized."
    }
    & docker @composePrefix run --rm --no-deps pentest-restore-audit `
        python manage.py write_audit_checkpoints
    if ($LASTEXITCODE -ne 0) {
        throw "The pre-backup signed checkpoints could not be written."
    }
    & docker @composePrefix run --rm --no-deps pentest-backup
    if ($LASTEXITCODE -ne 0) {
        throw "The disposable encrypted backup failed."
    }
    & docker @composePrefix run --rm --no-deps pentest-backup `
        /bin/sh /opt/pentest/verify-encrypted-repository.sh
    if ($LASTEXITCODE -ne 0) {
        throw "The encrypted repository plaintext check failed."
    }
    & docker @composePrefix run --rm --no-deps pentest-restore-source-advance
    if ($LASTEXITCODE -ne 0) {
        throw "The post-backup source advance failed."
    }
    & docker @composePrefix run --rm --no-deps pentest-restore-audit
    if ($LASTEXITCODE -ne 0) {
        throw "The stale source checkpoint was not rejected safely."
    }

    & docker @composePrefix run --rm --no-deps `
        -e RESTORE_TARGET_DB=household_budget_pentest pentest-restore-verify
    if ($LASTEXITCODE -eq 0) {
        throw "The restore rehearsal unexpectedly accepted the live database target."
    }

    & docker @composePrefix run --rm --no-deps `
        -e RESTORE_TARGET_DB=$restoreTarget pentest-restore-verify
    if ($LASTEXITCODE -ne 0) {
        throw "The encrypted snapshot could not be restored into a new target."
    }
    & docker @composePrefix run --rm --no-deps `
        -e RESTORE_TARGET_DB=$restoreTarget pentest-restore-verify
    if ($LASTEXITCODE -eq 0) {
        throw "The restore rehearsal unexpectedly overwrote an existing target."
    }

    & docker @composePrefix run --rm --no-deps `
        -e POSTGRES_DB=$restoreTarget pentest-db-bootstrap
    if ($LASTEXITCODE -ne 0) {
        throw "Least-privilege roles could not be applied to the restored target."
    }
    & docker @composePrefix run --rm --no-deps `
        -e POSTGRES_DB=$restoreTarget `
        -e PENTEST_RESTORE_EXPECTATION=restored-match `
        pentest-fixture-verify
    if ($LASTEXITCODE -ne 0) {
        throw "The restored multi-household fixture verification failed."
    }
    & docker @composePrefix run --rm --no-deps `
        -e POSTGRES_DB=$restoreTarget `
        -e PENTEST_RESTORE_EXPECTATION=restored-match `
        pentest-restore-audit
    if ($LASTEXITCODE -ne 0) {
        throw "The restored audit chains did not match their signed checkpoints."
    }
}
finally {
    & docker @composePrefix down --volumes --remove-orphans
    if ($LASTEXITCODE -ne 0) {
        Write-Error "The fixed disposable restore-rehearsal project could not be fully removed."
    }
}

Write-Host "Disposable encrypted backup, restore, and signed-checkpoint rehearsal completed."
