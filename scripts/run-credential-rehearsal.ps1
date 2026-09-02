[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot

function Remove-WslIncompatibleBuildCaches {
    param([Parameter(Mandatory = $true)][string]$Root)

    foreach ($name in @(".pytest-tmp", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".pip-audit-cache")) {
        $expectedPath = [IO.Path]::GetFullPath((Join-Path $Root $name))
        if (-not (Test-Path -LiteralPath $expectedPath)) {
            continue
        }
        $item = Get-Item -LiteralPath $expectedPath -Force
        if (
            -not $item.PSIsContainer -or
            ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            -not $item.FullName.Equals($expectedPath, [StringComparison]::OrdinalIgnoreCase)
        ) {
            throw "Refusing to remove an unexpected Docker build-cache path."
        }
        Remove-Item -LiteralPath $expectedPath -Recurse -Force
    }
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Remove-WslIncompatibleBuildCaches -Root $projectRoot
    $wslProjectRoot = (& wsl.exe wslpath -a $projectRoot).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $wslProjectRoot) {
        throw "Docker is not on the Windows path and the project path could not be mapped into WSL."
    }
    if ($wslProjectRoot.Contains("'")) {
        throw "The WSL project path cannot contain an apostrophe."
    }
    & wsl.exe sh -lc "cd '$wslProjectRoot' && sh ./scripts/run-credential-rehearsal.sh"
    exit $LASTEXITCODE
}

$composeFile = Join-Path $projectRoot "compose.pentest.yaml"
$projectName = "budgetapp-credential-rehearsal"
$composePrefix = @(
    "compose", "-p", $projectName, "-f", $composeFile, "--profile", "rotation"
)

& docker @composePrefix down --volumes --remove-orphans
if ($LASTEXITCODE -ne 0) {
    throw "Unable to clear the fixed disposable credential-rehearsal project."
}

try {
    & docker @composePrefix up --build --wait pentest-web
    if ($LASTEXITCODE -ne 0) {
        throw "The disposable credential-rehearsal application failed to start."
    }
    & docker @composePrefix run --rm --no-deps pentest-fixture-verify
    if ($LASTEXITCODE -ne 0) {
        throw "The disposable multi-household fixture verification failed."
    }
    & docker @composePrefix run --rm --no-deps pentest-auth-sessions
    if ($LASTEXITCODE -ne 0) {
        throw "Disposable password-and-TOTP session creation failed."
    }
    & docker @composePrefix run --rm --no-deps pentest-mfa-key-rotate
    if ($LASTEXITCODE -ne 0) {
        throw "The disposable MFA encryption-key rotation failed."
    }
    & docker @composePrefix stop pentest-web
    if ($LASTEXITCODE -ne 0) {
        throw "The pre-rotation application could not be stopped."
    }
    & docker @composePrefix up --build --wait --no-deps pentest-web-rotated
    if ($LASTEXITCODE -ne 0) {
        throw "The rotated-key application failed to start."
    }
    & docker @composePrefix run --build --rm --no-deps pentest-credential-rehearsal
    if ($LASTEXITCODE -ne 0) {
        throw "The disposable lost-device and credential-rotation probes failed."
    }
    & docker @composePrefix run --rm --no-deps pentest-db-admin-key-rotate
    if ($LASTEXITCODE -ne 0) {
        throw "The disposable PostgreSQL administrator credential rotation failed."
    }
}
finally {
    & docker @composePrefix down --volumes --remove-orphans
    if ($LASTEXITCODE -ne 0) {
        Write-Error "The fixed disposable credential-rehearsal project could not be fully removed."
    }
}

Write-Host "Disposable lost-device and credential-rotation rehearsal completed."
