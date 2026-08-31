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
    & wsl.exe sh -lc "cd '$wslProjectRoot' && sh ./scripts/run-audit-integrity.sh"
    exit $LASTEXITCODE
}

$composeFile = Join-Path $projectRoot "compose.pentest.yaml"
$projectName = "budgetapp-audit-integrity"
$composePrefix = @(
    "compose", "-p", $projectName, "-f", $composeFile, "--profile", "audit"
)

& docker @composePrefix down --volumes --remove-orphans
if ($LASTEXITCODE -ne 0) {
    throw "Unable to clear the fixed disposable audit-integrity project."
}

try {
    & docker @composePrefix up --build --wait pentest-web
    if ($LASTEXITCODE -ne 0) {
        throw "The disposable audit-integrity application failed to start."
    }
    & docker @composePrefix run --rm --no-deps pentest-fixture-verify
    if ($LASTEXITCODE -ne 0) {
        throw "The disposable multi-household fixture verification failed."
    }
    & docker @composePrefix run --build --rm --no-deps `
        -e PENTEST_AUDIT_SCENARIO=AUDIT-01 pentest-audit-runtime
    if ($LASTEXITCODE -ne 0) {
        throw "The runtime-role mutation-denial probes failed."
    }
    & docker @composePrefix run --build --rm --no-deps `
        -e PENTEST_AUDIT_SCENARIO=AUDIT-02 pentest-audit-checkpoint
    if ($LASTEXITCODE -ne 0) {
        throw "The audit chain-corruption probes failed."
    }
    & docker @composePrefix run --build --rm --no-deps `
        -e PENTEST_AUDIT_SCENARIO=AUDIT-03 pentest-audit-runtime
    if ($LASTEXITCODE -ne 0) {
        throw "The audit-append rollback probes failed."
    }
    & docker @composePrefix run --build --rm --no-deps `
        -e PENTEST_AUDIT_SCENARIO=AUDIT-04 pentest-audit-checkpoint
    if ($LASTEXITCODE -ne 0) {
        throw "The checkpoint and restore-mismatch probes failed."
    }
}
finally {
    & docker @composePrefix down --volumes --remove-orphans
    if ($LASTEXITCODE -ne 0) {
        Write-Error "The fixed disposable audit-integrity project could not be fully removed."
    }
}

Write-Host "Disposable audit-integrity probes completed."
