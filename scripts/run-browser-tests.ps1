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
    & wsl.exe sh -lc "cd '$wslProjectRoot' && sh ./scripts/run-browser-tests.sh"
    exit $LASTEXITCODE
}

$composeFile = Join-Path $projectRoot "compose.pentest.yaml"
$projectName = "budgetapp-browser"
$composePrefix = @("compose", "-p", $projectName, "-f", $composeFile, "--profile", "browser")

& docker @composePrefix down --volumes --remove-orphans
if ($LASTEXITCODE -ne 0) {
    throw "Unable to clear the fixed disposable browser-test project."
}

try {
    & docker @composePrefix build browser-tests
    if ($LASTEXITCODE -ne 0) {
        throw "The pinned browser-test image failed to build or pass its npm audit."
    }
    & docker @composePrefix up --build --wait pentest-web
    if ($LASTEXITCODE -ne 0) {
        throw "The disposable browser-test application failed to start."
    }
    & docker @composePrefix run --rm --no-deps browser-credentials-init
    if ($LASTEXITCODE -ne 0) {
        throw "Scoped disposable browser credential preparation failed."
    }
    & docker @composePrefix run --rm --no-deps browser-tests
    if ($LASTEXITCODE -ne 0) {
        throw "One or more isolated browser checks failed."
    }
}
finally {
    & docker @composePrefix down --volumes --remove-orphans
    if ($LASTEXITCODE -ne 0) {
        Write-Error "The fixed disposable browser-test project could not be fully removed."
    }
}

Write-Host "Chromium, Firefox, and WebKit browser checks completed in disposable containers."
