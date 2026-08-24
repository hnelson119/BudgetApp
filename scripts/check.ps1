$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
$pythonPath = Join-Path $projectRoot ".venv\Scripts\python.exe"

if (-not (Test-Path -LiteralPath $pythonPath)) {
    throw "Virtual environment not found. Create .venv and install the development dependencies first."
}

Push-Location $projectRoot
try {
    & $pythonPath manage.py check --settings=config.settings.test
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & $pythonPath manage.py makemigrations --check --dry-run --settings=config.settings.test
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & $pythonPath -m ruff check .
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & $pythonPath -m ruff format --check .
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & $pythonPath -m mypy audit budgets core debts goals households identity imports ledger periods reserves schedules spending
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & $pythonPath scripts\secret_scan.py
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    $sourceDirectories = @(
        "audit", "budgets", "config", "core", "debts", "goals", "households",
        "identity", "imports", "ledger", "notifications", "periods", "reserves",
        "schedules", "spending"
    )
    & $pythonPath -m bandit -q -c pyproject.toml -r @sourceDirectories
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & $pythonPath -m coverage erase
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & $pythonPath -m coverage run -m pytest
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & $pythonPath -m coverage report
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & $pythonPath scripts\check_branch_coverage.py --fail-under 80
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
finally {
    Pop-Location
}
