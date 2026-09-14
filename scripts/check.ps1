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

    & $pythonPath -m mypy audit budgets core debts goals households identity imports ledger notifications periods reserves schedules spending
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & $pythonPath scripts\secret_scan.py
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & $pythonPath scripts\check_cryptographic_inventory.py
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & $pythonPath scripts\check_logging_inventory.py
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & $pythonPath scripts\check_sbom.py
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & $pythonPath scripts\check_client_technologies.py
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & $pythonPath scripts\check_output_encoding.py
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & $pythonPath scripts\check_template_safety.py
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & $pythonPath scripts\check_os_command_safety.py
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & $pythonPath scripts\check_format_string_safety.py
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & $pythonPath scripts\check_communication_inventory.py
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & $pythonPath scripts\check_data_classification.py
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & $pythonPath scripts\check_canonical_decoding.py
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & $pythonPath scripts\check_managed_runtime_safety.py
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & $pythonPath scripts\check_input_validation_policy.py
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & $pythonPath scripts\check_authorization_policy.py
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & $pythonPath scripts\check_context_sanitization.py
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & $pythonPath scripts\check_regex_safety.py
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & $pythonPath scripts\check_release_evidence.py
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & $pythonPath scripts\check_device_test_evidence.py
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & $pythonPath scripts\check_adversarial_test_evidence.py
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    $sourceDirectories = @(
        "audit", "budgets", "config", "core", "debts", "deploy/pentest", "goals", "households",
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
