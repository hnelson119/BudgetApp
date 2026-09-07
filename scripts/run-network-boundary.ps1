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
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            # OneDrive may represent ignored cache directories as cloud reparse points.
            # They are excluded from the Docker context and must not be traversed or removed.
            continue
        }
        if (
            -not $item.PSIsContainer -or
            -not $item.FullName.Equals($expectedPath, [StringComparison]::OrdinalIgnoreCase)
        ) {
            throw "Refusing to remove an unexpected Docker build-cache path."
        }
        Remove-Item -LiteralPath $expectedPath -Recurse -Force
    }
}

function New-RandomSecret {
    param([Parameter(Mandatory = $true)][int]$ByteCount)

    $bytes = [byte[]]::new($ByteCount)
    try {
        [Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
        return [Convert]::ToBase64String($bytes)
    }
    finally {
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
}

function Remove-ValidatedTemporaryDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }
    $resolvedPath = [IO.Path]::GetFullPath($Path)
    $temporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd(
        [IO.Path]::DirectorySeparatorChar
    ) + [IO.Path]::DirectorySeparatorChar
    $item = Get-Item -LiteralPath $resolvedPath -Force
    if (
        -not $resolvedPath.StartsWith($temporaryRoot, [StringComparison]::OrdinalIgnoreCase) -or
        -not $item.Name.StartsWith("budgetapp-network-boundary-", [StringComparison]::Ordinal) -or
        -not $item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)
    ) {
        throw "Refusing to remove an unexpected network-boundary temporary directory."
    }
    Remove-Item -LiteralPath $resolvedPath -Recurse -Force
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
    & wsl.exe sh -lc "cd '$wslProjectRoot' && sh ./scripts/run-network-boundary.sh"
    exit $LASTEXITCODE
}

$composeFile = Join-Path $projectRoot "compose.yaml"
$probeScript = Join-Path $projectRoot "deploy\network\run-production-boundary.py"
$projectName = "budgetapp-network-boundary"
$hostname = "budget-probe.example.ts.net"
$temporaryDirectory = Join-Path (
    [IO.Path]::GetTempPath()
) ("budgetapp-network-boundary-" + [Guid]::NewGuid().ToString("N"))
$secretDirectory = Join-Path $temporaryDirectory "secrets"
$authorityDirectory = Join-Path $temporaryDirectory "postgres-authority"
$backupDirectory = Join-Path $temporaryDirectory "backups"
$checkpointDirectory = Join-Path $temporaryDirectory "checkpoints"
[IO.Directory]::CreateDirectory($secretDirectory) | Out-Null
[IO.Directory]::CreateDirectory($backupDirectory) | Out-Null
[IO.Directory]::CreateDirectory($checkpointDirectory) | Out-Null

$secretSizes = @{
    "django_secret_key" = 64
    "django_mfa_encryption_key" = 32
    "audit_checkpoint_signing_key" = 48
    "restic_repository_password" = 48
}
foreach ($secretName in $secretSizes.Keys) {
    $secretValue = New-RandomSecret -ByteCount $secretSizes[$secretName]
    [IO.File]::WriteAllText(
        (Join-Path $secretDirectory $secretName),
        $secretValue,
        [Text.UTF8Encoding]::new($false)
    )
    $secretValue = $null
}

$python = Join-Path $projectRoot ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $python)) {
    throw "The project virtual environment is required for PostgreSQL TLS generation."
}
& $python (Join-Path $projectRoot "scripts\generate-postgres-tls.py") `
    --authority-directory $authorityDirectory `
    --deployment-directory $secretDirectory `
    --secret-group-id 10002
if ($LASTEXITCODE -ne 0) {
    throw "The disposable PostgreSQL TLS material could not be generated."
}

$environmentValues = @{
    "APP_ENVIRONMENT" = "production"
    "APP_RELEASE" = "network-boundary-probe"
    "BUDGET_AUDIT_CHECKPOINT_DIRECTORY" = $checkpointDirectory
    "BUDGET_BACKUP_REPOSITORY" = $backupDirectory
    "BUDGET_SECRET_DIR" = $secretDirectory
    "BUDGET_SECRET_GID" = "10002"
    "DJANGO_ALLOWED_HOSTS" = $hostname
    "DJANGO_CSRF_TRUSTED_ORIGINS" = "https://$hostname"
}
$previousEnvironment = @{}
foreach ($name in $environmentValues.Keys) {
    $previousEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
    [Environment]::SetEnvironmentVariable($name, $environmentValues[$name], "Process")
}

$composePrefix = @("compose", "-p", $projectName, "-f", $composeFile)
$completed = $false
try {
    & docker @composePrefix down --volumes --remove-orphans
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to clear the fixed disposable network-boundary project."
    }
    & docker @composePrefix up --build --detach db
    if ($LASTEXITCODE -ne 0) {
        throw "The disposable production database failed to start."
    }
    & docker @composePrefix --profile maintenance run --rm db-bootstrap
    if ($LASTEXITCODE -ne 0) {
        throw "The disposable production database roles could not be bootstrapped."
    }
    & docker @composePrefix --profile maintenance run --build --rm migrate
    if ($LASTEXITCODE -ne 0) {
        throw "The disposable production schema migration failed."
    }
    & docker @composePrefix up --build --detach web ingress
    if ($LASTEXITCODE -ne 0) {
        throw "The disposable production web service failed to start."
    }

    & $python $probeScript `
        --compose-file $composeFile `
        --project-name $projectName `
        --hostname $hostname `
        --secret-directory $secretDirectory
    if ($LASTEXITCODE -ne 0) {
        throw "The disposable production-boundary probe failed."
    }
    $completed = $true
}
finally {
    & docker @composePrefix down --volumes --remove-orphans
    $cleanupExitCode = $LASTEXITCODE
    foreach ($name in $previousEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($name, $previousEnvironment[$name], "Process")
    }
    Remove-ValidatedTemporaryDirectory -Path $temporaryDirectory
    if ($cleanupExitCode -ne 0) {
        Write-Error "The fixed disposable network-boundary project could not be fully removed."
    }
}

if (-not $completed) {
    throw "The disposable production-boundary run did not complete."
}
Write-Host "Disposable production-boundary validation completed."
