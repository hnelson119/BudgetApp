$ErrorActionPreference = "Stop"

$localApplicationData = [IO.Path]::GetFullPath($env:LOCALAPPDATA)
$secretDirectory = [IO.Path]::GetFullPath(
    (Join-Path $localApplicationData "HouseholdBudget\test-secrets")
)
$expectedPrefix = $localApplicationData.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar

if (-not $secretDirectory.StartsWith($expectedPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "The local secret directory must remain inside the user's local application data."
}

[IO.Directory]::CreateDirectory($secretDirectory) | Out-Null

$secretSizes = @{
    "django_secret_key" = 64
    "postgres_admin_password" = 48
    "postgres_runtime_password" = 48
    "postgres_migration_password" = 48
    "postgres_backup_password" = 48
    "postgres_audit_password" = 48
    "restic_repository_password" = 48
}

foreach ($secretName in $secretSizes.Keys) {
    $secretPath = Join-Path $secretDirectory $secretName
    if (Test-Path -LiteralPath $secretPath) {
        if ((Get-Item -LiteralPath $secretPath).Length -eq 0) {
            throw "Existing local secret file is empty: $secretName"
        }
        Write-Output "Preserved existing local secret: $secretName"
        continue
    }

    $secretBytes = [byte[]]::new($secretSizes[$secretName])
    [Security.Cryptography.RandomNumberGenerator]::Fill($secretBytes)
    $secretValue = [Convert]::ToBase64String($secretBytes)
    [IO.File]::WriteAllText(
        $secretPath,
        $secretValue,
        [Text.UTF8Encoding]::new($false)
    )
    [Array]::Clear($secretBytes, 0, $secretBytes.Length)
    $secretValue = $null
    Write-Output "Created local test secret: $secretName"
}
