# Offline operator convenience wrapper. Passwords travel only through an
# anonymous stdin pipe, never command-line arguments, logs or temporary files.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$NodePath,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedNodeSha256,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{64}$')][string]$PowLimit,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{64}$')][string]$InitialTarget,
    [string]$WalletParent = (Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'CommonFoundry\RewardWallets'),
    [string]$BackupParent = (Join-Path ([Environment]::GetFolderPath('UserProfile')) 'CommonFoundry-Reward-Backups'),
    [Security.SecureString]$Password,
    [Security.SecureString]$PasswordConfirmation
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Convert-SecurePasswordToUtf8([Security.SecureString]$Value) {
    $buffer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
    $characters = New-Object char[] $Value.Length
    try {
        [Runtime.InteropServices.Marshal]::Copy($buffer, $characters, 0, $characters.Length)
        $encoding = New-Object Text.UTF8Encoding($false, $true)
        return ,$encoding.GetBytes($characters)
    } finally {
        [Array]::Clear($characters, 0, $characters.Length)
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($buffer)
    }
}

function Quote-NativeArgument([string]$Value) {
    if ($Value.Contains([char]0)) { throw 'An argument contains a NUL character.' }
    # Windows CommandLineToArgvW quoting; no shell evaluates these arguments.
    return '"' + [regex]::Replace([regex]::Replace($Value, '(\\*)"', '$1$1\"'), '(\\+)$', '$1$1') + '"'
}

function Invoke-CustodyCommand([string[]]$Arguments, [byte[]]$PasswordBytes) {
    if ((Get-FileHash -LiteralPath $resolvedNode -Algorithm SHA256).Hash -ne $ExpectedNodeSha256) {
        throw 'The selected node executable no longer matches its expected SHA-256.'
    }
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $resolvedNode
    $start.Arguments = ($Arguments | ForEach-Object { Quote-NativeArgument $_ }) -join ' '
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $start
    try {
        # Windows PowerShell 5.1 builds the redirected stdin writer from the
        # console encoding. A UTF-8 encoding with a BOM would change the wallet
        # password bytes when that writer is closed, even for BaseStream writes.
        $originalInputEncoding = [Console]::InputEncoding
        try {
            [Console]::InputEncoding = New-Object Text.UTF8Encoding($false, $true)
            [void]$process.Start()
        } finally {
            [Console]::InputEncoding = $originalInputEncoding
        }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $process.StandardInput.BaseStream.Write($PasswordBytes, 0, $PasswordBytes.Length)
        $process.StandardInput.BaseStream.Flush()
        $process.StandardInput.Close()
        $process.WaitForExit()
        $output = $stdout.GetAwaiter().GetResult()
        $failure = $stderr.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) { throw "Custody command failed. Preserve any partial output. $failure" }
        $report = $output | ConvertFrom-Json
        if ($report.schema -ne 'CMFD_MAINNET_REWARD_CUSTODY_V1' -or
            $report.mainnet_activation_authorized -ne $false -or
            $report.backups_authenticated -ne $true -or
            $report.wallets.Count -ne 2) { throw 'Unexpected native custody report.' }
        return $report
    } finally { $process.Dispose() }
}

$resolvedNode = (Resolve-Path -LiteralPath $NodePath).ProviderPath
if ((Get-FileHash -LiteralPath $resolvedNode -Algorithm SHA256).Hash -ne $ExpectedNodeSha256) {
    throw 'Node SHA-256 mismatch. No password has been requested or wallet created.'
}
if (-not [IO.Path]::IsPathRooted($WalletParent) -or -not [IO.Path]::IsPathRooted($BackupParent)) {
    throw 'Wallet and backup parent directories must be absolute paths.'
}

$passwordBytes = $null
$confirmationBytes = $null
try {
    if ($null -eq $Password) {
        Write-Host 'Choose a strong password for BOTH reward wallets. Keep it in your password manager.'
        Write-Host 'This is offline candidate preparation, not mainnet activation.'
        $Password = Read-Host 'Wallet password' -AsSecureString
    }
    if ($null -eq $PasswordConfirmation) { $PasswordConfirmation = Read-Host 'Confirm wallet password' -AsSecureString }
    $passwordBytes = Convert-SecurePasswordToUtf8 $Password
    $confirmationBytes = Convert-SecurePasswordToUtf8 $PasswordConfirmation
    if ($passwordBytes.Length -lt 12 -or $passwordBytes.Length -gt 1024) { throw 'Use a password containing 12 to 1024 UTF-8 bytes.' }
    $difference = $passwordBytes.Length -bxor $confirmationBytes.Length
    for ($index = 0; $index -lt [Math]::Min($passwordBytes.Length, $confirmationBytes.Length); $index++) {
        $difference = $difference -bor ($passwordBytes[$index] -bxor $confirmationBytes[$index])
    }
    if ($difference -ne 0) { throw 'Passwords did not match. No wallets were created.' }

    $attempt = [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss') + '-' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
    $workParent = Join-Path $WalletParent $attempt
    $backupParentForAttempt = Join-Path $BackupParent $attempt
    [void][IO.Directory]::CreateDirectory($workParent)
    [void][IO.Directory]::CreateDirectory($backupParentForAttempt)
    $wallets = Join-Path $workParent 'wallets'
    $backups = Join-Path $backupParentForAttempt 'backups'
    $public = Join-Path $workParent 'public'
    $common = @('--wallets-directory', $wallets, '--backups-directory', $backups, '--public-directory', $public, '--shared-passphrase-stdin')
    Write-Host 'Creating and authenticating the encrypted wallets and backups...'
    $prepared = Invoke-CustodyCommand (@('mainnet-custody-prepare', '--pow-limit', $PowLimit, '--initial-target', $InitialTarget) + $common) $passwordBytes
    Write-Host 'Checking the saved files in a separate node process...'
    $verified = Invoke-CustodyCommand (@('mainnet-custody-verify', '--expected-plan-digest', $prepared.launch_plan_digest) + $common) $passwordBytes
    if ($prepared.network_id -ne $verified.network_id -or $prepared.launch_plan_digest -ne $verified.launch_plan_digest) {
        throw 'The independent readback did not match the prepared network identity.'
    }
    Write-Host 'Complete. Copy the encrypted backups off this computer and retain your password separately.'
    Write-Host 'Only the files in the public directory may be shared for launch preparation.'
    [ordered]@{ status = 'prepared_and_verified_not_activated'; wallets_directory = $wallets; backups_directory = $backups; public_directory = $public; custody = $verified } | ConvertTo-Json -Depth 6
} finally {
    if ($null -ne $passwordBytes) { [Array]::Clear($passwordBytes, 0, $passwordBytes.Length) }
    if ($null -ne $confirmationBytes) { [Array]::Clear($confirmationBytes, 0, $confirmationBytes.Length) }
    if ($null -ne $Password) { $Password.Dispose() }
    if ($null -ne $PasswordConfirmation) { $PasswordConfirmation.Dispose() }
}
