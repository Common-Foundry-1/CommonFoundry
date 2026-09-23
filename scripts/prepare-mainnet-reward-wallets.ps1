# Offline operator convenience wrapper. Two distinct passwords travel only
# through a length-framed anonymous stdin pipe, never arguments, logs or files.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$NodePath,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedNodeSha256,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{64}$')][string]$PowLimit,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{64}$')][string]$InitialTarget,
    [string]$WalletParent = (Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'CommonFoundry\RewardWallets'),
    [string]$BackupParent = (Join-Path ([Environment]::GetFolderPath('UserProfile')) 'CommonFoundry-Reward-Backups'),
    [Security.SecureString]$StewardPassword,
    [Security.SecureString]$StewardPasswordConfirmation,
    [Security.SecureString]$CommunityPassword,
    [Security.SecureString]$CommunityPasswordConfirmation
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

function Assert-PasswordConfirmation([byte[]]$PasswordBytes, [byte[]]$ConfirmationBytes, [string]$Role) {
    if ($PasswordBytes.Length -lt 12 -or $PasswordBytes.Length -gt 1024) {
        throw "$Role password must contain 12 to 1024 UTF-8 bytes. No wallets were created."
    }
    $difference = $PasswordBytes.Length -bxor $ConfirmationBytes.Length
    for ($index = 0; $index -lt [Math]::Min($PasswordBytes.Length, $ConfirmationBytes.Length); $index++) {
        $difference = $difference -bor ($PasswordBytes[$index] -bxor $ConfirmationBytes[$index])
    }
    if ($difference -ne 0) { throw "$Role password confirmation did not match. No wallets were created." }
}

function New-DistinctPasswordFrame([byte[]]$StewardBytes, [byte[]]$CommunityBytes) {
    $difference = $StewardBytes.Length -bxor $CommunityBytes.Length
    for ($index = 0; $index -lt [Math]::Min($StewardBytes.Length, $CommunityBytes.Length); $index++) {
        $difference = $difference -bor ($StewardBytes[$index] -bxor $CommunityBytes[$index])
    }
    if ($difference -eq 0) { throw 'Steward and community passwords must differ. No wallets were created.' }
    $magic = [Text.Encoding]::ASCII.GetBytes("CMFD/REWARD-CUSTODY/TWO-PASSWORDS/V1`0")
    $frame = New-Object byte[] ($magic.Length + 4 + $StewardBytes.Length + $CommunityBytes.Length)
    [Array]::Copy($magic, 0, $frame, 0, $magic.Length)
    $offset = $magic.Length
    foreach ($password in @($StewardBytes, $CommunityBytes)) {
        $length = $password.Length
        $frame[$offset] = [byte]($length -band 255)
        $frame[$offset + 1] = [byte](($length -shr 8) -band 255)
        [Array]::Copy($password, 0, $frame, $offset + 2, $length)
        $offset += 2 + $length
    }
    return ,$frame
}

function Invoke-CustodyCommand([string[]]$Arguments, [byte[]]$PasswordFrame) {
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
        $process.StandardInput.BaseStream.Write($PasswordFrame, 0, $PasswordFrame.Length)
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

$stewardBytes = $null
$stewardConfirmationBytes = $null
$communityBytes = $null
$communityConfirmationBytes = $null
$passwordFrame = $null
try {
    if ($null -eq $StewardPassword) {
        Write-Host 'Choose TWO DIFFERENT strong passwords, one for each reward wallet. Save both separately.'
        Write-Host 'This is offline candidate preparation, not mainnet activation.'
        $StewardPassword = Read-Host 'Steward wallet password' -AsSecureString
    }
    if ($null -eq $StewardPasswordConfirmation) { $StewardPasswordConfirmation = Read-Host 'Confirm steward password' -AsSecureString }
    $stewardBytes = Convert-SecurePasswordToUtf8 $StewardPassword
    $stewardConfirmationBytes = Convert-SecurePasswordToUtf8 $StewardPasswordConfirmation
    Assert-PasswordConfirmation $stewardBytes $stewardConfirmationBytes 'Steward'
    if ($null -eq $CommunityPassword) { $CommunityPassword = Read-Host 'Community wallet password' -AsSecureString }
    if ($null -eq $CommunityPasswordConfirmation) { $CommunityPasswordConfirmation = Read-Host 'Confirm community password' -AsSecureString }
    $communityBytes = Convert-SecurePasswordToUtf8 $CommunityPassword
    $communityConfirmationBytes = Convert-SecurePasswordToUtf8 $CommunityPasswordConfirmation
    Assert-PasswordConfirmation $communityBytes $communityConfirmationBytes 'Community'
    $passwordFrame = New-DistinctPasswordFrame $stewardBytes $communityBytes

    $attempt = [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss') + '-' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
    $workParent = Join-Path $WalletParent $attempt
    $backupParentForAttempt = Join-Path $BackupParent $attempt
    [void][IO.Directory]::CreateDirectory($workParent)
    [void][IO.Directory]::CreateDirectory($backupParentForAttempt)
    $wallets = Join-Path $workParent 'wallets'
    $backups = Join-Path $backupParentForAttempt 'backups'
    $public = Join-Path $workParent 'public'
    $common = @('--wallets-directory', $wallets, '--backups-directory', $backups, '--public-directory', $public, '--distinct-passphrases-stdin')
    Write-Host 'Creating and authenticating the encrypted wallets and backups...'
    $prepared = Invoke-CustodyCommand (@('mainnet-custody-prepare', '--pow-limit', $PowLimit, '--initial-target', $InitialTarget) + $common) $passwordFrame
    Write-Host 'Checking the saved files in a separate node process...'
    $verified = Invoke-CustodyCommand (@('mainnet-custody-verify', '--expected-plan-digest', $prepared.launch_plan_digest) + $common) $passwordFrame
    if ($prepared.network_id -ne $verified.network_id -or $prepared.launch_plan_digest -ne $verified.launch_plan_digest) {
        throw 'The independent readback did not match the prepared network identity.'
    }
    Write-Host 'Complete. Copy the encrypted backups off this computer and retain BOTH passwords separately.'
    Write-Host 'Only the files in the public directory may be shared for launch preparation.'
    [ordered]@{ status = 'prepared_and_verified_not_activated'; wallets_directory = $wallets; backups_directory = $backups; public_directory = $public; custody = $verified } | ConvertTo-Json -Depth 6
} finally {
    if ($null -ne $passwordFrame) { [Array]::Clear($passwordFrame, 0, $passwordFrame.Length) }
    if ($null -ne $stewardBytes) { [Array]::Clear($stewardBytes, 0, $stewardBytes.Length) }
    if ($null -ne $stewardConfirmationBytes) { [Array]::Clear($stewardConfirmationBytes, 0, $stewardConfirmationBytes.Length) }
    if ($null -ne $communityBytes) { [Array]::Clear($communityBytes, 0, $communityBytes.Length) }
    if ($null -ne $communityConfirmationBytes) { [Array]::Clear($communityConfirmationBytes, 0, $communityConfirmationBytes.Length) }
    if ($null -ne $StewardPassword) { $StewardPassword.Dispose() }
    if ($null -ne $StewardPasswordConfirmation) { $StewardPasswordConfirmation.Dispose() }
    if ($null -ne $CommunityPassword) { $CommunityPassword.Dispose() }
    if ($null -ne $CommunityPasswordConfirmation) { $CommunityPasswordConfirmation.Dispose() }
}
