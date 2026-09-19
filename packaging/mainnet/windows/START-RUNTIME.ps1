#requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('Wallet','Node')][string]$Mode = 'Wallet',
    [string]$WalletPassphraseFile = $env:CMFD_WALLET_PASSPHRASE_FILE
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Set-Location -LiteralPath $PSScriptRoot
$node = Join-Path $PSScriptRoot 'cmfd-node.exe'
$launch = Join-Path $PSScriptRoot 'cmfd-launch.exe'
$prepare = Join-Path $PSScriptRoot 'PREPARE-RUNTIME.ps1'
$application = if ($Mode -eq 'Wallet') { Join-Path $PSScriptRoot 'common-foundry-wallet.exe' } else { $node }
foreach ($file in @($node,$launch,$prepare,$application)) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Required package file is missing: $file" }
}
if ($Mode -eq 'Node') {
    if ([string]::IsNullOrWhiteSpace($WalletPassphraseFile)) {
        $WalletPassphraseFile = (Read-Host 'Path to the existing wallet passphrase file').Trim()
    }
    if (-not [IO.Path]::IsPathRooted($WalletPassphraseFile) -or -not (Test-Path -LiteralPath $WalletPassphraseFile -PathType Leaf)) {
        throw 'Supply an absolute path to a passphrase file kept outside the node data directory.'
    }
    $WalletPassphraseFile = [IO.Path]::GetFullPath($WalletPassphraseFile)
    $dataPrefix = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'data-mainnet')) + [IO.Path]::DirectorySeparatorChar
    if ($WalletPassphraseFile.StartsWith($dataPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Keep the wallet passphrase file outside the node data directory.'
    }
}

# Authenticate the selected mainnet package before downloads or waiting.
& $node mainnet-launch-info
if ($LASTEXITCODE -ne 0) { throw 'The package mainnet identity could not be verified.' }
& $prepare -Destination (Join-Path $PSScriptRoot 'production-v4')
if (-not $?) { throw 'Mainnet runtime preparation failed.' }
if ($Mode -eq 'Wallet') {
    # The desktop app prepares keys offline and acquires the beacon in its own
    # cancellable background worker. Its node still enforces the launch gate.
    & $application
} else {
    & $launch fetch --runtime $node --wait
    if ($LASTEXITCODE -ne 0) { throw 'Launch preparation stopped. The node was not started.' }
    & $node --data-dir (Join-Path $PSScriptRoot 'data-mainnet') --wallet-passphrase-file $WalletPassphraseFile run --p2p-bind '0.0.0.0:29444' --allow-public-peers
}
exit $LASTEXITCODE
