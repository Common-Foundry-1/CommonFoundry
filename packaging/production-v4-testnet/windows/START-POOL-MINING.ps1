#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$WalletAddress,
    [string]$PoolUrl,
    [string]$WorkerName = $env:COMPUTERNAME,
    [string]$WslDistribution = 'Ubuntu-22.04'
)

$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($WalletAddress)) {
    Write-Host 'Paste the 64-character receive address shown by your Devnet-16 wallet.'
    $WalletAddress = (Read-Host 'Wallet address').Trim()
}
if ($WalletAddress -cnotmatch '^[0-9a-fA-F]{64}$') {
    throw 'WalletAddress must be exactly 64 hexadecimal characters.'
}
if ([string]::IsNullOrWhiteSpace($PoolUrl)) {
    Write-Host 'Paste the complete cmfd+tls pool URL supplied by the pool operator.'
    $PoolUrl = (Read-Host 'Pool URL').Trim()
}
if ($PoolUrl -cnotmatch '^cmfd\+tls://(?:[0-9]{1,3}(?:\.[0-9]{1,3}){3}|\[[0-9A-Fa-f:]+\]):[0-9]{1,5}\?pin=[0-9A-Fa-f]{64}$') {
    throw 'PoolUrl must use cmfd+tls://NUMERIC_IP:PORT?pin=64_HEX.'
}
if ([string]::IsNullOrWhiteSpace($WorkerName)) {
    $WorkerName = 'cmfd-miner'
}
$WorkerName = $WorkerName.Trim()
if ($WorkerName -cnotmatch '^[A-Za-z0-9._-]{1,32}$') {
    throw 'WorkerName must contain 1-32 letters, numbers, dots, underscores, or hyphens.'
}

& (Join-Path $PSScriptRoot 'PREPARE-V4-INPUTS.ps1') -Role Miner
$inputs = Join-Path $PSScriptRoot 'inputs'
$scratch = Join-Path $PSScriptRoot 'work\pool-search'
New-Item -ItemType Directory -Force -Path $scratch | Out-Null

$miner = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot 'cmfd-miner.exe')).Path
$modelBank = (Resolve-Path -LiteralPath (Join-Path $inputs 'MODEL-V2.bank')).Path
$replayWorker = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot 'cmfd-v4-replay')).Path
$scratch = [IO.Path]::GetFullPath($scratch)

& $miner pool `
    --pool $PoolUrl `
    --miner $WalletAddress `
    --worker $WorkerName `
    --production-v4-bank $modelBank `
    --production-v4-replay-worker $replayWorker `
    --production-v4-scratch $scratch `
    --production-v4-wsl-distribution $WslDistribution `
    --stats-seconds 5
exit $LASTEXITCODE
