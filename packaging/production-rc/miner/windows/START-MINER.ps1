#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$WalletAddress,
    [string]$PoolUrl,
    [string]$WorkerName = $env:COMPUTERNAME,
    [string]$WslDistribution = 'Ubuntu-22.04'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ([string]::IsNullOrWhiteSpace($WalletAddress)) {
    $WalletAddress = (Read-Host 'RCNet-1 wallet receive address (64 hex characters)').Trim()
}
if ($WalletAddress -cnotmatch '^[0-9a-fA-F]{64}$') {
    throw 'WalletAddress must be exactly 64 hexadecimal characters.'
}
if ([string]::IsNullOrWhiteSpace($PoolUrl)) {
    $PoolUrl = (Read-Host 'Certificate-pinned pool URL (cmfd+tls://IP:PORT?pin=...)').Trim()
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

& (Join-Path $PSScriptRoot 'PREPARE-V4-INPUTS.ps1') -Role PoolMiner
$inputs = Join-Path $PSScriptRoot 'inputs'
$scratch = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'work\pool-search'))
New-Item -ItemType Directory -Force -Path $scratch | Out-Null

& (Join-Path $PSScriptRoot 'cmfd-miner.exe') pool `
    --pool $PoolUrl `
    --miner $WalletAddress `
    --worker $WorkerName `
    --production-v4-bank (Join-Path $inputs 'MODEL-V2.bank') `
    --production-v4-replay-worker (Join-Path $PSScriptRoot 'cmfd-v4-replay') `
    --production-v4-scratch $scratch `
    --production-v4-wsl-distribution $WslDistribution `
    --stats-seconds 5
exit $LASTEXITCODE
