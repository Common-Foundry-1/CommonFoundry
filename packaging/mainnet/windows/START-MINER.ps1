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
Set-Location -LiteralPath $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($WalletAddress)) { $WalletAddress = (Read-Host 'Mainnet wallet receive address (64 hex characters)').Trim() }
if ($WalletAddress -cnotmatch '^[0-9a-fA-F]{64}$') { throw 'WalletAddress must be exactly 64 hexadecimal characters.' }
if ([string]::IsNullOrWhiteSpace($PoolUrl)) { $PoolUrl = (Read-Host 'Mainnet pool URL (cmfd+tls://IP:PORT?pin=...)').Trim() }
if ($PoolUrl -cnotmatch '^cmfd\+tls://(?:[0-9]{1,3}(?:\.[0-9]{1,3}){3}|\[[0-9A-Fa-f:]+\]):[0-9]{1,5}\?pin=[0-9a-fA-F]{64}$') { throw 'Use a complete certificate-pinned pool URL.' }
if ([string]::IsNullOrWhiteSpace($WorkerName)) { $WorkerName = 'cmfd-miner' }
if ($WorkerName -cnotmatch '^[A-Za-z0-9._-]{1,32}$') { throw 'WorkerName must contain 1-32 letters, numbers, dots, underscores or hyphens.' }
$miner = Join-Path $PSScriptRoot 'cmfd-miner.exe'
& $miner mainnet-launch-info
if ($LASTEXITCODE -ne 0) { throw 'The miner mainnet identity could not be verified.' }
& (Join-Path $PSScriptRoot 'PREPARE-V4-INPUTS.ps1') -Role PoolMiner `
    -FallbackReleaseBase 'https://github.com/JustAResearcher/CommonFoundry-Binaries/releases/download/v0.1.0-devnet.16'
if (-not $?) { throw 'Mining input preparation failed.' }
& (Join-Path $PSScriptRoot 'cmfd-launch.exe') fetch --runtime $miner --wait
if ($LASTEXITCODE -ne 0) { throw 'Launch preparation stopped. Mining was not started.' }
$scratch = Join-Path $PSScriptRoot 'work\pool-search'
New-Item -ItemType Directory -Force -Path $scratch | Out-Null
& $miner pool --pool $PoolUrl --miner $WalletAddress --worker $WorkerName `
    --production-v4-bank (Join-Path $PSScriptRoot 'inputs\MODEL-V2.bank') `
    --production-v4-replay-worker (Join-Path $PSScriptRoot 'cmfd-v4-replay') `
    --production-v4-scratch $scratch --production-v4-wsl-distribution $WslDistribution --stats-seconds 5
exit $LASTEXITCODE
