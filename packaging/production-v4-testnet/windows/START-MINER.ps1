#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Miner,
    [string]$Peer = '173.249.35.251:19444',
    [ValidateRange(0, [int]::MaxValue)]
    [int]$Blocks = 0,
    [string]$WslDistribution = 'Ubuntu-22.04'
)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($Miner)) {
    Write-Host 'Paste the 64-character receive address shown by your RCNet-1 wallet.'
    $Miner = (Read-Host 'Mining address').Trim()
}
if ($Miner -cnotmatch '^[0-9a-fA-F]{64}$') {
    throw 'Mining address must be exactly 64 hexadecimal characters.'
}
& (Join-Path $PSScriptRoot 'PREPARE-V4-INPUTS.ps1') -Role Miner
$inputs = Join-Path $PSScriptRoot 'inputs'
$work = Join-Path $PSScriptRoot 'work'
New-Item -ItemType Directory -Force -Path $work | Out-Null
& (Join-Path $PSScriptRoot 'run-production-v4-miner.ps1') `
    -Peer $Peer `
    -Miner $Miner `
    -ModelBank (Join-Path $inputs 'MODEL-V2.bank') `
    -FixedArtifactDirectory (Join-Path $inputs 'fixed') `
    -InputManifest (Join-Path $PSScriptRoot 'production-v4-rcnet-1-inputs.json') `
    -CmfdMiner (Join-Path $PSScriptRoot 'cmfd-miner.exe') `
    -ReplayBinary (Join-Path $PSScriptRoot 'cmfd-v4-replay') `
    -DynamicCommitmentBinary (Join-Path $PSScriptRoot 'real_dynamic_commitments') `
    -ProofBinary (Join-Path $PSScriptRoot 'real_bank0_relations') `
    -WorkDirectory $work `
    -WslDistribution $WslDistribution `
    -Blocks $Blocks `
    -InputsPrepared `
    -AllowPublicPeer
exit $LASTEXITCODE
