#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$Miner,
    [string]$Peer = '107.214.187.2:22444',
    [ValidateRange(0, [int]::MaxValue)]
    [int]$Blocks = 0,
    [string]$WslDistribution = 'Ubuntu-22.04'
)

$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'PREPARE-V4-INPUTS.ps1') -Role Miner
$inputs = Join-Path $PSScriptRoot 'inputs'
$work = Join-Path $PSScriptRoot 'work'
New-Item -ItemType Directory -Force -Path $work | Out-Null
& (Join-Path $PSScriptRoot 'run-production-v4-miner.ps1') `
    -Peer $Peer `
    -Miner $Miner `
    -ModelBank (Join-Path $inputs 'MODEL-V2.bank') `
    -FixedArtifactDirectory (Join-Path $inputs 'fixed') `
    -InputManifest (Join-Path $PSScriptRoot 'production-v4-testnet-1-inputs.json') `
    -CmfdMiner (Join-Path $PSScriptRoot 'cmfd-miner.exe') `
    -ReplayBinary (Join-Path $PSScriptRoot 'cmfd-v4-replay') `
    -DynamicCommitmentBinary (Join-Path $PSScriptRoot 'real_dynamic_commitments') `
    -ProofBinary (Join-Path $PSScriptRoot 'real_bank0_relations') `
    -WorkDirectory $work `
    -WslDistribution $WslDistribution `
    -Blocks $Blocks `
    -AllowPublicPeer
exit $LASTEXITCODE
