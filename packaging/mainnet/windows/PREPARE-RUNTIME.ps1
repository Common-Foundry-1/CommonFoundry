#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Destination = (Join-Path $PSScriptRoot 'production-v4'),
    [ValidateSet('Node','Miner')][string]$Role = 'Node'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
& (Join-Path $PSScriptRoot 'cmfd-node.exe') mainnet-launch-info
if ($LASTEXITCODE -ne 0) { throw 'The package mainnet plan could not be authenticated.' }
# These immutable model bytes were originally published with RC1. Their source
# catalog is provenance only; the compiled mainnet plan defines this network.
& (Join-Path $PSScriptRoot 'PREPARE-V4-INPUTS.ps1') -Role $Role -Destination $Destination `
    -FallbackReleaseBase 'https://github.com/JustAResearcher/CommonFoundry-Binaries/releases/download/v0.1.0-devnet.16'
if (-not $?) { throw 'Model-input preparation failed.' }
$record = 'FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json'
Copy-Item -LiteralPath (Join-Path $Destination "fixed\$record") -Destination (Join-Path $Destination $record) -Force
Write-Host 'Mainnet model inputs are ready. This does not activate the network.'
