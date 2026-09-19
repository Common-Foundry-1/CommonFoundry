#requires -Version 5.1
[CmdletBinding()]
param([string]$WslDistribution = 'Ubuntu-22.04')
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Write-Host 'Close the wallet first. Solo mining needs approximately 61 GB of model inputs and WSL2 with NVIDIA support.'
$destination = Join-Path $PSScriptRoot 'production-v4'
foreach ($worker in @('cmfd-v4-replay','real_bank0_relations')) {
    if (-not (Test-Path -LiteralPath (Join-Path $destination $worker) -PathType Leaf)) { throw "The packaged mining worker is missing: $worker" }
}
& wsl.exe -d $WslDistribution --exec /bin/sh -c 'command -v nvidia-smi >/dev/null || test -x /usr/lib/wsl/lib/nvidia-smi'
if ($LASTEXITCODE -ne 0) { throw 'WSL2 NVIDIA support is required for mining.' }
& (Join-Path $PSScriptRoot 'PREPARE-RUNTIME.ps1') -Role Miner -Destination $destination
if (-not $?) { throw 'Mining input preparation failed.' }
$linuxDirectory = (& wsl.exe -d $WslDistribution --exec wslpath -a -u $destination).Trim()
if ($LASTEXITCODE -ne 0 -or -not $linuxDirectory) { throw 'Could not resolve the mining directory in WSL.' }
& wsl.exe -d $WslDistribution --exec chmod +x "$linuxDirectory/cmfd-v4-replay" "$linuxDirectory/real_bank0_relations"
if ($LASTEXITCODE -ne 0) { throw 'Could not prepare the packaged mining workers.' }
Write-Host 'Solo-mining inputs are ready. Start the wallet; mining remains gated by activation.'
