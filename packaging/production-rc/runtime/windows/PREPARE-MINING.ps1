#requires -Version 5.1
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Write-Host 'Close the wallet before preparing mining. This explicitly downloads about 61 GB of inputs plus 37 MB of GPU workers.'
& wsl.exe -d Ubuntu-22.04 --exec /bin/sh -c 'command -v nvidia-smi >/dev/null || test -x /usr/lib/wsl/lib/nvidia-smi'
if ($LASTEXITCODE -ne 0) { throw 'Install WSL2 Ubuntu-22.04 with NVIDIA GPU support first.' }
$destination = Join-Path $PSScriptRoot 'production-v4'
New-Item -ItemType Directory -Force -Path $destination | Out-Null
$manifest = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'MINING-WORKERS.json') | ConvertFrom-Json
if ($manifest.schema_version -ne 1 -or $manifest.release_base -notlike 'https://github.com/JustAResearcher/CommonFoundry-Binaries/releases/download/v*') { throw 'Invalid mining worker manifest.' }
foreach ($worker in $manifest.workers) {
    if ($worker.name -cnotin @('cmfd-v4-replay', 'real_bank0_relations')) { throw 'Unknown mining worker.' }
    $output = Join-Path $destination $worker.name
    if ((Test-Path -LiteralPath $output -PathType Leaf) -and
        (Get-Item -LiteralPath $output).Length -eq $worker.bytes -and
        (Get-FileHash -LiteralPath $output -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $worker.sha256) { continue }
    $download = "$output.download"
    & curl.exe --fail --location --retry 3 --connect-timeout 30 --output $download "$($manifest.release_base)/$($worker.name)"
    if ($LASTEXITCODE -ne 0 -or (Get-Item -LiteralPath $download).Length -ne $worker.bytes -or
        (Get-FileHash -LiteralPath $download -Algorithm SHA256).Hash.ToLowerInvariant() -cne $worker.sha256) { throw "Mining worker download failed authentication: $($worker.name)" }
    Move-Item -LiteralPath $download -Destination $output -Force
}
$linuxDirectory = (& wsl.exe -d Ubuntu-22.04 --exec wslpath -a -u $destination).Trim()
if ($LASTEXITCODE -ne 0) { throw 'Could not resolve the mining directory in WSL.' }
& wsl.exe -d Ubuntu-22.04 --exec chmod +x "$linuxDirectory/cmfd-v4-replay" "$linuxDirectory/real_bank0_relations"
if ($LASTEXITCODE -ne 0) { throw 'Could not prepare the GPU workers.' }
& (Join-Path $PSScriptRoot 'PREPARE-V4-INPUTS.ps1') -Role Miner -Destination $destination `
    -FallbackReleaseBase 'https://github.com/JustAResearcher/CommonFoundry-Binaries/releases/download/v0.1.0-rc.1'
Copy-Item -LiteralPath (Join-Path $destination 'fixed/FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json') -Destination $destination -Force
Write-Host 'Mining inputs are ready. Reopen START-WALLET.bat, unlock your wallet, then choose Mining and Start Solo Mining.'
