#requires -Version 5.1
[CmdletBinding()]
param([string]$DataDirectory = (Join-Path $env:LOCALAPPDATA 'CommonFoundry\CompactTestnet1'), [switch]$VerifyOnly)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = $PSScriptRoot
$manifest = Get-Content -Raw -LiteralPath (Join-Path $root 'PACKAGE-MANIFEST.json') | ConvertFrom-Json
if ($manifest.network_id -cne '8a34c0d9eaa92c5eaec4af7fe146afdfa2ab6859918b7deb0c97e0a1f600d6d1') { throw 'Wrong wallet network identity.' }
foreach ($entry in $manifest.files.PSObject.Properties) {
    $name = [string]$entry.Name
    if ([IO.Path]::IsPathRooted($name) -or @($name -split '[/\\]') -contains '..') { throw 'Unsafe package entry.' }
    $file = Join-Path $root $name
    if (-not (Test-Path -LiteralPath $file -PathType Leaf) -or (Get-Item -LiteralPath $file).Length -ne [long]$entry.Value.bytes) { throw "Missing or changed package file: $name" }
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $file).Hash.ToLowerInvariant() -cne $entry.Value.sha256) { throw "Package checksum mismatch: $name" }
}
if ($VerifyOnly) { Write-Host 'Common Foundry wallet package verified.'; return }
$model = Join-Path $root 'runtime\production-v4'
& (Join-Path $root 'PREPARE-INPUTS.ps1') -Destination $model
$wallet = Join-Path $root 'runtime\common-foundry-wallet.exe'
$data = [IO.Path]::GetFullPath($DataDirectory)
New-Item -ItemType Directory -Force -Path $data | Out-Null
$arguments = @('--data-dir', ('"' + $data + '"'), '--peer', '209.145.48.36:23444', '--allow-public-peers', '--p2p-bind', '127.0.0.1:24444', '--prune-keep-blocks', '2880')
Start-Process -FilePath $wallet -WorkingDirectory (Split-Path $wallet) -ArgumentList $arguments -WindowStyle Normal
