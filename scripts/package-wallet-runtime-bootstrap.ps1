[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$ExpectedCommit,
    [Parameter(Mandatory)]
    [ValidatePattern('^0\.1\.0-rc\.[0-9]+$')]
    [string]$Version,
    [string]$OutputDirectory = (Join-Path (Split-Path -Parent $PSScriptRoot) 'target\runtime-bootstrap'),
    [string]$Node = (Join-Path (Split-Path -Parent $PSScriptRoot) 'target\release\cmfd-node.exe'),
    [string]$Wallet = (Join-Path (Split-Path -Parent $PSScriptRoot) 'target\release\common-foundry-wallet.exe')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$commit = (& git -C $projectRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $commit -cne $ExpectedCommit) { throw "Expected release commit $ExpectedCommit, found $commit" }
foreach ($path in @($Node, $Wallet)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required runtime binary is missing: $path" }
}
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
$packageName = "commonfoundry-rc-runtime-bootstrap-windows-x86_64-v$Version"
$stage = Join-Path $OutputDirectory $packageName
$archive = Join-Path $OutputDirectory "$packageName.zip"
if ((Test-Path -LiteralPath $stage) -or (Test-Path -LiteralPath $archive)) { throw "Package staging path or archive already exists: $OutputDirectory" }
New-Item -ItemType Directory -Force -Path $stage | Out-Null

$shared = Join-Path $projectRoot 'packaging\production-v4-pool\shared'
$runtime = Join-Path $projectRoot 'packaging\production-rc\runtime'
Copy-Item -LiteralPath $Wallet -Destination (Join-Path $stage 'common-foundry-wallet.exe')
Copy-Item -LiteralPath $Node -Destination (Join-Path $stage 'cmfd-node.exe')
Copy-Item -LiteralPath (Join-Path $runtime 'windows\PREPARE-RCNET-RUNTIME.ps1') -Destination $stage
Copy-Item -LiteralPath (Join-Path $runtime 'windows\START-WALLET.bat') -Destination $stage
Copy-Item -LiteralPath (Join-Path $runtime 'README.md') -Destination $stage
Copy-Item -LiteralPath (Join-Path $shared 'V4-INPUT-CHUNKS.json') -Destination $stage
Copy-Item -LiteralPath (Join-Path $shared 'production-v4-rcnet-1-inputs.json') -Destination $stage
Copy-Item -LiteralPath (Join-Path $shared 'FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json') -Destination $stage
Copy-Item -LiteralPath (Join-Path $projectRoot 'LICENSE') -Destination $stage
Copy-Item -LiteralPath (Join-Path $projectRoot 'THIRD_PARTY_NOTICES.md') -Destination $stage

$sourceDateEpoch = if ($env:SOURCE_DATE_EPOCH) { $env:SOURCE_DATE_EPOCH } else { (& git -C $projectRoot show -s --format=%ct $ExpectedCommit).Trim() }
$python = Get-Command py.exe -ErrorAction SilentlyContinue
if ($python) {
    & $python.Source -3 (Join-Path $PSScriptRoot 'release_integrity.py') archive-zip --stage $stage --output $archive --source-date-epoch $sourceDateEpoch
} else {
    & python (Join-Path $PSScriptRoot 'release_integrity.py') archive-zip --stage $stage --output $archive --source-date-epoch $sourceDateEpoch
}
if ($LASTEXITCODE -ne 0) { throw "Deterministic runtime bootstrap packaging failed with exit code $LASTEXITCODE" }
$file = Get-Item -LiteralPath $archive
[pscustomobject]@{
    Package = $file.FullName
    Bytes = $file.Length
    SHA256 = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    Runtime = 'ProductionV4 RCNet-1 wallet/node with authenticated model-bank downloader'
}
