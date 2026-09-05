[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^(?:[0-9a-f]{40}|[0-9a-f]{64})$')]
    [string]$ExpectedCommit,
    [string]$OutputDirectory,
    [string]$Miner,
    [string]$ReplayWorker = (Join-Path $PSScriptRoot '..\tools\production-v4-prover\target\release\cmfd-v4-replay')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$releaseIntegrity = Join-Path $PSScriptRoot 'release_integrity.py'
$currentCommit = (& git -C $projectRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $currentCommit -cne $ExpectedCommit) {
    throw "Expected release commit $ExpectedCommit, found $currentCommit"
}
if (-not (Test-Path -LiteralPath $ReplayWorker -PathType Leaf)) {
    throw "ProductionV4 replay worker is missing: $ReplayWorker"
}
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $projectRoot 'target\standalone-miner-package'
}
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
$sourceDateEpoch = if ($env:SOURCE_DATE_EPOCH) {
    $env:SOURCE_DATE_EPOCH
} else {
    (& git -C $projectRoot show -s --format=%ct $ExpectedCommit).Trim()
}
$metadata = & cargo metadata --manifest-path (Join-Path $projectRoot 'Cargo.toml') `
    --no-deps --format-version 1 --locked | ConvertFrom-Json
$version = ($metadata.packages | Where-Object name -eq 'cmfd-miner').version

$previousRustFlags = $env:RUSTFLAGS
$previousReleaseLabel = $env:CMFD_RELEASE_LABEL
$previousBuildSourceCommit = $env:CMFD_BUILD_SOURCE_COMMIT
try {
    if (-not $Miner) {
        $env:RUSTFLAGS = '-C target-feature=+crt-static'
        $env:CMFD_RELEASE_LABEL = $version
        $env:CMFD_BUILD_SOURCE_COMMIT = $ExpectedCommit
        & cargo build --manifest-path (Join-Path $projectRoot 'Cargo.toml') `
            --release --locked -p cmfd-miner --features production-rc
        if ($LASTEXITCODE -ne 0) {
            throw "RCNet-1 pool miner build failed with exit code $LASTEXITCODE"
        }
        $Miner = Join-Path $projectRoot 'target\release\cmfd-miner.exe'
    }
} finally {
    $env:RUSTFLAGS = $previousRustFlags
    $env:CMFD_RELEASE_LABEL = $previousReleaseLabel
    $env:CMFD_BUILD_SOURCE_COMMIT = $previousBuildSourceCommit
}

$minerIdentity = & $Miner network-info | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or $minerIdentity.build_source_commit -cne $ExpectedCommit -or
    $minerIdentity.proof_selection -cne 'ProductionV4' -or
    $minerIdentity.network_id -cne '3e99d45959c19c0053d8e9fef34875b57b46a8a1ce330637daddab515bc7b92d') {
    throw 'Miner does not report the expected RC4 source and RCNet-1 identity.'
}

$packageName = "commonfoundry-miner-v$version-windows-x86_64-wsl2"
$stage = Join-Path $OutputDirectory $packageName
$archive = Join-Path $OutputDirectory "$packageName.zip"
if ((Test-Path -LiteralPath $stage) -or (Test-Path -LiteralPath $archive)) {
    throw "Package staging path or archive already exists under $OutputDirectory"
}
New-Item -ItemType Directory -Path $stage -Force | Out-Null

$shared = Join-Path $projectRoot 'packaging\production-v4-pool\shared'
Copy-Item -LiteralPath $Miner -Destination (Join-Path $stage 'cmfd-miner.exe')
Copy-Item -LiteralPath $ReplayWorker -Destination (Join-Path $stage 'cmfd-v4-replay')
Copy-Item -LiteralPath (Join-Path $projectRoot 'packaging\production-rc\miner\windows\START-MINER.ps1') -Destination $stage
Copy-Item -LiteralPath (Join-Path $projectRoot 'packaging\production-rc\miner\windows\START-MINER.bat') -Destination $stage
Copy-Item -LiteralPath (Join-Path $projectRoot 'packaging\production-v4-testnet\windows\PREPARE-V4-INPUTS.ps1') -Destination $stage
Copy-Item -LiteralPath (Join-Path $shared 'V4-INPUT-CHUNKS.json') -Destination $stage
Copy-Item -LiteralPath (Join-Path $shared 'production-v4-rcnet-1-inputs.json') -Destination $stage
Copy-Item -LiteralPath (Join-Path $shared 'FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json') -Destination $stage
Copy-Item -LiteralPath (Join-Path $projectRoot 'docs\production-v4-pool-miner.md') -Destination (Join-Path $stage 'README.md')
Copy-Item -LiteralPath (Join-Path $projectRoot "docs\release-notes\v$version.md") -Destination (Join-Path $stage 'RELEASE_NOTES.md')
Copy-Item -LiteralPath (Join-Path $projectRoot 'LICENSE') -Destination $stage
Copy-Item -LiteralPath (Join-Path $projectRoot 'THIRD_PARTY_NOTICES.md') -Destination $stage

$python = Get-Command py.exe -ErrorAction SilentlyContinue
if ($python) {
    & $python.Source -3 $releaseIntegrity archive-zip --stage $stage --output $archive `
        --source-date-epoch $sourceDateEpoch
} else {
    & python $releaseIntegrity archive-zip --stage $stage --output $archive `
        --source-date-epoch $sourceDateEpoch
}
if ($LASTEXITCODE -ne 0) {
    throw "Deterministic miner packaging failed with exit code $LASTEXITCODE"
}

$file = Get-Item -LiteralPath $archive
[pscustomobject]@{
    Package = $file.FullName
    Bytes = $file.Length
    SHA256 = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    Runtime = 'ProductionV4 certificate-pinned pool miner via WSL2'
}
