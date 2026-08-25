[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^(?:[0-9a-f]{40}|[0-9a-f]{64})$')]
    [string]$ExpectedCommit,
    [string]$OutputDirectory,
    [string]$CudaBuildDirectory,
    [string]$CudaToolkit,
    [string]$OpenClBuildDirectory,
    [switch]$SkipOpenCl
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$releaseIntegrity = Join-Path $PSScriptRoot 'release_integrity.py'

function Invoke-ReleaseIntegrity {
    param([Parameter(Mandatory)][string[]]$ToolArguments)

    $python = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($python) {
        $toolOutput = @(& $python.Source -3 $releaseIntegrity @ToolArguments 2>&1)
    } else {
        $python = Get-Command python3.exe -ErrorAction SilentlyContinue
        if (-not $python) {
            $python = Get-Command python.exe -ErrorAction SilentlyContinue
        }
        if (-not $python) {
            throw 'Python 3 is required for build-receipt verification and deterministic packaging.'
        }
        $toolOutput = @(& $python.Source $releaseIntegrity @ToolArguments 2>&1)
    }
    if ($LASTEXITCODE -ne 0) {
        throw "release-integrity failed: $($toolOutput -join [Environment]::NewLine)"
    }
    Write-Verbose ($toolOutput -join [Environment]::NewLine)
}

$sourceDateEpoch = if ($env:SOURCE_DATE_EPOCH) {
    $env:SOURCE_DATE_EPOCH
} else {
    $commitEpoch = (& git -C $projectRoot show -s --format=%ct $ExpectedCommit).Trim()
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not resolve SOURCE_DATE_EPOCH from the release commit.'
    }
    $commitEpoch
}

if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $projectRoot 'target\standalone-miner-package'
}
if (-not $CudaBuildDirectory) {
    $CudaBuildDirectory = Join-Path $projectRoot 'target\gpu-miner-build-volta'
}
$OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
$CudaBuildDirectory = [System.IO.Path]::GetFullPath($CudaBuildDirectory)
$metadata = & cargo metadata `
    --manifest-path (Join-Path $projectRoot 'Cargo.toml') `
    --no-deps --format-version 1 --locked | ConvertFrom-Json
$version = ($metadata.packages | Where-Object name -eq 'cmfd-miner').version

$cudaLibrary = Join-Path $CudaBuildDirectory 'cmfd-forgematrix-v2-miner.dll'
if (-not (Test-Path -LiteralPath $cudaLibrary)) {
    & (Join-Path $PSScriptRoot 'build-cuda-miner.ps1') `
        -BuildDirectory $CudaBuildDirectory `
        -CudaToolkit $CudaToolkit `
        -ExpectedCommit $ExpectedCommit
}
$cudaReceipt = "$cudaLibrary.build-receipt"
Invoke-ReleaseIntegrity -ToolArguments @(
    'receipt-verify',
    '--repo', $projectRoot,
    '--expected-commit', $ExpectedCommit,
    '--kind', 'cuda',
    '--library', $cudaLibrary,
    '--receipt', $cudaReceipt,
    '--expected-build-script', 'scripts/build-cuda-miner.ps1',
    '--expected-target', 'x86_64-pc-windows-msvc',
    '--expected-architectures', 'sm_70;sm_75;sm_86;sm_89;sm_120;compute_70;compute_75-tensor-core',
    '--source-date-epoch', $sourceDateEpoch
)

# The OpenCL backend covers Intel Arc. It is packaged beside the CUDA library
# so one ZIP serves both vendors; -SkipOpenCl produces a CUDA-only package.
$openClLibrary = $null
$openClReceipt = $null
if (-not $SkipOpenCl) {
    if (-not $OpenClBuildDirectory) {
        $OpenClBuildDirectory = Join-Path $projectRoot 'target\gpu-opencl-build'
    }
    $OpenClBuildDirectory = [System.IO.Path]::GetFullPath($OpenClBuildDirectory)
    $openClLibrary = Join-Path $OpenClBuildDirectory 'cmfd-forgematrix-v2-opencl.dll'
    if (-not (Test-Path -LiteralPath $openClLibrary)) {
        & (Join-Path $PSScriptRoot 'build-opencl-miner.ps1') `
            -BuildDirectory $OpenClBuildDirectory `
            -ExpectedCommit $ExpectedCommit `
            -SkipDifferentialTest
    }
    $openClReceipt = "$openClLibrary.build-receipt"
    Invoke-ReleaseIntegrity -ToolArguments @(
        'receipt-verify',
        '--repo', $projectRoot,
        '--expected-commit', $ExpectedCommit,
        '--kind', 'opencl',
        '--library', $openClLibrary,
        '--receipt', $openClReceipt,
        '--expected-build-script', 'scripts/build-opencl-miner.ps1',
        '--expected-target', 'x86_64-pc-windows-msvc',
        '--expected-architectures', 'opencl_1_2',
        '--source-date-epoch', $sourceDateEpoch
    )
}

$previousRustFlags = $env:RUSTFLAGS
$previousReleaseLabel = $env:CMFD_RELEASE_LABEL
try {
    $env:RUSTFLAGS = '-C target-feature=+crt-static'
    $env:CMFD_RELEASE_LABEL = $version
    Push-Location $projectRoot
    try {
        & cargo build --release --locked -p cmfd-miner
        if ($LASTEXITCODE -ne 0) {
            throw "standalone miner Rust build failed with exit code $LASTEXITCODE"
        }
    } finally {
        Pop-Location
    }
} finally {
    $env:RUSTFLAGS = $previousRustFlags
    $env:CMFD_RELEASE_LABEL = $previousReleaseLabel
}

$packageName = "commonfoundry-miner-v$version-windows-x86_64"
$stage = Join-Path $OutputDirectory $packageName
$archive = Join-Path $OutputDirectory "$packageName.zip"
if (Test-Path -LiteralPath $stage) {
    throw "package staging directory already exists: $stage"
}
if (Test-Path -LiteralPath $archive) {
    throw "package archive already exists: $archive"
}

New-Item -ItemType Directory -Path $stage -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $projectRoot 'target\release\cmfd-miner.exe') -Destination $stage
Copy-Item -LiteralPath $cudaLibrary -Destination $stage
Copy-Item -LiteralPath $cudaReceipt -Destination $stage
if ($openClLibrary) {
    Copy-Item -LiteralPath $openClLibrary -Destination $stage
    Copy-Item -LiteralPath $openClReceipt -Destination $stage
}
Copy-Item -LiteralPath (Join-Path $projectRoot 'packaging\standalone-miner\windows\START-MINER.bat') -Destination $stage
Copy-Item -LiteralPath (Join-Path $projectRoot 'packaging\standalone-miner\windows\LIST-GPUS.bat') -Destination $stage
Copy-Item -LiteralPath (Join-Path $projectRoot 'packaging\standalone-miner\windows\README.txt') -Destination $stage
Copy-Item -LiteralPath (Join-Path $projectRoot 'docs\standalone-miner.md') -Destination $stage
if ($openClLibrary) {
    Copy-Item -LiteralPath (Join-Path $projectRoot 'docs\opencl-miner.md') -Destination $stage
}
Copy-Item -LiteralPath (Join-Path $projectRoot 'LICENSE') -Destination $stage
Copy-Item -LiteralPath (Join-Path $projectRoot 'THIRD_PARTY_NOTICES.md') -Destination $stage

Invoke-ReleaseIntegrity -ToolArguments @(
    'archive-zip',
    '--stage', $stage,
    '--output', $archive,
    '--source-date-epoch', $sourceDateEpoch
)
$file = Get-Item -LiteralPath $archive
$hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
[pscustomobject]@{
    Package = $file.FullName
    Bytes = $file.Length
    SHA256 = $hash
    NativeArchitectures = 'sm_70, sm_75, sm_86, sm_89, sm_120'
    PtxFallback = 'compute_70, compute_75 tensor core'
}
