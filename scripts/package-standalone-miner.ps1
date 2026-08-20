[CmdletBinding()]
param(
    [string]$OutputDirectory,
    [string]$CudaBuildDirectory,
    [string]$CudaToolkit,
    [string]$OpenClBuildDirectory,
    [switch]$SkipOpenCl
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $projectRoot 'target\standalone-miner-package'
}
if (-not $CudaBuildDirectory) {
    $CudaBuildDirectory = Join-Path $projectRoot 'target\gpu-miner-build-volta'
}
$OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
$CudaBuildDirectory = [System.IO.Path]::GetFullPath($CudaBuildDirectory)

$cudaLibrary = Join-Path $CudaBuildDirectory 'cmfd-forgematrix-v2-miner.dll'
if (-not (Test-Path -LiteralPath $cudaLibrary)) {
    & (Join-Path $PSScriptRoot 'build-cuda-miner.ps1') `
        -BuildDirectory $CudaBuildDirectory `
        -CudaToolkit $CudaToolkit
}

# The OpenCL backend covers Intel Arc. It is packaged beside the CUDA library
# so one ZIP serves both vendors; -SkipOpenCl produces a CUDA-only package.
$openClLibrary = $null
if (-not $SkipOpenCl) {
    if (-not $OpenClBuildDirectory) {
        $OpenClBuildDirectory = Join-Path $projectRoot 'target\gpu-opencl-build'
    }
    $OpenClBuildDirectory = [System.IO.Path]::GetFullPath($OpenClBuildDirectory)
    $openClLibrary = Join-Path $OpenClBuildDirectory 'cmfd-forgematrix-v2-opencl.dll'
    if (-not (Test-Path -LiteralPath $openClLibrary)) {
        & (Join-Path $PSScriptRoot 'build-opencl-miner.ps1') `
            -BuildDirectory $OpenClBuildDirectory `
            -SkipDifferentialTest
    }
}

$previousRustFlags = $env:RUSTFLAGS
try {
    $env:RUSTFLAGS = '-C target-feature=+crt-static'
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
}

$metadata = & cargo metadata --no-deps --format-version 1 --locked | ConvertFrom-Json
$version = ($metadata.packages | Where-Object name -eq 'cmfd-miner').version
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
if ($openClLibrary) {
    Copy-Item -LiteralPath $openClLibrary -Destination $stage
}
Copy-Item -LiteralPath (Join-Path $projectRoot 'packaging\standalone-miner\windows\START-MINER.bat') -Destination $stage
Copy-Item -LiteralPath (Join-Path $projectRoot 'packaging\standalone-miner\windows\LIST-GPUS.bat') -Destination $stage
Copy-Item -LiteralPath (Join-Path $projectRoot 'packaging\standalone-miner\windows\README.txt') -Destination $stage
Copy-Item -LiteralPath (Join-Path $projectRoot 'docs\standalone-miner.md') -Destination $stage
if ($openClLibrary) {
    Copy-Item -LiteralPath (Join-Path $projectRoot 'docs\opencl-miner.md') -Destination $stage
}
Copy-Item -LiteralPath (Join-Path $projectRoot 'LICENSE') -Destination $stage

Compress-Archive -LiteralPath $stage -DestinationPath $archive -CompressionLevel Optimal
$file = Get-Item -LiteralPath $archive
$hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
[pscustomobject]@{
    Package = $file.FullName
    Bytes = $file.Length
    SHA256 = $hash
    NativeArchitectures = 'sm_70, sm_75, sm_86, sm_89, sm_120'
    PtxFallback = 'compute_70'
}
