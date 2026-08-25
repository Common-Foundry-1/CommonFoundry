[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^(?:[0-9a-f]{40}|[0-9a-f]{64})$')]
    [string]$ExpectedCommit,
    [string]$BuildDirectory,
    [ValidateSet('Release', 'Debug')]
    [string]$Configuration = 'Release',
    [switch]$SkipDifferentialTest
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
            throw 'Python 3 is required for the native build identity receipt.'
        }
        $toolOutput = @(& $python.Source $releaseIntegrity @ToolArguments 2>&1)
    }
    if ($LASTEXITCODE -ne 0) {
        throw "release-integrity failed: $($toolOutput -join [Environment]::NewLine)"
    }
    Write-Verbose ($toolOutput -join [Environment]::NewLine)
}

if (-not $BuildDirectory) {
    $BuildDirectory = Join-Path $projectRoot 'target\gpu-opencl-build'
}
$BuildDirectory = [System.IO.Path]::GetFullPath($BuildDirectory)

$devCommandCandidates = @(
    'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat',
    'C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat'
)
$devCommand = $devCommandCandidates |
    Where-Object { Test-Path -LiteralPath $_ } |
    Select-Object -First 1
if (-not $devCommand) {
    throw 'Visual Studio C++ developer environment was not found.'
}

# The OpenCL ICD is resolved at run time, so only a C++ toolchain is required
# here. Intel Arc mining needs the Intel graphics driver installed on the rig.
$gpuSource = Join-Path $projectRoot 'gpu'
$configureAndBuild = '"{0}" -arch=x64 -host_arch=x64 && cmake -S "{1}" -B "{2}" -G Ninja -DCMAKE_BUILD_TYPE={3} -DCMFD_ENABLE_CUDA=OFF -DCMFD_ENABLE_OPENCL=ON && cmake --build "{2}" --target cmfd-forgematrix-v2-opencl' -f `
    $devCommand, $gpuSource, $BuildDirectory, $Configuration
& cmd.exe /d /s /c $configureAndBuild
if ($LASTEXITCODE -ne 0) {
    throw "OpenCL miner build failed with exit code $LASTEXITCODE."
}

$library = Join-Path $BuildDirectory 'cmfd-forgematrix-v2-opencl.dll'
if (-not (Test-Path -LiteralPath $library)) {
    throw "OpenCL miner library was not produced at $library"
}

if (-not $SkipDifferentialTest) {
    Push-Location $projectRoot
    try {
        $previousLibrary = $env:CMFD_OPENCL_MINER_LIBRARY
        $previousBackend = $env:CMFD_GPU_BACKEND
        $env:CMFD_OPENCL_MINER_LIBRARY = $library
        $env:CMFD_GPU_BACKEND = 'opencl'
        & cargo test -p common-foundry-wallet `
            cuda::tests::available_cuda_backend_matches_authoritative_v2_digests -- --nocapture
        if ($LASTEXITCODE -ne 0) {
            throw "OpenCL differential test failed with exit code $LASTEXITCODE."
        }
    } finally {
        $env:CMFD_OPENCL_MINER_LIBRARY = $previousLibrary
        $env:CMFD_GPU_BACKEND = $previousBackend
        Pop-Location
    }
}

$file = Get-Item -LiteralPath $library
$stream = [System.IO.File]::OpenRead($library)
try {
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $digest = $sha256.ComputeHash($stream)
    } finally {
        $sha256.Dispose()
    }
} finally {
    $stream.Dispose()
}
$hash = -join ($digest | ForEach-Object { $_.ToString('x2') })
$cmakeVersionOutput = @(& cmake --version)
$cmakeVersionExitCode = $LASTEXITCODE
if ($cmakeVersionExitCode -ne 0) {
    throw 'Could not capture the CMake version.'
}
$cmakeVersion = (($cmakeVersionOutput | Select-Object -First 1) -join ' ').Trim()
$receipt = "$library.build-receipt"
Invoke-ReleaseIntegrity -ToolArguments @(
    'receipt-write',
    '--repo', $projectRoot,
    '--expected-commit', $ExpectedCommit,
    '--kind', 'opencl',
    '--library', $library,
    '--build-script', 'scripts/build-opencl-miner.ps1',
    '--toolchain', "$cmakeVersion; $devCommand",
    '--target', 'x86_64-pc-windows-msvc',
    '--architectures', 'opencl_1_2',
    '--output', $receipt
)
[pscustomobject]@{
    Library = $file.FullName
    BuildReceipt = $receipt
    Bytes = $file.Length
    SHA256 = $hash
    Runtime = 'OpenCL 1.2 or newer ICD, resolved at run time'
}
