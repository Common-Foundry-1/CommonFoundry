[CmdletBinding()]
param(
    [string]$BuildDirectory,
    [ValidateSet('Release', 'Debug')]
    [string]$Configuration = 'Release',
    [switch]$SkipDifferentialTest
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
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
[pscustomobject]@{
    Library = $file.FullName
    Bytes = $file.Length
    SHA256 = $hash
    Runtime = 'OpenCL 1.2 or newer ICD, resolved at run time'
}
