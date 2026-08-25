[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^(?:[0-9a-f]{40}|[0-9a-f]{64})$')]
    [string]$ExpectedCommit,
    [string]$BuildDirectory,
    [string]$CudaToolkit,
    [string]$CutlassRoot,
    [ValidateSet('Release', 'Debug')]
    [string]$Configuration = 'Release',
    [switch]$SkipDifferentialTest
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$releaseIntegrity = Join-Path $PSScriptRoot 'release_integrity.py'
$cutlassCommit = 'ad7b2f5e84fcfa124cb02b91d5bd26d238c0459e'
$cutlassRepository = 'https://github.com/NVIDIA/cutlass.git'
$cutlassTag = 'v3.9.2'

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
    $BuildDirectory = Join-Path $projectRoot 'target\gpu-miner-build'
}
$BuildDirectory = [System.IO.Path]::GetFullPath($BuildDirectory)

$git = Get-Command git.exe -ErrorAction SilentlyContinue
if (-not $git) {
    throw 'Git is required to acquire and verify the pinned CUTLASS source.'
}
if (-not $CutlassRoot) {
    $CutlassRoot = Join-Path $BuildDirectory '_deps\cutlass-3.9.2'
}
$CutlassRoot = [System.IO.Path]::GetFullPath($CutlassRoot)
if (-not (Test-Path -LiteralPath $CutlassRoot)) {
    $cutlassParent = Split-Path -Parent $CutlassRoot
    New-Item -ItemType Directory -Path $cutlassParent -Force | Out-Null
    & $git.Source clone --filter=blob:none --depth=1 --branch $cutlassTag `
        $cutlassRepository $CutlassRoot
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not clone the pinned CUTLASS source.'
    }
    & $git.Source -C $CutlassRoot checkout --detach $cutlassCommit
    if ($LASTEXITCODE -ne 0) {
        throw "Could not check out CUTLASS commit $cutlassCommit."
    }
}
$cutlassRevisionOutput = @(& $git.Source -C $CutlassRoot rev-parse HEAD)
$cutlassRevisionExitCode = $LASTEXITCODE
$actualCutlassCommit = ($cutlassRevisionOutput -join '').Trim()
if ($cutlassRevisionExitCode -ne 0 -or $actualCutlassCommit -ne $cutlassCommit) {
    throw "CUTLASS must be the pinned commit $cutlassCommit; got $actualCutlassCommit."
}
$cutlassChanges = @(& $git.Source -C $CutlassRoot status --porcelain --untracked-files=all)
if ($LASTEXITCODE -ne 0 -or $cutlassChanges.Count -ne 0) {
    throw 'The pinned CUTLASS checkout has local or untracked changes.'
}

$toolkitCandidates = @()
if ($CudaToolkit) {
    $toolkitCandidates += [System.IO.Path]::GetFullPath($CudaToolkit)
}
$toolkitCandidates += @(
    'C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v12.9',
    'C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v12.8'
)
$nvcc = $toolkitCandidates |
    ForEach-Object { Join-Path $_ 'bin\nvcc.exe' } |
    Where-Object { Test-Path -LiteralPath $_ } |
    Select-Object -First 1
if (-not $nvcc) {
    $nvccCommand = Get-Command nvcc.exe -ErrorAction SilentlyContinue
    if ($nvccCommand) {
        $nvcc = $nvccCommand.Source
    } else {
        throw 'nvcc.exe was not found. Install CUDA Toolkit 12.8 or 12.9.'
    }
}

$supported = @(& $nvcc --list-gpu-code)
foreach ($architecture in @('sm_70', 'sm_75', 'sm_86', 'sm_89', 'sm_120')) {
    if ($supported -notcontains $architecture) {
        throw "The selected CUDA toolkit cannot emit $architecture. CUDA 12.8 or 12.9 is required for one Volta-through-Blackwell library."
    }
}

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

$gpuSource = Join-Path $projectRoot 'gpu'
$configureAndBuild = '"{0}" -arch=x64 -host_arch=x64 && cmake -S "{1}" -B "{2}" -G Ninja -DCMAKE_BUILD_TYPE={3} -DCMAKE_CUDA_COMPILER="{4}" -DCMFD_CUTLASS_ROOT="{5}" && cmake --build "{2}" --target cmfd-forgematrix-v2-miner' -f `
    $devCommand, $gpuSource, $BuildDirectory, $Configuration, $nvcc, $CutlassRoot
& cmd.exe /d /s /c $configureAndBuild
if ($LASTEXITCODE -ne 0) {
    throw "CUDA miner build failed with exit code $LASTEXITCODE."
}

$library = Join-Path $BuildDirectory 'cmfd-forgematrix-v2-miner.dll'
if (-not (Test-Path -LiteralPath $library)) {
    throw "CUDA miner library was not produced at $library"
}

$cudaBin = Split-Path -Parent $nvcc
$cuobjdump = Join-Path $cudaBin 'cuobjdump.exe'
if (-not (Test-Path -LiteralPath $cuobjdump)) {
    throw 'cuobjdump.exe was not found beside nvcc.exe.'
}
$nativeImages = @(& $cuobjdump --list-elf $library)
$ptxImages = @(& $cuobjdump --list-ptx $library)
foreach ($architecture in @('sm_70', 'sm_75', 'sm_86', 'sm_89', 'sm_120')) {
    if (-not ($nativeImages -match [regex]::Escape($architecture))) {
        throw "The library is missing its native $architecture image."
    }
}
if (-not ($ptxImages -match 'sm_70')) {
    throw 'The library is missing its forward-compatible compute_70 PTX image.'
}
if (-not ($ptxImages -match 'sm_75')) {
    throw 'The library is missing its signed-INT8 Tensor Core compute_75 PTX image.'
}
$ptxAssembly = @(& $cuobjdump --dump-ptx $library)
if ($LASTEXITCODE -ne 0 -or -not ($ptxAssembly -match `
        'mma\.sync\.aligned\.m8n8k16\.row\.col\.satfinite\.s32\.s8\.s8\.s32')) {
    throw 'The compute_75 PTX does not contain the required signed-INT8 Tensor Core MMA.'
}

if (-not $SkipDifferentialTest) {
    Push-Location $projectRoot
    try {
        $previousLibrary = $env:CMFD_CUDA_MINER_LIBRARY
        $previousRequireTensorCore = $env:CMFD_REQUIRE_TENSOR_CORE
        $env:CMFD_CUDA_MINER_LIBRARY = $library
        $env:CMFD_REQUIRE_TENSOR_CORE = '1'
        & cargo test -p common-foundry-wallet `
            cuda::tests::available_cuda_backend_matches_authoritative_v2_digests -- --nocapture
        if ($LASTEXITCODE -ne 0) {
            throw "CUDA differential test failed with exit code $LASTEXITCODE."
        }
        & cargo run --release -p cmfd-cuda --example production_differential
        if ($LASTEXITCODE -ne 0) {
            throw "Production-geometry CUDA differential test failed with exit code $LASTEXITCODE."
        }
    } finally {
        $env:CMFD_CUDA_MINER_LIBRARY = $previousLibrary
        $env:CMFD_REQUIRE_TENSOR_CORE = $previousRequireTensorCore
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
$nvccVersion = ((& $nvcc --version) -join ' ').Trim()
if ($LASTEXITCODE -ne 0) {
    throw 'Could not capture the CUDA compiler version.'
}
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
    '--kind', 'cuda',
    '--library', $library,
    '--build-script', 'scripts/build-cuda-miner.ps1',
    '--toolchain', "$nvccVersion; $cmakeVersion; $devCommand; CUTLASS $actualCutlassCommit",
    '--target', 'x86_64-pc-windows-msvc',
    '--architectures', 'sm_70;sm_75;sm_86;sm_89;sm_120;compute_70;compute_75-tensor-core',
    '--output', $receipt
)
[pscustomobject]@{
    Library = $file.FullName
    BuildReceipt = $receipt
    Bytes = $file.Length
    SHA256 = $hash
    NativeArchitectures = 'sm_70, sm_75, sm_86, sm_89, sm_120'
    PtxFallback = 'compute_70, compute_75 tensor core'
    CutlassCommit = $actualCutlassCommit
}
