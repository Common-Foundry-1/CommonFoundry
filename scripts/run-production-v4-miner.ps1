#requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Peer,

    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$Miner,

    [Parameter(Mandatory)]
    [string]$ModelBank,

    [Parameter(Mandatory)]
    [string]$FixedArtifactDirectory,

    [Parameter(Mandatory)]
    [string]$CmfdMiner,

    [Parameter(Mandatory)]
    [string]$ReplayBinary,

    [Parameter(Mandatory)]
    [string]$DynamicCommitmentBinary,

    [Parameter(Mandatory)]
    [string]$ProofBinary,

    [Parameter(Mandatory)]
    [string]$WorkDirectory,

    [string]$WslDistribution = 'Ubuntu-22.04',

    [ValidateRange(0, 64)]
    [int]$CudaDevice = 0,

    [ValidateRange(15000, 131072)]
    [int]$MinimumGpuMemoryMiB = 15000,

    [ValidatePattern('^[0-9]+\.[0-9]+$')]
    [string]$RequiredComputeCapability = '12.0',

    [ValidateRange(0, [uint64]::MaxValue)]
    [uint64]$Nonce = 0,

    [ValidateRange(0, [int]::MaxValue)]
    [int]$Blocks = 0,

    [switch]$AllowPublicPeer,
    [switch]$KeepAcceptedWork,
    [switch]$ValidateOnly
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not $IsWindows) {
    throw 'The ProductionV4 miner launcher must run on Windows.'
}

function Resolve-ExistingFile {
    param([string]$Path, [string]$Label)
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw "$Label is not a file: $resolved"
    }
    return $resolved
}

function Resolve-ExistingDirectory {
    param([string]$Path, [string]$Label)
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    if (-not (Test-Path -LiteralPath $resolved -PathType Container)) {
        throw "$Label is not a directory: $resolved"
    }
    return $resolved
}

function Convert-ToWslPath {
    param([string]$Path)
    $portablePath = $Path.Replace('\', '/')
    $converted = @(& wsl.exe -d $WslDistribution -- wslpath -a -u $portablePath)
    if ($LASTEXITCODE -ne 0 -or $converted.Count -ne 1) {
        throw "failed to convert Windows path for $WslDistribution`: $Path"
    }
    return [string]$converted[0]
}

function Invoke-Checked {
    param([string]$Program, [string[]]$Arguments, [string]$Label)
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Label exited with code $LASTEXITCODE"
    }
}

function Invoke-WslChecked {
    param([string]$Program, [string[]]$Arguments, [string]$Label)
    $environment = @(
        "CUDA_VISIBLE_DEVICES=$CudaDevice",
        'CUDA_HOME=/usr/local/cuda-12.8',
        'CUDA_PATH=/usr/local/cuda-12.8',
        'CUDAToolkit_ROOT=/usr/local/cuda-12.8',
        'LD_LIBRARY_PATH=/usr/local/cuda-12.8/lib64'
    )
    Invoke-Checked wsl.exe (@('-d', $WslDistribution, '--', 'env') + $environment + @($Program) + $Arguments) $Label
}

$modelBankPath = Resolve-ExistingFile $ModelBank 'model bank'
$artifactDirectoryPath = Resolve-ExistingDirectory $FixedArtifactDirectory 'fixed artifact directory'
$cmfdMinerPath = Resolve-ExistingFile $CmfdMiner 'cmfd-miner'
$replayBinaryPath = Resolve-ExistingFile $ReplayBinary 'V4 replay binary'
$dynamicCommitmentBinaryPath = Resolve-ExistingFile $DynamicCommitmentBinary 'V4 dynamic commitment binary'
$proofBinaryPath = Resolve-ExistingFile $ProofBinary 'V4 proof binary'
$workDirectoryPath = Resolve-ExistingDirectory $WorkDirectory 'work directory'
$fixedRecordPath = Resolve-ExistingFile (
    Join-Path $artifactDirectoryPath 'FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json'
) 'fixed artifact record'

0..2 | ForEach-Object {
    Resolve-ExistingFile (
        Join-Path $artifactDirectoryPath "FORGEMATRIX-V4-FIXED-BANK-$_.row-major.codeword"
    ) "bank $_ row-major fixed codeword" | Out-Null
    Resolve-ExistingFile (
        Join-Path $artifactDirectoryPath "FORGEMATRIX-V4-FIXED-BANK-$_.tree"
    ) "bank $_ fixed Merkle tree" | Out-Null
}

$gpuQuery = @(& wsl.exe -d $WslDistribution -- nvidia-smi "--id=$CudaDevice" `
    '--query-gpu=name,memory.total,compute_cap' '--format=csv,noheader,nounits')
if ($LASTEXITCODE -ne 0 -or $gpuQuery.Count -ne 1) {
    throw "failed to inspect CUDA device $CudaDevice in $WslDistribution"
}
$gpuLine = [string]$gpuQuery[0]
$gpuFields = $gpuLine.Split(',').ForEach({ $_.Trim() })
if ($gpuFields.Count -ne 3) {
    throw "unexpected nvidia-smi output: $gpuLine"
}
$gpuMemoryMiB = 0
if (-not [int]::TryParse($gpuFields[1], [ref]$gpuMemoryMiB)) {
    throw "invalid GPU memory value: $($gpuFields[1])"
}
if ($gpuMemoryMiB -lt $MinimumGpuMemoryMiB) {
    throw "GPU $($gpuFields[0]) has $gpuMemoryMiB MiB; at least $MinimumGpuMemoryMiB MiB is required"
}
if ($gpuFields[2] -ne $RequiredComputeCapability) {
    throw "GPU $($gpuFields[0]) has compute capability $($gpuFields[2]); this build requires $RequiredComputeCapability"
}
Write-Host "ProductionV4 GPU: $($gpuFields[0]), $gpuMemoryMiB MiB, compute $($gpuFields[2])"

$modelBankWsl = Convert-ToWslPath $modelBankPath
$artifactDirectoryWsl = Convert-ToWslPath $artifactDirectoryPath
$replayBinaryWsl = Convert-ToWslPath $replayBinaryPath
$dynamicCommitmentBinaryWsl = Convert-ToWslPath $dynamicCommitmentBinaryPath
$proofBinaryWsl = Convert-ToWslPath $proofBinaryPath

if ($ValidateOnly) {
    Write-Host 'ProductionV4 miner launcher validation passed.'
    return
}

$accepted = 0
while ($Blocks -eq 0 -or $accepted -lt $Blocks) {
    $attemptName = 'attempt-{0:D8}-{1}' -f ($accepted + 1), ([DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssfffffffZ'))
    $attemptDirectory = Join-Path $workDirectoryPath $attemptName
    if (Test-Path -LiteralPath $attemptDirectory) {
        throw "attempt directory already exists: $attemptDirectory"
    }
    New-Item -ItemType Directory -Path $attemptDirectory | Out-Null

    $template = Join-Path $attemptDirectory 'template.json'
    $coefficients = Join-Path $attemptDirectory 'replay-coefficients.bin'
    $tracePrefix = Join-Path $attemptDirectory 'trace'
    $dynamicCommitments = Join-Path $attemptDirectory 'dynamic-commitments.json'
    $finalActivation = "$tracePrefix-final-activation.bin"
    $proof = Join-Path $attemptDirectory 'transparent-proof.bin'

    $snapshotArguments = @(
        'snapshot-v4-template',
        '--peer', $Peer,
        '--miner', $Miner,
        '--nonce', $Nonce.ToString([Globalization.CultureInfo]::InvariantCulture),
        '--fixed-record', $fixedRecordPath,
        '--coefficients-output', $coefficients,
        '--output', $template
    )
    if ($AllowPublicPeer) {
        $snapshotArguments += '--allow-public-peers'
    }
    Invoke-Checked $cmfdMinerPath $snapshotArguments 'ProductionV4 template snapshot'

    $templateWsl = Convert-ToWslPath $template
    $coefficientsWsl = Convert-ToWslPath $coefficients
    $tracePrefixWsl = Convert-ToWslPath $tracePrefix
    $dynamicCommitmentsWsl = Convert-ToWslPath $dynamicCommitments
    $finalActivationWsl = Convert-ToWslPath $finalActivation
    $proofWsl = Convert-ToWslPath $proof

    Invoke-WslChecked $replayBinaryWsl @(
        $modelBankWsl, $coefficientsWsl, $tracePrefixWsl
    ) 'ProductionV4 replay'
    Invoke-WslChecked $dynamicCommitmentBinaryWsl @(
        $tracePrefixWsl, $dynamicCommitmentsWsl
    ) 'ProductionV4 dynamic commitments'
    Invoke-WslChecked $proofBinaryWsl @(
        $modelBankWsl,
        $artifactDirectoryWsl,
        $templateWsl,
        $tracePrefixWsl,
        $dynamicCommitmentsWsl,
        $finalActivationWsl,
        $proofWsl
    ) 'ProductionV4 proof'

    $submitArguments = @(
        'submit-v4-template',
        '--peer', $Peer,
        '--template', $template,
        '--transparent-proof', $proof,
        '--fixed-record', $fixedRecordPath
    )
    if ($AllowPublicPeer) {
        $submitArguments += '--allow-public-peers'
    }
    Invoke-Checked $cmfdMinerPath $submitArguments 'ProductionV4 block submission'
    $accepted++
    Write-Host "Accepted ProductionV4 block $accepted for this launcher session."

    if (-not $KeepAcceptedWork) {
        $resolvedAttempt = (Resolve-Path -LiteralPath $attemptDirectory).Path
        if ((Split-Path -Parent $resolvedAttempt) -ne $workDirectoryPath) {
            throw "refusing to remove an attempt outside the work directory: $resolvedAttempt"
        }
        Remove-Item -LiteralPath $resolvedAttempt -Recurse -Force
    }
}
