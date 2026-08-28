#requires -Version 5.1
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
    [string]$InputManifest,

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

if ($env:OS -cne 'Windows_NT') {
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
    param(
        [string]$Program,
        [string[]]$Arguments,
        [string]$Label,
        [string]$LogPath
    )
    & $Program @Arguments >> $LogPath 2>&1
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "$Label exited with code $exitCode"
    }
}

function Invoke-WslChecked {
    param(
        [string]$Program,
        [string[]]$Arguments,
        [string]$Label,
        [string]$LogPath
    )
    $environment = @(
        "CUDA_VISIBLE_DEVICES=$CudaDevice",
        'CUDA_HOME=/usr/local/cuda-12.8',
        'CUDA_PATH=/usr/local/cuda-12.8',
        'CUDAToolkit_ROOT=/usr/local/cuda-12.8',
        'LD_LIBRARY_PATH=/usr/local/cuda-12.8/lib64'
    )
    Invoke-Checked wsl.exe `
        (@('-d', $WslDistribution, '--', 'env') + $environment + @($Program) + $Arguments) `
        $Label `
        $LogPath
}

function Start-GpuSampler {
    param([string]$OutputPath)
    Start-Job -ArgumentList $WslDistribution, $CudaDevice, $OutputPath -ScriptBlock {
        param($Distribution, $Device, $Path)
        while ($true) {
            $sample = @(& wsl.exe -d $Distribution -- nvidia-smi "--id=$Device" `
                '--query-gpu=power.draw,temperature.gpu' '--format=csv,noheader,nounits' 2>$null)
            if ($LASTEXITCODE -eq 0 -and $sample.Count -eq 1) {
                Add-Content -LiteralPath $Path -Value ([string]$sample[0]) -Encoding Ascii
            }
            Start-Sleep -Seconds 2
        }
    }
}

function Stop-GpuSampler {
    param($Job)
    if ($null -eq $Job) {
        return
    }
    Stop-Job -Job $Job -ErrorAction SilentlyContinue
    Wait-Job -Job $Job -ErrorAction SilentlyContinue | Out-Null
    Receive-Job -Job $Job -ErrorAction SilentlyContinue | Out-Null
    Remove-Job -Job $Job -Force -ErrorAction SilentlyContinue
}

function Read-GpuStats {
    param([string]$Path)
    $powerTotal = 0.0
    $temperatureMaximum = [double]::NaN
    $sampleCount = 0
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        foreach ($line in Get-Content -LiteralPath $Path) {
            $fields = ([string]$line).Split(',').ForEach({ $_.Trim() })
            if ($fields.Count -ne 2) {
                continue
            }
            $power = 0.0
            $temperature = 0.0
            if (-not [double]::TryParse(
                $fields[0],
                [Globalization.NumberStyles]::Float,
                [Globalization.CultureInfo]::InvariantCulture,
                [ref]$power
            )) {
                continue
            }
            if (-not [double]::TryParse(
                $fields[1],
                [Globalization.NumberStyles]::Float,
                [Globalization.CultureInfo]::InvariantCulture,
                [ref]$temperature
            )) {
                continue
            }
            $powerTotal += $power
            if ([double]::IsNaN($temperatureMaximum) -or $temperature -gt $temperatureMaximum) {
                $temperatureMaximum = $temperature
            }
            $sampleCount++
        }
    }
    [pscustomobject]@{
        AveragePower = if ($sampleCount -eq 0) { [double]::NaN } else { $powerTotal / $sampleCount }
        MaximumTemperature = $temperatureMaximum
        SampleCount = $sampleCount
    }
}

function Write-MinerStats {
    param(
        [int]$Accepted,
        [int]$Rejected,
        [double]$AveragePower,
        [double]$MaximumTemperature,
        [double]$SessionEnergyKwh,
        [double]$ElapsedSeconds
    )
    $powerText = if ([double]::IsNaN($AveragePower)) { 'N/A' } else { $AveragePower.ToString('F1', [Globalization.CultureInfo]::InvariantCulture) }
    $temperatureText = if ([double]::IsNaN($MaximumTemperature)) { 'N/A' } else { $MaximumTemperature.ToString('F0', [Globalization.CultureInfo]::InvariantCulture) }
    $efficiencyText = if ($SessionEnergyKwh -le 0.0) { 'N/A' } else { ($Accepted / $SessionEnergyKwh).ToString('F2', [Globalization.CultureInfo]::InvariantCulture) }
    $elapsedText = if ([double]::IsNaN($ElapsedSeconds)) { 'N/A' } else { $ElapsedSeconds.ToString('F1', [Globalization.CultureInfo]::InvariantCulture) }
    Write-Host "MINER STATS | accepted $Accepted | rejected $Rejected | avg $powerText W | efficiency $efficiencyText accepted/kWh | temp $temperatureText C | last $elapsedText s"
}

function Remove-AttemptDirectory {
    param([string]$Path)
    $resolvedAttempt = (Resolve-Path -LiteralPath $Path).Path
    if ((Split-Path -Parent $resolvedAttempt) -ne $workDirectoryPath) {
        throw "refusing to remove an attempt outside the work directory: $resolvedAttempt"
    }
    Remove-Item -LiteralPath $resolvedAttempt -Recurse -Force
}

function Assert-InputManifest {
    param([string]$ManifestPath, [hashtable]$ExpectedInputs)
    $manifest = Get-Content -Raw -LiteralPath $ManifestPath | ConvertFrom-Json
    if ($manifest.schema_version -ne 1) {
        throw "unsupported ProductionV4 input manifest version: $($manifest.schema_version)"
    }
    $entries = @($manifest.files)
    if ($entries.Count -ne $ExpectedInputs.Count) {
        throw "input manifest contains $($entries.Count) files; expected $($ExpectedInputs.Count)"
    }
    $seen = @{}
    [uint64]$totalBytes = 0
    foreach ($entry in $entries) {
        $name = [string]$entry.name
        if ($seen.ContainsKey($name)) {
            throw "input manifest repeats $name"
        }
        $seen[$name] = $true
        if (-not $ExpectedInputs.ContainsKey($name)) {
            throw "input manifest contains unexpected file $name"
        }
        $path = [string]$ExpectedInputs[$name]
        $item = Get-Item -LiteralPath $path
        if ([uint64]$item.Length -ne [uint64]$entry.bytes) {
            throw "input length mismatch for $name"
        }
        $sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant()
        if ($sha256 -cne [string]$entry.sha256) {
            throw "input SHA-256 mismatch for $name"
        }
        $totalBytes += [uint64]$item.Length
    }
    if ($totalBytes -ne [uint64]$manifest.total_bytes) {
        throw "input manifest total is $($manifest.total_bytes); authenticated $totalBytes bytes"
    }
}

$modelBankPath = Resolve-ExistingFile $ModelBank 'model bank'
$artifactDirectoryPath = Resolve-ExistingDirectory $FixedArtifactDirectory 'fixed artifact directory'
$inputManifestPath = Resolve-ExistingFile $InputManifest 'ProductionV4 input manifest'
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
$expectedInputs = @{
    'MODEL-V2.bank' = $modelBankPath
    'FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json' = $fixedRecordPath
}
0..2 | ForEach-Object {
    $expectedInputs["FORGEMATRIX-V4-FIXED-BANK-$_.row-major.codeword"] = Join-Path (
        $artifactDirectoryPath
    ) "FORGEMATRIX-V4-FIXED-BANK-$_.row-major.codeword"
    $expectedInputs["FORGEMATRIX-V4-FIXED-BANK-$_.tree"] = Join-Path (
        $artifactDirectoryPath
    ) "FORGEMATRIX-V4-FIXED-BANK-$_.tree"
}
Assert-InputManifest $inputManifestPath $expectedInputs

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
$rejected = 0
$attempts = 0
$sessionEnergyKwh = 0.0
$logDirectory = Join-Path $workDirectoryPath 'logs'
New-Item -ItemType Directory -Force -Path $logDirectory | Out-Null
Write-MinerStats $accepted $rejected ([double]::NaN) ([double]::NaN) $sessionEnergyKwh ([double]::NaN)
while ($Blocks -eq 0 -or $accepted -lt $Blocks) {
    $attempts++
    $attemptName = 'attempt-{0:D8}-{1}' -f $attempts, ([DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssfffffffZ'))
    $attemptDirectory = Join-Path $workDirectoryPath $attemptName
    if (Test-Path -LiteralPath $attemptDirectory) {
        throw "attempt directory already exists: $attemptDirectory"
    }
    New-Item -ItemType Directory -Path $attemptDirectory | Out-Null
    $attemptLog = Join-Path $logDirectory "$attemptName.log"
    $gpuSamples = Join-Path $attemptDirectory 'gpu-samples.csv'
    New-Item -ItemType File -Path $attemptLog | Out-Null

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
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $sampler = $null
    $outcome = $null
    $failure = $null
    try {
        $sampler = Start-GpuSampler $gpuSamples
        Invoke-Checked $cmfdMinerPath $snapshotArguments 'ProductionV4 template snapshot' $attemptLog

        $templateWsl = Convert-ToWslPath $template
        $coefficientsWsl = Convert-ToWslPath $coefficients
        $tracePrefixWsl = Convert-ToWslPath $tracePrefix
        $dynamicCommitmentsWsl = Convert-ToWslPath $dynamicCommitments
        $finalActivationWsl = Convert-ToWslPath $finalActivation
        $proofWsl = Convert-ToWslPath $proof

        Invoke-WslChecked $replayBinaryWsl @(
            $modelBankWsl, $coefficientsWsl, $tracePrefixWsl
        ) 'ProductionV4 replay' $attemptLog
        Invoke-WslChecked $dynamicCommitmentBinaryWsl @(
            $tracePrefixWsl, $dynamicCommitmentsWsl
        ) 'ProductionV4 dynamic commitments' $attemptLog
        Invoke-WslChecked $proofBinaryWsl @(
            $modelBankWsl,
            $artifactDirectoryWsl,
            $templateWsl,
            $tracePrefixWsl,
            $dynamicCommitmentsWsl,
            $finalActivationWsl,
            $proofWsl
        ) 'ProductionV4 proof' $attemptLog

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
        & $cmfdMinerPath @submitArguments >> $attemptLog 2>&1
        $submitExitCode = $LASTEXITCODE
        if ($submitExitCode -eq 0) {
            $accepted++
            $outcome = 'accepted'
        } elseif (
            (Select-String -LiteralPath $attemptLog -SimpleMatch 'ProductionV4 block was rejected by the node' -Quiet) -or
            (Select-String -LiteralPath $attemptLog -SimpleMatch 'frozen ProductionV4 template is stale' -Quiet)
        ) {
            $rejected++
            $outcome = 'rejected'
        } else {
            throw "ProductionV4 block submission exited with code $submitExitCode"
        }
    } catch {
        $failure = $_
    } finally {
        Stop-GpuSampler $sampler
        $timer.Stop()
    }

    $gpu = Read-GpuStats $gpuSamples
    if (-not [double]::IsNaN($gpu.AveragePower)) {
        $sessionEnergyKwh += $gpu.AveragePower * $timer.Elapsed.TotalSeconds / 3600000.0
    }

    if ($null -ne $failure) {
        Write-Host "MINER ERROR | $($failure.Exception.Message) | log $attemptLog" -ForegroundColor Red
        Get-Content -LiteralPath $attemptLog -Tail 40
        throw $failure
    }

    Write-MinerStats `
        $accepted `
        $rejected `
        $gpu.AveragePower `
        $gpu.MaximumTemperature `
        $sessionEnergyKwh `
        $timer.Elapsed.TotalSeconds

    if ($outcome -eq 'rejected' -or -not $KeepAcceptedWork) {
        Remove-AttemptDirectory $attemptDirectory
    }
}
