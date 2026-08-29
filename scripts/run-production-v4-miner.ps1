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

    [ValidateRange(1, 300)]
    [int]$TemplateRefreshSeconds = 15,

    [switch]$AllowPublicPeer,
    [switch]$KeepAcceptedWork,
    [switch]$InputsPrepared,
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

function Convert-ToWslPaths {
    param([string[]]$Paths)

    $wslRoots = @{}
    foreach ($path in $Paths) {
        $root = [IO.Path]::GetPathRoot($path)
        if ([string]::IsNullOrWhiteSpace($root) -or $root.StartsWith('\\')) {
            throw "cannot convert non-drive path for $WslDistribution`: $path"
        }
        if (-not $wslRoots.ContainsKey($root)) {
            $wslRoot = $null
            $wslExitCode = -1
            for ($attempt = 1; $attempt -le 3; $attempt++) {
                $previousErrorActionPreference = $ErrorActionPreference
                try {
                    $ErrorActionPreference = 'Continue'
                    $rawOutput = @(& wsl.exe -d $WslDistribution --exec wslpath -a -u $root 2>&1)
                    $wslExitCode = $LASTEXITCODE
                } finally {
                    $ErrorActionPreference = $previousErrorActionPreference
                }
                $convertedRoots = @(
                    foreach ($line in $rawOutput) {
                        $text = [string]$line
                        if ($text.StartsWith('/', [StringComparison]::Ordinal)) {
                            $text.TrimEnd('/')
                        }
                    }
                )
                if ($wslExitCode -eq 0 -and $convertedRoots.Count -eq 1) {
                    $wslRoot = $convertedRoots[0]
                    break
                }
                if ($attempt -lt 3) {
                    Start-Sleep -Seconds (2 * $attempt)
                }
            }
            if ($null -eq $wslRoot) {
                throw "failed to convert drive $root for $WslDistribution after 3 attempts (WSL exit code $wslExitCode)"
            }
            $wslRoots[$root] = $wslRoot
        }
    }

    return @(
        foreach ($path in $Paths) {
            $root = [IO.Path]::GetPathRoot($path)
            $relative = $path.Substring($root.Length).Replace('\', '/')
            if ($relative.Length -eq 0) {
                "$($wslRoots[$root])/"
            } else {
                "$($wslRoots[$root])/$relative"
            }
        }
    )
}

function Convert-FromWslPath {
    param([string]$Path)
    if ($WslDistribution -cnotmatch '^[A-Za-z0-9_.-]+$' -or -not $Path.StartsWith('/')) {
        throw 'cannot convert unsafe WSL path to Windows'
    }
    $relative = $Path.TrimStart('/').Replace('/', '\')
    return "\\wsl.localhost\$WslDistribution\$relative"
}

function Invoke-NativeLogged {
    param(
        [string]$Program,
        [string[]]$Arguments,
        [string]$LogPath
    )
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        # Windows PowerShell promotes native stderr to NativeCommandError. The
        # V4 tools intentionally write telemetry there, so process exit status
        # - not stderr output - determines success.
        $ErrorActionPreference = 'Continue'
        & $Program @Arguments >> $LogPath 2>&1
        return $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
}

function Invoke-NativeCaptureLogged {
    param(
        [string]$Program,
        [string[]]$Arguments,
        [string]$LogPath
    )
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = @(& $Program @Arguments 2>&1)
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    foreach ($line in $output) {
        Add-Content -LiteralPath $LogPath -Encoding Ascii -Value ([string]$line)
    }
    [pscustomobject]@{
        ExitCode = $exitCode
        Output = @($output | ForEach-Object { [string]$_ })
    }
}

function Start-PersistentWslWorker {
    param(
        [string]$Program,
        [string[]]$Arguments,
        [string]$ReadyMarker,
        [string]$LogPath,
        [string]$Label
    )
    $tokens = @(
        'env',
        "CUDA_VISIBLE_DEVICES=$CudaDevice",
        'CUDA_HOME=/usr/local/cuda-12.8',
        'CUDA_PATH=/usr/local/cuda-12.8',
        'CUDAToolkit_ROOT=/usr/local/cuda-12.8',
        'LD_LIBRARY_PATH=/usr/local/cuda-12.8/lib64',
        $Program
    ) + $Arguments
    if ($WslDistribution -cnotmatch '^[A-Za-z0-9_.-]+$') {
        throw "unsafe WSL distribution name: $WslDistribution"
    }
    foreach ($token in $tokens) {
        if ($token -cnotmatch '^[A-Za-z0-9_./:=+-]+$') {
            throw "unsafe persistent-worker argument: $token"
        }
    }
    $command = ($tokens -join ' ') + ' 2>&1'
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = (Get-Command wsl.exe).Source
    $startInfo.Arguments = "-d $WslDistribution -- bash -lc `"$command`""
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    if (-not $process.Start()) {
        throw "failed to start $Label"
    }
    $process.StandardInput.NewLine = "`n"
    try {
        while ($true) {
            $line = $process.StandardOutput.ReadLine()
            if ($null -eq $line) {
                throw "$Label exited before $ReadyMarker"
            }
            Add-Content -LiteralPath $LogPath -Encoding Ascii -Value $line
            if ($line -ceq $ReadyMarker) {
                break
            }
        }
    } catch {
        if (-not $process.HasExited) {
            $process.Kill()
            $process.WaitForExit()
        }
        $process.Dispose()
        throw
    }
    [pscustomobject]@{
        Process = $process
        Input = $process.StandardInput
        Output = $process.StandardOutput
        Label = $Label
    }
}

function Invoke-PersistentWslWorker {
    param(
        $Worker,
        [string[]]$Fields,
        [string]$DoneMarker,
        [string]$LogPath
    )
    foreach ($field in $Fields) {
        if ([string]::IsNullOrWhiteSpace($field) -or $field.Contains("`t") -or $field.Contains("`n")) {
            throw "invalid $($Worker.Label) command field"
        }
    }
    $Worker.Input.WriteLine(($Fields -join "`t"))
    $Worker.Input.Flush()
    while ($true) {
        $line = $Worker.Output.ReadLine()
        if ($null -eq $line) {
            throw "$($Worker.Label) exited before $DoneMarker"
        }
        Add-Content -LiteralPath $LogPath -Encoding Ascii -Value $line
        if ($line -ceq $DoneMarker) {
            return
        }
    }
}

function Stop-PersistentWslWorker {
    param($Worker)
    if ($null -eq $Worker) {
        return
    }
    try {
        if (-not $Worker.Process.HasExited) {
            $Worker.Input.WriteLine('QUIT')
            $Worker.Input.Flush()
            if (-not $Worker.Process.WaitForExit(5000)) {
                $Worker.Process.Kill()
                $Worker.Process.WaitForExit()
            }
        }
    } catch {
        if (-not $Worker.Process.HasExited) {
            $Worker.Process.Kill()
            $Worker.Process.WaitForExit()
        }
    } finally {
        $Worker.Process.Dispose()
    }
}

function Invoke-Checked {
    param(
        [string]$Program,
        [string[]]$Arguments,
        [string]$Label,
        [string]$LogPath
    )
    $exitCode = Invoke-NativeLogged $Program $Arguments $LogPath
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

function Invoke-WslCapture {
    param(
        [string[]]$Arguments,
        [string]$Label
    )
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = @(& wsl.exe -d $WslDistribution -- @Arguments 2>&1)
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    if ($exitCode -ne 0) {
        throw "$Label exited with code $exitCode`: $($output -join [Environment]::NewLine)"
    }
    return @($output | ForEach-Object { [string]$_ })
}

function Initialize-WslFileCache {
    param(
        [string]$Source,
        [string]$Destination,
        [uint64]$ExpectedBytes,
        [string]$ExpectedSha256,
        [string]$Label
    )
    $state = @(Invoke-WslCapture -Arguments @(
        'bash', $wslCacheHelperWsl, 'cache-state',
        $Destination,
        $ExpectedBytes.ToString([Globalization.CultureInfo]::InvariantCulture),
        $ExpectedSha256
    ) -Label "$Label probe")[-1]
    if ($state -eq 'cached') {
        return 'cached'
    }
    Write-Host "Preparing one-time fast cache: $Label..."
    $result = @(Invoke-WslCapture -Arguments @(
        'bash', $wslCacheHelperWsl, 'cache-file',
        $Source, $Destination,
        $ExpectedBytes.ToString([Globalization.CultureInfo]::InvariantCulture),
        $ExpectedSha256
    ) -Label $Label)
    return $result[-1]
}

function Write-PhaseTelemetry {
    param(
        [string]$LogPath,
        [string]$Phase,
        [Diagnostics.Stopwatch]$Timer
    )
    Add-Content -LiteralPath $LogPath -Encoding Ascii -Value (
        'CMFD_V4_MINER_PHASE phase={0} wall_seconds={1}' -f $Phase, (
            $Timer.Elapsed.TotalSeconds.ToString('F6', [Globalization.CultureInfo]::InvariantCulture)
        )
    )
}

function Invoke-TimedChecked {
    param(
        [scriptblock]$Action,
        [string]$Phase,
        [string]$LogPath
    )
    $phaseTimer = [Diagnostics.Stopwatch]::StartNew()
    try {
        & $Action
    } finally {
        $phaseTimer.Stop()
        Write-PhaseTelemetry $LogPath $Phase $phaseTimer
    }
}

function Remove-WslOwnedDirectory {
    param(
        [string]$Root,
        [string]$Target,
        [string]$Prefix
    )
    Invoke-WslCapture -Arguments @(
        'bash', $wslCacheHelperWsl, 'remove-owned', $Root, $Target, $Prefix
    ) -Label 'ProductionV4 WSL scratch cleanup' | Out-Null
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
    param(
        [string]$ManifestPath,
        [hashtable]$ExpectedInputs,
        [switch]$Prepared
    )
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
        $reusableCache = $name.EndsWith('.row-major.codeword', [StringComparison]::Ordinal)
        $fixedRecord = $name -ceq 'FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json'
        if ((-not $reusableCache) -and ((-not $Prepared) -or $fixedRecord)) {
            $sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant()
            if ($sha256 -cne [string]$entry.sha256) {
                throw "input SHA-256 mismatch for $name"
            }
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
$wslCacheHelperPath = Resolve-ExistingFile (
    Join-Path $PSScriptRoot 'production-v4-wsl-cache.sh'
) 'V4 WSL cache helper'
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
Assert-InputManifest $inputManifestPath $expectedInputs -Prepared:$InputsPrepared

$modelBankWsl, $artifactDirectoryWsl, $replayBinaryWsl, $dynamicCommitmentBinaryWsl, $proofBinaryWsl, $wslCacheHelperWsl = @(
    Convert-ToWslPaths @(
        $modelBankPath,
        $artifactDirectoryPath,
        $replayBinaryPath,
        $dynamicCommitmentBinaryPath,
        $proofBinaryPath,
        $wslCacheHelperPath
    )
)

if ($ValidateOnly) {
    Write-Host 'ProductionV4 miner launcher validation passed.'
    return
}

$manifest = Get-Content -Raw -LiteralPath $inputManifestPath | ConvertFrom-Json
$manifestByName = @{}
foreach ($entry in @($manifest.files)) {
    $manifestByName[[string]$entry.name] = $entry
}
$cacheRootOutput = @(Invoke-WslCapture -Arguments @(
    'bash', $wslCacheHelperWsl, 'cache-root'
) -Label 'ProductionV4 WSL cache location')
if ($cacheRootOutput.Count -ne 1 -or -not $cacheRootOutput[0].StartsWith('/')) {
    throw 'failed to resolve the ProductionV4 WSL cache location'
}
$cacheRoot = $cacheRootOutput[0]
$modelEntry = $manifestByName['MODEL-V2.bank']
$cachedModelBankWsl = "$cacheRoot/model/$([string]$modelEntry.sha256).bank"

$cacheMiss = $false
if ((Initialize-WslFileCache `
    $modelBankWsl `
    $cachedModelBankWsl `
    ([uint64]$modelEntry.bytes) `
    ([string]$modelEntry.sha256) `
    'ProductionV4 model cache') -eq 'populated') {
    $cacheMiss = $true
}

$cachedTreePaths = @()
for ($bank = 0; $bank -lt 3; $bank++) {
    $treeName = "FORGEMATRIX-V4-FIXED-BANK-$bank.tree"
    $treeEntry = $manifestByName[$treeName]
    $sourceTreeWsl = "$artifactDirectoryWsl/$treeName"
    $cachedTreeWsl = "$cacheRoot/tree/$([string]$treeEntry.sha256).tree"
    if ((Initialize-WslFileCache `
        $sourceTreeWsl `
        $cachedTreeWsl `
        ([uint64]$treeEntry.bytes) `
        ([string]$treeEntry.sha256) `
        "ProductionV4 fixed tree $bank cache") -eq 'populated') {
        $cacheMiss = $true
    }
    $cachedTreePaths += $cachedTreeWsl
}
if ($cacheMiss) {
    Write-Host 'ProductionV4 fast WSL cache is ready.'
}

$cachedArtifactDirectoryWsl = "$cacheRoot/fixed"
$fixedViewArguments = @(
    'bash', $wslCacheHelperWsl, 'fixed-view',
    $cachedArtifactDirectoryWsl,
    "$artifactDirectoryWsl/FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json"
)
for ($bank = 0; $bank -lt 3; $bank++) {
    $fixedViewArguments += $cachedTreePaths[$bank]
    $fixedViewArguments += "$artifactDirectoryWsl/FORGEMATRIX-V4-FIXED-BANK-$bank.row-major.codeword"
}
Invoke-WslCapture -Arguments $fixedViewArguments `
    -Label 'ProductionV4 cached fixed-artifact view' | Out-Null

$scratchRootOutput = @(Invoke-WslCapture -Arguments @(
    'bash', $wslCacheHelperWsl, 'scratch-root'
) -Label 'ProductionV4 WSL scratch location')
if ($scratchRootOutput.Count -ne 1 -or -not $scratchRootOutput[0].StartsWith('/')) {
    throw 'failed to resolve the ProductionV4 WSL scratch location'
}
$nativeWorkRootWsl = $scratchRootOutput[0]
$sessionName = 'session-{0}-{1}' -f $PID, ([DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssfffffffZ'))
$nativeSessionWsl = "$nativeWorkRootWsl/$sessionName"
Invoke-WslCapture -Arguments @(
    'bash', $wslCacheHelperWsl, 'make-owned', $nativeWorkRootWsl, $nativeSessionWsl, 'session-'
) -Label 'ProductionV4 WSL scratch setup' | Out-Null

$persistentReplayWsl = "$nativeSessionWsl/cmfd-v4-replay"
$persistentProofWsl = "$nativeSessionWsl/cmfd-v4-prover"
Invoke-WslCapture -Arguments @(
    'cp', '--', $replayBinaryWsl, $persistentReplayWsl
) -Label 'ProductionV4 replay-worker staging' | Out-Null
Invoke-WslCapture -Arguments @(
    'cp', '--', $proofBinaryWsl, $persistentProofWsl
) -Label 'ProductionV4 proof-worker staging' | Out-Null
Invoke-WslCapture -Arguments @(
    'chmod', '0700', $persistentReplayWsl, $persistentProofWsl
) -Label 'ProductionV4 worker permissions' | Out-Null

$accepted = 0
$rejected = 0
$attempts = 0
$sessionEnergyKwh = 0.0
$logDirectory = Join-Path $workDirectoryPath 'logs'
New-Item -ItemType Directory -Force -Path $logDirectory | Out-Null
$sessionLog = Join-Path $logDirectory (
    'session-{0}.log' -f ([DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssfffffffZ'))
)
New-Item -ItemType File -Path $sessionLog | Out-Null
$proofWorker = $null
$replayWorker = $null
$keepReplayResident = $gpuMemoryMiB -ge 20000
Write-MinerStats $accepted $rejected ([double]::NaN) ([double]::NaN) $sessionEnergyKwh ([double]::NaN)
try {
$proofWorker = Start-PersistentWslWorker `
    $persistentProofWsl `
    @('--server', $cachedModelBankWsl, $cachedArtifactDirectoryWsl) `
    'CMFD_V4_PROOF_READY' `
    $sessionLog `
    'ProductionV4 proof worker'
$replayWorker = Start-PersistentWslWorker `
    $persistentReplayWsl `
    @('--server', $cachedModelBankWsl) `
    'CMFD_V4_REPLAY_READY' `
    $sessionLog `
    'ProductionV4 replay worker'
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
        Invoke-TimedChecked {
            Invoke-Checked $cmfdMinerPath $snapshotArguments 'ProductionV4 template snapshot' $attemptLog
        } 'snapshot' $attemptLog

        $templateWindowsWsl, $coefficientsWindowsWsl, $proofWindowsWsl = @(
            Convert-ToWslPaths @($template, $coefficients, $proof)
        )
        $attemptDirectoryWindowsWsl = $templateWindowsWsl.Substring(
            0,
            $templateWindowsWsl.LastIndexOf('/')
        )
        $attemptWsl = "$nativeSessionWsl/$attemptName"
        Invoke-WslCapture -Arguments @(
            'bash', $wslCacheHelperWsl, 'make-owned', $nativeSessionWsl, $attemptWsl, 'attempt-'
        ) -Label 'ProductionV4 WSL attempt setup' | Out-Null
        $tracePrefixWsl = "$attemptWsl/trace"
        $finalActivationWsl = "$tracePrefixWsl-final-activation.bin"
        $searchTracePrefixWsl = "$attemptWsl/search"
        $searchFinalActivationWsl = "$searchTracePrefixWsl-final-activation.bin"
        $searchFinalActivationWindows = Convert-FromWslPath $searchFinalActivationWsl
        $proofWsl = "$attemptWsl/transparent-proof.bin"

        $candidateTemplate = $template
        $candidateTemplateWsl = $templateWindowsWsl
        $candidateCoefficientsWsl = $coefficientsWindowsWsl
        $candidateNonce = $Nonce
        $searchTimer = [Diagnostics.Stopwatch]::StartNew()
        try {
            while ($true) {
                Invoke-PersistentWslWorker `
                    $replayWorker `
                    @('RUN', 'search', $candidateCoefficientsWsl, $searchTracePrefixWsl) `
                    'CMFD_V4_REPLAY_DONE' `
                    $attemptLog
                $inspection = Invoke-NativeCaptureLogged $cmfdMinerPath @(
                    'inspect-v4-work',
                    '--template', $candidateTemplate,
                    '--final-activation', $searchFinalActivationWindows,
                    '--fixed-record', $fixedRecordPath
                ) $attemptLog
                if ($inspection.ExitCode -ne 0) {
                    throw "ProductionV4 work inspection exited with code $($inspection.ExitCode)"
                }
                $workLines = @($inspection.Output | Where-Object {
                    $_.StartsWith('CMFD_V4_WORK ', [StringComparison]::Ordinal)
                })
                $workMatch = if ($workLines.Count -eq 1) {
                    [regex]::Match($workLines[0], ' qualified=(true|false) ')
                } else {
                    $null
                }
                if ($null -eq $workMatch -or -not $workMatch.Success) {
                    throw 'ProductionV4 work inspection did not return one canonical result'
                }
                if ($workMatch.Groups[1].Value -ceq 'true') {
                    break
                }
                if ($searchTimer.Elapsed.TotalSeconds -ge $TemplateRefreshSeconds) {
                    $outcome = 'refresh'
                    break
                }
                if ($candidateNonce -eq [uint64]::MaxValue) {
                    throw 'ProductionV4 nonce space exhausted'
                }
                $candidateNonce++
                $candidateTemplate = Join-Path $attemptDirectory "template-$candidateNonce.json"
                $candidateCoefficients = Join-Path $attemptDirectory "replay-coefficients-$candidateNonce.bin"
                $bind = Invoke-NativeCaptureLogged $cmfdMinerPath @(
                    'bind-v4-nonce',
                    '--template', $template,
                    '--nonce', $candidateNonce.ToString([Globalization.CultureInfo]::InvariantCulture),
                    '--fixed-record', $fixedRecordPath,
                    '--coefficients-output', $candidateCoefficients,
                    '--output', $candidateTemplate
                ) $attemptLog
                if ($bind.ExitCode -ne 0) {
                    throw "ProductionV4 nonce binding exited with code $($bind.ExitCode)"
                }
                $candidateTemplateWindowsWsl = "$attemptDirectoryWindowsWsl/template-$candidateNonce.json"
                $candidateCoefficientsWindowsWsl = "$attemptDirectoryWindowsWsl/replay-coefficients-$candidateNonce.bin"
                $candidateTemplateWsl = $candidateTemplateWindowsWsl
                $candidateCoefficientsWsl = $candidateCoefficientsWindowsWsl
            }
        } finally {
            $searchTimer.Stop()
            Write-PhaseTelemetry $attemptLog 'search' $searchTimer
        }
        if ($outcome -ne 'refresh') {
            Invoke-TimedChecked {
                Invoke-PersistentWslWorker `
                    $replayWorker `
                    @('RUN', 'full', $candidateCoefficientsWsl, $tracePrefixWsl) `
                    'CMFD_V4_REPLAY_DONE' `
                    $attemptLog
                Invoke-WslCapture -Arguments @(
                    'cmp', '--', $searchFinalActivationWsl, $finalActivationWsl
                ) -Label 'ProductionV4 search/full replay comparison' | Out-Null
            } 'winning_replay' $attemptLog
            if (-not $keepReplayResident) {
                Invoke-PersistentWslWorker `
                    $replayWorker `
                    @('EVICT') `
                    'CMFD_V4_REPLAY_EVICTED' `
                    $attemptLog
            }
            Invoke-TimedChecked {
                Invoke-PersistentWslWorker `
                    $proofWorker `
                    @('RUN', $candidateTemplateWsl,
                    $tracePrefixWsl,
                    $finalActivationWsl,
                    $proofWsl) `
                    'CMFD_V4_PROOF_DONE' `
                    $attemptLog
            } 'proof' $attemptLog
            Invoke-WslCapture -Arguments @(
                'cp', '--', $proofWsl, $proofWindowsWsl
            ) -Label 'ProductionV4 proof export' | Out-Null

            $submitArguments = @(
                'submit-v4-template',
                '--peer', $Peer,
                '--template', $candidateTemplate,
                '--transparent-proof', $proof,
                '--fixed-record', $fixedRecordPath
            )
            if ($AllowPublicPeer) {
                $submitArguments += '--allow-public-peers'
            }
            $submitTimer = [Diagnostics.Stopwatch]::StartNew()
            try {
                $submitExitCode = Invoke-NativeLogged $cmfdMinerPath $submitArguments $attemptLog
            } finally {
                $submitTimer.Stop()
                Write-PhaseTelemetry $attemptLog 'submit' $submitTimer
            }
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

    if ($outcome -eq 'accepted' -and $KeepAcceptedWork) {
        $attemptDirectoryWsl = @(Convert-ToWslPaths @($attemptDirectory))[0]
        Invoke-WslCapture -Arguments @(
            'bash', $wslCacheHelperWsl, 'preserve-attempt', $attemptWsl, $attemptDirectoryWsl
        ) -Label 'ProductionV4 accepted-work preservation' | Out-Null
    }
    Remove-WslOwnedDirectory $nativeSessionWsl $attemptWsl 'attempt-'

    if ($outcome -ne 'accepted' -or -not $KeepAcceptedWork) {
        Remove-AttemptDirectory $attemptDirectory
    }
}
} finally {
    Stop-PersistentWslWorker $replayWorker
    Stop-PersistentWslWorker $proofWorker
    Remove-WslOwnedDirectory $nativeWorkRootWsl $nativeSessionWsl 'session-'
}
