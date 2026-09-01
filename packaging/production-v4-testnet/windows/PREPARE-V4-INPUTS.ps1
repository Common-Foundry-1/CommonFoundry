#requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('Node', 'Miner', 'PoolMiner')]
    [string]$Role = 'Miner',
    [string]$Destination = (Join-Path $PSScriptRoot 'inputs'),
    [string]$ReleaseBase = 'https://downloads.commonfoundry.ai/v0.1.0-rc.1',
    [string]$FallbackReleaseBase = 'https://github.com/Common-Foundry-1/CommonFoundry/releases/download/v0.1.0-rc.1',
    [ValidateRange(1, 16)]
    [int]$DownloadConcurrency = 16
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Test-Identity {
    param([string]$Path, [uint64]$Bytes, [string]$Sha256)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    if ([uint64](Get-Item -LiteralPath $Path).Length -ne $Bytes) { return $false }
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant() -ceq $Sha256
}

function Test-Length {
    param([string]$Path, [uint64]$Bytes)
    return (Test-Path -LiteralPath $Path -PathType Leaf) -and
        [uint64](Get-Item -LiteralPath $Path).Length -eq $Bytes
}

function Test-ReusableCacheName {
    param([string]$Name)
    return $Name.EndsWith('.row-major.codeword', [StringComparison]::Ordinal)
}

function Get-MissingPart {
    param($Part, [string]$PartDirectory, [string[]]$ReleaseBases)
    $partPath = Join-Path $PartDirectory ([string]$Part.name)
    if (Test-Identity $partPath ([uint64]$Part.bytes) ([string]$Part.sha256)) {
        return $null
    }
    $download = "$partPath.download"
    if (Test-Path -LiteralPath $download -PathType Leaf) {
        $downloadBytes = [uint64](Get-Item -LiteralPath $download).Length
        if ($downloadBytes -gt [uint64]$Part.bytes -or
            ($downloadBytes -eq [uint64]$Part.bytes -and
             -not (Test-Identity $download ([uint64]$Part.bytes) ([string]$Part.sha256)))) {
            Remove-Item -LiteralPath $download -Force
        }
    }
    [pscustomobject]@{
        Part = $Part
        Path = $partPath
        Download = $download
        Urls = @($ReleaseBases | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Select-Object -Unique | ForEach-Object { "$($_.TrimEnd('/'))/$($Part.name)" })
    }
}

function Receive-PartDownload {
    param($ActiveDownload)
    try {
        Receive-Job -Job $ActiveDownload.Job -ErrorAction Stop | Out-Null
        if ($ActiveDownload.Job.State -ne 'Completed') {
            throw "Download failed: $($ActiveDownload.Item.Part.name)"
        }
        $item = $ActiveDownload.Item
        if (-not (Test-Identity $item.Download ([uint64]$item.Part.bytes) ([string]$item.Part.sha256))) {
            Remove-Item -LiteralPath $item.Download -Force -ErrorAction SilentlyContinue
            throw "Downloaded part failed authentication: $($item.Part.name)"
        }
        Move-Item -LiteralPath $item.Download -Destination $item.Path -Force
        Write-Host "Authenticated $($item.Part.name)"
    } finally {
        Remove-Job -Job $ActiveDownload.Job -Force -ErrorAction SilentlyContinue
    }
}

function Get-PartPaths {
    param($Parts, [string]$PartDirectory, [string[]]$ReleaseBases, [int]$Concurrency)
    $curlPath = (Get-Command curl.exe -ErrorAction Stop).Source
    $items = @($Parts | ForEach-Object { Get-MissingPart $_ $PartDirectory $ReleaseBases } |
        Where-Object { $null -ne $_ })
    $pending = [Collections.Queue]::new()
    foreach ($item in $items) { $pending.Enqueue($item) }
    $active = @()
    try {
        while ($pending.Count -gt 0 -or $active.Count -gt 0) {
            while ($pending.Count -gt 0 -and $active.Count -lt $Concurrency) {
                $item = $pending.Dequeue()
                $existingBytes = if (Test-Path -LiteralPath $item.Download -PathType Leaf) {
                    [uint64](Get-Item -LiteralPath $item.Download).Length
                } else { [uint64]0 }
                Write-Host "Downloading $($item.Part.name) ($existingBytes of $($item.Part.bytes) bytes already present)"
                $job = Start-Job -ScriptBlock {
                    param($CurlPath, $UrlList, $Output)
                    $downloaded = $false
                    foreach ($url in @($UrlList -split "`n")) {
                        & $CurlPath --location --fail --silent --show-error --retry 5 --retry-delay 3 `
                            --connect-timeout 30 --speed-limit 1024 --speed-time 30 --continue-at - `
                            --output $Output $url
                        if ($LASTEXITCODE -eq 0) {
                            $downloaded = $true
                            break
                        }
                    }
                    if (-not $downloaded) { throw 'All download sources failed.' }
                } -ArgumentList $curlPath, ([string]::Join("`n", $item.Urls)), $item.Download
                $active += [pscustomobject]@{ Job = $job; Item = $item }
            }
            if ($active.Count -gt 0) {
                $completedJob = Wait-Job -Job @($active.Job) -Any
                $completed = $active | Where-Object { $_.Job.Id -eq $completedJob.Id } | Select-Object -First 1
                Receive-PartDownload $completed
                $active = @($active | Where-Object { $_.Job.Id -ne $completedJob.Id })
            }
        }
    } catch {
        foreach ($running in $active) {
            Stop-Job -Job $running.Job -ErrorAction SilentlyContinue
            Remove-Job -Job $running.Job -Force -ErrorAction SilentlyContinue
        }
        throw
    }
    @($Parts | ForEach-Object { Join-Path $PartDirectory ([string]$_.name) })
}

$manifestPath = Join-Path $PSScriptRoot 'V4-INPUT-CHUNKS.json'
$manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
if ($manifest.schema_version -ne 1 -or $manifest.release -ne 'v0.1.0-rc.1') {
    throw 'Unsupported ProductionV4 input chunk manifest.'
}
$inputManifestPath = Join-Path $PSScriptRoot 'production-v4-rcnet-1-inputs.json'
$inputManifest = Get-Content -Raw -LiteralPath $inputManifestPath | ConvertFrom-Json
if ($inputManifest.schema_version -ne 1 -or
    $inputManifest.network -cne 'CommonFoundry RCNet-1') {
    throw 'Unsupported ProductionV4 input manifest.'
}
$inputEntries = @{}
foreach ($entry in @($inputManifest.files)) {
    $name = [string]$entry.name
    if ($inputEntries.ContainsKey($name)) {
        throw "ProductionV4 input manifest repeats $name"
    }
    $inputEntries[$name] = $entry
}
foreach ($file in @($manifest.files)) {
    $name = [string]$file.name
    if (-not $inputEntries.ContainsKey($name) -or
        [uint64]$inputEntries[$name].bytes -ne [uint64]$file.bytes -or
        [string]$inputEntries[$name].sha256 -cne [string]$file.sha256) {
        throw "ProductionV4 input manifests disagree about $name"
    }
}
$destinationPath = [IO.Path]::GetFullPath($Destination)
$partDirectory = Join-Path $destinationPath '.parts'
New-Item -ItemType Directory -Force -Path $destinationPath, $partDirectory | Out-Null

$manifestRole = if ($Role -ceq 'PoolMiner') { 'pool-miner' } else { $Role.ToLowerInvariant() }
foreach ($file in $manifest.files) {
    if (@($file.roles) -notcontains $manifestRole) { continue }
    $output = Join-Path $destinationPath ([string]$file.relative_path)
    $reusableCache = Test-ReusableCacheName ([string]$file.name)
    $ready = if ($reusableCache) {
        Test-Length $output ([uint64]$file.bytes)
    } else {
        Test-Identity $output ([uint64]$file.bytes) ([string]$file.sha256)
    }
    if ($ready) {
        $status = if ($reusableCache) { 'Reusing' } else { 'Authenticated existing' }
        Write-Host "$status $($file.name)"
        continue
    }
    $parent = Split-Path -Parent $output
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
    $partPaths = @(Get-PartPaths $file.parts $partDirectory @($ReleaseBase, $FallbackReleaseBase) $DownloadConcurrency)
    $partial = "$output.partial"
    Remove-Item -LiteralPath $partial -Force -ErrorAction SilentlyContinue
    $target = [IO.File]::Open($partial, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    $sha256 = [Security.Cryptography.IncrementalHash]::CreateHash(
        [Security.Cryptography.HashAlgorithmName]::SHA256
    )
    try {
        $buffer = New-Object byte[] (8 * 1024 * 1024)
        foreach ($partPath in $partPaths) {
            $source = [IO.File]::OpenRead($partPath)
            try {
                while (($read = $source.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    $target.Write($buffer, 0, $read)
                    $sha256.AppendData($buffer, 0, $read)
                }
            } finally {
                $source.Dispose()
            }
        }
    } finally {
        $target.Dispose()
    }
    $assembledHash = [BitConverter]::ToString($sha256.GetHashAndReset()).Replace('-', '').ToLowerInvariant()
    $sha256.Dispose()
    if (-not (Test-Length $partial ([uint64]$file.bytes)) -or
        $assembledHash -cne [string]$file.sha256) {
        Remove-Item -LiteralPath $partial -Force -ErrorAction SilentlyContinue
        throw "Assembled file failed authentication: $($file.name)"
    }
    Move-Item -LiteralPath $partial -Destination $output -Force
    foreach ($partPath in $partPaths) {
        Remove-Item -LiteralPath $partPath -Force
    }
    Write-Host "Prepared $($file.name)"
}

$fixedSource = Join-Path $PSScriptRoot 'FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json'
$fixedTarget = Join-Path $destinationPath 'fixed\FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json'
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $fixedTarget) | Out-Null
Copy-Item -LiteralPath $fixedSource -Destination $fixedTarget -Force
Write-Host "ProductionV4 $Role inputs are ready under $destinationPath"
