#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Destination = (Join-Path $PSScriptRoot 'production-v4'),
    [string]$ReleaseBase = 'https://github.com/JustAResearcher/CommonFoundry-Binaries/releases/download/v0.1.0-devnet.16',
    [ValidateRange(1, 16)]
    [int]$DownloadConcurrency = 4
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Test-Identity {
    param([string]$Path, [uint64]$Bytes, [string]$Sha256)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    if ([uint64](Get-Item -LiteralPath $Path).Length -ne $Bytes) { return $false }
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant() -ceq $Sha256
}

function Get-MissingPart {
    param($Part, [string]$PartDirectory, [string]$ReleaseBase)
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
        Url = "$($ReleaseBase.TrimEnd('/'))/$($Part.name)"
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
    param($Parts, [string]$PartDirectory, [string]$ReleaseBase, [int]$Concurrency)
    $curlPath = (Get-Command curl.exe -ErrorAction Stop).Source
    $items = @($Parts | ForEach-Object { Get-MissingPart $_ $PartDirectory $ReleaseBase } |
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
                    param($CurlPath, $Url, $Output)
                    & $CurlPath --location --fail --silent --show-error --retry 5 --retry-delay 3 `
                        --connect-timeout 30 --speed-limit 1024 --speed-time 30 --continue-at - `
                        --output $Output $Url
                    if ($LASTEXITCODE -ne 0) { throw "curl exited with code $LASTEXITCODE" }
                } -ArgumentList $curlPath, $item.Url, $item.Download
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

$manifest = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'V4-INPUT-CHUNKS.json') | ConvertFrom-Json
if ($manifest.schema_version -ne 1 -or $manifest.release -ne 'v0.1.0-devnet.16') {
    throw 'Unsupported ProductionV4 input chunk manifest.'
}
$file = @($manifest.files | Where-Object { @($_.roles) -contains 'node' })
if ($file.Count -ne 1 -or $file[0].relative_path -ne 'MODEL-V2.bank') {
    throw 'The ProductionV4 manifest does not contain exactly one node model bank.'
}
$file = $file[0]
$destinationPath = [IO.Path]::GetFullPath($Destination)
$partDirectory = Join-Path $destinationPath '.parts'
New-Item -ItemType Directory -Force -Path $destinationPath, $partDirectory | Out-Null
$output = Join-Path $destinationPath 'MODEL-V2.bank'

if (-not (Test-Identity $output ([uint64]$file.bytes) ([string]$file.sha256))) {
    $partPaths = @(Get-PartPaths $file.parts $partDirectory $ReleaseBase $DownloadConcurrency)
    $partial = "$output.partial"
    Remove-Item -LiteralPath $partial -Force -ErrorAction SilentlyContinue
    $target = [IO.File]::Open($partial, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        foreach ($partPath in $partPaths) {
            $source = [IO.File]::OpenRead($partPath)
            try { $source.CopyTo($target, 8 * 1024 * 1024) } finally { $source.Dispose() }
        }
    } finally {
        $target.Dispose()
    }
    if (-not (Test-Identity $partial ([uint64]$file.bytes) ([string]$file.sha256))) {
        throw 'The assembled ProductionV4 model bank failed authentication.'
    }
    Move-Item -LiteralPath $partial -Destination $output -Force
    foreach ($partPath in $partPaths) {
        Remove-Item -LiteralPath $partPath -Force
    }
}

Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json') `
    -Destination (Join-Path $destinationPath 'FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json') -Force
Write-Host "ProductionV4 node inputs are authenticated under $destinationPath"
