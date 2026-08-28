#requires -Version 7.0
[CmdletBinding()]
param(
    [string]$Destination = (Join-Path $PSScriptRoot 'production-v4'),
    [string]$ReleaseBase = 'https://github.com/JustAResearcher/CommonFoundry-Binaries/releases/download/v0.1.0-devnet.16'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Test-Identity {
    param([string]$Path, [uint64]$Bytes, [string]$Sha256)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    if ([uint64](Get-Item -LiteralPath $Path).Length -ne $Bytes) { return $false }
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant() -ceq $Sha256
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
    $partPaths = foreach ($part in $file.parts) {
        $partPath = Join-Path $partDirectory ([string]$part.name)
        if (-not (Test-Identity $partPath ([uint64]$part.bytes) ([string]$part.sha256))) {
            $download = "$partPath.download"
            Remove-Item -LiteralPath $download -Force -ErrorAction SilentlyContinue
            Write-Host "Downloading $($part.name)"
            Invoke-WebRequest -Uri "$ReleaseBase/$($part.name)" -OutFile $download
            if (-not (Test-Identity $download ([uint64]$part.bytes) ([string]$part.sha256))) {
                Remove-Item -LiteralPath $download -Force -ErrorAction SilentlyContinue
                throw "Downloaded part failed authentication: $($part.name)"
            }
            Move-Item -LiteralPath $download -Destination $partPath -Force
        }
        $partPath
    }
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
