[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$OutputArchive,
    [string]$NodeBinary,
    [string]$ReferenceSignerBinary
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-RegularFile {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$Label)
    $item = Get-Item -LiteralPath ([IO.Path]::GetFullPath($Path)) -Force -ErrorAction Stop
    if ($item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "$Label must be a regular non-reparse file: $($item.FullName)"
    }
    Assert-NoReparsePath -Path $item.FullName -Label $Label
    return $item.FullName
}

function Resolve-RealDirectory {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$Label)
    $item = Get-Item -LiteralPath ([IO.Path]::GetFullPath($Path)) -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "$Label must be a real non-reparse directory: $($item.FullName)"
    }
    Assert-NoReparsePath -Path $item.FullName -Label $Label
    return $item.FullName
}

function Assert-NoReparsePath {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$Label)
    $item = Get-Item -LiteralPath ([IO.Path]::GetFullPath($Path)) -Force -ErrorAction Stop
    while ($null -ne $item) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Label traverses a reparse point: $($item.FullName)"
        }
        if ($item -is [IO.DirectoryInfo]) {
            $item = $item.Parent
        } else {
            $item = $item.Directory
        }
    }
}

function Get-CanonicalBinaryName {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$BaseName
    )
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $header = [byte[]]::new(64)
        if ($stream.Read($header, 0, $header.Length) -lt 4) {
            throw "$BaseName is too short to be a supported executable"
        }
        if ($header[0] -eq 0x7f -and $header[1] -eq 0x45 -and
            $header[2] -eq 0x4c -and $header[3] -eq 0x46) {
            return $BaseName
        }
        if ($header[0] -ne 0x4d -or $header[1] -ne 0x5a -or $stream.Length -lt 68) {
            throw "$BaseName must be a Windows PE or Linux ELF executable"
        }
        $peOffset = [BitConverter]::ToUInt32($header, 0x3c)
        if ($peOffset -gt ($stream.Length - 4)) {
            throw "$BaseName has an invalid Windows PE header offset"
        }
        $stream.Position = $peOffset
        $signature = [byte[]]::new(4)
        if ($stream.Read($signature, 0, 4) -ne 4 -or
            $signature[0] -ne 0x50 -or $signature[1] -ne 0x45 -or
            $signature[2] -ne 0 -or $signature[3] -ne 0) {
            throw "$BaseName has an invalid Windows PE signature"
        }
        return "$BaseName.exe"
    } finally {
        $stream.Dispose()
    }
}

function Test-SafeBundleName {
    param([Parameter(Mandatory = $true)][string]$Name)
    return $Name -cnotmatch '(?i)(passphrase|password|secret|credential|private|seed|token|wallet\.key|journal\.key|auth(?:entication)?(?:\.|-|_)file|\.env(?:\.|$)|\.(?:pem|pfx|p12)$)'
}

function Test-PathWithin {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Root
    )
    $candidate = [IO.Path]::GetFullPath($Path)
    $rootPath = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    return $candidate.Equals($rootPath, [StringComparison]::OrdinalIgnoreCase) -or
        $candidate.StartsWith($rootPath + '\', [StringComparison]::OrdinalIgnoreCase)
}

function Assert-ErrorCatalogRoutes {
    param([Parameter(Mandatory = $true)][string]$Path)
    $catalog = Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json -ErrorAction Stop
    $routingKey = @($catalog.routing_key)
    if ($routingKey.Count -ne 2 -or
        [string]$routingKey[0] -cne 'error.code' -or
        [string]$routingKey[1] -cne 'error.data.code') {
        throw 'error catalog must route on the ordered error.code and error.data.code pair'
    }
    $routes = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($group in @($catalog.groups)) {
        if ($group.jsonrpc_code -isnot [int] -and $group.jsonrpc_code -isnot [long]) {
            throw 'error catalog JSON-RPC codes must be integers'
        }
        if ($group.retryable -isnot [bool]) {
            throw 'error catalog retryable values must be booleans'
        }
        foreach ($dataCode in @($group.data_codes)) {
            if ([string]$dataCode -cnotmatch '^[a-z][a-z0-9_]*$') {
                throw 'error catalog contains a noncanonical data code'
            }
            $route = "$([long]$group.jsonrpc_code)|$([string]$dataCode)"
            if (-not $routes.Add($route)) {
                throw "error catalog contains a duplicate composite route: $route"
            }
        }
    }
}

$repository = Split-Path -Parent $PSScriptRoot
$outputPath = [IO.Path]::GetFullPath($OutputArchive)
if ([IO.Path]::GetExtension($outputPath) -cne '.zip') {
    throw 'OutputArchive must end in .zip'
}
if (Test-Path -LiteralPath $outputPath) {
    throw "refusing to overwrite existing archive: $outputPath"
}
$outputParent = Split-Path -Parent $outputPath
if (-not (Test-Path -LiteralPath $outputParent -PathType Container)) {
    throw "output directory does not exist: $outputParent"
}
$outputParent = Resolve-RealDirectory -Path $outputParent -Label 'output directory'
foreach ($sourceRootName in @('exchange-kit', 'exchange-ops', 'docs', 'scripts')) {
    $sourceRoot = Join-Path $repository $sourceRootName
    if (Test-PathWithin -Path $outputPath -Root $sourceRoot) {
        throw "OutputArchive must be outside packaged source directories: $sourceRoot"
    }
}

$requiredFiles = @(
    'exchange-kit\COMPATIBILITY.md',
    'exchange-kit\ERROR-CATALOG.md',
    'exchange-kit\errors.json',
    'exchange-kit\examples\chain-and-deposits.json',
    'exchange-kit\examples\custody-v0.5.json',
    'exchange-kit\openrpc.json',
    'exchange-kit\schemas\error-catalog.schema.json',
    'exchange-kit\schemas\example-transcript.schema.json',
    'exchange-kit\schemas\exchange-rpc.schema.json',
    'exchange-kit\START-HERE.md',
    'exchange-ops\backup-recovery.md',
    'exchange-ops\diligence\QUESTIONNAIRE.md',
    'exchange-ops\diligence\SECURITY-CONTACTS.template.md',
    'exchange-ops\diligence\TECHNICAL-FACT-SHEET.md',
    'exchange-ops\linux\commonfoundry-exchange.service.in',
    'exchange-ops\proxy\nginx-mtls.conf.in',
    'exchange-ops\readiness-gates.json',
    'exchange-ops\README.md',
    'exchange-ops\upgrade-rollback.md',
    'exchange-ops\windows\Start-CommonFoundryExchange.ps1',
    'docs\exchange-custody-acl-qualification.md',
    'docs\exchange-custody-audit-candidate.md',
    'docs\exchange-custody-v0.5.md',
    'docs\exchange-integration.md',
    'scripts\pin-exchange-withdrawal-anchor.ps1',
    'scripts\qualify-exchange-custody-acl.ps1',
    'scripts\qualify-exchange-custody-acl.sh',
    'scripts\rehearse-exchange-custody-v3.ps1',
    'scripts\tests\exchange-custody-acl-safe-windows.json'
)
$allowedSourceFiles = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($relative in $requiredFiles) {
    $allowedSourceFiles.Add($relative.Replace('/', '\')) | Out-Null
}
foreach ($rootName in @('exchange-kit', 'exchange-ops')) {
    $root = Resolve-RealDirectory -Path (Join-Path $repository $rootName) -Label $rootName
    foreach ($item in Get-ChildItem -LiteralPath $root -Force -Recurse) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "reparse points are forbidden in the integration kit: $($item.FullName)"
        }
        if (-not $item.PSIsContainer) {
            $relative = $item.FullName.Substring($repository.Length).TrimStart('\')
            if (-not $allowedSourceFiles.Contains($relative)) {
                throw "unreviewed source file is forbidden in the integration kit: $relative"
            }
        }
    }
}
Assert-ErrorCatalogRoutes -Path (Join-Path $repository 'exchange-kit\errors.json')

$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ('cmfd-exchange-kit-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($temporaryRoot) | Out-Null
$resolvedTemporary = (Resolve-Path -LiteralPath $temporaryRoot).Path
$resolvedSystemTemp = (Resolve-Path -LiteralPath ([IO.Path]::GetTempPath())).Path.TrimEnd('\')
if (-not $resolvedTemporary.StartsWith($resolvedSystemTemp + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'temporary integration-kit path escaped the system temporary directory'
}

try {
    foreach ($relative in $requiredFiles) {
        $source = Resolve-RegularFile -Path (Join-Path $repository $relative) -Label $relative
        $destination = Join-Path $temporaryRoot $relative
        [IO.Directory]::CreateDirectory((Split-Path -Parent $destination)) | Out-Null
        [IO.File]::Copy($source, $destination, $false)
    }
    $scriptDestination = Join-Path $temporaryRoot 'tools'
    [IO.Directory]::CreateDirectory($scriptDestination) | Out-Null
    foreach ($name in @('exchange_conformance.py', 'exchange_coordinator.py')) {
        $source = Resolve-RegularFile -Path (Join-Path $PSScriptRoot $name) -Label $name
        [IO.File]::Copy($source, (Join-Path $scriptDestination $name), $false)
    }

    $optionalFiles = @(
        @{ Input = $NodeBinary; BaseName = 'cmfd-node' },
        @{ Input = $ReferenceSignerBinary; BaseName = 'cmfd-exchange-signer-reference' }
    )
    $includedOptional = New-Object System.Collections.Generic.List[string]
    foreach ($entry in $optionalFiles) {
        if (-not [string]::IsNullOrWhiteSpace($entry.Input)) {
            $source = Resolve-RegularFile -Path $entry.Input -Label $entry.BaseName
            $name = Get-CanonicalBinaryName -Path $source -BaseName $entry.BaseName
            [IO.File]::Copy($source, (Join-Path $temporaryRoot $name), $false)
            $includedOptional.Add($name)
        }
    }

    $manifestEntries = New-Object System.Collections.Generic.List[object]
    foreach ($item in Get-ChildItem -LiteralPath $temporaryRoot -File -Recurse | Sort-Object FullName) {
        $relative = $item.FullName.Substring($temporaryRoot.Length).TrimStart('\').Replace('\', '/')
        if (-not (Test-SafeBundleName -Name $relative)) {
            throw "integration kit contains a forbidden secret-like path: $relative"
        }
        $manifestEntries.Add([ordered]@{
            path = $relative
            length = [string]$item.Length
            sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        })
    }
    $manifest = [ordered]@{
        schema = 'CMFD_EXCHANGE_INTEGRATION_BUNDLE_V1'
        production_ready = $false
        optional_release_artifacts = $includedOptional.ToArray()
        files = $manifestEntries.ToArray()
        signature = $null
        signature_requirement = 'The release owner must sign the final archive digest under the published release policy before distribution.'
    }
    $manifestPath = Join-Path $temporaryRoot 'MANIFEST.json'
    $manifestBytes = [Text.UTF8Encoding]::new($false).GetBytes(
        (($manifest | ConvertTo-Json -Depth 8) + [Environment]::NewLine)
    )
    [IO.File]::WriteAllBytes($manifestPath, $manifestBytes)

    Compress-Archive -Path (Join-Path $temporaryRoot '*') -DestinationPath $outputPath -CompressionLevel Optimal
    $archiveItem = Get-Item -LiteralPath $outputPath
    [pscustomobject]@{
        schema = 'CMFD_EXCHANGE_INTEGRATION_BUNDLE_BUILD_V1'
        production_ready = $false
        archive = $archiveItem.FullName
        length = [string]$archiveItem.Length
        sha256 = (Get-FileHash -LiteralPath $archiveItem.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        signature = $null
    } | ConvertTo-Json -Depth 4
} finally {
    if (Test-Path -LiteralPath $resolvedTemporary -PathType Container) {
        $checked = (Resolve-Path -LiteralPath $resolvedTemporary).Path
        if (-not $checked.StartsWith($resolvedSystemTemp + '\', [StringComparison]::OrdinalIgnoreCase)) {
            throw 'refusing to clean a temporary path outside the system temporary directory'
        }
        Remove-Item -LiteralPath $checked -Recurse -Force
    }
}
