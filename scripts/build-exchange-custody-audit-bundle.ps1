[CmdletBinding()]
param(
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $repoRoot 'output\audit'
}
$outputRoot = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $outputRoot -Force | Out-Null

$stamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
$bundleName = "Common-Foundry-exchange-custody-v0.5-audit-candidate-$stamp"
$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$stageRoot = [IO.Path]::GetFullPath((Join-Path $tempRoot ($bundleName + '-' + [Guid]::NewGuid().ToString('N'))))
if (-not $stageRoot.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'refusing to stage outside the system temporary directory'
}
$payloadRoot = Join-Path $stageRoot $bundleName

$rootFiles = @(
    '.gitattributes',
    '.gitignore',
    'Cargo.lock',
    'Cargo.toml',
    'LICENSE',
    'README.md',
    'SECURITY.md',
    'THIRD_PARTY_NOTICES.md'
)
$trees = @('crates', 'third_party')
$explicitFiles = @(
    'apps\wallet\src-tauri\Cargo.toml',
    'apps\wallet\src-tauri\build.rs',
    'docs\exchange-custody-acl-qualification.md',
    'docs\exchange-custody-audit-candidate.md',
    'docs\exchange-custody-internal-adversarial-review.md',
    'docs\exchange-custody-v0.5.md',
    'docs\exchange-integration.md',
    'scripts\build-exchange-custody-audit-bundle.ps1',
    'scripts\pin-exchange-withdrawal-anchor.ps1',
    'scripts\qualify-exchange-custody-acl.ps1',
    'scripts\qualify-exchange-custody-acl.sh',
    'scripts\rehearse-exchange-custody-v3.ps1',
    'scripts\test-exchange-rpc.ps1',
    'scripts\tests\exchange-custody-acl-safe-windows.json'
)

$forbiddenExtensions = @('.env', '.jks', '.key', '.kdbx', '.p12', '.pem', '.pfx')
$sourceTreeExtensions = @('.gitignore', '.json', '.md', '.rs', '.toml')

function Assert-NoReparseSourceAncestor {
    param([Parameter(Mandatory)][string]$Path)

    $cursor = Get-Item -LiteralPath (Split-Path -Parent $Path) -Force
    while ($true) {
        $linkTypeProperty = $cursor.PSObject.Properties['LinkType']
        if (($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            ($null -ne $linkTypeProperty -and $null -ne $cursor.LinkType)) {
            throw "refusing to package through a linked or reparse-point directory: $($cursor.FullName)"
        }
        if ($cursor.FullName -eq $repoRoot) {
            break
        }
        $parent = Split-Path -Parent $cursor.FullName
        if ([string]::IsNullOrWhiteSpace($parent) -or
            -not $cursor.FullName.StartsWith(($repoRoot + [IO.Path]::DirectorySeparatorChar), [StringComparison]::OrdinalIgnoreCase)) {
            throw "source ancestor escapes repository: $Path"
        }
        $cursor = Get-Item -LiteralPath $parent -Force
    }
}

function Assert-NonSecretAuditInput {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$DisplayPath,
        [switch]$RequireSourceFile
    )

    Assert-NoReparseSourceAncestor -Path $Path
    $item = Get-Item -LiteralPath $Path -Force
    $linkTypeProperty = $item.PSObject.Properties['LinkType']
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        ($null -ne $linkTypeProperty -and $null -ne $item.LinkType)) {
        throw "refusing to package or inspect a linked or reparse-point input: $DisplayPath"
    }
    $extension = [IO.Path]::GetExtension($item.Name).ToLowerInvariant()
    $name = $item.Name.ToLowerInvariant()
    if ($forbiddenExtensions -contains $extension -or
        $name -eq 'wallet.key' -or
        (($name -match 'keyring|passphrase') -and -not ($sourceTreeExtensions -contains $extension))) {
        throw "refusing to package or inspect a secret-bearing input: $DisplayPath"
    }
    if ($RequireSourceFile -and
        -not ($sourceTreeExtensions -contains $extension) -and
        -not ($name -eq 'license-mit')) {
        throw "refusing to package a non-source tree artifact: $DisplayPath"
    }
    $normalizedDisplayPath = $DisplayPath.Replace('\', '/').ToLowerInvariant()
    if ($RequireSourceFile -and $normalizedDisplayPath -match '(^|/)(target|tmp|temp|output|audit)(/|$)') {
        throw "refusing to package a generated source-tree path: $DisplayPath"
    }
}

function Copy-AuditFile {
    param(
        [Parameter(Mandatory)][string]$RelativePath,
        [switch]$RequireSourceFile
    )

    $source = [IO.Path]::GetFullPath((Join-Path $repoRoot $RelativePath))
    if (-not $source.StartsWith(($repoRoot + [IO.Path]::DirectorySeparatorChar), [StringComparison]::OrdinalIgnoreCase)) {
        throw "source path escapes repository: $RelativePath"
    }
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
        throw "required audit input is missing: $RelativePath"
    }
    Assert-NonSecretAuditInput -Path $source -DisplayPath $RelativePath -RequireSourceFile:$RequireSourceFile
    $destination = Join-Path $payloadRoot $RelativePath
    $destinationParent = Split-Path -Parent $destination
    New-Item -ItemType Directory -Path $destinationParent -Force | Out-Null
    Copy-Item -LiteralPath $source -Destination $destination
}

try {
    New-Item -ItemType Directory -Path $payloadRoot -Force | Out-Null

    foreach ($relative in $rootFiles) {
        Copy-AuditFile -RelativePath $relative
    }
    foreach ($tree in $trees) {
        $treeRoot = Join-Path $repoRoot $tree
        Get-ChildItem -LiteralPath $treeRoot -File -Recurse | ForEach-Object {
            $relative = [IO.Path]::GetRelativePath($repoRoot, $_.FullName)
            Copy-AuditFile -RelativePath $relative -RequireSourceFile
        }
    }
    foreach ($relative in $explicitFiles) {
        Copy-AuditFile -RelativePath $relative
    }
    Get-ChildItem -LiteralPath (Join-Path $repoRoot 'apps\wallet\src-tauri\src') -File -Recurse | ForEach-Object {
        $relative = [IO.Path]::GetRelativePath($repoRoot, $_.FullName)
        Copy-AuditFile -RelativePath $relative -RequireSourceFile
    }

    $metadata = [ordered]@{
        schema = 'common-foundry-exchange-custody-audit-candidate-v1'
        status = 'audit_candidate'
        external_audit_completed = $false
        created_utc = [DateTime]::UtcNow.ToString('o')
        source_commit = (git -C $repoRoot rev-parse HEAD).Trim()
        source_branch = (git -C $repoRoot branch --show-current).Trim()
        source_worktree_clean = -not [bool](git -C $repoRoot status --short)
        rustc = (rustc --version).Trim()
        cargo = (cargo --version).Trim()
        warning = 'No runtime key, keyring envelope, passphrase, credential, journal, anchor, wallet, external test-evidence file, or production data is intentionally included.'
    }
    $metadata | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath (Join-Path $payloadRoot 'AUDIT-SNAPSHOT.json') -Encoding utf8NoBOM

    $manifestPath = Join-Path $payloadRoot 'MANIFEST.sha256'
    $manifestLines = Get-ChildItem -LiteralPath $payloadRoot -File -Recurse |
        Where-Object { $_.FullName -ne $manifestPath } |
        ForEach-Object {
            $relative = [IO.Path]::GetRelativePath($payloadRoot, $_.FullName).Replace('\', '/')
            $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash.ToLowerInvariant()
            "$hash  $relative"
        } |
        Sort-Object
    $manifestLines | Set-Content -LiteralPath $manifestPath -Encoding ascii

    $archivePath = Join-Path $outputRoot ($bundleName + '.zip')
    Compress-Archive -LiteralPath $payloadRoot -DestinationPath $archivePath -CompressionLevel Optimal
    $archiveHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $archivePath).Hash.ToLowerInvariant()
    $sidecarPath = $archivePath + '.sha256'
    "$archiveHash  $([IO.Path]::GetFileName($archivePath))" | Set-Content -LiteralPath $sidecarPath -Encoding ascii

    [ordered]@{
        archive = $archivePath
        archive_sha256 = $archiveHash
        sidecar = $sidecarPath
        manifest_entries = $manifestLines.Count
        external_audit_completed = $false
    } | ConvertTo-Json -Depth 3
}
finally {
    if (Test-Path -LiteralPath $stageRoot) {
        $resolvedStage = [IO.Path]::GetFullPath($stageRoot)
        if ($resolvedStage.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -and
            ([IO.Path]::GetFileName($resolvedStage)).StartsWith('Common-Foundry-exchange-custody-v0.5-audit-candidate-', [StringComparison]::Ordinal)) {
            Remove-Item -LiteralPath $resolvedStage -Recurse -Force
        }
    }
}
