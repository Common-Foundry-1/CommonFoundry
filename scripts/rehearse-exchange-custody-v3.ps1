[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Stage', 'Exercise')]
    [string]$Mode,

    [Parameter(Mandatory = $true)]
    [string]$RehearsalRoot,

    [Parameter(Mandatory = $true)]
    [string]$NodeBinary,

    [string]$SourceDataDir,
    [string]$WalletPassphraseFile,
    [string]$JournalKeyFile,
    [string]$V2AnchorFile,
    [string]$EvidenceFile,
    [string]$PolicyFile,
    [string]$KeyringAnchorFile,
    [string]$KeyringPassphraseFile,
    [string]$ValidatedSnapshotOutput,
    [string]$KeyringRelativePath = 'exchange-keyring.bin',
    [string]$ConfirmationPlanDigest,
    [string[]]$NodeProfileArgument = @(),
    [string]$Cargo = 'cargo',
    [switch]$SkipRustMatrix
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'this runner currently qualifies only the Windows copy/lock/ACL path'
}

$Script:StageReportName = 'exchange-custody-rehearsal-stage.json'
$Script:EvidenceReportName = 'exchange-custody-rehearsal-evidence.json'
$Script:PlanName = 'migration-plan.json'
$Script:ProposedAnchorName = 'withdrawal-anchor-v3.proposed.json'
$Script:CustodyPrefix = 'exchange-withdrawals'

function Resolve-FullPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    return [IO.Path]::GetFullPath($Path)
}

function Resolve-ExistingFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $resolved = Resolve-FullPath -Path $Path
    $item = Get-Item -LiteralPath $resolved -Force -ErrorAction Stop
    if ($item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "$Label must be a regular, non-reparse file: $resolved"
    }
    return $item.FullName
}

function Resolve-ExistingDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $resolved = Resolve-FullPath -Path $Path
    $item = Get-Item -LiteralPath $resolved -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "$Label must be a real directory, not a reparse point: $resolved"
    }
    return $item.FullName.TrimEnd([IO.Path]::DirectorySeparatorChar)
}

function Test-PathWithin {
    param(
        [Parameter(Mandatory = $true)][string]$Child,
        [Parameter(Mandatory = $true)][string]$Parent
    )
    $comparison = if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        [StringComparison]::OrdinalIgnoreCase
    } else {
        [StringComparison]::Ordinal
    }
    $childPath = (Resolve-FullPath -Path $Child).TrimEnd([IO.Path]::DirectorySeparatorChar)
    $parentPath = (Resolve-FullPath -Path $Parent).TrimEnd([IO.Path]::DirectorySeparatorChar)
    if ($childPath.Equals($parentPath, $comparison)) {
        return $true
    }
    return $childPath.StartsWith($parentPath + [IO.Path]::DirectorySeparatorChar, $comparison)
}

function Assert-RehearsalChild {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Root
    )
    if (-not (Test-PathWithin -Child $Path -Parent $Root) -or
        (Resolve-FullPath -Path $Path) -eq (Resolve-FullPath -Path $Root)) {
        throw "refusing to mutate a path outside the dedicated rehearsal root: $Path"
    }
}

function Protect-RehearsalDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        return
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $grant = '{0}:(OI)(CI)(F)' -f $identity
    & icacls.exe $Path '/inheritance:r' '/grant:r' $grant | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "failed to protect rehearsal directory ACL: $Path"
    }
}

function New-ProtectedDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (Test-Path -LiteralPath $Path) {
        throw "refusing to reuse an existing rehearsal path: $Path"
    }
    [IO.Directory]::CreateDirectory($Path) | Out-Null
    Protect-RehearsalDirectory -Path $Path
}

function Copy-TreeNoReparse {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination
    )
    foreach ($item in Get-ChildItem -LiteralPath $Source -Force) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "reparse points are forbidden in a custody rehearsal copy: $($item.FullName)"
        }
        if ($item.Name -eq 'node.lock') {
            continue
        }
        $target = Join-Path $Destination $item.Name
        if ($item.PSIsContainer) {
            [IO.Directory]::CreateDirectory($target) | Out-Null
            Copy-TreeNoReparse -Source $item.FullName -Destination $target
        } else {
            [IO.File]::Copy($item.FullName, $target, $false)
        }
    }
}

function Get-FileSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-DirectoryManifest {
    param([Parameter(Mandatory = $true)][string]$Root)
    $rootPath = Resolve-ExistingDirectory -Path $Root -Label 'manifest root'
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($item in Get-ChildItem -LiteralPath $rootPath -Force -Recurse | Sort-Object FullName) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "reparse points are forbidden in a custody rehearsal manifest: $($item.FullName)"
        }
        if ($item.PSIsContainer -or $item.Name -eq 'node.lock') {
            continue
        }
        $relative = $item.FullName.Substring($rootPath.Length).TrimStart('\', '/').Replace('\', '/')
        $items.Add([ordered]@{
            path = $relative
            length = [string]$item.Length
            sha256 = Get-FileSha256 -Path $item.FullName
        })
    }
    return $items.ToArray()
}

function Get-ManifestSha256 {
    param([Parameter(Mandatory = $true)][object[]]$Manifest)
    $json = $Manifest | ConvertTo-Json -Depth 8 -Compress
    $bytes = [Text.Encoding]::UTF8.GetBytes($json)
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($hasher.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    } finally {
        $hasher.Dispose()
    }
}

function Get-StringSha256 {
    param([Parameter(Mandatory = $true)][string]$Value)
    $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($hasher.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    } finally {
        $hasher.Dispose()
    }
}

function Get-CustodyManifest {
    param([Parameter(Mandatory = $true)][string]$DataDir)
    return @(Get-DirectoryManifest -Root $DataDir | Where-Object {
        $_.path.StartsWith($Script:CustodyPrefix, [StringComparison]::Ordinal) -or
        $_.path -eq $KeyringRelativePath.Replace('\', '/')
    })
}

function Write-JsonCreateNew {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][object]$Value
    )
    $json = $Value | ConvertTo-Json -Depth 32
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json + [Environment]::NewLine)
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    } finally {
        $stream.Dispose()
    }
}

function Invoke-NodeJson {
    param(
        [Parameter(Mandatory = $true)][string]$Binary,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$ErrorFile
    )
    $output = @(& $Binary @Arguments 2> $ErrorFile)
    if ($LASTEXITCODE -ne 0) {
        $errorText = if (Test-Path -LiteralPath $ErrorFile) {
            (Get-Content -LiteralPath $ErrorFile -Raw)
        } else {
            ''
        }
        throw "cmfd-node failed with exit code $LASTEXITCODE. $errorText"
    }
    $text = ($output -join [Environment]::NewLine).Trim()
    if ([string]::IsNullOrWhiteSpace($text)) {
        throw 'cmfd-node returned no JSON report'
    }
    try {
        return $text | ConvertFrom-Json -ErrorAction Stop
    } catch {
        throw "cmfd-node returned a non-JSON report: $text"
    }
}

function Get-RequiredStageValue {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [AllowNull()][object]$Value
    )
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) {
        throw "$Name is required in Stage mode"
    }
    return [string]$Value
}

function Get-RequiredExerciseValue {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [AllowNull()][object]$Value
    )
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) {
        throw "$Name is required in Exercise mode"
    }
    return [string]$Value
}

function Invoke-RustCrashMatrix {
    param([Parameter(Mandatory = $true)][string]$RepositoryRoot)
    Push-Location $RepositoryRoot
    try {
        $output = @(& $Cargo test '-p' 'cmfd-node' '--lib' '--features' 'production-v4-testnet' `
            'exchange_custody_rehearsal::deterministic_crash_recovery_matrix_emits_checksum_evidence' `
            '--no-fail-fast' '--' '--nocapture' 2>&1)
        if ($LASTEXITCODE -ne 0) {
            throw "Rust custody crash matrix failed:`n$($output -join [Environment]::NewLine)"
        }
        $prefix = 'CMFD_EXCHANGE_CUSTODY_REHEARSAL_EVIDENCE='
        $line = $output | Where-Object { ([string]$_).StartsWith($prefix, [StringComparison]::Ordinal) } |
            Select-Object -Last 1
        if ($null -eq $line) {
            throw 'Rust custody crash matrix did not emit its checksum evidence record'
        }
        return ([string]$line).Substring($prefix.Length) | ConvertFrom-Json -ErrorAction Stop
    } finally {
        Pop-Location
    }
}

function Get-BaseNodeArguments {
    param(
        [Parameter(Mandatory = $true)][string]$DataDir,
        [Parameter(Mandatory = $true)][string]$WalletPassphrase,
        [Parameter(Mandatory = $true)][string]$JournalKey,
        [Parameter(Mandatory = $true)][string]$Anchor
    )
    return @(
        '--data-dir', $DataDir,
        '--wallet-passphrase-file', $WalletPassphrase,
        '--exchange-withdrawal-journal-key-file', $JournalKey,
        '--exchange-withdrawal-anchor-file', $Anchor
    ) + @($NodeProfileArgument)
}

$nodePath = Resolve-ExistingFile -Path $NodeBinary -Label 'cmfd-node binary'
$rootPath = Resolve-FullPath -Path $RehearsalRoot

if ($Mode -eq 'Stage') {
    $sourceInput = Get-RequiredStageValue -Name 'SourceDataDir' -Value $SourceDataDir
    $sourcePath = Resolve-ExistingDirectory -Path $sourceInput -Label 'source data directory'
    if ((Test-PathWithin -Child $rootPath -Parent $sourcePath) -or
        (Test-PathWithin -Child $sourcePath -Parent $rootPath)) {
        throw 'source data directory and rehearsal root must be disjoint'
    }
    $parent = Split-Path -Parent $rootPath
    [void](Resolve-ExistingDirectory -Path $parent -Label 'rehearsal parent directory')
    New-ProtectedDirectory -Path $rootPath
    $dataPath = Join-Path $rootPath 'data'
    $handoffPath = Join-Path $rootPath 'handoff'
    New-ProtectedDirectory -Path $dataPath
    New-ProtectedDirectory -Path $handoffPath

    $walletPassphrasePath = Resolve-ExistingFile -Path (Get-RequiredStageValue -Name 'WalletPassphraseFile' -Value $WalletPassphraseFile) -Label 'wallet passphrase'
    $journalKeyPath = Resolve-ExistingFile -Path (Get-RequiredStageValue -Name 'JournalKeyFile' -Value $JournalKeyFile) -Label 'journal key'
    $v2AnchorPath = Resolve-ExistingFile -Path (Get-RequiredStageValue -Name 'V2AnchorFile' -Value $V2AnchorFile) -Label 'v2 anchor'
    $evidencePath = Resolve-ExistingFile -Path (Get-RequiredStageValue -Name 'EvidenceFile' -Value $EvidenceFile) -Label 'migration evidence'
    $policyPath = Resolve-ExistingFile -Path (Get-RequiredStageValue -Name 'PolicyFile' -Value $PolicyFile) -Label 'withdrawal policy'
    $keyringAnchorPath = Resolve-ExistingFile -Path (Get-RequiredStageValue -Name 'KeyringAnchorFile' -Value $KeyringAnchorFile) -Label 'keyring anchor'
    $keyringPassphrasePath = Resolve-ExistingFile -Path (Get-RequiredStageValue -Name 'KeyringPassphraseFile' -Value $KeyringPassphraseFile) -Label 'keyring passphrase'

    $lockPath = Join-Path $sourcePath 'node.lock'
    if (-not (Test-Path -LiteralPath $lockPath -PathType Leaf)) {
        throw 'source node.lock is absent; start and cleanly stop the source node before staging'
    }
    $sourceLock = [IO.File]::Open($lockPath, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    try {
        $sourceBefore = Get-DirectoryManifest -Root $sourcePath
        Copy-TreeNoReparse -Source $sourcePath -Destination $dataPath
        $sourceAfter = Get-DirectoryManifest -Root $sourcePath
    } finally {
        $sourceLock.Dispose()
    }
    $sourceBeforeDigest = Get-ManifestSha256 -Manifest $sourceBefore
    $sourceAfterDigest = Get-ManifestSha256 -Manifest $sourceAfter
    if ($sourceBeforeDigest -ne $sourceAfterDigest) {
        throw 'source data changed while it was copied; discard this rehearsal root'
    }
    $copyDigest = Get-ManifestSha256 -Manifest (Get-DirectoryManifest -Root $dataPath)
    if ($copyDigest -ne $sourceBeforeDigest) {
        throw 'the rehearsal data copy does not exactly match the locked source manifest'
    }

    if ([IO.Path]::IsPathRooted($KeyringRelativePath) -or $KeyringRelativePath.Contains('..')) {
        throw 'KeyringRelativePath must be a simple path below the copied data directory'
    }
    $keyringPath = Resolve-ExistingFile -Path (Join-Path $dataPath $KeyringRelativePath) -Label 'copied keyring'
    if (-not (Test-PathWithin -Child $keyringPath -Parent $dataPath)) {
        throw 'copied keyring escaped the rehearsal data directory'
    }

    $planPath = Join-Path $handoffPath $Script:PlanName
    $validatedSnapshotPath = Resolve-FullPath -Path (Get-RequiredStageValue -Name 'ValidatedSnapshotOutput' -Value $ValidatedSnapshotOutput)
    if (Test-Path -LiteralPath $validatedSnapshotPath) {
        throw "ValidatedSnapshotOutput must be create-new: $validatedSnapshotPath"
    }
    [void](Resolve-ExistingDirectory -Path (Split-Path -Parent $validatedSnapshotPath) -Label 'validated snapshot parent')
    if ((Test-PathWithin -Child $validatedSnapshotPath -Parent $rootPath) -or
        (Test-PathWithin -Child $validatedSnapshotPath -Parent $sourcePath)) {
        throw 'ValidatedSnapshotOutput must be outside both the rehearsal root and source data directory'
    }
    $proposedAnchorPath = Join-Path $handoffPath $Script:ProposedAnchorName
    $errorPath = Join-Path $rootPath 'stage.stderr.txt'
    $arguments = Get-BaseNodeArguments -DataDir $dataPath -WalletPassphrase $walletPassphrasePath `
        -JournalKey $journalKeyPath -Anchor $v2AnchorPath
    $arguments += @(
        'exchange-v3-migration-plan',
        '--evidence-file', $evidencePath,
        '--policy-file', $policyPath,
        '--keyring-file', $keyringPath,
        '--keyring-anchor-file', $keyringAnchorPath,
        '--keyring-passphrase-file', $keyringPassphrasePath,
        '--validated-snapshot-output', $validatedSnapshotPath,
        '--v3-anchor-output', $proposedAnchorPath,
        '--plan-output', $planPath
    )
    $planReport = Invoke-NodeJson -Binary $nodePath -Arguments $arguments -ErrorFile $errorPath

    $stageReport = [ordered]@{
        schema = 'common-foundry-exchange-custody-rehearsal-stage-v1'
        status = 'staged; transfer validated_snapshot_file to independent control before Exercise'
        physical_power_cut = $false
        source_data_dir = $sourcePath
        rehearsal_root = $rootPath
        rehearsal_data_dir = $dataPath
        source_manifest_sha256 = $sourceBeforeDigest
        copied_manifest_sha256 = $copyDigest
        nonsecret_control_sha256 = [ordered]@{
            migration_evidence = Get-FileSha256 -Path $evidencePath
            withdrawal_policy = Get-FileSha256 -Path $policyPath
            copied_keyring_envelope = Get-FileSha256 -Path $keyringPath
            keyring_anchor = Get-FileSha256 -Path $keyringAnchorPath
            v2_anchor = Get-FileSha256 -Path $v2AnchorPath
        }
        plan = $planReport
        validated_snapshot_file = $validatedSnapshotPath
        proposed_v3_anchor_file = $proposedAnchorPath
    }
    $stageReportPath = Join-Path $rootPath $Script:StageReportName
    Write-JsonCreateNew -Path $stageReportPath -Value $stageReport
    $stageReport | ConvertTo-Json -Depth 32
    return
}

$rootPath = Resolve-ExistingDirectory -Path $rootPath -Label 'rehearsal root'
$stageReportPath = Resolve-ExistingFile -Path (Join-Path $rootPath $Script:StageReportName) -Label 'stage report'
$stage = Get-Content -LiteralPath $stageReportPath -Raw | ConvertFrom-Json -ErrorAction Stop
if ($stage.schema -ne 'common-foundry-exchange-custody-rehearsal-stage-v1') {
    throw 'the rehearsal stage report schema is invalid'
}
if ((Resolve-FullPath -Path $stage.rehearsal_root) -ne $rootPath) {
    throw 'the stage report does not bind this rehearsal root'
}
$sourceInput = Get-RequiredExerciseValue -Name 'SourceDataDir' -Value $SourceDataDir
$sourcePath = Resolve-ExistingDirectory -Path $sourceInput -Label 'source data directory'
if ((Resolve-FullPath -Path $stage.source_data_dir) -ne $sourcePath) {
    throw 'SourceDataDir does not match the staged source path'
}
$walletPassphrasePath = Resolve-ExistingFile -Path (Get-RequiredExerciseValue -Name 'WalletPassphraseFile' -Value $WalletPassphraseFile) -Label 'wallet passphrase'
$journalKeyPath = Resolve-ExistingFile -Path (Get-RequiredExerciseValue -Name 'JournalKeyFile' -Value $JournalKeyFile) -Label 'journal key'
$v2AnchorPath = Resolve-ExistingFile -Path (Get-RequiredExerciseValue -Name 'V2AnchorFile' -Value $V2AnchorFile) -Label 'v2 anchor'
$confirmation = Get-RequiredExerciseValue -Name 'ConfirmationPlanDigest' -Value $ConfirmationPlanDigest
if ($confirmation -cnotmatch '^[0-9a-f]{64}$' -or $stage.plan.plan_digest -cne $confirmation) {
    throw 'ConfirmationPlanDigest must be the exact lowercase digest in the staged plan report'
}
$dataPath = Resolve-ExistingDirectory -Path $stage.rehearsal_data_dir -Label 'rehearsal data directory'
if ($dataPath -ne (Resolve-FullPath -Path (Join-Path $rootPath 'data'))) {
    throw 'the stage report rehearsal data path is not the dedicated data child'
}
$handoffPath = Resolve-ExistingDirectory -Path (Join-Path $rootPath 'handoff') -Label 'rehearsal handoff directory'
$planPath = Resolve-ExistingFile -Path (Join-Path $handoffPath $Script:PlanName) -Label 'migration plan'
$proposedAnchorPath = Join-Path $handoffPath $Script:ProposedAnchorName
$planDocument = Get-Content -LiteralPath $planPath -Raw | ConvertFrom-Json -ErrorAction Stop
if ($planDocument.schema -ne 'common-foundry-exchange-v3-migration-plan-v2' -or
    $planDocument.plan_digest -cne $confirmation -or
    (Resolve-FullPath -Path $planDocument.plan_file) -ne $planPath -or
    (Resolve-FullPath -Path $planDocument.data_dir) -ne $dataPath -or
    (Resolve-FullPath -Path $planDocument.v3_anchor_output) -ne (Resolve-FullPath -Path $proposedAnchorPath) -or
    (Resolve-FullPath -Path $planDocument.journal_key_file) -ne $journalKeyPath) {
    throw 'the staged plan does not bind the exact rehearsal paths and confirmation'
}
$validatedSnapshotPath = Resolve-ExistingFile -Path $planDocument.validated_snapshot_file -Label 'independently controlled validated snapshot'
if ((Test-PathWithin -Child $validatedSnapshotPath -Parent $rootPath) -or
    (Test-PathWithin -Child $validatedSnapshotPath -Parent $sourcePath)) {
    throw 'the validated snapshot is not independent of the source and rehearsal roots'
}
$plannedKeyringPath = Resolve-ExistingFile -Path $planDocument.keyring_file -Label 'planned keyring'
if ($plannedKeyringPath -ne (Resolve-FullPath -Path (Join-Path $dataPath $KeyringRelativePath))) {
    throw 'the staged plan keyring is not the exact copied keyring'
}
if ((Get-FileSha256 -Path $planDocument.evidence_file) -ne $stage.nonsecret_control_sha256.migration_evidence -or
    (Get-FileSha256 -Path $planDocument.policy_file) -ne $stage.nonsecret_control_sha256.withdrawal_policy -or
    (Get-FileSha256 -Path $plannedKeyringPath) -ne $stage.nonsecret_control_sha256.copied_keyring_envelope -or
    (Get-FileSha256 -Path $planDocument.keyring_anchor_file) -ne $stage.nonsecret_control_sha256.keyring_anchor -or
    (Get-FileSha256 -Path $v2AnchorPath) -ne $stage.nonsecret_control_sha256.v2_anchor) {
    throw 'a staged nonsecret migration control changed before Exercise'
}

$lockPath = Join-Path $sourcePath 'node.lock'
$sourceLock = [IO.File]::Open($lockPath, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
try {
    $currentSourceDigest = Get-ManifestSha256 -Manifest (Get-DirectoryManifest -Root $sourcePath)
} finally {
    $sourceLock.Dispose()
}
if ($currentSourceDigest -ne $stage.source_manifest_sha256) {
    throw 'the source node changed after staging; create a new rehearsal instead of applying this plan'
}

$baselineV2 = Join-Path $rootPath 'baseline-v2'
$baselineV3 = Join-Path $rootPath 'baseline-v3'
New-ProtectedDirectory -Path $baselineV2
Copy-TreeNoReparse -Source $dataPath -Destination $baselineV2

$applyError = Join-Path $rootPath 'apply-baseline.stderr.txt'
$applyArguments = Get-BaseNodeArguments -DataDir $dataPath -WalletPassphrase $walletPassphrasePath `
    -JournalKey $journalKeyPath -Anchor $v2AnchorPath
$applyArguments += @(
    'exchange-v3-migration-apply',
    '--plan-file', $planPath,
    '--confirmation-plan-digest', $confirmation
)
$baselineApply = Invoke-NodeJson -Binary $nodePath -Arguments $applyArguments -ErrorFile $applyError
New-ProtectedDirectory -Path $baselineV3
Copy-TreeNoReparse -Source $dataPath -Destination $baselineV3

$goldenCustody = Get-CustodyManifest -DataDir $baselineV3
$goldenCustodyDigest = Get-ManifestSha256 -Manifest $goldenCustody
$goldenAnchorSha256 = Get-FileSha256 -Path (Resolve-ExistingFile -Path $proposedAnchorPath -Label 'proposed v3 anchor')
$goldenKeyringSha256 = Get-FileSha256 -Path (Resolve-ExistingFile -Path (Join-Path $baselineV3 $KeyringRelativePath) -Label 'golden keyring')
$backupNames = @($baselineApply.backup_files | ForEach-Object { [IO.Path]::GetFileName([string]$_) })
if ($backupNames.Count -ne 3) {
    throw 'migration apply did not report the exact three retained v2 backups'
}
$slotZero = 'exchange-withdrawals.0.bin'
$slotOne = 'exchange-withdrawals.1.bin'
$v3Marker = 'exchange-withdrawals.v3.initialized'
$cases = @(
    [ordered]@{ name = 'before_proposed_anchor_create'; anchor = $false; overlays = @() },
    [ordered]@{ name = 'after_proposed_anchor_create'; anchor = $true; overlays = @() },
    [ordered]@{ name = 'after_v2_slot0_backup'; anchor = $true; overlays = @($backupNames[0]) },
    [ordered]@{ name = 'after_v2_slot1_backup'; anchor = $true; overlays = @($backupNames[0], $backupNames[1]) },
    [ordered]@{ name = 'after_legacy_marker_backup'; anchor = $true; overlays = @($backupNames[0], $backupNames[1], $backupNames[2]) },
    [ordered]@{ name = 'after_v3_slot0_replace'; anchor = $true; overlays = @($backupNames[0], $backupNames[1], $backupNames[2], $slotZero) },
    [ordered]@{ name = 'after_v3_slot1_replace'; anchor = $true; overlays = @($backupNames[0], $backupNames[1], $backupNames[2], $slotZero, $slotOne) },
    [ordered]@{ name = 'after_v3_activation_marker'; anchor = $true; overlays = @($backupNames[0], $backupNames[1], $backupNames[2], $slotZero, $slotOne, $v3Marker) }
)
$caseReports = New-Object System.Collections.Generic.List[object]
$anchorBytes = [IO.File]::ReadAllBytes($proposedAnchorPath)
foreach ($case in $cases) {
    Assert-RehearsalChild -Path $dataPath -Root $rootPath
    Remove-Item -LiteralPath $dataPath -Recurse -Force
    New-ProtectedDirectory -Path $dataPath
    Copy-TreeNoReparse -Source $baselineV2 -Destination $dataPath
    foreach ($name in $case.overlays) {
        [IO.File]::Copy((Join-Path $baselineV3 $name), (Join-Path $dataPath $name), $true)
    }
    if ($case.anchor) {
        [IO.File]::WriteAllBytes($proposedAnchorPath, $anchorBytes)
    } elseif (Test-Path -LiteralPath $proposedAnchorPath) {
        Assert-RehearsalChild -Path $proposedAnchorPath -Root $rootPath
        Remove-Item -LiteralPath $proposedAnchorPath -Force
    }
    $caseError = Join-Path $rootPath (('{0}.stderr.txt' -f $case.name))
    $caseApply = Invoke-NodeJson -Binary $nodePath -Arguments $applyArguments -ErrorFile $caseError
    $custody = Get-CustodyManifest -DataDir $dataPath
    $custodyDigest = Get-ManifestSha256 -Manifest $custody
    if ($custodyDigest -ne $goldenCustodyDigest) {
        throw "checkpoint $($case.name) did not recover the exact golden custody files"
    }
    $anchorSha256 = Get-FileSha256 -Path $proposedAnchorPath
    if ($anchorSha256 -ne $goldenAnchorSha256) {
        throw "checkpoint $($case.name) changed the proposed v3 anchor"
    }
    $keyringSha256 = Get-FileSha256 -Path (Join-Path $dataPath $KeyringRelativePath)
    if ($keyringSha256 -ne $goldenKeyringSha256) {
        throw "checkpoint $($case.name) changed the encrypted keyring envelope"
    }
    $caseReports.Add([ordered]@{
        checkpoint = $case.name
        resumed = [bool]$caseApply.resumed
        custody_files_sha256 = $custodyDigest
        proposed_anchor_sha256 = $anchorSha256
        keyring_envelope_sha256 = $keyringSha256
        initial_anchor = $caseApply.initial_anchor
    })
}

$rustEvidence = $null
if (-not $SkipRustMatrix) {
    $repositoryRoot = Resolve-ExistingDirectory -Path (Join-Path $PSScriptRoot '..') -Label 'repository root'
    $rustEvidence = Invoke-RustCrashMatrix -RepositoryRoot $repositoryRoot
}

$sourceLock = [IO.File]::Open($lockPath, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
try {
    $finalSourceDigest = Get-ManifestSha256 -Manifest (Get-DirectoryManifest -Root $sourcePath)
} finally {
    $sourceLock.Dispose()
}
if ($finalSourceDigest -ne $stage.source_manifest_sha256) {
    throw 'the source data changed during the rehearsal; evidence is invalid'
}

$evidenceReport = [ordered]@{
    schema = 'common-foundry-exchange-custody-live-copy-rehearsal-v1'
    status = 'deterministic_checkpoint_recovery_passed'
    simulation = 'exact durable checkpoint reconstruction on a disposable copy'
    physical_power_cut = $false
    target_storage_power_loss_qualified = $false
    source_data_unchanged = $true
    source_manifest_sha256 = $finalSourceDigest
    golden_v3_custody_files_sha256 = $goldenCustodyDigest
    migration_checkpoints = $caseReports.ToArray()
    synthetic_atomic_boundary_matrix = $rustEvidence
    limitations = @(
        'This is not a physical power-cut or storage-controller write-cache test.',
        'Run a separate target-host abrupt-power-loss rehearsal with non-production keys and independently retained controls.',
        'The Stage and Exercise identities must preserve the documented independent validated-snapshot boundary.'
    )
    evidence_sha256 = ''
}
$evidenceReport.evidence_sha256 = Get-StringSha256 -Value ($evidenceReport | ConvertTo-Json -Depth 32 -Compress)
$evidenceReportPath = Join-Path $rootPath $Script:EvidenceReportName
Write-JsonCreateNew -Path $evidenceReportPath -Value $evidenceReport
$evidenceReport | ConvertTo-Json -Depth 32
