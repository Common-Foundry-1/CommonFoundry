#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Wallet,
    [Parameter(Mandatory=$true)][string]$Node,
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{40}$')][string]$SourceCommit,
    [string]$KitVersion='0.2.0',
    [switch]$SourceDirty,
    [switch]$AllowUnsignedPreview
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$repo=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$output=[IO.Path]::GetFullPath($OutputDirectory)
$name="commonfoundry-compact-testnet-v$KitVersion-windows-x86_64"
$stage=Join-Path $output $name
if(Test-Path -LiteralPath $stage){throw 'Choose a new output directory; this package already exists.'}
New-Item -ItemType Directory -Path (Join-Path $stage 'runtime') -Force | Out-Null
$approved=@{}
foreach($item in @(@($Wallet,'common-foundry-wallet.exe'),@($Node,'cmfd-node.exe'))){
    $source=[IO.Path]::GetFullPath([string]$item[0]);$label=[string]$item[1]
    if(-not(Test-Path -LiteralPath $source -PathType Leaf)){throw "Missing $label"}
    $signature=Get-AuthenticodeSignature -LiteralPath $source
    if(-not $AllowUnsignedPreview){
        if($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate -or
           -not @($signature.SignerCertificate.EnhancedKeyUsageList | Where-Object ObjectId -eq '1.3.6.1.5.5.7.3.3').Count -or
           -not $signature.TimeStamperCertificate){throw "$label needs valid, timestamped Authenticode with the Code Signing EKU."}
    }
    $approved[$label]=[string]$signature.Status
    Copy-Item -LiteralPath $source -Destination (Join-Path $stage "runtime/$label")
    if((Get-FileHash -Algorithm SHA256 $source).Hash -ne (Get-FileHash -Algorithm SHA256 (Join-Path $stage "runtime/$label")).Hash){throw "Copied $label differs"}
}
$files=@{
    'packaging/compact-proof-testnet/windows/START-WALLET.bat'='START-WALLET.bat'
    'packaging/compact-proof-testnet/windows/START-WALLET.ps1'='START-WALLET.ps1'
    'packaging/compact-proof-testnet/windows/PREPARE-INPUTS.ps1'='PREPARE-INPUTS.ps1'
    'packaging/compact-proof-testnet/windows/README.md'='README.md'
    'packaging/production-v4-pool/shared/V4-INPUT-CHUNKS.json'='V4-INPUT-CHUNKS.json'
    'packaging/production-v4-pool/shared/FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json'='FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json'
    'LICENSE'='LICENSE'
    'THIRD_PARTY_NOTICES.md'='THIRD_PARTY_NOTICES.md'
}
foreach($entry in $files.GetEnumerator()) { Copy-Item -LiteralPath (Join-Path $repo $entry.Key) -Destination (Join-Path $stage $entry.Value) }
$info=[ordered]@{schema='CMFD_COMPACT_TESTNET_WINDOWS_PACKAGE_V1';version=$KitVersion;source_commit=$SourceCommit;source_dirty=[bool]$SourceDirty;network_id='8a34c0d9eaa92c5eaec4af7fe146afdfa2ab6859918b7deb0c97e0a1f600d6d1';seed='209.145.48.36:23444';roles=@('GUI wallet','CPU node');authenticode_required=(-not [bool]$AllowUnsignedPreview);signature_status=$approved}
[IO.File]::WriteAllText((Join-Path $stage 'BUILD-INFO.json'),(($info|ConvertTo-Json -Depth 5)+"`n"))
$manifest=[ordered]@{network_id=$info.network_id;files=[ordered]@{}}
Get-ChildItem -LiteralPath $stage -File -Recurse | ForEach-Object {
    $relative=$_.FullName.Substring($stage.Length+1).Replace('\','/')
    $manifest.files[$relative]=[ordered]@{bytes=$_.Length;sha256=(Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash.ToLowerInvariant()}
}
[IO.File]::WriteAllText((Join-Path $stage 'PACKAGE-MANIFEST.json'),(($manifest|ConvertTo-Json -Depth 8)+"`n"))
Add-Type -AssemblyName System.IO.Compression
$archive=Join-Path $output "$name.zip"
$zip=[IO.Compression.ZipFile]::Open($archive,[IO.Compression.ZipArchiveMode]::Create)
try{
    Get-ChildItem -LiteralPath $stage -File -Recurse | ForEach-Object {
        $relative=$_.FullName.Substring($output.Length+1).Replace('\','/')
        [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip,$_.FullName,$relative,[IO.Compression.CompressionLevel]::Optimal)|Out-Null
    }
} finally { $zip.Dispose() }
$hash=(Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant()
[IO.File]::WriteAllText((Join-Path $output 'SHA256SUMS.txt'),"$hash  $name.zip`n")
[pscustomobject]@{archive=$archive;bytes=(Get-Item -LiteralPath $archive).Length;sha256=$hash;signing=$approved}
