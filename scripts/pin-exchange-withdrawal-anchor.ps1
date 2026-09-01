#Requires -Version 5.1

<#
.SYNOPSIS
Pins a v0.4 or v0.5 exchange-withdrawal journal anchor from a saved JSON response.

.DESCRIPTION
Reads a saved chain-preview-v0.4 or chain-preview-v0.5 JSON-RPC response, or its
result document, extracts the top-level anchor, validates the exact four-field schema, and
atomically writes that anchor to the configured external anchor file.

The script is deliberately offline: it never contacts RPC and never reads or
writes the node data directory. Point AnchorPath at the separately controlled
file configured with --exchange-withdrawal-anchor-file.

If an anchor already exists, the script refuses a journal-key or journal-
instance mismatch, a lower generation, or a different commitment at the same
generation. Re-pinning an identical anchor succeeds without rewriting it.

.PARAMETER ResponseFile
Path to a saved JSON-RPC response or the response's result document.

.PARAMETER AnchorPath
Path to the separately controlled external anchor file.

.EXAMPLE
PS> .\scripts\pin-exchange-withdrawal-anchor.ps1 `
      -ResponseFile .\preparewithdrawal-response.json `
      -AnchorPath D:\ExchangeState\common-foundry-withdrawal-anchor.json

Pins the Prepared anchor before releasewithdrawal is called.

.EXAMPLE
PS> .\scripts\pin-exchange-withdrawal-anchor.ps1 `
      -ResponseFile .\releaseauthorized-response.json `
      -AnchorPath D:\ExchangeState\common-foundry-withdrawal-anchor.json

For v0.5, advances the external anchor to ReleaseAuthorized after the first
releasewithdrawal call. Retry releasewithdrawal with the exact same canonical
request and policy-valid approval only after this pin succeeds.

.EXAMPLE
PS> .\scripts\pin-exchange-withdrawal-anchor.ps1 `
      -ResponseFile .\releasewithdrawal-response.json `
      -AnchorPath D:\ExchangeState\common-foundry-withdrawal-anchor.json

Advances the external anchor after the final Released response has been saved.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]$ResponseFile,

    [Parameter(Mandatory = $true, Position = 1)]
    [ValidateNotNullOrEmpty()]
    [string]$AnchorPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$ExpectedApiVersions = @('chain-preview-v0.4', 'chain-preview-v0.5')
$ExpectedAnchorFields = @(
    'key_id',
    'journal_instance_id',
    'generation',
    'commitment'
)
$StrictUtf8 = [Text.UTF8Encoding]::new($false, $true)
$OutputUtf8 = [Text.UTF8Encoding]::new($false)

function Assert-JsonObject {
    param(
        [AllowNull()]
        [object]$Value,
        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    if ($null -eq $Value -or -not ($Value -is [Management.Automation.PSCustomObject])) {
        throw "$Context must be a JSON object."
    }
}

function Get-ExactProperty {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Object,
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    $matches = @($Object.PSObject.Properties | Where-Object { $_.Name -ceq $Name })
    if ($matches.Count -eq 0) {
        throw "$Context is missing the exact '$Name' property."
    }
    if ($matches.Count -ne 1) {
        throw "$Context contains the '$Name' property more than once."
    }
    return $matches[0].Value
}

function Test-ExactProperty {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Object,
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    return @($Object.PSObject.Properties | Where-Object { $_.Name -ceq $Name }).Count -eq 1
}

function Read-JsonFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [long]$MaximumBytes,
        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Context does not exist or is not a regular file: $Path"
    }
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.Length -gt $MaximumBytes) {
        throw "$Context exceeds the $MaximumBytes-byte safety limit: $Path"
    }

    try {
        $text = [IO.File]::ReadAllText($Path, $StrictUtf8)
    }
    catch {
        throw "$Context is not valid UTF-8 or could not be read: $Path. $($_.Exception.Message)"
    }
    if ([string]::IsNullOrWhiteSpace($text)) {
        throw "$Context is empty: $Path"
    }

    try {
        return ConvertFrom-Json -InputObject $text -ErrorAction Stop
    }
    catch {
        throw "$Context is not valid JSON: $Path. $($_.Exception.Message)"
    }
}

function ConvertTo-ValidatedAnchor {
    param(
        [AllowNull()]
        [object]$Anchor,
        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    Assert-JsonObject -Value $Anchor -Context $Context
    $properties = @($Anchor.PSObject.Properties)
    $propertyNames = @($properties | ForEach-Object { $_.Name })
    if ($properties.Count -ne $ExpectedAnchorFields.Count) {
        throw "$Context must contain exactly: $($ExpectedAnchorFields -join ', ')."
    }
    foreach ($expectedField in $ExpectedAnchorFields) {
        if (-not ($propertyNames -ccontains $expectedField)) {
            throw "$Context must contain exactly: $($ExpectedAnchorFields -join ', ')."
        }
    }

    $keyId = Get-ExactProperty -Object $Anchor -Name 'key_id' -Context $Context
    $instanceId = Get-ExactProperty -Object $Anchor -Name 'journal_instance_id' -Context $Context
    $generation = Get-ExactProperty -Object $Anchor -Name 'generation' -Context $Context
    $commitment = Get-ExactProperty -Object $Anchor -Name 'commitment' -Context $Context

    foreach ($hexField in @(
        @{ Name = 'key_id'; Value = $keyId },
        @{ Name = 'journal_instance_id'; Value = $instanceId },
        @{ Name = 'commitment'; Value = $commitment }
    )) {
        if (-not ($hexField.Value -is [string]) -or
            $hexField.Value -cnotmatch '^[0-9a-f]{64}$') {
            throw "$Context.$($hexField.Name) must be a 64-character lowercase hexadecimal string."
        }
        if ($hexField.Value -ceq ('0' * 64)) {
            throw "$Context.$($hexField.Name) must not be all zeroes."
        }
    }

    if (-not ($generation -is [string]) -or
        $generation -cnotmatch '^[1-9][0-9]*$') {
        throw "$Context.generation must be a canonical, nonzero decimal string."
    }
    [uint64]$generationValue = 0
    if (-not [uint64]::TryParse(
            $generation,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$generationValue
        )) {
        throw "$Context.generation is outside the unsigned 64-bit range."
    }

    return [pscustomobject][ordered]@{
        key_id = $keyId
        journal_instance_id = $instanceId
        generation = $generation
        commitment = $commitment
    }
}

function Get-AnchorFromResponseDocument {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Root
    )

    Assert-JsonObject -Value $Root -Context 'response document'
    $hasJsonRpc = Test-ExactProperty -Object $Root -Name 'jsonrpc'
    $hasResult = Test-ExactProperty -Object $Root -Name 'result'
    $hasError = Test-ExactProperty -Object $Root -Name 'error'

    if ($hasJsonRpc -or $hasResult -or $hasError) {
        if (-not $hasJsonRpc -or -not $hasResult) {
            throw 'JSON-RPC response must contain exact jsonrpc and result properties.'
        }
        $jsonRpc = Get-ExactProperty -Object $Root -Name 'jsonrpc' -Context 'JSON-RPC response'
        if (-not ($jsonRpc -is [string]) -or $jsonRpc -cne '2.0') {
            throw 'JSON-RPC response jsonrpc must be exactly "2.0".'
        }
        if ($hasError) {
            $rpcError = Get-ExactProperty -Object $Root -Name 'error' -Context 'JSON-RPC response'
            if ($null -ne $rpcError) {
                throw 'Refusing to pin an anchor from a JSON-RPC error response.'
            }
        }
        $result = Get-ExactProperty -Object $Root -Name 'result' -Context 'JSON-RPC response'
    }
    else {
        $result = $Root
    }

    Assert-JsonObject -Value $result -Context 'exchange-withdrawal result document'
    $apiVersion = Get-ExactProperty -Object $result -Name 'api_version' -Context 'exchange-withdrawal result document'
    if (-not ($apiVersion -is [string]) -or $ExpectedApiVersions -cnotcontains $apiVersion) {
        throw "Result api_version must be exactly one of: $($ExpectedApiVersions -join ', ')."
    }
    $anchor = Get-ExactProperty -Object $result -Name 'anchor' -Context 'exchange-withdrawal result document'
    return ConvertTo-ValidatedAnchor -Anchor $anchor -Context 'exchange-withdrawal result anchor'
}

function Test-AnchorsEqual {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Left,
        [Parameter(Mandatory = $true)]
        [object]$Right
    )

    return $Left.key_id -ceq $Right.key_id -and
        $Left.journal_instance_id -ceq $Right.journal_instance_id -and
        $Left.generation -ceq $Right.generation -and
        $Left.commitment -ceq $Right.commitment
}

function Read-ExistingAnchor {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing an anchor path that is a reparse point: $Path"
    }
    $root = Read-JsonFile -Path $Path -MaximumBytes 16384 -Context 'existing anchor file'
    return ConvertTo-ValidatedAnchor -Anchor $root -Context 'existing anchor file'
}

function Assert-ValidAdvance {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Existing,
        [Parameter(Mandatory = $true)]
        [object]$Candidate
    )

    if ($Candidate.key_id -cne $Existing.key_id) {
        throw 'Refusing anchor journal-key mismatch.'
    }
    if ($Candidate.journal_instance_id -cne $Existing.journal_instance_id) {
        throw 'Refusing anchor journal-instance mismatch.'
    }

    [uint64]$existingGeneration = [uint64]::Parse(
        $Existing.generation,
        [Globalization.NumberStyles]::None,
        [Globalization.CultureInfo]::InvariantCulture
    )
    [uint64]$candidateGeneration = [uint64]::Parse(
        $Candidate.generation,
        [Globalization.NumberStyles]::None,
        [Globalization.CultureInfo]::InvariantCulture
    )
    if ($candidateGeneration -lt $existingGeneration) {
        throw "Refusing anchor rollback from generation $existingGeneration to $candidateGeneration."
    }
    if ($candidateGeneration -eq $existingGeneration -and
        $Candidate.commitment -cne $Existing.commitment) {
        throw "Refusing same-generation anchor divergence at generation $candidateGeneration."
    }
}

function Write-AnchorAtomically {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [object]$Anchor,
        [AllowNull()]
        [object]$ExpectedExisting
    )

    $directory = [IO.Path]::GetDirectoryName($Path)
    $temporaryPath = Join-Path $directory ('.cmfd-anchor-' + [Guid]::NewGuid().ToString('N') + '.tmp')
    $backupPath = Join-Path $directory ('.cmfd-anchor-' + [Guid]::NewGuid().ToString('N') + '.bak')
    $json = (ConvertTo-Json -InputObject $Anchor -Compress -Depth 3) + [Environment]::NewLine
    $bytes = $OutputUtf8.GetBytes($json)
    $stream = $null
    $replacementCompleted = $false
    try {
        $stream = [IO.FileStream]::new(
            $temporaryPath,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None,
            4096,
            [IO.FileOptions]::WriteThrough
        )
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
        $stream.Dispose()
        $stream = $null

        if ($null -ne $ExpectedExisting) {
            if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
                throw 'Anchor file disappeared while the update was being prepared.'
            }
            $current = Read-ExistingAnchor -Path $Path
            if (-not (Test-AnchorsEqual -Left $current -Right $ExpectedExisting)) {
                throw 'Anchor file changed concurrently; refusing to overwrite it.'
            }
            [IO.File]::Replace($temporaryPath, $Path, $backupPath)
            $replacementCompleted = $true
        }
        else {
            if (Test-Path -LiteralPath $Path) {
                throw 'Anchor path appeared while the update was being prepared; refusing to overwrite it.'
            }
            [IO.File]::Move($temporaryPath, $Path)
        }
    }
    finally {
        if ($null -ne $stream) {
            $stream.Dispose()
        }
        if (Test-Path -LiteralPath $temporaryPath -PathType Leaf) {
            Remove-Item -LiteralPath $temporaryPath -Force
        }
        if ($replacementCompleted -and (Test-Path -LiteralPath $backupPath -PathType Leaf)) {
            try {
                Remove-Item -LiteralPath $backupPath -Force
            }
            catch {
                Write-Warning "Anchor advanced, but its temporary backup could not be removed: $backupPath"
            }
        }
    }
}

$ResponseFile = [IO.Path]::GetFullPath($ResponseFile)
$AnchorPath = [IO.Path]::GetFullPath($AnchorPath)
if ([StringComparer]::OrdinalIgnoreCase.Equals($ResponseFile, $AnchorPath)) {
    throw 'ResponseFile and AnchorPath must be different files.'
}
if (-not (Test-Path -LiteralPath $ResponseFile -PathType Leaf)) {
    throw "Response file does not exist or is not a regular file: $ResponseFile"
}

$anchorDirectory = [IO.Path]::GetDirectoryName($AnchorPath)
if ([string]::IsNullOrEmpty($anchorDirectory) -or
    -not (Test-Path -LiteralPath $anchorDirectory -PathType Container)) {
    throw "Anchor output directory does not exist: $anchorDirectory"
}
if (Test-Path -LiteralPath $AnchorPath -PathType Container) {
    throw "Anchor output path is a directory: $AnchorPath"
}

$response = Read-JsonFile -Path $ResponseFile -MaximumBytes 1048576 -Context 'saved exchange-withdrawal response'
$candidate = Get-AnchorFromResponseDocument -Root $response

$lockPath = Join-Path $anchorDirectory ('.' + [IO.Path]::GetFileName($AnchorPath) + '.pin.lock')
if (Test-Path -LiteralPath $lockPath -PathType Leaf) {
    $lockItem = Get-Item -LiteralPath $lockPath -Force
    if (($lockItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing a pin lock that is a reparse point: $lockPath"
    }
}

$lockStream = $null
$lockAcquired = $false
try {
    try {
        $lockStream = [IO.FileStream]::new(
            $lockPath,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::ReadWrite,
            [IO.FileShare]::None
        )
        $lockAcquired = $true
    }
    catch [IO.IOException] {
        throw "Anchor pin lock already exists; another operation may be running: $lockPath"
    }

    $existing = $null
    if (Test-Path -LiteralPath $AnchorPath -PathType Leaf) {
        $existing = Read-ExistingAnchor -Path $AnchorPath
        Assert-ValidAdvance -Existing $existing -Candidate $candidate
        if (Test-AnchorsEqual -Left $existing -Right $candidate) {
            [pscustomobject][ordered]@{
                status = 'unchanged'
                anchor_path = $AnchorPath
                key_id = $candidate.key_id
                journal_instance_id = $candidate.journal_instance_id
                generation = $candidate.generation
                commitment = $candidate.commitment
            }
            return
        }
    }
    elseif (Test-Path -LiteralPath $AnchorPath) {
        throw "Anchor output path is not a regular file: $AnchorPath"
    }

    Write-AnchorAtomically -Path $AnchorPath -Anchor $candidate -ExpectedExisting $existing
    $written = Read-ExistingAnchor -Path $AnchorPath
    if (-not (Test-AnchorsEqual -Left $written -Right $candidate)) {
        throw 'Post-write verification found an anchor mismatch.'
    }

    [pscustomobject][ordered]@{
        status = 'pinned'
        anchor_path = $AnchorPath
        key_id = $candidate.key_id
        journal_instance_id = $candidate.journal_instance_id
        generation = $candidate.generation
        commitment = $candidate.commitment
    }
}
finally {
    if ($null -ne $lockStream) {
        $lockStream.Dispose()
    }
    if ($lockAcquired -and (Test-Path -LiteralPath $lockPath -PathType Leaf)) {
        try {
            Remove-Item -LiteralPath $lockPath -Force
        }
        catch {
            Write-Warning "Could not remove completed pin lock file: $lockPath"
        }
    }
}
