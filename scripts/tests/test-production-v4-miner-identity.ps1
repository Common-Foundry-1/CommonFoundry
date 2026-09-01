#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Launcher
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ([string]::IsNullOrWhiteSpace($Launcher)) {
    $Launcher = Join-Path $PSScriptRoot '..\run-production-v4-miner.ps1'
}

$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    $Launcher,
    [ref]$tokens,
    [ref]$errors
)
if ($errors.Count -ne 0) {
    throw "launcher parse failed: $($errors[0].Message)"
}
$requiredFunctions = @(
    'ConvertFrom-UniqueJson',
    'Assert-InputManifest',
    'Assert-MinerNetworkIdentityJson'
)
foreach ($name in $requiredFunctions) {
    $function = $ast.Find({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq $name
    }, $true)
    if ($null -eq $function) {
        throw "missing $name"
    }
    Invoke-Expression $function.Extent.Text
}

function Assert-Rejected {
    param([string]$Json, [string]$ExpectedNetworkId, [string]$Label)
    $rejected = $false
    try {
        Assert-MinerNetworkIdentityJson $Json $ExpectedNetworkId | Out-Null
    } catch {
        $rejected = $true
    }
    if (-not $rejected) {
        throw "identity validator accepted $Label"
    }
}

$networkId = '12' * 32
$otherNetworkId = '34' * 32
$valid = '{"format":"commonfoundry-miner-network-info","format_version":1,"network_id":"' +
    $networkId +
    '","network_name":"CommonFoundry ProductionV4 Testnet-1","network_profile":"ProductionV4 Testnet-1","proof_selection":"ProductionV4","build_source_commit":null}'
if ((Assert-MinerNetworkIdentityJson $valid $networkId) -cne $networkId) {
    throw 'identity validator did not return the authenticated network ID'
}

Assert-Rejected $valid $otherNetworkId 'a miner compiled for another network'
Assert-Rejected ($valid.Replace('"ProductionV4","build_source_commit"', '"ProductionV3","build_source_commit"')) $networkId 'a non-ProductionV4 miner'
Assert-Rejected ($valid.Replace('"format_version":1', '"format_version":true')) $networkId 'a non-integer schema version'
Assert-Rejected ($valid.Replace('{"format"', '{ "format"')) $networkId 'noncanonical whitespace'
Assert-Rejected ($valid.Replace('"build_source_commit":null', '"build_source_commit":"' + ('AA' * 20) + '"')) $networkId 'an uppercase source commit'
Assert-Rejected ($valid.Substring(0, $valid.Length - 1) + ',"unexpected":true}') $networkId 'an unexpected field'
Assert-Rejected ($valid.Replace('"network_id":"' + $networkId + '"', '"network_id":"' + $networkId + '","network_id":"' + $networkId + '"')) $networkId 'a duplicate field'
Assert-Rejected ($valid + "`n") $networkId 'more than one JSON line'

$temporaryDirectory = Join-Path ([IO.Path]::GetTempPath()) (
    'cmfd-v4-manifest-identity-{0}' -f [Guid]::NewGuid().ToString('N')
)
[IO.Directory]::CreateDirectory($temporaryDirectory) | Out-Null
try {
    $inputPath = Join-Path $temporaryDirectory 'MODEL-V2.bank'
    [IO.File]::WriteAllBytes($inputPath, [byte[]](1, 2, 3))
    $sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $inputPath).Hash.ToLowerInvariant()
    $manifestPath = Join-Path $temporaryDirectory 'inputs.json'
    $validManifest = '{"schema_version":1,"network":"CommonFoundry ProductionV4 Testnet-1","network_id":"' +
        $networkId +
        '","total_bytes":3,"files":[{"name":"MODEL-V2.bank","bytes":3,"sha256":"' +
        $sha256 +
        '"}]}'
    $utf8 = [Text.UTF8Encoding]::new($false)
    [IO.File]::WriteAllText($manifestPath, $validManifest, $utf8)
    $validated = Assert-InputManifest $manifestPath @{ 'MODEL-V2.bank' = $inputPath }
    if ($validated.NetworkId -cne $networkId -or $validated.Manifest.network_id -cne $networkId) {
        throw 'valid input manifest did not return one reusable validated object'
    }

    $duplicateTopLevel = $validManifest.Replace(
        '"network_id":"' + $networkId + '"',
        '"network_id":"' + $networkId + '","network_id":"' + $otherNetworkId + '"'
    )
    $duplicateTopLevelReversed = $validManifest.Replace(
        '"network_id":"' + $networkId + '"',
        '"network_id":"' + $otherNetworkId + '","network_id":"' + $networkId + '"'
    )
    $duplicateTopLevelEscaped = $validManifest.Replace(
        '"network_id":"' + $networkId + '"',
        '"network_id":"' + $networkId + '","network\u005fid":"' + $otherNetworkId + '"'
    )
    $duplicateNested = $validManifest.Replace(
        '"name":"MODEL-V2.bank"',
        '"name":"MODEL-V2.bank","name":"other.bank"'
    )
    foreach ($case in @(
        @{ Label = 'duplicate top-level network_id'; Json = $duplicateTopLevel },
        @{ Label = 'reversed duplicate top-level network_id'; Json = $duplicateTopLevelReversed },
        @{ Label = 'escaped duplicate top-level network_id'; Json = $duplicateTopLevelEscaped },
        @{ Label = 'duplicate nested file field'; Json = $duplicateNested }
    )) {
        [IO.File]::WriteAllText($manifestPath, [string]$case.Json, $utf8)
        $rejected = $false
        try {
            Assert-InputManifest $manifestPath @{ 'MODEL-V2.bank' = $inputPath } | Out-Null
        } catch {
            $rejected = $true
        }
        if (-not $rejected) {
            throw "input manifest validator accepted $($case.Label)"
        }
    }
    if ($validated.Manifest.network_id -cne $networkId) {
        throw 'validated manifest object changed after the source file changed'
    }
    $launcherSource = Get-Content -Raw -LiteralPath $Launcher
    if (
        $launcherSource -cnotmatch '\$manifest = \$manifestValidation\.Manifest' -or
        $launcherSource -cmatch '\$manifest = Get-Content -Raw -LiteralPath \$inputManifestPath'
    ) {
        throw 'launcher does not reuse the duplicate-checked manifest object'
    }
} finally {
    if (Test-Path -LiteralPath $temporaryDirectory -PathType Container) {
        Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force
    }
}

Write-Output 'ProductionV4 PowerShell manifest and miner identity tests passed.'
