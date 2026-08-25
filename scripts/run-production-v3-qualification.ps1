#requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^(?:[0-9a-f]{40}|[0-9a-f]{64})$')]
    [string]$ExpectedCommit,

    [Parameter(Mandatory)]
    [string]$Bank,

    [Parameter(Mandatory)]
    [string]$Record,

    [Parameter(Mandatory)]
    [string]$Request,

    [Parameter(Mandatory)]
    [string]$OutputDirectory,

    [Parameter(Mandatory)]
    [string]$ScratchDirectory,

    [ValidateRange(1, [long]::MaxValue)]
    [long]$ScratchMarginBytes = 17179869184,

    [ValidateRange(1, [int]::MaxValue)]
    [int]$MaximumNativeBlockRows = 131072,

    [ValidateRange(1, 3600)]
    [int]$CancellationGraceSeconds = 120
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not $IsWindows) {
    throw 'The production V3 qualification operator harness must run on Windows.'
}

$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$harness = Join-Path $PSScriptRoot 'production_v3_qualification.py'
$python = Get-Command py.exe -ErrorAction SilentlyContinue
if ($python) {
    $pythonArguments = @('-3')
} else {
    $python = Get-Command python3.exe -ErrorAction SilentlyContinue
    if (-not $python) {
        $python = Get-Command python.exe -ErrorAction SilentlyContinue
    }
    if (-not $python) {
        throw 'Python 3 is required for the production V3 qualification harness.'
    }
    $pythonArguments = @()
}

$arguments = @(
    $harness,
    '--repo', $projectRoot,
    '--expected-commit', $ExpectedCommit,
    '--bank', $Bank,
    '--record', $Record,
    '--request', $Request,
    '--output-directory', $OutputDirectory,
    '--scratch-directory', $ScratchDirectory,
    '--scratch-margin-bytes', $ScratchMarginBytes.ToString([Globalization.CultureInfo]::InvariantCulture),
    '--maximum-native-block-rows', $MaximumNativeBlockRows.ToString([Globalization.CultureInfo]::InvariantCulture),
    '--cancellation-grace-seconds', $CancellationGraceSeconds.ToString([Globalization.CultureInfo]::InvariantCulture)
)

& $python.Source @pythonArguments @arguments
if ($LASTEXITCODE -ne 0) {
    throw "Production V3 qualification harness exited with code $LASTEXITCODE."
}
