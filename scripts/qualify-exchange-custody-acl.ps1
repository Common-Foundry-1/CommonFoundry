[CmdletBinding(DefaultParameterSetName = 'Live')]
param(
    [Parameter(Mandatory = $true)]
    [string]$NodeExecutable,

    [Parameter(Mandatory = $true, ParameterSetName = 'Live')]
    [string]$Config,

    [Parameter(Mandatory = $true, ParameterSetName = 'Fixture')]
    [string]$Fixture,

    [Parameter(Mandatory = $true)]
    [string]$Output
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-DirectFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    if (-not [IO.Path]::IsPathFullyQualified($Path)) {
        throw "$Label must be an absolute path."
    }
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "$Label must be a direct regular file."
    }
    return $item.FullName
}

$node = Resolve-DirectFile -Path $NodeExecutable -Label 'NodeExecutable'
if (-not [IO.Path]::IsPathFullyQualified($Output)) {
    throw 'Output must be an absolute path.'
}
if (Test-Path -LiteralPath $Output) {
    throw 'Output already exists; qualification evidence is create-new.'
}

if ($PSCmdlet.ParameterSetName -eq 'Live') {
    $inputPath = Resolve-DirectFile -Path $Config -Label 'Config'
    Write-Verbose 'Live qualification must be launched as the configured non-elevated node service identity.'
    & $node exchange-v3-acl-qualify --config $inputPath --output $Output
} else {
    $inputPath = Resolve-DirectFile -Path $Fixture -Label 'Fixture'
    Write-Verbose 'Fixture qualification cannot establish an installed-host result.'
    & $node exchange-v3-acl-fixture-qualify --fixture $inputPath --output $Output
}

if ($LASTEXITCODE -ne 0) {
    throw "cmfd-node rejected ACL qualification with exit code $LASTEXITCODE."
}
