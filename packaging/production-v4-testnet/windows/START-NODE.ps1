#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Peer = '107.214.187.2:22444',
    [string]$DataDirectory = (Join-Path $PSScriptRoot 'node-data'),
    [switch]$PublicListener
)

$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'PREPARE-V4-INPUTS.ps1') -Role Node
$inputs = Join-Path $PSScriptRoot 'inputs'
$arguments = @(
    '--data-dir', $DataDirectory,
    '--production-v4-bank', (Join-Path $inputs 'MODEL-V2.bank'),
    '--production-v4-fixed-record', (Join-Path $inputs 'fixed\FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json'),
    'run', '--bind', '127.0.0.1:22443'
)
if ($PublicListener) {
    $arguments += @('--p2p-bind', '0.0.0.0:22444')
} else {
    $arguments += @('--p2p-bind', '127.0.0.1:22444')
}
if ($Peer) { $arguments += @('--peer', $Peer, '--allow-public-peers') }
& (Join-Path $PSScriptRoot 'cmfd-node.exe') @arguments
exit $LASTEXITCODE
