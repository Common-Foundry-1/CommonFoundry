# Temporary recovery for the v1.0.0 drand v2 beacon-ID URL bug.
# Run from an already verified, extracted mainnet runtime or miner package.
[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$PackageDirectory)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$package = [IO.Path]::GetFullPath($PackageDirectory)
$launch = Join-Path $package 'cmfd-launch.exe'
$runtime = if (Test-Path -LiteralPath (Join-Path $package 'cmfd-node.exe') -PathType Leaf) {
    Join-Path $package 'cmfd-node.exe'
} elseif (Test-Path -LiteralPath (Join-Path $package 'cmfd-miner.exe') -PathType Leaf) {
    Join-Path $package 'cmfd-miner.exe'
} else { throw 'This folder has neither a packaged mainnet node nor miner.' }
if (-not (Test-Path -LiteralPath $launch -PathType Leaf)) { throw 'Packaged cmfd-launch.exe is missing.' }
$sidecar = Join-Path $package 'production-mainnet'
if (-not (Test-Path -LiteralPath $sidecar -PathType Container)) { throw 'Mainnet plan folder is missing.' }
$output = Join-Path $sidecar 'LAUNCH-BEACON.json'
if (Test-Path -LiteralPath $output) { throw 'A launch beacon already exists. Do not overwrite it.' }
$identityText = & $runtime mainnet-launch-info
if ($LASTEXITCODE -ne 0) { throw 'The packaged runtime did not authenticate its mainnet plan.' }
$identity = $identityText | ConvertFrom-Json
if ($identity.beacon_round -ne 32747812 -or $identity.genesis_policy -ne 'requires_verified_launch_beacon') {
    throw 'The packaged runtime has an unexpected launch policy.'
}
$digest = [string]$identity.launch_plan.launch_plan_digest
if ($digest -notmatch '^[0-9a-f]{64}$') { throw 'The packaged runtime has an invalid plan digest.' }
$pending = Join-Path $sidecar ('.LAUNCH-BEACON.pending-' + [guid]::NewGuid().ToString('N') + '.json')
$url = 'https://api.drand.sh/v2/beacons/quicknet/rounds/32747812'
$curl = Join-Path $env:SystemRoot 'System32\curl.exe'
& $curl --disable --silent --show-error --fail --proto '=https' --connect-timeout 3 --max-time 8 --max-filesize 4096 --output $pending $url
if ($LASTEXITCODE -ne 0) { throw 'The pinned public drand response could not be fetched.' }
$verifiedText = & $launch verify --certificate $pending --launch-plan-digest $digest
if ($LASTEXITCODE -ne 0) { throw 'The response failed the packaged launch signature verifier.' }
$verified = $verifiedText | ConvertFrom-Json
if ($verified.round -ne 32747812 -or $verified.launch_plan_digest -cne $digest) {
    throw 'The verified response does not match the packaged launch policy.'
}
if (Test-Path -LiteralPath $output) { throw 'A launch beacon appeared during verification. Do not overwrite it.' }
Rename-Item -LiteralPath $pending -NewName 'LAUNCH-BEACON.json' -ErrorAction Stop
& $launch fetch --runtime $runtime
if ($LASTEXITCODE -ne 0) { throw 'The published beacon did not pass the packaged fetch verifier.' }
Write-Host 'Verified launch beacon installed. Reopen the wallet or miner launcher.'
