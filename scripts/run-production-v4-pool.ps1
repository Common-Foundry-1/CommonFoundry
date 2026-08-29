[CmdletBinding()]
param(
    [string]$PublicNumericAddress,
    [string]$PrivateBindAddress,
    [string]$ModelBank,
    [string]$FixedRecord,
    [string]$DataDirectory = (Join-Path $PSScriptRoot 'pool-data'),
    [string]$WslDistribution = 'Ubuntu-22.04',
    [string]$Peer,
    [switch]$AllowPublicPeers,
    [uint16]$PoolPort = 22445,
    [string]$P2pBind = '0.0.0.0:22444',
    [string]$DashboardBind = '127.0.0.1:22446',
    [uint16]$ShareLeadingZeroBits = 7,
    [uint64]$MinimumPayoutAtoms = 100,
    [uint64]$PayoutFeeAtoms = 1
)

$ErrorActionPreference = 'Stop'

$node = Join-Path $PSScriptRoot 'cmfd-node.exe'
$replayWorker = Join-Path $PSScriptRoot 'cmfd-v4-replay'
$proofWorker = Join-Path $PSScriptRoot 'real_bank0_relations'
$dashboardAssets = Join-Path $PSScriptRoot 'dashboard'
$scratchDirectory = Join-Path $PSScriptRoot 'pool-scratch'
$tlsDirectory = Join-Path $PSScriptRoot 'pool-tls'
$certificate = Join-Path $tlsDirectory 'pool-cert.der'
$privateKey = Join-Path $tlsDirectory 'pool-key.der'

$requiredFiles = @($node, $replayWorker, $proofWorker)
foreach ($file in $requiredFiles) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
        throw "Required file is missing: $file"
    }
}
if ([string]::IsNullOrWhiteSpace($PublicNumericAddress)) {
    $PublicNumericAddress = (Read-Host 'Public numeric IP address miners will use').Trim()
}
if ([string]::IsNullOrWhiteSpace($PrivateBindAddress)) {
    $PrivateBindAddress = (Read-Host 'Private LAN IP address of this pool host').Trim()
}
$parsedPublicAddress = $null
if (-not [Net.IPAddress]::TryParse($PublicNumericAddress, [ref]$parsedPublicAddress)) {
    throw 'PublicNumericAddress must be a numeric IPv4 or IPv6 address.'
}
$parsedPrivateAddress = $null
if (-not [Net.IPAddress]::TryParse($PrivateBindAddress, [ref]$parsedPrivateAddress)) {
    throw 'PrivateBindAddress must be a numeric IPv4 or IPv6 address.'
}
if (-not (Test-Path -LiteralPath (Join-Path $dashboardAssets 'index.html') -PathType Leaf)) {
    throw "Built dashboard is missing: $dashboardAssets\index.html"
}
if ($PrivateBindAddress -in @('0.0.0.0', '::')) {
    throw "PrivateBindAddress must be the host's private LAN address, not a wildcard."
}
$publicUrlHost = if ($parsedPublicAddress.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) {
    "[$PublicNumericAddress]"
} else {
    $PublicNumericAddress
}
$privateBindHost = if ($parsedPrivateAddress.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) {
    "[$PrivateBindAddress]"
} else {
    $PrivateBindAddress
}
if ([string]::IsNullOrWhiteSpace($WslDistribution)) {
    throw 'WslDistribution is required by the Windows pool package.'
}
$wsl = Get-Command wsl.exe -ErrorAction SilentlyContinue
if (-not $wsl) {
    throw 'WSL2 is required. Install WSL with Ubuntu 22.04, then run START-POOL.bat again.'
}
& $wsl.Source -d $WslDistribution --exec sh -lc 'command -v nvidia-smi >/dev/null 2>&1 && nvidia-smi -L >/dev/null 2>&1'
if ($LASTEXITCODE -ne 0) {
    throw "NVIDIA CUDA is unavailable inside $WslDistribution. Verify the NVIDIA driver and WSL GPU support."
}
if ([string]::IsNullOrWhiteSpace($ModelBank) -and [string]::IsNullOrWhiteSpace($FixedRecord)) {
    $prepareInputs = Join-Path $PSScriptRoot 'PREPARE-V4-INPUTS.ps1'
    if (-not (Test-Path -LiteralPath $prepareInputs -PathType Leaf)) {
        throw "Required input bootstrap is missing: $prepareInputs"
    }
    Write-Host 'Preparing authenticated ProductionV4 pool inputs. The first run downloads about 61 GB.'
    & $prepareInputs -Role Miner
    $inputs = Join-Path $PSScriptRoot 'inputs'
    $ModelBank = Join-Path $inputs 'MODEL-V2.bank'
    $FixedRecord = Join-Path $inputs 'fixed\FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json'
} elseif ([string]::IsNullOrWhiteSpace($ModelBank) -or [string]::IsNullOrWhiteSpace($FixedRecord)) {
    throw 'Supply both ModelBank and FixedRecord, or omit both to use authenticated automatic downloads.'
}
foreach ($file in @($ModelBank, $FixedRecord)) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
        throw "Required file is missing: $file"
    }
}
if ((Test-Path -LiteralPath $certificate) -xor (Test-Path -LiteralPath $privateKey)) {
    throw 'The pool TLS certificate and private key must either both exist or both be absent.'
}

New-Item -ItemType Directory -Force $DataDirectory, $scratchDirectory, $tlsDirectory | Out-Null
if (-not (Test-Path -LiteralPath $certificate)) {
    & $node `
        --production-v4-bank (Resolve-Path -LiteralPath $ModelBank).Path `
        --production-v4-fixed-record (Resolve-Path -LiteralPath $FixedRecord).Path `
        pool-certificate `
        --certificate $certificate `
        --private-key $privateKey
    if ($LASTEXITCODE -ne 0) {
        throw "cmfd-node pool-certificate exited with code $LASTEXITCODE"
    }
}

$pin = (Get-FileHash -LiteralPath $certificate -Algorithm SHA256).Hash.ToLowerInvariant()
$publicUrl = "cmfd+tls://${publicUrlHost}:$PoolPort`?pin=$pin"
$arguments = @(
    '--data-dir', $DataDirectory,
    '--production-v4-bank', (Resolve-Path -LiteralPath $ModelBank).Path,
    '--production-v4-fixed-record', (Resolve-Path -LiteralPath $FixedRecord).Path,
    'pool-serve',
    '--bind', "${privateBindHost}:$PoolPort",
    '--p2p-bind', $P2pBind,
    '--certificate', $certificate,
    '--private-key', $privateKey,
    '--share-leading-zero-bits', $ShareLeadingZeroBits,
    '--production-v4-pool-replay-worker', $replayWorker,
    '--production-v4-pool-proof-worker', $proofWorker,
    '--production-v4-pool-scratch', $scratchDirectory,
    '--enable-testnet-payouts',
    '--pool-minimum-payout-atoms', $MinimumPayoutAtoms,
    '--pool-payout-fee-atoms', $PayoutFeeAtoms,
    '--pool-dashboard-assets', $dashboardAssets,
    '--pool-public-url', $publicUrl,
    '--pool-dashboard-bind', $DashboardBind,
    '--allow-public-pool-clients'
)
$arguments += @('--production-v4-pool-wsl-distribution', $WslDistribution)
if ($Peer) {
    $arguments += @('--peer', $Peer)
}
if ($AllowPublicPeers) {
    $arguments += '--allow-public-peers'
}
Write-Host "Pool URL: $publicUrl"
Write-Host "Dashboard: http://$DashboardBind/"
& $node @arguments
exit $LASTEXITCODE
