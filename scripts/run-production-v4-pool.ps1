[CmdletBinding()]
param(
    [string]$PublicNumericAddress,
    [string]$PrivateBindAddress,
    [string]$ModelBank,
    [string]$FixedRecord,
    [string]$DataDirectory,
    [string]$WslDistribution = 'Ubuntu-22.04',
    [string]$Peer,
    [switch]$AllowPublicPeers,
    [uint16]$PoolPort = 19445,
    [string]$P2pBind = '0.0.0.0:19444',
    [string]$DashboardBind = '127.0.0.1:19446',
    [uint16]$ShareLeadingZeroBits = 7,
    [uint64]$MinimumPayoutAtoms = 100,
    [uint64]$PayoutFeeAtoms = 10000000,
    [ValidateRange(0, 10000)][uint16]$OperatorFeeBps = 300,
    [ValidateRange(0, 65536)][uint32]$PplnsWindowShares = 0,
    [switch]$IgnoreSavedSettings
)

$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($DataDirectory)) {
    $DataDirectory = Join-Path $PSScriptRoot 'pool-data'
}

$node = Join-Path $PSScriptRoot 'cmfd-node.exe'
$replayWorker = Join-Path $PSScriptRoot 'cmfd-v4-replay'
$proofWorker = Join-Path $PSScriptRoot 'real_bank0_relations'
$dashboardAssets = Join-Path $PSScriptRoot 'dashboard'
$scratchDirectory = Join-Path $PSScriptRoot 'pool-scratch'
$tlsDirectory = Join-Path $PSScriptRoot 'pool-tls'
$certificate = Join-Path $tlsDirectory 'pool-cert.der'
$privateKey = Join-Path $tlsDirectory 'pool-key.der'
$DataDirectory = [IO.Path]::GetFullPath($DataDirectory)
$controlDirectory = Join-Path $DataDirectory 'pool-control'
$stateFile = Join-Path $controlDirectory 'pool-state.json'
$settingsFile = Join-Path $controlDirectory 'pool-settings.json'
$shutdownRequestFile = Join-Path $controlDirectory 'shutdown.request'
$logDirectory = Join-Path $DataDirectory 'logs'

function Write-AtomicJson {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Value
    )
    $temporary = "$Path.$PID.tmp"
    try {
        $Value | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $temporary -Encoding UTF8
        Move-Item -LiteralPath $temporary -Destination $Path -Force
    } finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
}

function Test-SavedProcess {
    param([Parameter(Mandatory = $true)]$State)
    if ($State.schema -ne 'CommonFoundry/ProductionV4/PoolProcess/v1') {
        throw "Pool process state has an unsupported schema: $stateFile"
    }
    try {
        $process = Get-Process -Id ([int]$State.pid) -ErrorAction Stop
        return $process.StartTime.ToUniversalTime().Ticks -eq [int64]$State.process_start_utc_ticks
    } catch {
        return $false
    }
}

New-Item -ItemType Directory -Force $DataDirectory, $controlDirectory, $logDirectory | Out-Null
if (-not $IgnoreSavedSettings -and (Test-Path -LiteralPath $settingsFile -PathType Leaf)) {
    if ((Get-Item -LiteralPath $settingsFile).Length -gt 65536) {
        throw "Pool settings file is unexpectedly large: $settingsFile"
    }
    $saved = Get-Content -LiteralPath $settingsFile -Raw | ConvertFrom-Json
    if ($saved.schema -ne 'CommonFoundry/ProductionV4/PoolSettings/v1') {
        throw "Pool settings file has an unsupported schema: $settingsFile"
    }
    if (-not $PSBoundParameters.ContainsKey('PublicNumericAddress')) { $PublicNumericAddress = [string]$saved.public_numeric_address }
    if (-not $PSBoundParameters.ContainsKey('PrivateBindAddress')) { $PrivateBindAddress = [string]$saved.private_bind_address }
    if (-not $PSBoundParameters.ContainsKey('ModelBank')) { $ModelBank = [string]$saved.model_bank }
    if (-not $PSBoundParameters.ContainsKey('FixedRecord')) { $FixedRecord = [string]$saved.fixed_record }
    if (-not $PSBoundParameters.ContainsKey('WslDistribution')) { $WslDistribution = [string]$saved.wsl_distribution }
    if (-not $PSBoundParameters.ContainsKey('Peer')) { $Peer = [string]$saved.peer }
    if (-not $PSBoundParameters.ContainsKey('AllowPublicPeers')) { $AllowPublicPeers = [bool]$saved.allow_public_peers }
    if (-not $PSBoundParameters.ContainsKey('PoolPort')) { $PoolPort = [uint16]$saved.pool_port }
    if (-not $PSBoundParameters.ContainsKey('P2pBind')) { $P2pBind = [string]$saved.p2p_bind }
    if (-not $PSBoundParameters.ContainsKey('DashboardBind')) { $DashboardBind = [string]$saved.dashboard_bind }
    if (-not $PSBoundParameters.ContainsKey('ShareLeadingZeroBits')) { $ShareLeadingZeroBits = [uint16]$saved.share_leading_zero_bits }
    if (-not $PSBoundParameters.ContainsKey('MinimumPayoutAtoms')) { $MinimumPayoutAtoms = [uint64]$saved.minimum_payout_atoms }
    if (-not $PSBoundParameters.ContainsKey('PayoutFeeAtoms')) { $PayoutFeeAtoms = [uint64]$saved.payout_fee_atoms }
    if (-not $PSBoundParameters.ContainsKey('OperatorFeeBps') -and $saved.PSObject.Properties.Name -contains 'operator_fee_bps') { $OperatorFeeBps = [uint16]$saved.operator_fee_bps }
    if (-not $PSBoundParameters.ContainsKey('PplnsWindowShares') -and $saved.PSObject.Properties.Name -contains 'pplns_window_shares') { $PplnsWindowShares = [uint32]$saved.pplns_window_shares }
}
if (Test-Path -LiteralPath $stateFile -PathType Leaf) {
    $existingState = Get-Content -LiteralPath $stateFile -Raw | ConvertFrom-Json
    if (Test-SavedProcess -State $existingState) {
        throw "A pool instance is already running with process ID $($existingState.pid)."
    }
    Remove-Item -LiteralPath $stateFile, $shutdownRequestFile -Force -ErrorAction SilentlyContinue
} elseif (Test-Path -LiteralPath $shutdownRequestFile) {
    Remove-Item -LiteralPath $shutdownRequestFile -Force
}

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
    '--pool-operator-fee-bps', $OperatorFeeBps,
    '--pool-pplns-window-shares', $PplnsWindowShares,
    '--pool-dashboard-assets', $dashboardAssets,
    '--pool-public-url', $publicUrl,
    '--pool-dashboard-bind', $DashboardBind,
    '--shutdown-request-file', $shutdownRequestFile,
    '--allow-public-pool-clients',
    '--allow-address-only-payouts'
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
Write-Host ("PPLNS: {0:N2}% operator fee; {1}" -f ($OperatorFeeBps / 100), $(if ($PplnsWindowShares -eq 0) { 'automatic one-block share window' } else { "$PplnsWindowShares-share window" }))
$settings = [ordered]@{
    schema = 'CommonFoundry/ProductionV4/PoolSettings/v1'
    public_numeric_address = $PublicNumericAddress
    private_bind_address = $PrivateBindAddress
    model_bank = (Resolve-Path -LiteralPath $ModelBank).Path
    fixed_record = (Resolve-Path -LiteralPath $FixedRecord).Path
    wsl_distribution = $WslDistribution
    peer = $Peer
    allow_public_peers = [bool]$AllowPublicPeers
    pool_port = $PoolPort
    p2p_bind = $P2pBind
    dashboard_bind = $DashboardBind
    share_leading_zero_bits = $ShareLeadingZeroBits
    minimum_payout_atoms = $MinimumPayoutAtoms
    payout_fee_atoms = $PayoutFeeAtoms
    operator_fee_bps = $OperatorFeeBps
    pplns_window_shares = $PplnsWindowShares
}
Write-AtomicJson -Path $settingsFile -Value $settings
$process = Get-Process -Id $PID
$logFile = Join-Path $logDirectory ("pool-{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
$state = [ordered]@{
    schema = 'CommonFoundry/ProductionV4/PoolProcess/v1'
    pid = $PID
    process_start_utc_ticks = $process.StartTime.ToUniversalTime().Ticks
    dashboard_url = "http://$DashboardBind/"
    log_file = $logFile
}
Write-AtomicJson -Path $stateFile -Value $state
Write-Host "Log: $logFile"

$transcriptStarted = $false
try {
    Start-Transcript -LiteralPath $logFile -Append | Out-Null
    $transcriptStarted = $true
    & $node @arguments
    $poolExit = $LASTEXITCODE
} finally {
    if ($transcriptStarted) {
        Stop-Transcript | Out-Null
    }
    try {
        $currentState = Get-Content -LiteralPath $stateFile -Raw -ErrorAction Stop | ConvertFrom-Json
        if ([int]$currentState.pid -eq $PID -and [int64]$currentState.process_start_utc_ticks -eq $process.StartTime.ToUniversalTime().Ticks) {
            Remove-Item -LiteralPath $stateFile, $shutdownRequestFile -Force -ErrorAction SilentlyContinue
        }
    } catch {
        # Preserve a replacement or malformed state file for operator inspection.
    }
}
exit $poolExit
