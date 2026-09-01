[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$NodeBinary,
    [Parameter(Mandatory = $true)][string]$DataDir,
    [Parameter(Mandatory = $true)][string]$WalletPassphraseFile,
    [Parameter(Mandatory = $true)][string]$JournalKeyFile,
    [Parameter(Mandatory = $true)][string]$JournalAnchorFile,
    [Parameter(Mandatory = $true)][string]$IntegrationAuthFile,
    [Parameter(Mandatory = $true)][string]$WithdrawalAuthFile,
    [Parameter(Mandatory = $true)][string]$PolicyFile,
    [Parameter(Mandatory = $true)][string]$KeyringFile,
    [Parameter(Mandatory = $true)][string]$KeyringAnchorFile,
    [Parameter(Mandatory = $true)][string]$KeyringPassphraseFile,
    [Parameter(Mandatory = $true)][string]$ExchangeRpcBind,
    [Parameter(Mandatory = $true)][string]$NativeRpcBind,
    [Parameter(Mandatory = $true)][string]$P2pBind,
    [string[]]$Peer = @(),
    [switch]$AllowPublicPeers
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -lt 7) {
    throw 'The Windows exchange launcher requires PowerShell 7 or newer.'
}

function Resolve-CanonicalFixedVolumePath {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$Label)
    $fullPath = [IO.Path]::GetFullPath($Path)
    if ($fullPath -cnotmatch '^[A-Za-z]:\\' -or $fullPath.Substring(2).Contains(':')) {
        throw "$Label must use a normal local drive-letter path"
    }
    $driveLetter = $fullPath.Substring(0, 1)
    $volumes = @(Get-Volume -DriveLetter $driveLetter -ErrorAction SilentlyContinue)
    if ($volumes.Count -ne 1 -or [string]$volumes[0].DriveType -cne 'Fixed') {
        throw "$Label must be on one directly mounted fixed volume"
    }
    return $fullPath
}

function Resolve-RegularFile {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$Label)
    $canonicalInput = Resolve-CanonicalFixedVolumePath -Path $Path -Label $Label
    $item = Get-Item -LiteralPath $canonicalInput -Force -ErrorAction Stop
    if ($item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "$Label must be a regular non-reparse file: $($item.FullName)"
    }
    [void](Resolve-CanonicalFixedVolumePath -Path $item.FullName -Label $Label)
    Assert-NoReparsePath -Path $item.FullName -Label $Label
    return $item.FullName
}

function Resolve-RealDirectory {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$Label)
    $canonicalInput = Resolve-CanonicalFixedVolumePath -Path $Path -Label $Label
    $item = Get-Item -LiteralPath $canonicalInput -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "$Label must be a real non-reparse directory: $($item.FullName)"
    }
    [void](Resolve-CanonicalFixedVolumePath -Path $item.FullName -Label $Label)
    Assert-NoReparsePath -Path $item.FullName -Label $Label
    return $item.FullName
}

function Assert-NoReparsePath {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$Label)
    $item = Get-Item -LiteralPath ([IO.Path]::GetFullPath($Path)) -Force -ErrorAction Stop
    while ($null -ne $item) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Label traverses a reparse point: $($item.FullName)"
        }
        if ($item -is [IO.DirectoryInfo]) {
            $item = $item.Parent
        } else {
            $item = $item.Directory
        }
    }
}

function Assert-OutsideDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Directory,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $root = [IO.Path]::GetFullPath($Directory).TrimEnd('\')
    $candidate = [IO.Path]::GetFullPath($Path)
    if ($candidate.Equals($root, [StringComparison]::OrdinalIgnoreCase) -or
        $candidate.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label must be outside the node data directory: $candidate"
    }
}

function Assert-InsideDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Directory,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $root = [IO.Path]::GetFullPath($Directory).TrimEnd('\')
    $candidate = [IO.Path]::GetFullPath($Path)
    if (-not $candidate.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label must be inside the node data directory: $candidate"
    }
}

function Assert-LoopbackEndpoint {
    param([Parameter(Mandatory = $true)][string]$Value, [Parameter(Mandatory = $true)][string]$Label)
    $endpoint = $null
    if (-not [Net.IPEndPoint]::TryParse($Value, [ref]$endpoint) -or
        -not [Net.IPAddress]::IsLoopback($endpoint.Address)) {
        throw "$Label must be a numeric loopback IP endpoint"
    }
    return $endpoint
}

function Resolve-NumericEndpoint {
    param([Parameter(Mandatory = $true)][string]$Value, [Parameter(Mandatory = $true)][string]$Label)
    $endpoint = $null
    if (-not [Net.IPEndPoint]::TryParse($Value, [ref]$endpoint)) {
        throw "$Label must be a numeric IP endpoint"
    }
    return $endpoint
}

$node = Resolve-RegularFile -Path $NodeBinary -Label 'node binary'
$data = Resolve-RealDirectory -Path $DataDir -Label 'data directory'
$walletPassphrase = Resolve-RegularFile -Path $WalletPassphraseFile -Label 'wallet passphrase file'
$journalKey = Resolve-RegularFile -Path $JournalKeyFile -Label 'journal key file'
$journalAnchor = Resolve-RegularFile -Path $JournalAnchorFile -Label 'journal anchor file'
$integrationAuth = Resolve-RegularFile -Path $IntegrationAuthFile -Label 'integration authentication file'
$withdrawalAuth = Resolve-RegularFile -Path $WithdrawalAuthFile -Label 'withdrawal authentication file'
$policy = Resolve-RegularFile -Path $PolicyFile -Label 'withdrawal policy file'
$keyring = Resolve-RegularFile -Path $KeyringFile -Label 'keyring file'
$keyringAnchor = Resolve-RegularFile -Path $KeyringAnchorFile -Label 'keyring anchor file'
$keyringPassphrase = Resolve-RegularFile -Path $KeyringPassphraseFile -Label 'keyring passphrase file'
if (-not [IO.Path]::GetFileName($node).Equals('cmfd-node.exe', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'NodeBinary must use the canonical Windows name cmfd-node.exe'
}
$controlPaths = @(
    @{ Path = $walletPassphrase; Label = 'wallet passphrase file' },
    @{ Path = $journalKey; Label = 'journal key file' },
    @{ Path = $journalAnchor; Label = 'journal anchor file' },
    @{ Path = $integrationAuth; Label = 'integration authentication file' },
    @{ Path = $withdrawalAuth; Label = 'withdrawal authentication file' },
    @{ Path = $policy; Label = 'withdrawal policy file' },
    @{ Path = $keyringAnchor; Label = 'keyring anchor file' },
    @{ Path = $keyringPassphrase; Label = 'keyring passphrase file' }
)
$seenControlPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($controlPath in $controlPaths) {
    if (-not $seenControlPaths.Add($controlPath.Path)) {
        throw "$($controlPath.Label) must use a distinct control-file path"
    }
}
foreach ($externalPath in @(@{ Path = $node; Label = 'node binary' }) + $controlPaths) {
    Assert-OutsideDirectory -Path $externalPath.Path -Directory $data -Label $externalPath.Label
}
Assert-InsideDirectory -Path $keyring -Directory $data -Label 'keyring file'
$exchangeEndpoint = Assert-LoopbackEndpoint -Value $ExchangeRpcBind -Label 'exchange RPC bind'
$nativeEndpoint = Assert-LoopbackEndpoint -Value $NativeRpcBind -Label 'native RPC bind'
if ($exchangeEndpoint.Equals($nativeEndpoint)) {
    throw 'exchange RPC bind and native RPC bind must be distinct endpoints'
}
$p2pEndpoint = Resolve-NumericEndpoint -Value $P2pBind -Label 'P2P bind'
if (-not $AllowPublicPeers -and -not [Net.IPAddress]::IsLoopback($p2pEndpoint.Address)) {
    throw 'a non-loopback P2P bind requires -AllowPublicPeers'
}
$resolvedPeers = New-Object System.Collections.Generic.List[string]
foreach ($address in $Peer) {
    $resolvedPeers.Add((Resolve-NumericEndpoint -Value $address -Label 'peer').ToString())
}

$arguments = @(
    '--data-dir', $data,
    '--wallet-passphrase-file', $walletPassphrase,
    '--exchange-withdrawal-journal-key-file', $journalKey,
    '--exchange-withdrawal-anchor-file', $journalAnchor,
    'run',
    '--bind', $NativeRpcBind,
    '--exchange-rpc-bind', $ExchangeRpcBind,
    '--exchange-rpc-auth-file', $integrationAuth,
    '--exchange-rpc-withdrawal-auth-file', $withdrawalAuth,
    '--exchange-custody-v3-policy-file', $policy,
    '--exchange-custody-v3-keyring-file', $keyring,
    '--exchange-custody-v3-keyring-anchor-file', $keyringAnchor,
    '--exchange-custody-v3-keyring-passphrase-file', $keyringPassphrase,
    '--p2p-bind', $p2pEndpoint.ToString()
)
foreach ($address in $resolvedPeers) {
    $arguments += @('--peer', $address)
}
if ($AllowPublicPeers) {
    $arguments += '--allow-public-peers'
}

& $node @arguments
exit $LASTEXITCODE
