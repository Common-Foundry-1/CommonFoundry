# Desktop node peer configuration

## Choosing an explicit data directory

Normal double-click startup keeps the existing per-network application-data
location. Operators can instead pass `--data-dir <absolute-path>` to select
the exact wallet/node data directory, for example
`--data-dir "C:\CommonFoundry\mainnet-wallet"` on Windows or
`--data-dir /home/operator/commonfoundry/mainnet-wallet` on Linux. This does
not move or copy an existing wallet. Back it up before changing locations.
With an explicit directory, the embedded browser profile also lives beneath
that directory in `webview-profile`, keeping desktop test/portable state separate.

The argument must name a non-root absolute local directory without `..`
components. Windows network, device and verbatim paths are rejected. Normal
filesystem ownership, network identity, wallet encryption and launch checks
still apply; this option cannot switch networks or activate mainnet early.
Close any running wallet before using it: a second launch still only focuses
the existing single-instance window and does not change its data directory.

## Historical Devnet-0 peer examples

The examples below are for the original Devnet-0 profile. For a mainnet package,
use its `--help` output for the compiled port/identity and the packaged mainnet
instructions, not these older addresses or test-network launchers.

Common Foundry Wallet normally starts by double-clicking its shortcut. With no
arguments, the embedded Devnet-0 node listens on `127.0.0.1:18444` and connects
to a bootstrap peer at `107.214.187.2:18444` for initial sync.

The easiest way to manage outbound peers is **Network -> Configured peers** in
the wallet. Enter a numeric IP address (port `18444` is added automatically) or
an explicit `IP:port`. Additions and removals take effect immediately and are
restored on the next launch. **Reset** restores the community bootstrap peer.

Operators can start the packaged executable from a terminal and add one or more
static peers. `--peer` is repeatable. `--p2p-bind` changes the address
used for inbound P2P connections; it is optional and defaults to
`127.0.0.1:18444`. Command-line peer options override saved GUI peers for that
launch. Close any running wallet first: a second launch only focuses the
existing single-instance window.

Additional flags: `--help`, `--version`, and `-v | -vv | -vvv` for basic
startup verbosity logging.

Windows PowerShell (replace the executable path with the installed location):

```powershell
& 'C:\path\to\common-foundry-wallet.exe' `
  --p2p-bind 192.168.50.10:18444 `
  --peer 192.168.50.11:18444 `
  --peer 192.168.50.12:18444
```

Linux AppImage:

```bash
./Common-Foundry-Wallet.AppImage \
  --p2p-bind 192.168.50.10:18444 \
  --peer 192.168.50.11:18444 \
  --peer 192.168.50.12:18444
```

Every value must be a numeric `IP:port`. IPv6 addresses use bracket notation,
for example `--peer [fd12:3456::12]:18444`. Loopback, RFC1918 IPv4, IPv6
unique-local, and IPv6 link-local addresses work by default. Public addresses
require the explicit `--allow-public-peers` option. Unspecified addresses such
as `0.0.0.0`, multicast/broadcast addresses, duplicate peers, zero ports, and
the wallet's own listener address remain rejected.

### Small direct-IP public test network

One reachable node can act as the hub. Forward router TCP port `18444` to that
computer's private LAN address, allow that TCP port through its firewall, and
start the Windows wallet with:

```powershell
& 'C:\path\to\common-foundry-wallet.exe' `
  --p2p-bind 192.168.1.50:18444 `
  --allow-public-peers
```

Linux testers then need only the hub's public IP:

```bash
./Common-Foundry-Wallet.AppImage \
  --allow-public-peers \
  --peer PUBLIC_IP:18444
```

Each configured static-peer session pulls blocks and transactions, then offers
locally active blocks missing after the peer's advertised tip. A single
tester-to-hub peer entry therefore synchronizes mined blocks in both directions;
the hub does not need a reciprocal entry for that tester.

The Devnet-0 P2P transport is neither authenticated nor encrypted. The public
flag is a conspicuous, test-only opt-in; it does not provide discovery, bans,
reputation, or DDoS resistance. Never forward RPC port `18443`, never use this
mode for valuable funds, and stop the listener when the test is over.

## Pool configuration

Pool mining is configured inside **Mining -> Pool**, not with a wallet process
argument. The URL format is exact:

```text
cmfd+tls://127.0.0.1:18445?pin=<64-hex-certificate-sha256>
```

The host must be a numeric loopback, RFC1918 IPv4, or IPv6 unique-local
address; use brackets around IPv6. DNS names, public addresses, paths, extra
query parameters, zero ports, and malformed pins are rejected. Worker names
must match `[A-Za-z0-9._-]{1,32}`.

This is the CMFD Devnet pool v2 protocol over TLS 1.3, not Stratum. The pin is
the SHA-256 digest of the exact DER leaf certificate printed by
`cmfd-node pool-certificate` and `cmfd-node pool-serve`; verify it through a
trusted path before connecting. Miners need only that public pin; they must
never receive the pool's private-key DER. The pool then issues a fresh challenge
that this wallet signs with its receive key, authenticating the payout identity
without transmitting the private key. Pool share, block, and credited-atom
values are stored in a bounded, durable, reorganization-aware test ledger.
The pool operator can enable mature-reward testnet settlement; each exact signed
payout is journaled before broadcast and reconciled with the active chain. See
[../../../docs/devnet-0.md](../../../docs/devnet-0.md) for pool operator
commands and the complete security boundary.
