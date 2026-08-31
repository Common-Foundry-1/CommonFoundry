# ProductionV4 test-pool operator guide

The Common Foundry ProductionV4 pool package runs a certificate-pinned Devnet pool,
a full P2P node, persistent CUDA replay and proof workers, durable PPLNS and
payout accounting, and a read-only web dashboard. Windows and native Linux
packages use the same protocol and ledger rules.

This is Devnet software. Credits and payouts have no monetary value.

## Host requirements

- One NVIDIA GPU supported by the ProductionV4 CUDA workers. The current
  qualification host uses an RTX 5090; operators should treat other GPUs as
  test configurations and report results.
- 64 GB system RAM recommended.
- At least 90 GB of free disk space for the authenticated 61 GB input set,
  resumable download parts, the chain, and scratch files.
- A stable broadband connection and a public numeric IPv4 or IPv6 address.
- TCP 22445 forwarded to the pool host for miners. TCP 22444 is the P2P port.
- Windows: Windows 11, WSL2, Ubuntu 22.04, and NVIDIA GPU support working inside
  WSL. The supplied Windows node starts the Linux CUDA workers through WSL.
- Linux: x86-64 Linux, Python 3, curl, an NVIDIA driver, and the CUDA 12 runtime.

The first start downloads the same signed-off ProductionV4 input manifest used
by the official miner. Downloads are resumable, use the Common Foundry download
service with the GitHub binary release as fallback, and are checked against
pinned byte lengths and SHA-256 hashes before the pool starts.

## Windows

1. Extract the ZIP to a local NTFS drive with at least 90 GB free.
2. Confirm `wsl -d Ubuntu-22.04 --exec nvidia-smi` works in a terminal.
3. Double-click `START-POOL.bat`.
4. Enter the public numeric IP miners will use and this computer's private LAN
   IP when prompted.
5. Allow inbound TCP 22444 and 22445 in Windows Firewall and forward those ports
   in the router when the host is behind NAT.

The console prints the exact `cmfd+tls://...` miner URL after generating the
pool certificate. Share that complete URL, including its certificate pin. Never
share `pool-tls/pool-key.der`.

Power users can pass named options through the launcher:

```powershell
.\START-POOL.bat -PublicNumericAddress 203.0.113.20 -PrivateBindAddress 192.168.1.20
```

The default operator fee is 3% (`300` basis points). To change it for blocks
found after the next start, pass `-OperatorFeeBps`; for example, 1.5% is:

```powershell
.\START-POOL.bat -OperatorFeeBps 150
```

`-PplnsWindowShares 0` is the default and automatically selects a rolling
window equal to one expected block of share work. An operator may instead set
an explicit window from 1 through 65,536 shares. Both values are saved after a
successful start and reused by restart and autostart controls.

The package includes local operator controls. They authenticate the saved
process identity before acting and request a graceful ledger-preserving stop;
they never force-kill a process:

```text
POOL-STATUS.bat
STOP-POOL.bat
RESTART-POOL.bat
INSTALL-POOL-AUTOSTART.bat
REMOVE-POOL-AUTOSTART.bat
```

Autostart is installed for the current Windows user and opens the pool console
visibly after that user signs in. Saved settings are reused, so no address
prompt is shown after the first successful start. Pass
`-DataDirectory D:\path\to\pool-data` to any control when using a custom data
directory.

## Native Linux

Extract the archive on a Linux filesystem and run:

```bash
chmod +x START-POOL.sh PREPARE-V4-INPUTS.sh cmfd-node cmfd-v4-replay real_bank0_relations
./START-POOL.sh 203.0.113.20 192.168.1.20
```

The first argument is the public numeric IP and the second is the host's private
LAN IP. Omitting either value prompts for it. The optional third argument is a
custom pool data directory.

Use `CMFD_POOL_PEER=IP:22444` and `CMFD_POOL_ALLOW_PUBLIC_PEERS=1` to configure a
static public P2P peer. Other operator overrides are listed near the top of
`START-POOL.sh`.

Set `CMFD_POOL_OPERATOR_FEE_BPS` to change the 300-basis-point default and
`CMFD_POOL_PPLNS_WINDOW_SHARES` to change the window. Zero keeps the automatic
one-expected-block window. These settings apply to blocks found after the pool
starts; every discovered block permanently records the fee and window that
were active when it was found.

Linux controls use the same graceful authenticated request path:

```bash
./POOL-STATUS.sh
./STOP-POOL.sh
./RESTART-POOL.sh
```

To install or remove a current-user systemd service:

```bash
./INSTALL-POOL-SERVICE.sh
./REMOVE-POOL-SERVICE.sh
```

The service starts immediately and is enabled for future user sessions. An
administrator can run `loginctl enable-linger USERNAME` when the pool must
start at boot before that user logs in. Use `systemctl --user status
commonfoundry-production-v4-pool` and `journalctl --user -u
commonfoundry-production-v4-pool` for service diagnostics.

## Dashboard and miner connections

The dashboard is available on the pool host at <http://127.0.0.1:22446>. It
shows pool health, chain height, workers, accepted and rejected shares, PPLNS
window size, per-block reward and fee accounting, matured operator fees,
credit, and payout status. The dashboard is deliberately loopback-only. Publish
it through an authenticated reverse proxy or tunnel if remote viewing is
needed; do not expose a separate node-control API.

Miners connect with the exact URL printed at startup. The protocol uses TLS 1.3
with an exact certificate SHA-256 pin. The standalone miner identifies its
payout with the wallet receive address configured in `START-POOL-MINING.bat`;
the wallet miner may additionally authenticate that address with its signing
key. It is a Common Foundry protocol, not Bitcoin Stratum.

ProductionV4 Devnet defaults to a seven-leading-zero-bit share target, one bit
easier than the current block target. The wallet searches server-issued jobs
with its persistent batched CUDA worker, while the pool independently performs
the authenticated GPU replay before accepting or crediting every submitted
nonce. Client results are never trusted.

## PPLNS rewards and operator fee

Every accepted share records its exact work from the server-controlled share
target. When the pool finds a block, the winning share is added in discovery
order and the last N shares are frozen for that block. The default automatic N
is the ceiling of block work divided by share work, equivalent to one expected
block of shares; mixed-difficulty windows remain fair because allocation is
weighted by exact work rather than raw share count.

The pool waits for the coinbase maturity of 100 confirmations before crediting
the block. At maturity it deducts the fee frozen with that block—3% by default—
and distributes every remaining atom across the frozen window. Integer rounding
uses deterministic largest remainders, so the operator fee plus all miner
allocations always equals the block's actual miner reward. Orphaned blocks do
not create rewards, and the durable journal prevents a restart from applying a
mature block twice.

The operator fee remains in the pool wallet as operator revenue. It is separate
from `PayoutFeeAtoms` / `CMFD_POOL_PAYOUT_FEE_ATOMS`, which is the network fee
burned by each miner payout transaction.

## Persistence and backups

Stop the pool before backing up `pool-data` and `pool-tls`. The TLS private key
and node wallet key are operator secrets. Restoring both directories preserves
the advertised certificate pin, pool identity, chain, credits, and payout
journal. The large `inputs` directory can be downloaded and verified again.

Each start writes a timestamped log under `pool-data/logs`; the status command
prints the active log path. A clean shutdown preserves the ledger. On the next
start, authenticated inputs and saved operator settings are reused, and the
persistent workers are prepared again before miner connections open. If a host
loses power, stale process state is discarded only after its saved process ID
and start identity are shown not to be running.
