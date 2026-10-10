# ProductionV4 test-pool operator guide

The Common Foundry ProductionV4 pool package runs a certificate-pinned Devnet pool,
a full P2P node, persistent CUDA replay and proof workers, durable PPLNS and
payout accounting, a read-only public-statistics dashboard, and a separate
loopback-only operator console. Windows and native Linux packages use the same
protocol and ledger rules.

This is Devnet software. Credits and payouts have no monetary value.

## Host requirements

- One NVIDIA GPU supported by the ProductionV4 CUDA workers. The current
  qualification host uses an RTX 5090; operators should treat other GPUs as
  test configurations and report results.
- 64 GB system RAM recommended.
- At least 90 GB of free disk space for the authenticated 61 GB input set,
  resumable download parts, the chain, and scratch files.
- A stable broadband connection and a public numeric IPv4 or IPv6 address.
- TCP 19445 forwarded to the pool host for miners. TCP 19444 is the P2P port.
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
5. Allow inbound TCP 19444 and 19445 in Windows Firewall and forward those ports
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

Double-click `OPEN-OPERATOR-DASHBOARD.bat` to open the local operator console at
<http://127.0.0.1:19448>. Keep its small console window open while using the web
controls. The page can start, gracefully stop, or restart the pool, view the
latest log, and update the operator fee and PPLNS window used after the next
start. Guarded stop and restart controls require an explicit confirmation.

## Native Linux

Extract the archive on a Linux filesystem and run:

```bash
chmod +x START-POOL.sh PREPARE-V4-INPUTS.sh cmfd-node cmfd-v4-replay real_bank0_relations
./START-POOL.sh 203.0.113.20 192.168.1.20
```

The first argument is the public numeric IP and the second is the host's private
LAN IP. Omitting either value prompts for it. The optional third argument is a
custom pool data directory.

Use `CMFD_POOL_PEER=IP:19444` and `CMFD_POOL_ALLOW_PUBLIC_PEERS=1` to configure a
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

Run `./OPEN-OPERATOR-DASHBOARD.sh` to open the same local operator console on
Linux. Press Ctrl+C in its terminal to close only the operator console; the
pool process continues running.

## Dashboard and miner connections

The dashboard is available on the pool host at <http://127.0.0.1:19446>. It
shows pool health, chain height, workers, accepted and rejected shares, PPLNS
window size, per-block reward and fee accounting, matured operator fees,
credit, and payout status. The dashboard is deliberately loopback-only. Publish
it through an authenticated reverse proxy or tunnel if remote viewing is
needed.

The proof worker runs on the pool process's default CUDA device unless
`--production-v4-pool-proof-gpu` names a GPU (`proof_gpu` in `pool.json`). A
proof needs about 7 GiB of free VRAM while a replay worker keeps about 6.5 GiB
resident, so on 16 GB cards the proof GPU must not also run a replay worker;
the pool logs a warning when it does. A proof-worker failure on a chain-winning
share is retried once after the worker restarts.

`pool-serve` accepts 256 simultaneous miner connections by default and at most
64 from one source address. Change them with `--pool-max-connections` (1 to
4096) and `--pool-max-connections-per-source` (1 to 256); the service
launcher reads the same values from `max_connections` and
`max_connections_per_source` in `pool.json`. The official miner opens one
connection per GPU (one `cmfd-miner pool` process per card), so with it the
total is a GPU count and the per-source limit caps the GPUs behind one
public address; a miner that drives a whole rig from one process uses one
connection per rig. The dashboard shows the configured capacity next to the
active connection count.

The operator console is separately available at <http://127.0.0.1:19448> after
running the supplied operator-dashboard launcher. It binds exclusively to
`127.0.0.1`, validates the browser host and origin, and requires an in-memory
same-origin request token for every mutation. It does not emit CORS permissions
and must not be reverse proxied or exposed to the internet. Settings writes are
atomic, preserve all other saved pool configuration, and only change future
blocks after a restart. Stop and restart always use the pool's authenticated,
ledger-preserving graceful-shutdown request; they never force-kill the pool.

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

## Bonus reserve

A sponsor (for example the Common Foundry stewardship fund) can fund a mining
bonus on a community pool. The bonus is pool-local accounting: it changes no
consensus rule and no wire message. The operator starts `pool-serve` with
`--pool-bonus-rate-bps N` (1 to 10000) and `--pool-bonus-sponsor KEY`, the
sponsor's 64-hex x-only key; both are required together, and the sponsor must
differ from the pool's own block-reward destination. The service launcher reads
the same values from `bonus_rate_bps` and `bonus_sponsor` in `pool.json`.

The sponsor funds the reserve by sending CMFD from that key to the pool's
wallet key, the `block_reward_destination` printed at startup. A transaction
counts once it has at least six confirmations, when it has an input signed by
the sponsor key, no input signed by the pool wallet key, and outputs locked to
the pool wallet key that are spendable at their block's height (a time-locked
output never funds the reserve); the sum of those outputs is added to the
reserve. Each funding transaction is registered once by its txid, so
rescanning the same heights never double-counts, and the ledger keeps at most
4096 funding transactions: a transfer beyond that is logged and skipped, so
fund in a few large transfers. The pool looks for sponsor transfers 64 heights
per tick and records how far it has scanned in the ledger. When the bonus is
first enabled the scan starts at the current tip, so fund the reserve after
that start, or pass `--pool-bonus-scan-from-height H` (`bonus_scan_from_height`
in `pool.json`) with the funding block's height; that flag only applies while
the ledger has no scan mark yet. Once a mark exists the flag is ignored and
the pool logs a warning at startup when the mark is already at or above it; a
transfer below the mark is never registered. Enabling the bonus writes bonus
fields into the pool ledger, which from then on loads only with this release
or later; keep that in mind before rolling `pool-serve` back.

At maturity each miner's net PPLNS allocation (after the operator fee) earns
`floor(allocation × rate / 10000)` extra atoms from the reserve. No operator
fee is taken from the bonus. When the reserve is smaller than the total bonus
the block would earn, the remaining reserve is split across the allocations in
proportion to their bonus with deterministic largest remainders, so the sum
paid is exactly the reserve, and later blocks earn no bonus until the sponsor
tops it up. Bonus credit is ordinary credit: it adds to the miner's balance,
counts in the 24-hour earnings, and is paid by the normal payout transactions.

The reserve stays in the pool wallet, so payout protection counts those coins
as ordinary wallet assets; it does not treat the unspent reserve as a
liability. If a registered funding transaction is reorganized away, the
reserve is not reversed (a transaction mined again under the same txid is not
registered twice): the wallet simply holds fewer coins than
`bonus_reserve_atoms` says, and the loss surfaces only through the ordinary
payout funding checks, once outstanding credits exceed the mature wallet
funds, and only after payout protection has been armed by an earlier incident.
After a deep reorganization compare the reserve with the wallet balance and
ask the sponsor to fund again.

Pass the same `--pool-bonus-rate-bps` to `pool-payout-status` and
`pool-payout-reconcile`. Those offline commands distribute any pool block that
reached maturity while the pool was stopped, once; without the rate such a
block earns no bonus, and a distribution is never repeated.

The dashboard shows the bonus next to the operator fee (`bonus_rate_bps`,
`bonus_sponsor`, `bonus_reserve_atoms`, `bonus_funded_atoms` and
`bonus_credited_atoms` on the pool snapshot) with a Bonus column in the block
table (`bonus_atoms` per block). The ledger snapshot printed by
`pool-payout-status` carries the lifetime `bonus_funded_atoms`,
`bonus_credited_atoms`, the current `bonus_reserve_atoms`, the
`bonus_scanned_height`, the registered `bonus_funding` transactions and
`bonus_atoms` per payout key.

## Persistence and backups

Stop the pool before backing up `pool-data` and `pool-tls`. The TLS private key
and node wallet key are operator secrets. Restoring both directories preserves
the advertised certificate pin, pool identity, chain, credits, and payout
journal. The large `inputs` directory can be downloaded and verified again.

A payout reserved in the journal remains reserved during a temporary mempool
input conflict. Reconciliation retries that exact signed transaction after the
conflict clears; it must not release the credit and generate a replacement merely
because another unconfirmed transaction is using the same input.

The ledger keeps, for each payout, the chain tip it was created at and either
where it was found (block height and identifier) or the tip it was last
absent through, so creating a payout or restarting the pool no longer sweeps
the chain: a confirmed payout whose block is still on the active chain is
verified without reading a block, and an unconfirmed one is looked for only
in the blocks added since the last check. A reorganization does not reopen
the chain either: a kept position whose block was replaced still bounds the
lookup at the fork point, so only the blocks of the new branch are read. A
pool upgraded from an older build should expect one sweep for each payout
recorded before this build that is still unconfirmed at its first check, or
whose block is replaced before that check; it runs during the startup
reconciliation, or on the reconcile thread afterwards when the node was still
catching up with the ledger at startup. After it, those records are bounded
too.

Reconciliation after a chain tip change (pool block states, bonus funding,
payout states and new payouts) runs on its own `cmfd-pool-reconcile` thread.
The listener and share threads only note the new tip and hand out the new
job, so miner connections and share results are never blocked by a block
read or a ledger write.

The shared source now persists payout holds when an already-distributed PPLNS
reward loses mature canonical backing. Earned credits and signed-payment
reservations are preserved; affected new payments/retries pause, and a shared
funding shortfall pauses all automatic payouts. Restart or restored backing does
not clear a hold. Offline `pool-payout-status` and `pool-payout-reconcile` commands
provide exact-tip/generation and funding-checked operator recovery without
sending payments; the status report also lists the next automatic payout run
as a dry run. See [the operator procedure and storage restrictions](pool-deep-reorg-policy.md).
This source change still requires packaging/rehearsal and an authorized upgrade;
it has not changed the running RC pool.

Each start writes a timestamped log under `pool-data/logs`; the status command
prints the active log path. A clean shutdown preserves the ledger. On the next
start, authenticated inputs and saved operator settings are reused, and the
persistent workers are prepared again before miner connections open. If a host
loses power, stale process state is discarded only after its saved process ID
and start identity are shown not to be running.
