# Private Devnet-0

Devnet-0 is a bounded multi-node consensus, fork-choice, persistence, mempool,
and synchronization harness. It is not a public testnet and must not carry
value. RPC is restricted to loopback addresses. P2P listeners and explicitly
configured static peers may use loopback or private IP addresses.

The network uses the tiny ForgeMatrix v2 reference profile. Its proof is
compact on the wire, but every validator recomputes all four tiny-model layers.
This is not a succinct or production proof, and the production v2 profile
remains disabled.

## Consensus identity and data directories

Every peer handshake binds the full network ID and immutable consensus
fingerprint. That fingerprint includes the current emission schedule:

- the 500 CMFD launch subsidy decreases linearly for 2,628,000 blocks, which is
  nominally five 365-day years at the 60-second target;
- pre-tail blocks pay 70% to the miner, 25% as an immediately spendable
  steward award, and 5% as an immediately spendable community fund;
- scheduled pre-tail emission totals 657,000,249.98688 CMFD;
- the final declining reward is 0.00019025 CMFD at height 2,628,000;
- the permanent 5 CMFD miner-only tail begins at height 2,628,001, so the
  intentional boundary jumps from 0.00019025 CMFD to 5 CMFD; and
- every transaction and channel-close fee is burned.

See [consensus/emission.md](consensus/emission.md) for the exact integer formula
and rounding rules. The five-year duration is height-based; wall-clock duration
depends on achieved block cadence.

Data directories created with an earlier consensus fingerprint, including the
former emission schedule, are rejected by design. Do not delete or rewrite an
old directory to force it open. Keep it for inspection and give the current
binary a fresh empty path, such as `.\devnet-0-linear5y\node-a`. Each running
process also needs its own data directory.

A persistent `node.lock` file inside each directory is normal. The file records
the current PID for diagnostics, while a nonblocking OS-level exclusive lock on
its open handle is authoritative. Process exit, including hard termination,
releases that OS lock; an unlocked file is refreshed on the next open. Do not
delete `node.lock` merely because it remains on disk.

## Build and run one node

From Windows PowerShell in the repository root:

```powershell
Set-Location C:\Source\CommonFoundry
cargo build -p cmfd-node --locked

.\target\debug\cmfd-node.exe `
  --data-dir .\devnet-0-linear5y\node-a `
  run `
  --bind 127.0.0.1:18443 `
  --p2p-bind 127.0.0.1:18444
```

The defaults are data directory `commonfoundry-devnet0`, RPC
`127.0.0.1:18443`, and P2P `127.0.0.1:18444`. Explicit paths and ports are
recommended so that adding peers cannot accidentally reuse state or a socket.

The offline commands open, replay, and exclusively lock their selected data
directory:

```powershell
# Mine, validate, persist, and apply one block, then exit.
.\target\debug\cmfd-node.exe --data-dir .\devnet-0-linear5y\offline mine-once

# Replay the complete block log and print status, then exit.
.\target\debug\cmfd-node.exe --data-dir .\devnet-0-linear5y\offline status
```

`mine-once` pays this data directory's test wallet unless a valid x-only
Schnorr public key is supplied, as 64 hex characters or as a checksummed
`tcmfd1...` address:

```powershell
.\target\debug\cmfd-node.exe `
  --data-dir .\devnet-0-linear5y\offline `
  mine-once `
  --miner <64-hex-key-or-tcmfd1-address> `
  --attempts 1000000
```

Only one process may open a data directory. While `run` owns it, use RPC rather
than the offline `status` or `mine-once` commands.

## Run the local wallet

The native wallet owns an embedded Devnet node, its data-directory lock, and
the default P2P listener. Stop any separate node using `127.0.0.1:18444`, then
run:

```powershell
Set-Location C:\Source\CommonFoundry\apps\wallet
npm ci
npm run desktop:dev
```

The native window calls a bounded Tauri IPC allowlist. It does not start the
HTTP RPC listener on `18443`. Its chain data is kept in the operating system's
application-data directory under `org.commonfoundry.wallet.devnet/devnet-0`,
rather than the command-line node's working-directory default.

For browser development, leave a command-line node running on its default RPC
address and use `npm run dev` instead. Open <http://127.0.0.1:5173>. Vite maps
the wallet's `/rpc` requests to `http://127.0.0.1:18443`, removing the `/rpc`
prefix. This keeps the node loopback-only and does not add permissive browser
CORS headers.

The GUI uses the node's active chain and mempool rather than sample data. It
shows balances and transaction history, displays and copies the receive
destination, signs and submits sends, and can run a continuous, cancellable
Solo or Pool miner against the tiny reference profile. An optional CUDA backend
accelerates its exact INT8 matrix stage on one supported NVIDIA GPU; Rust
recomputes every below-target candidate before it is submitted or credited. Its
reported rate is complete ForgeMatrix nonce evaluations per second, not raw GPU
TOPS, and the software does not prove physical GPU or VRAM use. See
[ForgeMatrix v2 CUDA miner](cuda-miner.md). Transaction fees are burned. Mined rewards remain immature for 100 confirmations and cannot be
spent or consolidated before then.

The Overview displays wallet balances rounded to two decimal places while
transaction construction and confirmation retain the full eight-decimal atom
precision. The Network page shows recent inbound and outbound peer sessions,
their reported heights and tips, reachability, and success/failure counts. Peer
observations are bounded runtime telemetry and reset when the node restarts.

The standalone multi-GPU miner connects directly to this node's P2P address.
Normal `cmfd-miner mine` mode does not run or synchronize another node: it asks
the wallet/node for a complete template tied to the miner's receive address,
searches that immutable challenge, and submits the completed block for ordinary
validation. The node remains responsible for chain sync, mempool selection,
durable storage, and fork choice. See
[Standalone CUDA miner](standalone-miner.md) for launcher and failover details.

The Pool mode connects to the CMFD Devnet pool v2 protocol. Enter a URL in the
exact form `cmfd+tls://NUMERIC_IP:PORT?pin=64_HEX` and a worker name matching
`[A-Za-z0-9._-]{1,32}`. Loopback, private, and public numeric IP addresses are
accepted; DNS names are rejected. A pool server refuses public source
addresses by default and must opt in with `--allow-public-pool-clients`.
This is a CMFD-specific TLS 1.3 protocol, not Bitcoin Stratum. The embedded
wallet signs the pool's fresh connection challenge, binding its receive key,
worker name, network identity, and consensus fingerprint without sending the
private key.

For miner wallet hygiene, **Transactions -> Consolidate mining outputs**
combines eligible outputs into one self-owned output. The node deterministically
selects mature, unreserved outputs smallest-first, with a requested maximum of
2 through 128 inputs. The selected fee is burned, and unconfirmed transactions
reserve their inputs; mine the current consolidation before submitting the next
batch.

Each new data directory creates a distinct unencrypted Schnorr test key in
`wallet.key`. Stop the node before backing up that exact 32-byte file and never
share it. Unix creation requests mode `0600`; Windows relies on the containing
directory's ACLs. An existing nonempty Devnet-2 directory retains the old
source-visible demonstration key during migration so its prior test outputs do
not become stranded. Neither mode provides encryption, mnemonic recovery,
hardware-wallet integration, or production custody; never send either real
value.

The packaged wallet can also connect its embedded node to static P2P peers.
Open **Network -> Configured peers** to add a numeric peer IP, remove a peer, or
restore the community bootstrap. A missing port defaults to `18444`; changes
apply immediately and persist across wallet restarts. Command-line operators
can still supply repeatable `--peer` values; numeric public command-line peers
require the explicit `--allow-public-peers` option. See
[../apps/wallet/src-tauri/README.md](../apps/wallet/src-tauri/README.md) for the
exact Windows and Linux command-line options.

## Run a local pool

Build `cmfd-node` as above. From the repository root, create a fresh TLS
certificate and private key. The command uses create-new semantics and refuses
to overwrite either output:

```powershell
New-Item -ItemType Directory -Force .\devnet-0-linear5y\pool-tls | Out-Null

$certificateInfo = .\target\debug\cmfd-node.exe pool-certificate `
  --certificate .\devnet-0-linear5y\pool-tls\pool-cert.der `
  --private-key .\devnet-0-linear5y\pool-tls\pool-key.der |
  ConvertFrom-Json

$certificateInfo
$poolUrl = "cmfd+tls://127.0.0.1:18445?pin=$($certificateInfo.certificate_sha256)"
$poolUrl
```

The certificate is public. Keep `pool-key.der` and the pool data directory
restricted to the pool operator account, and give miners only the printed
certificate SHA-256 pin, never the private key. On Unix the generator creates
the private-key DER with mode `0600`; on Windows it relies on the containing
directory's ACLs, so create or select a directory whose ACL grants access only
to the operator. Start the pool in a second PowerShell window:

```powershell
Set-Location C:\Source\CommonFoundry

.\target\debug\cmfd-node.exe `
  --data-dir .\devnet-0-linear5y\pool `
  pool-serve `
  --bind 127.0.0.1:18445 `
  --p2p-bind 127.0.0.1:18454 `
  --peer 127.0.0.1:18444 `
  --certificate .\devnet-0-linear5y\pool-tls\pool-cert.der `
  --private-key .\devnet-0-linear5y\pool-tls\pool-key.der `
  --share-leading-zero-bits 7 `
  --enable-testnet-payouts `
  --pool-minimum-payout-atoms 100 `
  --pool-payout-fee-atoms 1
```

Paste the printed `$poolUrl` into **Mining -> Pool**, choose a worker name such
as `rig-01`, and start mining. The default bind is `127.0.0.1:18445`; remote
testing requires an explicit private bind such as `192.168.50.20:18445`.
Miners on that LAN use the private numeric IP. A public pool forwards its public
TCP port to that private bind and advertises the public numeric IP with the same
certificate pin. Add `--allow-public-pool-clients` on a public pool; the native
ProductionV4 launchers supply it automatically. Hostnames are deliberately not
accepted.
`--share-leading-zero-bits` may be 0 through 7 on Devnet-0 and defaults to 7;
smaller values make test shares easier. If `--miner` is omitted, blocks pay the
pool node data directory's wallet destination. A supplied `--miner` must be an
x-only Schnorr public key: 64 hex characters or a checksummed `tcmfd1...`
address.

ProductionV4 operators may add `--pool-dashboard-assets <built-dist>` and
`--pool-public-url <exact-pinned-url>` together. The read-only dashboard binds
to loopback by default at `127.0.0.1:22446`; use a reverse proxy or tunnel to
publish the GUI without exposing a second unauthenticated node control surface.
Native Linux and Windows/WSL2 launchers are documented in
`production-v4-pool.md`. On the current ProductionV4 Devnet, the pool defaults
to a seven-leading-zero-bit share target, one bit easier than the block target.
The wallet searches server-issued jobs with persistent batched CUDA, and the
pool performs the exact authenticated replay itself before accepting or
crediting a nonce; it does not trust client-reported work.

`pool-serve` owns its selected data directory and starts the TLS pool plus a P2P
inbound listener and optional static-peer poller on the same node; it does not
start RPC. Its P2P default is `127.0.0.1:18444`, so the command above assigns
`18454` to avoid colliding with the wallet and polls the wallet on `18444`.
`--peer` is repeatable and uses the same private-address checks as `run`.
For bidirectional block synchronization, launch the packaged wallet with
`--peer 127.0.0.1:18454` as described in the desktop peer README linked above.
That one static link pulls pool blocks into the wallet and offers wallet blocks
back to the pool node; a reciprocal entry is not required.

### Pool protocol and accounting boundary

The transport is TLS 1.3 with 4-byte big-endian length-prefixed, bounded JSON
messages. The wallet authenticates the server by SHA-256 hashing the exact
leaf-certificate DER bytes and comparing all 32 bytes with the URL pin. The
certificate's handshake signature is still verified. There is no certificate
authority lookup, client certificate, or automatic pin distribution, so
transfer and verify the pin through a separate trusted path. After TLS
connects, the server sends a fresh random challenge. The wallet signs a
domain-separated digest of the challenge, network, consensus fingerprint,
worker label, and payout key, proving control of that receive key for the
session. TLS protects the pool socket only; Devnet P2P remains a separate
unencrypted, unauthenticated protocol.

The authenticated client hello commits to pool protocol v2, network ID,
consensus fingerprint, worker label, payout key, and the challenge signature.
The server then returns a session ID and a job containing an immutable
`BlockChallenge`, a distinct easier share target, and a server-issued job ID.
A worker that reconnects with the same worker label and payout key gets its
previous session back, counters included, while no connection of that session
is open; only a new worker and payout pair adds a session record. A
share submission contains only that job ID and a nonce. It does not contain a
trusted work digest or proof.

For every submitted nonce, the server independently evaluates the exact
committed ForgeMatrix relation and obtains its work digest without applying a
target. It then compares the recomputed digest separately with the share target
and with the chain target already committed inside `BlockChallenge`. The share
target must be easier than or equal to the chain target and never replaces or
mutates it. A share-only result cannot construct a block. If the digest also
meets the original chain target, the server reconstructs the block and passes
it through ordinary node submission and consensus validation.

Stale jobs, duplicate nonces, low-difficulty shares, malformed or oversized
frames, excess connections, and configured job/session/ledger limits are
rejected. Frames are capped at 16 KiB, with at most 64 concurrent sessions,
1,000,000 messages per session, 65,536 valid nonce records per job, 1,024 recent
session records, 1,024 payout identities, 65,536 pool-block records, and 65,536
payout-transaction records. Every payout identity proves key control through a
fresh Schnorr challenge. Accepted shares enter a durable exact-work-weighted
PPLNS history. A found block freezes its discovery-time rolling window, actual
miner reward, and operator fee; the default window is one expected block of
share work and the default fee is 300 basis points. After 100 confirmations,
the fee is retained by the pool wallet and every remaining atom is distributed
deterministically across the frozen window. A network-bound, checksummed
two-slot ledger survives process restarts, migrates authenticated v1
accounting, recovers interrupted block accounting exactly once, and labels pool
blocks canonical, orphaned, or unresolved as fork choice changes. Valid pool
blocks send the miner reward to the server's `--miner` destination.

`--enable-testnet-payouts` activates mature-reward settlement and requires
`--miner` to be this pool node's wallet destination. The default threshold is
100 earned atoms and the default burned fee is one atom. The pool reserves
credit only after durably journaling the exact signed transaction, rebroadcasts
prepared transactions after restart, records confirmations from the active
chain, and releases credit when a reorganization invalidates its inputs. RCNet
qualification next adds verification-queue stress testing, load and fuzz
coverage, independent interoperability testing, and external review.

Share replay has a separate bounded admission gate. The defaults run one
verification at a time and queue eight authenticated shares for up to five
seconds; overflow returns `share_verifier_busy` so miners can retry. Each
session can burst eight submissions and then refills at four per second. The
pool accepts eight connections per source by default (configurable up to 16),
and four objective protocol or authentication failures inside one minute apply
one minute of source backoff. The source table is capped at 1,024 entries.
Operators can tune the verifier admission bounds with
`--pool-max-connections-per-source`,
`--pool-max-concurrent-share-verifications` and
`--pool-max-queued-share-verifications` without changing consensus.

A ProductionV4 pool can also check shares in GPU batches. By default each
share is replayed on its own. With `--pool-share-batch-size N` (2 to 64), a
batch thread collects shares and replays up to N of them in one call to the
persistent replay worker. A batch runs once N shares are waiting, or once its
oldest share has waited `--pool-share-batch-wait-ms` (default 100, at most
1000). Each share still gets its own exact work digest, and a share that meets
the chain target is replayed in full and proved exactly as before. While
batching is on, up to N plus `--pool-max-queued-share-verifications` shares
may wait; beyond that the pool answers `share_verifier_busy`. Batching is
local to the pool: miners, the protocol and consensus are unchanged. With the
fused replay worker a batch of 8 checked about 35 shares per second on an
RTX 4090 against about 8 one at a time, and about 15 on an RTX 5070 Ti against
about 6; larger batches gained less. With older replay workers, batches above
2 are slower, so measure on your verifier GPU.

A pool with several GPUs can check shares on all of them. Each
`--production-v4-pool-replay-gpu <device>` (a CUDA device index or GPU UUID,
repeatable) starts one replay worker pinned to that GPU, and the batch threads
take batches from one queue, so the workers run side by side. A batch whose
replay worker fails outright is handed to the next worker once before its
shares are rejected (with one worker, to the same worker after its restart);
a batch that ran into the worker deadline is not retried. The proof worker
and single-share replays stay on the pool's own GPU. Omitting the flag keeps
one replay worker on the pool's GPU; it is not available under WSL. Every
replay worker loads the model bank on its GPU, so each listed GPU needs the
replay worker's memory, and startup takes about as long as one model load.

The pool ledger is written as one JSON snapshot, and the node refuses to load
or write a snapshot above `--pool-ledger-max-bytes` (default 64 MiB) so a
corrupt or runaway file cannot exhaust memory. A pool with thousands of
sessions and payout cards outgrows the default; raise the limit (1 MiB to
1 GiB) on `pool-serve`, and pass the same value to `pool-payout-status` and
`pool-payout-reconcile`, which open the same ledger offline. A snapshot above
the limit fails startup with a message naming the file size and the flag.

## Run two or three local nodes

Build once, then run each command in a separate PowerShell window. The fully
connected static topology makes block and transaction propagation
bidirectional even though each node initiates its own pull sessions.

```powershell
# Terminal A
Set-Location C:\Source\CommonFoundry
.\target\debug\cmfd-node.exe --data-dir .\devnet-0-linear5y\node-a run `
  --bind 127.0.0.1:18443 --p2p-bind 127.0.0.1:18444 `
  --peer 127.0.0.1:18454 --peer 127.0.0.1:18464

# Terminal B
Set-Location C:\Source\CommonFoundry
.\target\debug\cmfd-node.exe --data-dir .\devnet-0-linear5y\node-b run `
  --bind 127.0.0.1:18453 --p2p-bind 127.0.0.1:18454 `
  --peer 127.0.0.1:18444 --peer 127.0.0.1:18464

# Terminal C
Set-Location C:\Source\CommonFoundry
.\target\debug\cmfd-node.exe --data-dir .\devnet-0-linear5y\node-c run `
  --bind 127.0.0.1:18463 --p2p-bind 127.0.0.1:18464 `
  --peer 127.0.0.1:18444 --peer 127.0.0.1:18454
```

Peers that are not running yet do not prevent startup; the static poller tries
again every two seconds. For a two-node network, omit Terminal C and its
`--peer 127.0.0.1:18464` option from A and B. `--peer` is repeatable, and the
listener rejects public addresses unless `--allow-public-peers` is present. It
always rejects unsafe/unspecified addresses, duplicate peers, and its own
address.

Each two-second peer poll performs the compatibility handshake, pulls at most
16 blocks first, then requests the remote mempool inventory and at most 64
unknown transaction bodies. Every returned body must match its advertised ID
and pass the node's normal consensus and mempool admission rules. After pulling,
the same static link offers bounded locally active block batches following the
peer's advertised tip. Each submitted block receives an accepted, already-known,
or rejected acknowledgement after the receiving node's normal validation path.
Transactions remain pull-only; there is no general gossip broadcast.

## Run a small direct-IP test network

This is the simplest Windows-hub/Linux-tester layout. Public connections use
the explicit `--allow-public-peers` option.

For the community Devnet, the current bootstrap endpoint is:

```text
107.214.187.2:18444
```

Start a packaged wallet with
`--allow-public-peers --peer 107.214.187.2:18444` to follow it. The endpoint is
best-effort and may change between Devnet releases; the release announcement
and community test issue are the authoritative current values.

1. On the Windows router, forward **TCP 18444 only** to the Windows computer's
   private LAN address. Do not forward RPC port 18443.
2. Allow inbound TCP 18444 through Windows Firewall on the intended profile.
3. Start the Windows wallet from PowerShell, replacing the executable path and
   LAN address:

```powershell
& 'C:\path\to\common-foundry-wallet.exe' `
  --p2p-bind 192.168.1.50:18444 `
  --allow-public-peers
```

4. Give each Linux tester the Windows router's public IP. They start the
   AppImage with:

```bash
chmod +x Common-Foundry-Wallet.AppImage
./Common-Foundry-Wallet.AppImage \
  --allow-public-peers \
  --peer PUBLIC_IP:18444
```

The Windows wallet can now Solo mine and the Linux wallets will synchronize its
blocks on their regular peer poll. Compare block height, tip, and cumulative
work on the Network page. That same configured connection offers independently
mined Linux blocks back to the hub. Testers do not need to forward a port merely
to follow or mine through the hub.

`--allow-public-peers` does not add peer identity, encryption, discovery,
automatic bans, reputation, or demonstrated DDoS resistance. Stop the public
listener after the bounded test, never expose RPC, and never use this mode with
valuable funds.

## Optional isolated proof verification

The node can verify externally received Devnet blocks in a persistent contained
child instead of inside the long-running process. This remains optional for
Devnet. The same `cmfd-node` executable can act as its own hash-pinned worker,
so no additional binary is required. The worker completes its startup identity
self-test once and then serves canonical requests sequentially.

On Windows PowerShell:

```powershell
$worker = (Resolve-Path .\cmfd-node.exe).Path
$workerHash = (Get-FileHash -Algorithm SHA256 $worker).Hash
.\cmfd-node.exe `
  --proof-verifier-worker $worker `
  --proof-verifier-worker-sha256 $workerHash `
  --proof-verifier-timeout-ms 30000 `
  --proof-verifier-memory-bytes 2147483648 `
  run --allow-public-peers
```

On Linux:

```bash
worker="$(readlink -f ./cmfd-node)"
worker_hash="$(sha256sum "$worker" | cut -d ' ' -f 1)"
./cmfd-node \
  --proof-verifier-worker "$worker" \
  --proof-verifier-worker-sha256 "$worker_hash" \
  --proof-verifier-timeout-ms 30000 \
  --proof-verifier-memory-bytes 2147483648 \
  run --allow-public-peers
```

Startup fails if the path is not absolute, the hash does not match, or either
limit is zero. Node status reports `external_worker` plus the active limits.
The node runs a private synchronized copy and rechecks its hash before every
process generation. Timeout, crash, malformed or oversized output, and response
substitution kill that generation and fail the current verifier request; a
later request must pass startup again. Replacement startup and authentication
run in one single-flight supervisor outside the peer request. A failed
replacement keeps that single-flight state through a bounded one-second
backoff so peer retries cannot create a process-spawn storm. While the
supervisor is running, or after its attempt is unavailable, block submissions
receive the retryable `Busy` result; a request never waits through the
900-second startup limit. The worker becomes admissible again only after its
full authenticated handshake succeeds. Invalid proofs receive `Rejected`
without restarting a healthy generation. Devnet keeps its V2 verifier and
never opts into V3 merely because an external worker was configured.

### P2P `SubmitBlock` timeout and admission contract

Mining and relay clients use a dedicated 120-second response budget for
`SubmitBlock`; the ordinary 10-second peer idle timeout does not apply while
waiting for `BlockSubmissionResult`. The receiving node stops authoritative
acceptance at 110 seconds and permits no response write at or after 115
seconds. Those two five-second margins reserve bounded time for durable commit,
response serialization, scheduling, and transport before the client deadline.
The same 110-second server-owned deadline follows the request through FIFO
admission, proof dispatch, reconstruction, and an atomic pre-append
linearization point. Cancellation/deadline and commit race through one shared
`Active -> Cancelled | Committing` state. `Cancelled` can never append. A
post-CAS clock recheck relinquishes `Committing` to `Cancelled` if the deadline
expired across the transition; otherwise append, synchronization, and state
commit must complete or latch the node storage-faulted. The 115-second cutoff
also bounds acquisition
of the node-status lock, response serialization, and every response write; a
late response writes no new frame bytes and the connection fails closed.

Production-profile remote proof work has a hard cap of eight sessions across
the active request and FIFO waiters. Its admission wait is at most 60 seconds.
The shared verifier then permits one active proof and at most eight normal
waiters with a five-second queue wait; locally found blocks use a separate
two-waiter priority lane. Every wait and the worker request are additionally
bounded by the request's remaining 110-second lifetime. Cached proofs still
take their FIFO turn, but do not dispatch the expensive relation again.

Capacity exhaustion, admission or request deadline expiry, and an unavailable
or restarting worker return `Busy`. Miners must retain and retry the exact
block/proof while a compatible peer still reports its parent as the active
tip; they must not fetch a fresh template solely because of `Busy`. The
standalone miner retries across reconnects for one interruptible 20-minute
total budget, then records an abandonment; a changed tip records a distinct
stale submission. A cryptographically invalid proof returns `Rejected`;
duplicates return `AlreadyKnown`. Shutdown is polled during bounded connect
attempts and throughout hello, submission-write, and response-read I/O.
Submission disconnects and peer protocol errors (including malformed frames
and wrong response IDs) have separate miner counters; neither is counted as a
cryptographic rejection. Node status reports each admission class as
`proof_verification_normal_admission`,
`proof_verification_priority_admission`, and
`proof_verification_remote_admission`, with `active`, `queued`, `wait_events`,
`rejections`, and `proof_failures`. It also reports
`proof_verification_remote_admission_capacity` and
`proof_verification_remote_admission_wait_timeout_ms`. External-worker status
also exposes `proof_verification_teardown_failures`; this counter can rise while
the original request classification remains unchanged. Rejections count work
refused before verifier dispatch; proof failures count invalid or faulted
requests after dispatch, so operators can distinguish saturation from proof or
worker faults.

## Loopback RPC

The first node above uses `http://127.0.0.1:18443`.

| Method | Endpoint | Result |
|---|---|---|
| `GET` | `/health` | Storage health and Devnet identity |
| `GET` | `/v1/status` | Fingerprint, active tip, cumulative work, target, UTXO count, and mempool totals |
| `GET` | `/v1/mempool` | Ordered transaction IDs, encoded sizes, burned fees, and pool totals |
| `GET` | `/v1/wallet` | Data-directory wallet destination, active-chain balances, output counts, mempool state, and history |
| `GET` | `/v1/template?miner=<64-hex-key-or-tcmfd1-address>` | JSON template containing the current mempool transactions and exact burned fees |
| `POST` | `/v1/wallet/send` | Sign and admit a test-wallet send from JSON `recipient`, `amount`, and `fee` fields |
| `POST` | `/v1/wallet/consolidate` | Consolidate mature, unreserved test-wallet outputs from JSON `fee` and `max_inputs` fields |
| `POST` | `/v1/transaction` | Admit one canonical raw transaction to the volatile mempool |
| `POST` | `/v1/mine?miner=<64-hex-key-or-tcmfd1-address>&attempts=<1..1000000>` | Build, mine, validate, persist, and apply one block; body must be empty |
| `POST` | `/v1/block` | Validate, persist, and index one canonical raw block |

The wallet routes (`/v1/wallet` and everything under `/v1/wallet/`),
`/v1/mine`, `/v1/transaction` and `/v1/block` are local-only, because they read
the node wallet or change node state. They answer only when the `Host` header
names this machine: an IPv4 literal in `127.0.0.0/8`, `[::1]` or `localhost`, in
any case and with any port. A browser `Origin` header, when present, must be an
`http` or `https` loopback origin (`null` is refused), and
`Sec-Fetch-Site: cross-site` is refused. Anything else, including a missing or
repeated `Host`, gets `403 Forbidden` with a JSON `error`. This stops a web page
that re-resolves its own hostname to 127.0.0.1 (DNS rebinding) from reading or
spending the node wallet or submitting to the node. curl, PowerShell, Python
`urllib` and the wallet's Vite proxy already send a loopback `Host` for
`127.0.0.1` URLs. The public reads (`/health`, `/v1/status`, `/v1/mempool`,
`/v1/template` and the `/v1/explorer` paths) ignore these headers, so the
explorer can still reach its read paths through a tunnel that forwards its
public hostname. HTTP/1.0 requests are rejected with `400` on every route.

Wallet send and consolidation requests require the
`Content-Type: application/json` header; CMFD amounts are decimal strings with
at most eight decimal places. Canonical transaction and block submissions
require
`Content-Type: application/octet-stream`. Their body limits are 64 KiB and
1 MiB respectively. Template JSON is descriptive; `/v1/block` accepts the
canonical binary block frame, not that JSON.

From 1.0.16, on a network with a work rule, nodes independently re-execute each
block's work before they accept it, and `/v1/status` carries a `work_rule`
object (`null` on a network without one). Its `validated_height` is the height
up to which every active block has been checked; `unsettled_height` and
`unsettled_block_id` name the stored block just above it when one engine found
its work does not match and nothing has settled it; `backlog_paused` is true
while the check of stored blocks is paused (a laptop on battery); `halted` and
`engine_state` report whether blocks are admitted at all. `bank` says whether
the CPU engine holds the model bank in memory (`resident`), so a block's check
reads no disk, or reads it from the bank file for each block (`streamed`).
`run --work-bank` chooses: the default `auto` holds it resident (about 6 GiB)
when the memory available leaves 2 GiB beside it. On Linux, available memory
also counts the limits of the node's cgroups (a container's memory limit or a
systemd `MemoryMax=`), so a node limited to less than about 8 GiB streams.
Within a limit, file cache the kernel counts as active (for example the bank
pages the node just read) counts as used, so `auto` may stream even where the
limit leaves room; set `--work-bank resident` on such a host instead.
`pool-serve` streams it unless `--work-bank` says otherwise; the desktop
wallet always streams it. `--work-bank resident` refuses to start, naming
memory, when the bank cannot be allocated; on Linux with memory overcommit the
allocation may succeed anyway and the kernel's out-of-memory killer then acts,
so force it only on a host known to have the room. The resident copy is
ordinary memory, not locked: on a host with swap it can be paged out under
memory pressure, so keep swap off or `vm.swappiness` low on servers that rely
on it, and prefer hosts with ECC memory. If a held byte changes in memory,
the node's re-execution mismatches and it refuses blocks until its next
known-answer round, which checks the held layers, takes the engine out of
service. Loading it reads and checks the whole bank a second time at startup,
after the read the node does when it opens; on a slow disk with a cold cache
that adds about a minute before the node serves anything.

`/v1/wallet` reports the same `validated_height`, a `balances.verifying_atoms`
total and a
`verifying_utxo_count` for coins in blocks above it (the wallet's own change
is not among them: it can be spent at once). History entries in those blocks
read `verifying`, except payments the wallet sent. `/v1/wallet/send` refuses a
payment that needs those coins with the retryable `wallet_funds_verifying`
(HTTP 422), to retry once the validated height passes them;
`/v1/wallet/consolidate` leaves them out.

The desktop wallet, started with the default `--work-check standard`, catches
up faster after time offline. It takes a block without re-executing its work
only when two Common Foundry relays run by different providers list it, the
block lies at least 60 blocks below the height both report, and it extends the
wallet's own tip; the newest blocks are always re-executed here, and the rest
in the background, lowest first. Its coins become available once at least 60
blocks this computer re-executed sit on top. Such a wallet's `/v1/status`
`work_rule` carries a `wallet_catch_up` object: `state` (`caught_up`,
`catching_up`, `checking_newest`, `waiting_for_check` with a `reason` of
`earlier_blocks`, `difficulty` or `other`, `single_source` while fewer than two
relays can be reached, or `release_stale` once the release's checkpoint block
is more than 60 days old), `available_height`, `blocks_left` (the count the
wallet shows), `newest_checked` of `newest_needed`, `sources_answering`, and
`granted_above_available`, during which Solo mining waits. Its `/v1/wallet`
then carries `available_height`: coins in blocks up to it are spendable, the
rest count as `verifying`, and `validated_height` keeps its meaning. Servers,
pools, relays and a wallet started with `--work-check full` never carry either
field.

A block that only one of the node's engines finds does not match is refused
(`work_mismatch_unconfirmed`) at no cost to its peer. Each peer address (an
IPv6 /64 counts as one) may have at most 2 such refusals in any 10 minutes.
After that, its other blocks that would need a work check are answered as
busy (`work_check_deferred`, retryable) and run nothing until its oldest
refusal is 10 minutes old. This covers blocks a peer sends, blocks a sync
session fetches from it and blocks noted for the background check. The
peer's reputation does not change, it is not held off as a sync target, and
the same block from any other peer is checked as usual. A block's work counts
against the first peer whose copy of it was checked, not against every peer
that relays it. Operator-configured, bootstrap and loopback peers are not
counted. A mismatch that two engines agree on still costs its peer a penalty
and a cooldown.

PowerShell examples while `run` is active:

```powershell
$base = 'http://127.0.0.1:18443'
$wallet = Invoke-RestMethod -Uri "$base/v1/wallet"
$miner = $wallet.destination

Invoke-RestMethod -Uri "$base/health"
Invoke-RestMethod -Uri "$base/v1/status"
Invoke-RestMethod -Uri "$base/v1/mempool"
Invoke-RestMethod -Uri "$base/v1/template?miner=$miner"

$mineUri = "$base/v1/mine?miner=$miner&attempts=1000000"
$mined = curl.exe --silent --show-error --request POST `
  --header 'Content-Length: 0' $mineUri | ConvertFrom-Json
$mined

Invoke-RestMethod -Method Post `
  -Uri "$base/v1/transaction" `
  -ContentType application/octet-stream `
  -InFile .\transaction.cmfd

Invoke-RestMethod -Method Post `
  -Uri "$base/v1/block" `
  -ContentType application/octet-stream `
  -InFile .\block.cmfd
```

The example derives the miner destination from the node's wallet rather than a
hard-coded key. The GUI and wallet RPC sign without returning the private bytes,
but the local file is unencrypted and there is no mnemonic recovery or
production custody. A raw `transaction.cmfd` submitted directly to
`/v1/transaction` must still already be a correctly signed canonical
transaction.

## Multi-node acceptance checks

With all three nodes running, mine on A, wait for at least one two-second poll
round, then compare their live status:

```powershell
$miner = (Invoke-RestMethod -Uri 'http://127.0.0.1:18443/v1/wallet').destination
$mineUri = "http://127.0.0.1:18443/v1/mine?miner=$miner&attempts=1000000"
curl.exe --silent --show-error --request POST `
  --header 'Content-Length: 0' $mineUri | ConvertFrom-Json

Start-Sleep -Seconds 5
$rpcPorts = 18443, 18453, 18463
$statuses = foreach ($port in $rpcPorts) {
  Invoke-RestMethod -Uri "http://127.0.0.1:$port/v1/status"
}
$statuses | Format-Table accepted_height, tip, cumulative_work, mempool_transactions

if (@($statuses.consensus_fingerprint | Sort-Object -Unique).Count -ne 1) {
  throw 'consensus fingerprints differ'
}
if (@($statuses.accepted_height | Sort-Object -Unique).Count -ne 1 -or
    @($statuses.tip | Sort-Object -Unique).Count -ne 1 -or
    @($statuses.cumulative_work | Sort-Object -Unique).Count -ne 1) {
  throw 'nodes have not converged'
}
```

Mine the next block through B's RPC port (`18453`) to check the reverse path.
For restart/replay, stop C, mine additional blocks on A or B, restart C with the
same command and data directory, and confirm the three fields converge again.

If a signed `transaction.cmfd` is available, submit it to A with the RPC example
above. After a poll round, all three `/v1/mempool` responses should contain the
same transaction ID. Mine through B, wait for block convergence, and confirm
that the confirmed transaction is absent from every volatile pool.

For an isolated fork-choice exercise, start A and B without `--peer`, mine a
different branch into each directory, and give one branch strictly more
cumulative work. Restart either one with the other as a static peer. Both must
retain a local tip on equal work and switch only when the competing branch has
strictly greater cumulative work.

## Mempool, fork choice, and persistence

The active-chain mempool is deliberately small and deterministic:

- at most 1,024 transactions and 512 KiB of canonical transaction bytes;
- transaction IDs order the block template;
- every input must already be confirmed on the active chain, so unconfirmed
  parents and package relay are unsupported;
- first admission wins an input conflict;
- the minimum relay fee is one atom per started KiB, and all admitted fees are
  burned when mined; and
- the pool is revalidated after an active-tip change and is not persisted
  across restart.

Static peers advertise mempool transaction IDs in deterministic order. A
polling node skips IDs it already has, downloads no more than 64 unknown bodies
per peer poll, verifies the ID/body binding, and runs each transaction through
the same admission path used by RPC. A malformed or missing response ends only
that peer session; later polling rounds and the inbound listener continue.

Every received block is fully consensus-validated before indexing. Valid side
branches are retained, and the active tip changes only for strictly greater
cumulative work; an equal-work branch does not replace the current tip. The
node stores the immutable consensus fingerprint in `network.meta` and accepted
blocks, including side branches, in an append-only checksummed `blocks.log`.
Startup verifies canonical encodings, checksums, and consensus rules before
reconstructing forks, cumulative work, and the active tip.

Active-chain block validation commits only a touched-state delta rather than
cloning the full UTXO set. Extending a side branch still reconstructs that
branch from genesis. This is simple and auditable for Devnet-0, but is not a
scalable public-network design.

## Current boundary

Devnet-0 keeps peer identity authentication, encrypted P2P transport, NAT
traversal, demonstrated DDoS maturity, and production wallet/key custody as
public-network gates. Its pool ledger and opt-in testnet payouts are durable;
those controls are test infrastructure rather than production custody.
Its local GUI signs with a distinct per-data-directory key on new installs, but
that raw key is unencrypted and has no mnemonic recovery or audited custody.
The pool's pinned TLS server transport does not change the P2P boundary: peer
compatibility checks do not establish who operates the remote process, and
peers never supply the local block-acceptance time. All network-facing use must
remain on an isolated, valueless private network.

The compact v2 proof is also still a full-recomputation reference path. A
production succinct proof, raw-model commitment ceremony/link, independent
implementations, benchmarks, adversarial public testnet, and audits remain
mandatory gates in [../SECURITY.md](../SECURITY.md).
