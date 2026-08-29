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

`mine-once` pays this data directory's test wallet unless a valid 64-character
x-only Schnorr public key is supplied:

```powershell
.\target\debug\cmfd-node.exe `
  --data-dir .\devnet-0-linear5y\offline `
  mine-once `
  --miner <64-hex-x-only-public-key> `
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
exact form `cmfd+tls://PRIVATE_IP:PORT?pin=64_HEX` and a worker name matching
`[A-Za-z0-9._-]{1,32}`. The endpoint must be a numeric loopback, RFC1918 IPv4,
or IPv6 unique-local address; DNS names and public addresses are rejected.
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
  --share-leading-zero-bits 7
```

Paste the printed `$poolUrl` into **Mining -> Pool**, choose a worker name such
as `rig-01`, and start mining. The default bind is `127.0.0.1:18445`; remote
private-LAN testing requires an explicit private bind such as
`192.168.50.20:18445`, and the URL must use that same reachable numeric IP.
`--share-leading-zero-bits` may be 0 through 7 on Devnet-0 and defaults to 7;
smaller values make test shares easier. If `--miner` is omitted, blocks pay the
pool node data directory's wallet destination. A supplied `--miner` must be a
64-character x-only Schnorr public key.

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
authority lookup, client certificate, worker identity proof, or automatic pin
distribution, so transfer and verify the pin through a separate trusted path.
Worker and payout claims are not client-authenticated; session counters are
therefore not identity-secure. TLS protects the pool socket only; Devnet P2P
remains a separate unencrypted, unauthenticated protocol.

The client hello commits to the pool protocol version, network ID, consensus
fingerprint, worker label, and payout label. The server returns a session ID
and a job containing an immutable `BlockChallenge`, a distinct easier share
target, and a server-issued job ID. A share submission contains only that job
ID and a nonce. It does not contain a trusted work digest or proof.

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
session records, 1,024 payout identities, and 65,536 pool-block records. Every
payout identity proves key control through a fresh Schnorr challenge. Accepted
shares increment a durable test counter; the default is one credited Devnet
atom per accepted share. A network-bound, checksummed two-slot ledger survives
process restarts, recovers interrupted block credits exactly once, and labels
pool blocks canonical, orphaned, or unresolved as fork choice changes. Valid
pool blocks send the miner reward to the server's `--miner` destination.
Credited test atoms are accounting units until the on-chain settlement stage is
enabled.

The next pool milestone adds mature-reward settlement transactions. RCNet then
adds verification-queue stress testing, load and fuzz coverage, independent
interoperability testing, and external review.

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
| `GET` | `/v1/template?miner=<64-hex-x-only-public-key>` | JSON template containing the current mempool transactions and exact burned fees |
| `POST` | `/v1/wallet/send` | Sign and admit a test-wallet send from JSON `recipient`, `amount`, and `fee` fields |
| `POST` | `/v1/wallet/consolidate` | Consolidate mature, unreserved test-wallet outputs from JSON `fee` and `max_inputs` fields |
| `POST` | `/v1/transaction` | Admit one canonical raw transaction to the volatile mempool |
| `POST` | `/v1/mine?miner=<64-hex-x-only-public-key>&attempts=<1..1000000>` | Build, mine, validate, persist, and apply one block; body must be empty |
| `POST` | `/v1/block` | Validate, persist, and index one canonical raw block |

Wallet send and consolidation requests require the
`Content-Type: application/json` header; CMFD amounts are decimal strings with
at most eight decimal places. Canonical transaction and block submissions
require
`Content-Type: application/octet-stream`. Their body limits are 64 KiB and
1 MiB respectively. Template JSON is descriptive; `/v1/block` accepts the
canonical binary block frame, not that JSON.

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

Devnet-0 has no public-peer discovery, peer identity authentication, encrypted
P2P transport, NAT traversal, reputation/ban system, demonstrated DDoS
maturity, production wallet/key custody, durable pool payouts, or optimized
GPU miner.
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
