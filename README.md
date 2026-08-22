# CommonFoundry

CommonFoundry (CMFD) is a research-first cryptocurrency implementation built
around ForgeMatrix, a block-bound proof of work whose proposed production
kernel is dominated by signed INT8 x INT8 matrix multiplication with exact
INT32 accumulation.

The [technical white paper](docs/whitepaper.md) explains the motivation,
consensus architecture, monetary policy, ForgeMatrix v2 relation, proposed
succinct proof system, inference-market protocol, threat model, and activation
requirements in detail.

This repository contains the consensus oracle, a seedless v2 model format, the
exact small-profile v2 arithmetic relation, a test-size matrix sumcheck
transcript, Rust/CUDA arithmetic smoke vectors, monetary policy, signed UTXO
validation, chain-derived difficulty, an inference payment-channel state
machine, and adversarial tests. Canonical bounded wire encodings now cover
transactions, tagged v1/v2 proofs, and blocks. Block validation and `ChainState`
are bound to immutable network parameters.

The tagged v2 path accepted by Devnet-0 is deliberately tiny. Its proof is a
compact serialized claim, but every verifier recomputes every model layer. It
is **not** a succinct proof or a production verifier, and the production-sized
v2 profile remains disabled. A production transparent PCS, complete succinct
proof, model-link certificate, soundness analysis, benchmarks, independent
implementations, adversarial public testnet, and two audits are still required;
the full gates are in [SECURITY.md](SECURITY.md).

The optional `remainder-prototype` feature is a complete proof experiment for
the tiny 2x4x4 relation, not an activated block proof. Its measured transcript
is about 302.7 MB and takes about 123 seconds to verify, so the generic backend
has been rejected for production use. It remains useful only for checking that
the proposed matrix, transition, range, block, nonce, target, and output
bindings are expressible end to end.

## What ForgeMatrix proves

ForgeMatrix v1 evaluates a fixed, committed sequence of dense integer matrices.
Every layer consumes the prior layer, applies a block-specific nonlinear mask,
and feeds the next layer. The final activation digest is bound to the previous
block, transaction Merkle root, height, timestamp, target, model root, and
nonce.

The reference verifier recomputes the complete function. It does not trust a
miner-supplied claim that a matrix, output, model, or GPU operation happened.

ForgeMatrix validates the output of the committed matrix relation. It cannot
prove the physical location of those bytes. A miner may keep the model in VRAM,
stream it from host memory, or implement equivalent arithmetic on different
hardware. Resident execution being faster is an unverified design hypothesis,
not a consensus claim.

There is no consensus VRAM minimum. Lower-memory cards can in principle tile or
stream and still mine valid blocks; their speed and complete winner-proof
memory requirements have not been measured. Mining compatibility is separate
from whether a paid inference job fits on the same card.

## Build and test

```powershell
cargo test --workspace
cargo run -p cmfd-consensus -- vector
cargo run -p cmfd-consensus -- economics --height 2628001 --fees 100000
cargo run -p cmfd-consensus -- profile16gb
```

To run the separate CUDA arithmetic smoke tests:

```powershell
.\scripts\test-cuda.ps1 -Version v1
.\scripts\test-cuda.ps1 -Version v2
```

The optional miner backend is a different, batched CUDA path. Build its
Volta and RTX 20/30/40/50-series fat library and run the CPU/CUDA differential
canary with:

```powershell
.\scripts\build-cuda-miner.ps1
```

Intel Arc and other OpenCL GPUs use a second backend library that speaks the
same ABI:

```powershell
.\scripts\build-opencl-miner.ps1
```

See [ForgeMatrix v2 CUDA miner](docs/cuda-miner.md) for the exact trust
boundary, supported architectures, wallet packaging, and tester procedure, and
[ForgeMatrix v2 OpenCL miner](docs/opencl-miner.md) for the Intel Arc backend,
its backend-selection variables, and its known limits.

The feature-gated succinct-proof research has a separate optional CUDA backend
for exact Goldilocks DFT/LDE work and the value-MMCS Poseidon2 first digest
layer. CPU proving remains the default, and the accelerated entry point accepts
only an explicit CUDA library path and device. The direct API loads native code
in-process and is for trusted development only; every returned proof must pass
the unchanged CPU verifier. Callers that need crash containment can instead use
the separate proof worker, which pins the worker executable and CUDA library by
SHA-256 and adds bounded binary IPC and process-tree termination. That path has
been tested end to end with a 64-byte tree proof, but it is not an
operating-system sandbox.

External block admission can also run the active V2 verifier in a short-lived
child process. The operator supplies an absolute `cmfd-node` or
`cmfd-proof-worker` path and its SHA-256 pin through
`--proof-verifier-worker` and `--proof-verifier-worker-sha256`; wall-time and
memory limits are explicit. The parent accepts a result only after a canonical
response echoes identities bound to the exact verifier parameters, block
challenge, proof type, and proof bytes. Timeout, crash, output overflow,
malformed response, identity substitution, and hash mismatch all fail closed.
This mode is optional on Devnet and supports only the active V2 verifier. It
does not activate the reserved V3 proof or replace the required production
parser, measurements, and audit.

At the 32,768-row checkpoint on an RTX 5090, an unoptimized Cargo test-profile
CPU run took 348.28 seconds (64.503 setup, 283.416 prove; 238,698-byte canonical
zlib payload). CUDA DFT plus Poseidon2 took 76.71 seconds (7.700 setup, 68.551
prove; 237,292 bytes), a 4.54x speedup and 78% less wall time. The monolithic
Poseidon2 CUDA ABI v1 is test-profile-only: it caps a call at `2^24` rows and
`2^31` field limbs. The production `2^27`-row LDE would require 291 GiB and
87 GiB inputs for widths 291 and 87, plus a 4 GiB digest layer, so a
streaming/out-of-core prover remains required.

The independent `proof_stream` ABI v1 now accepts up to 64 ordered, equal-height
physical-bit-reversed coefficient matrices, a `2^20` source height, seven added
bits, `2^27` output rows, 4,096 total columns, and `2^31` input limbs. It emits
monotonic power-of-two row chunks of at most `2^16` rows, without crossing a
source-height coset block, together with exact unpadded Poseidon2 leaf digests.
At `32,768 x 291`, `+7`, its digest-only stream phase measured 308.345 ms and
13.60 million rows/s on an RTX 5090 while avoiding a 9.094 GiB host LDE.

The worker can drain those rows into a no-overwrite sealed spill artifact whose
ordered matrix widths and shifts, geometry, physical layout, and canonical
little-endian limbs are BLAKE3-bound. Partial or failed artifacts are not
published; a reader authenticates the complete file when opening it and the
fixed-size chunks used by every later row read. This is a storage-integrity seam, not a
consensus proof or a production prover. Production-scale Plonky3 PCS
consumption is not yet fully out of core. See
[the custom proof specification](docs/consensus/forgematrix-custom-proof.md)
for the measured scope and remaining activation gates.

The WHIR path also has authenticated ephemeral residual and extension-codeword
artifacts. The production residual geometry is 24 GiB plus about 2 MiB of
authentication metadata; the next `2^29`-row cubic extension codeword is
exactly 48 GiB plus about 2 MiB. A fallible artifact-backed WHIR state now
consumes those residuals, adopts disk-backed extension commitments and
authenticated BLAKE3 openings, and streams later folding and constraint rounds
with bounded buffers. Tested commitments, openings, transcript challenges, and
complete proof bytes match the dense prover; storage failure poisons the
attempt without a dense retry. The prover state now uses the
demand-authenticated format-v2 tree, whose exact `2^29`-row artifact is
34,359,738,592 bytes and whose openings authenticate only the requested paths
against separately authenticated codeword rows. The legacy format-v1 store
remains capped at `2^18` rows, while the exact reference extension encoder is
still capped at `2^20` rows. Its current file-backed DFT would move about
1.97 TiB at production geometry, so a blocked or GPU transform for the
`2^29`-row extension codeword of an n=31 role still stands between this
checkpoint and a complete proof run. The native v2 proof codec is now fixed-width and
configuration-derived, with a canonical first-reference Merkle dictionary and
no general-purpose compression. Its decoder enforces a tree-level,
configuration-derived maximum on distinct authentication nodes; the inner
codec is hard-versioned so the stricter accepted grammar is part of the WHIR
suite identity. Ten real 13-variable explicit envelopes
measured 188,104 through 190,024 bytes and passed the unchanged verifier, but
the Merkle-tree geometry also gives a transcript-independent maximum of
203,576 bytes including the outer wire header. This is one WHIR proof rather
than the complete production aggregate. The public 16-variable and 1 MiB
research limits therefore remain unchanged; 15- and 16-variable standalone
envelopes are deliberately rejected because they cannot fit the network proof
budget.

The opt-in `production-whir-candidate` feature now derives a separately
versioned verifier/parser geometry for the exact n=19 base and n=31 weight
roles without raising those legacy limits. It pins the n=19 native
dictionary-free floor at 133,298 bytes and the n=31 floor at 268,640 bytes.
Because the latter already exceeds the complete 262,128-byte proof payload by
6,512 bytes before any Merkle dictionary or outer aggregate component, n=31
parsing fails closed before proof decoding or proof-sized allocation.
Production therefore needs a smaller proof geometry or a different
aggregation/compression design; increasing the wire cap is not treated as
completion.

The execution-trace candidate now pins 439 ordered semantic columns in a
512-slot, nine-selector layout over a 26-variable local domain. Executable
budget checks show that thirteen independent proofs have a 3,365,110-byte
dictionary-free floor and that even selector-first opening needs 1,085,208
bytes of first-round semantic values before Merkle paths or other messages
(4,340,832 bytes with the ordinary local fold). A bounded
reference commits four columns, folds the selector variables, and completes one
CPU-verified WHIR proof while rejecting substitution, reordering, omission,
and transcript replay. The algebraic row fold is therefore fixed; a succinct
authenticated opening for it remains the production proof-size gate.

The trace-specific parameter boundary is now executable rather than inferred.
Goldilocks two-adicity limits the selector-first starting inverse rate to
`2^-6`. At the required 128-bit non-conjectural unique-decoding setting, zero
grinding needs 131 initial queries (536,576 value bytes), and even a practical
16-bit grinding ceiling needs 115 (471,040 bytes). An otherwise empty proof can
fit at most 63 such queries, which would require at least 67 bits of grinding.
A CapacityBound comparison fits conservatively in 193,444 bytes with no
grinding but relies on the pinned library's Reed-Solomon capacity/correlated-
agreement conjecture; a JohnsonBound comparison fits in 239,616 bytes only
with 48-bit grinding. Neither is an activation candidate. Production therefore
still requires a non-conjectural succinct commitment rather than a parameter
change disguised as completion.

The next non-conjectural layout is now fixed in code. It keeps only the 12
algebraic transition values in each core table (11 for initialization because
its input is fixed), giving 47 semantic columns. An earlier four-column,
64-row transpose was rejected after exact FRI accounting: its bank trace had
`n=32`, so log blowup four would require an impossible `n=36` Goldilocks LDE.
The replacement packs two range specifications into each of four rows per
cell, using 28 digit columns and seven table-multiplicity columns. Main widths
are 46 for initialization and 47 for a bank. Its bank trace is `n=28`; the FRI
LDE is exactly `n=32`, within Goldilocks two-adicity. The reusable 66-column
preprocessing plan contains selectors, lookup IDs, the fixed nibble table, and
the exact 7 layer, 7 row, and 12 column bits; it contains no per-block mask.
The AIR selects the challenge-derived affine coefficients from those bits and
enforces the mask directly. Canonical rows, padding, lookup topology, source
bounds, ordered core mapping, and V2 layout digest are tested. Actual
production PCS roots and aggregate payload measurement are still required
before this layout can mint a verified production trace.

A test-only 128-cell batch-STARK proves that packed range handoff and the
transition arithmetic end to end. The core mask is rederived from the
challenge polynomial, all seven ForgeMatrix transition equations are enforced,
eight independent LogUp buses bind each core source/slack pair, and seven
nibble buses range-check four packed digit columns apiece against the fixed
`0..15` table. The pinned prototype has maximum degree nine, 145 constraints,
three quotient splits, 48 base-field lookup auxiliary openings at each local
and next evaluation, and 128-bit computed list-decoding security at FRI log
blowup four with 57 queries, one above the measured minimum. Its shared-pair
LogUp challenge error is bounded below `2^-163`. The 512-row proof has a
222,960-byte fixed-width bincode baseline; repeated best-zlib runs measured
160,461 to 160,667 bytes, and a 165,000-byte regression ceiling is tested.
This is not the production native codec or a production-shape size result.
Every core column, active digit, padding, multiplicity, preprocessing, and
degree-shape mutation is rejected.

Exact production geometry also rules out ordinary batch-STARK FRI as the
activation transport for this reduction. A valid 57-query transcript whose
queries occupy distinct six-bit prefix buckets has a 333,792-byte lower bound
even with globally deduplicated Merkle paths. That is already 71,664 bytes over
the 262,128-byte native proof budget before roots, proof-of-work witnesses,
lookup terminals, input commitment paths, or headers. The compact arithmetic
and range reduction remains useful, but production needs a different succinct
commitment or aggregation layer; the current FRI path cannot guarantee the
wire cap.

The feature-gated BLS12-381 Dory replacement now aggregates the production
matrix, transition, range, wiring, fixed-model, equality-link, and final-output
claims into a canonical n=33 frame projected at 133,409 bytes. A companion
cross-field AIR proves that the exact activation bytes hashed by BLAKE3 have the
same multilinear evaluation opened by Dory. Its bounded canonical zlib codec
measured 156,500 to 156,650 bytes on the 32-byte bridge fixture, down from
222,256 to 222,384 native bytes. The resulting cross-shape composition remains
27,799 to 27,949 bytes over the 262,128-byte payload cap. Query/grinding and
higher-blowup sweeps do not close that gap at an operationally acceptable cost,
and a 56-point sweep across FRI terminal lengths zero through seven and maximum
fold arities one through seven found a best 154,606-byte bridge at terminal
length six and maximum fold arity two. That still composes to 288,033 bytes,
25,905 bytes over the cap. The V3 selector therefore remains absent and
consensus fails closed. A narrower bridge
or different sound aggregation layer, a complete n=33 run, independent review,
and audits remain activation gates.

The complete tiny structured fixture now combines its arithmetic arguments, a
split WHIR opening proof, and the exact one-block BLAKE3 argument below the
network limit. Geometry-derived maxima are 154,252 bytes for WHIR and 87,556
bytes for BLAKE3; with 16,804 fixed aggregate bytes, the aggregate is bounded at
258,612 bytes. Retaining the current 193-byte V2 frame and a four-byte aggregate
length gives a 258,809-byte full-wire ceiling, 3,335 bytes below 256 KiB. This is
a deterministic tiny-profile bound, not a production-profile measurement.

Dedicated rigs can use the [standalone multi-GPU miner](docs/standalone-miner.md),
whose Windows ZIP includes editable `START-MINER.bat` and `LIST-GPUS.bat`
launchers. Its live console reports per-GPU and rig hashrate, power, hashes per
watt, temperature, fan, utilization, clocks, VRAM use, uptime, and work counts.
Automatic multi-worker scheduling divides host preparation threads across the
selected GPUs to keep more CUDA batches in flight; operators can override the
worker count per GPU when tuning power use.
Normal standalone mining is a thin client: the selected wallet/node supplies a
complete payout-bound template and remains responsible for chain sync and block
acceptance. The rig stores no separate chain database and reports a block only
after a node acknowledges it.

`profile16gb` reports the disabled, seed-based v1 candidate; it is not the v2
profile. The v2 CLI/test paths are deliberately capped to tiny research shapes
so every vector can be recomputed quickly on an ordinary CPU.

## Devnet-0

`cmfd-node` is a bounded multi-node Devnet-0 runtime. RPC stays loopback-only.
P2P defaults to loopback or private addresses; public numeric addresses require
the explicit `--allow-public-peers` test-only flag. From a Windows PowerShell
prompt in the repository root:

```powershell
cargo run -p cmfd-node -- mine-once
cargo run -p cmfd-node -- status
cargo run -p cmfd-node -- run --p2p-bind 127.0.0.1:18444
```

The defaults are RPC `127.0.0.1:18443`, P2P `127.0.0.1:18444`, and data
directory `commonfoundry-devnet0`. The loopback RPC exposes health/status,
templates, a bounded volatile mempool, canonical transaction/block submission,
and development mining. Static peers exchange canonical blocks bidirectionally
in bounded batches, then pull unknown mempool transactions through the same
admission rules; transaction propagation remains pull-only. Each
block is fully validated before it is indexed, the active branch is selected by
strictly greater cumulative work, and the checksummed block log is replayed on
startup to reconstruct forks and the active tip.

The community Devnet bootstrap is currently `107.214.187.2:18444`. Testers can
join it by starting the wallet with
`--allow-public-peers --peer 107.214.187.2:18444`. This is a best-effort testing
endpoint rather than automatic discovery; node RPC remains local and is not
published. Operators can also run a private direct-IP topology as documented
in [docs/devnet-0.md](docs/devnet-0.md).

### Local Devnet wallet

The native wallet runs its own embedded Devnet-0 node. Do not leave a separate
node on the default P2P port while starting it. From PowerShell:

```powershell
Set-Location C:\Source\CommonFoundry\apps\wallet
npm ci
npm run desktop:dev
```

The desktop application stores its chain data under the operating system's
application-data directory, opens P2P on `127.0.0.1:18444`, and communicates
with the React interface through a narrow Tauri command allowlist. It does not
open the node HTTP RPC port. A production-style Windows installer can be built
with `npm run desktop:build`; Linux builds use the same command and the
platform-specific Tauri bundle configuration.

The browser-only developer mode remains available by running a separate
`cmfd-node`, then `npm run dev`. Vite listens only on loopback and proxies
requests under `/rpc` to `http://127.0.0.1:18443`; the node RPC is not exposed
directly to the browser or public network.

The wallet reads real active-chain balances and history, displays the receive
destination, creates signed sends, runs cancellable continuous Solo or Pool
mining, and consolidates mining outputs through the embedded node. With the
optional CUDA library present, the wallet accelerates the INT8 matrix stage on
one NVIDIA GPU; otherwise it uses the CPU reference evaluator. Every CUDA
candidate is fully recomputed in Rust before submission. Mining reports
complete ForgeMatrix nonce attempts per second, not raw GPU TOPS. Mined rewards
require 100 confirmations before they are spendable. Consolidation selects mature, unreserved outputs in smallest-first
order, accepts 2 through 128 inputs, creates one wallet output, and burns the
chosen transaction fee.

The Mining page supports both continuous solo mining and the CMFD Devnet pool
v1 protocol. Pool mode uses TLS 1.3 with an exact SHA-256 pin of the server's
leaf certificate and accepts only numeric loopback or private-network
endpoints in this form:

```text
cmfd+tls://127.0.0.1:18445?pin=<64-hex-certificate-sha256>
```

This protocol is not Stratum compatible. The pool sends the immutable block
challenge and a separate easier share target. Workers submit only the issued
job ID and nonce; the server independently recomputes the committed
ForgeMatrix relation, compares its work digest with the share target, and
submits a block only when the same digest also meets the unchanged chain
target. Pool counters are bounded, volatile, session-only, valueless, and
nonwithdrawable. They are neither funds nor an on-chain payout ledger.

Generate a test certificate and start a local pool from the repository root:

```powershell
cargo build -p cmfd-node --locked
New-Item -ItemType Directory -Force .\devnet-0-linear5y\pool-tls | Out-Null

.\target\debug\cmfd-node.exe pool-certificate `
  --certificate .\devnet-0-linear5y\pool-tls\pool-cert.der `
  --private-key .\devnet-0-linear5y\pool-tls\pool-key.der

.\target\debug\cmfd-node.exe `
  --data-dir .\devnet-0-linear5y\pool `
  pool-serve `
  --bind 127.0.0.1:18445 `
  --p2p-bind 127.0.0.1:18454 `
  --certificate .\devnet-0-linear5y\pool-tls\pool-cert.der `
  --private-key .\devnet-0-linear5y\pool-tls\pool-key.der `
  --share-leading-zero-bits 7
```

Copy the `certificate_sha256` printed by either command into the wallet URL.
Publish only the certificate and its pin, never `pool-key.der`. The generator
creates the key with mode `0600` on Unix; on Windows, restrict the key and pool
data directories with operator-only ACLs. TLS authenticates the pinned server,
not worker or payout claims, so the volatile counters are not identity-secure.
The explicit `18454` P2P bind avoids the wallet's default `18444`; configure one
static peer link between the wallet and pool node for bidirectional block sync.
See [docs/devnet-0.md](docs/devnet-0.md) for the full pool boundary and
[apps/wallet/src-tauri/README.md](apps/wallet/src-tauri/README.md) for desktop
static-peer command-line options.

Each new data directory creates a distinct Schnorr test key in `wallet.key`;
the node never returns its private bytes through RPC or desktop IPC. Stop the
node before backing up that file and do not share it. An existing nonempty
Devnet-2 directory retains its original demonstration key during migration so
an upgrade cannot strand its test outputs.

Devnet-0 is the active Common Foundry testing network. It currently uses
manually configured peers rather than automatic discovery. See
[docs/devnet-0.md](docs/devnet-0.md) for node and pool commands, RPC examples,
acceptance checks, and operating limits; detailed protocol limitations remain
in [SECURITY.md](SECURITY.md).

See [docs/consensus/forgematrix-v1.md](docs/consensus/forgematrix-v1.md), the
[recommended v2 research specification](docs/consensus/forgematrix-v2.md), and
[SECURITY.md](SECURITY.md) before modifying consensus code. The inference
payment flow and its current integration boundary are documented in
[docs/marketplace/payment-channels.md](docs/marketplace/payment-channels.md).

## Economics

- 60-second target blocks and a 180-header difficulty window;
- a 500 CMFD launch subsidy that decreases linearly over 2,628,000 blocks,
  exactly five 365-day years at the target rate;
- each pre-tail block splits emission 70% to the miner, 25% as an immediately
  spendable steward award, and 5% to an immediately spendable community fund;
- 657,000,249.98688 CMFD of scheduled pre-tail emission in total;
- a permanent 5 CMFD miner-only tail subsidy beginning at block 2,628,001; and
- all transaction and channel-close fees burned rather than paid to miners.

The declining component reaches zero at the five-year boundary and is then
replaced by the tail. Because the tail remains 5 CMFD, the final declining
reward (0.00019025 CMFD) is followed by the 5 CMFD tail reward; this boundary is
intentional and consensus-tested. The exact height and rounding rules are in
[docs/consensus/emission.md](docs/consensus/emission.md).

Inference revenue is not a block subsidy. A customer authorizes cumulative
payments from a prepaid channel directly to the GPU provider as output is
streamed in bounded chunks. `cmfd-marketplace` implements that signed protocol,
and the consensus UTXO rules enforce exact settlement or a time-locked refund.
