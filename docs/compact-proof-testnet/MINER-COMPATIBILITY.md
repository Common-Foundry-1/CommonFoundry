# Miner preparation for the compact-proof mainnet fork

Miner version: **1.0.22**, pre-activation pool-client compatibility.

Activation was moved from 65,535 to 67,535 on 2026-11-11. This changes the
consensus fingerprint. Reference pool miner 1.0.21 recognizes the superseded
proposal and must be replaced before connecting to the updated fork pool.
The compact mainnet proof-system digest and mining calculation are unchanged.

## What developers need to change

The planned mainnet fork at height 67,535 retains the mainnet network ID,
ForgeMatrix search calculation, model bank and GPU search kernels. Pool miners
still submit the server-issued job ID and nonce. The pool constructs the block
proof. A pool miner does not need the compact prover on every mining rig.

The reference client previously accepted one compiled consensus fingerprint.
The candidate standalone mainnet miner explicitly enables a bounded policy
accepting the existing mainnet fingerprint and the pinned compact-mainnet
fingerprint. Generic library clients remain strict unless they opt in using
`PoolClientConfig::with_compact_mainnet_compatibility()`.

| Item | Exact value |
| --- | --- |
| Mainnet network ID | `88296bc39c10e8bc1dd4818d4d42412fe5f08210651110377f495da299812f62` |
| Existing mainnet fingerprint | `e9d81f15c580031302656609eb24fa8351efe0a34135ad894c793f3dd9044079` |
| Compact-mainnet fingerprint | `9009948f6eab38b5b3dcee13eda9f6ef03e0db863c435cb97c1d4c3e124eb360` |
| Planned activation height | `67535` |
| Compact-mainnet proof-system digest | `d1671fc4760134bf86f0b37d8694f4827037e5cea2642e312cb2eb705f3aef0d` |
| Pool protocol version | `2` |

Keep TLS 1.3 and the configured certificate SHA-256 pin. Read the pool's
`auth_challenge`; check protocol version and network ID, then require one of
the two exact allowed consensus fingerprints. Bind the payout-authentication
signature to that selected fingerprint. Echo it in `hello` and require the
same value in `hello_ack`. Do not switch identities during one handshake.
Reject unknown fingerprints before signing or submitting work. A reconnect
negotiates afresh so the same miner can connect to the upgraded pool.

Do not use the compact **testnet** network ID or fingerprint for mainnet.
Do not accept an arbitrary fingerprint supplied by a pool. Pool jobs and
share targets retain their existing validation. This preparation does not
implement node peer coexistence or change pool-ledger identity rules.

## Reference candidate checks

`cmfd-miner pool-compatibility-info` prints machine-readable supported pins,
source identity and scope without opening CUDA, a model bank or a wallet.
The existing canonical `network-info` output is preserved for launcher and
package compatibility. Connection logs print the identity actually selected.

Focused tests use isolated loopback TLS servers and ephemeral test keys:

```powershell
$env:CMFD_BUILD_SOURCE_COMMIT = (git rev-parse HEAD).Trim()
cargo test -p cmfd-node --lib --features production-mainnet compact_pool_compatibility --locked
cargo test -p cmfd-miner --features production-mainnet --locked
```

The transport tests cover both allowed pins, address-only and signed payout
authentication, nonce-only submission, unknown identities, wrong networks,
changed acknowledgement identity and incorrect TLS pins. They are protocol
tests, not fresh mainnet block or GPU mining evidence.

## Build and candidate downloads

Build the frozen source with `CMFD_BUILD_SOURCE_COMMIT` set to its exact
commit and `cargo build --release --locked -p cmfd-miner --features
production-mainnet`. Use the platform's usual release compiler and runtime
settings. `scripts/package-compact-miner-kit.py` builds complete native and
HiveOS kits from the signed v1.0.20 miner distribution, replacing the standalone
miner and recording the inherited launcher, CUDA runtime and GPU workers with
their original provenance. It verifies the signed baseline, every inherited
file and the new executable's source identity and two-fingerprint policy.
Native Windows EXE kits additionally require valid timestamped Authenticode
signatures. The Windows WSL2 edition instead ships the Linux payload and runs
through the installed Microsoft-signed `wsl.exe`; it contains no new Windows EXE.

Extract kits into a new directory and use the included launcher. The Windows
WSL2 edition includes `START-HERE.txt` with its one-line terminal command. Reuse
the existing verified input bank to avoid downloading it again. Preserve the
pool URL, certificate pin, payout address, worker name and GPU settings. For
HiveOS, use the complete `commonfoundry-mainnet-hiveos-1.0.22.tar.gz` installation
URL in the custom-miner flight sheet. Keep the original installation for
rollback. These packages do not change an installed fleet automatically.

## What remains before a production release

This miner does not activate the hard fork and does not generate compact
mainnet block proofs in solo mode. The accompanying node/pool fork source implements
height-aware proof selection, historical storage and peer transitions,
compact-mainnet proving and stale-job retirement. Qualify the miner against
that full pool across H-1, H and H+1, including reconnects and fresh accepted
shares/blocks, before claiming complete mainnet-fork qualification. The
compatibility prerelease is distributed separately from stable node/wallet
updates. See [the mainnet implementation plan](MAINNET-IMPLEMENTATION-PLAN.md).

## Draft message for third-party miner developers

We are preparing Common Foundry's compact-proof fork at height 67,535.
ForgeMatrix's search calculation and model stay the same, so existing GPU
search kernels should carry over. Pools will construct the new block proof.
Please add support for the exact current and compact-mainnet fingerprints
listed above, retaining network and TLS pin checks and binding authentication
to the selected identity. The reference compatibility candidate and transport
tests are ready for integration testing; final cross-height pool/GPU
qualification is still pending. Please report your miner version, platform,
selected fingerprint and reconnect/share results when the full fork pool is
available.
