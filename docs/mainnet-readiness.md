# October 3 mainnet readiness

## Fixed schedule

- Source and matching packages: **2026-10-02 17:00:00 UTC**, noon CDT.
- Mainnet mining: **2026-10-03 17:00:00 UTC**, noon CDT.
- Local zone: `America/Chicago`; the dates are in daylight time, UTC-05:00.
- The preparation window is exactly 86,400 seconds.

## Source baseline

The readiness branch starts at `08e63ad3862b82f7d2fc3853711bc4c1b314db66`,
the signed RC5 miner.2 release source. It includes RC5
`ae00bcacde01aaf1e54dcc0297d388165d677af2` and the qualified Ada/Blackwell
miner changes. The dirty older `C:\Source\CommonFoundry` checkout is not
the source for these changes. No running RC services are changed.

## Fair-start construction

The proposed mainnet genesis is SHA-256 over this exact byte sequence:

```text
"CMFD/MAINNET/BEACON-GENESIS/V1\0"
|| canonical_mainnet_launch_plan_sha256[32]
|| pinned_quicknet_chain_hash[32]
|| pinned_round_big_endian_u64[8]
|| verified_compressed_G1_signature[48]
```

The launch plan binds finalized economic parameters, the minimum transaction
burn, proof and artifact identities, reward destinations, the schedule, and
the beacon policy before source release. `cmfd-node mainnet-plan` derives it
from compiled artifact/rule identities plus explicitly supplied starting target
and reward receiving addresses. It will not silently select the RC addresses.
The digest in the formula is SHA-256 of the ASCII domain
`CMFD/MAINNET/LAUNCH-PLAN/V1` followed by a zero byte and compact serialized
`payload` bytes. The independent network ID uses its own mainnet BLAKE3 domain.
Final runtime plan parsing also requires the exact release-pinned plan digest.
The exact quicknet round is **32,747,812**. Its scheduled time is precisely the
announced start; it is not the latest round, the preceding round, or a selectable
fallback. If the round is late or unavailable, nodes wait for that same round.
Do not change the round or use operator-generated entropy as a fallback.

`cmfd-launch` verifies the round with `drand-verify = 0.6.2`, using quicknet's
RFC9380 G1-signature scheme and checked public-key deserialization. It derives
randomness locally from the signature. Relay-provided public keys and randomness
are not accepted. Parsing is bounded to 4 KiB and rejects extra/duplicate fields.
Its authenticated output type cannot be deserialized or constructed by callers.

The threshold beacon adds an explicit assumption: enough drand participants
must remain honest and withhold future-round shares until their scheduled time.
It does not guarantee equal Internet latency or equal mining hardware. It prevents
useful advance work only when the authenticated genesis is required by every
node, pool, wallet, mining, replay, and block-validation entry point.

The verifier, canonical plan builder, and opaque mainnet runtime context now
exist. The shared node-opening path requires that context before opening any
artifacts or chain storage. Its authenticated genesis feeds the same immutable
parameters used by replay, block admission, and the thin-miner parameter API.
Bare public mainnet profiles and mutated contexts are rejected. Mainnet wallet
keys follow the encrypted-key requirement.

`production-mainnet` is now a distinct node/wallet/miner build feature. It
requires a finalized `mainnet_release_pin.inc.rs` and the matching shared
consensus `mainnet_network_id.inc.rs`. Both remain `None` until the owner confirms
the parameters and the required approvals are accepted. Builds reject absent
pins and reject single-producer RC approvals as mainnet authorization.

The shared node-opening path and thin-miner handshake resolve the verified
runtime context automatically in a mainnet build. Miner work commands require
the same context before opening workers; device listing and static miner
identity remain available during setup. Wallet builds have a distinct mainnet
application identifier. `cmfd-node mainnet-launch-info` checks the pinned plan
before launch without needing the future beacon or opening chain storage.

The runtime sidecars are `production-mainnet/MAINNET-PLAN.json` and
`production-mainnet/LAUNCH-BEACON.json` beside each executable. Missing/early
beacons are retryable and never cached; a successful authenticated result is
retained immutably for the process. No caller-selected key, round, clock, or
plan hash can override the compiled mainnet loader.

`cmfd-launch fetch --runtime ABSOLUTE-NODE-OR-MINER-PATH --wait` now validates
the package's pre-launch identity, waits for the exact start, and tries the
three fixed drand relays for the same round. It verifies before publication,
reuses valid cached certificates, preserves invalid existing files, and handles
Ctrl+C, child-process timeouts and oversized responses. Mainnet Windows/Linux
node/miner launchers prepare inputs before waiting and start only after the gate
succeeds. The wallet opens its offline preparation interface before activation,
creates an encrypted wallet with a separate backup, and authenticates existing
keys before exposing their public receiving address. No decrypted signing key is
retained by preparation. A cancellable background worker retrieves the beacon;
the user explicitly unlocks and connects after verification. Node startup remains
independently gated, including direct executable starts. Standalone nodes accept
an external wallet passphrase file.
The source checksum typo for fixed-bank-0.tree is corrected and cross-manifest
consistency has a regression test. Node seed defaults now select the compiled
network's port rather than hard-coding the RC port.

**Mainnet integration remains incomplete.** Final pin values, accepted review
evidence, mainnet release packaging and finalization, and the real launch
rehearsal are still pending. The runtime
explicitly refuses legacy wire/fee defaults for a new mainnet ID.
The proposed service ports are 29443/29444/29445, separate from RC; the current
RC seed host is only a prospective endpoint until mainnet service provisioning
is verified. Existing RCNet identities and consensus remain unchanged.
A successful CLI verification is not mainnet approval.

Primary references: [drand specification](https://docs.drand.love/docs/specification/),
[drand security model](https://docs.drand.love/docs/security-model/), and
[drand-verify](https://docs.rs/drand-verify/0.6.2/drand_verify/).
Quicknet key, period, genesis, and chain hash were compared across api.drand.sh
and api3.drand.sh on 2026-09-19. Historical round 123 is the offline positive vector.

## Outstanding evidence and implementation

| Requirement | Current state | Completion evidence |
|---|---|---|
| One canonical source baseline | Readiness branch created from miner.2 | Final frozen source commit and source publication target |
| Exact UTC release/mining schedule | Pinned in cmfd-launch | Schedule CLI and timestamp tests |
| Signed launch-time entropy | Verifier, node/miner startup wiring and retrieval/waiting launchers implemented; packaged rehearsal pending | Signature mutation vectors plus actual packaged replay and anti-precomputation rehearsal |
| Mainnet network/consensus identity | Shared identity registry and mainnet build feature implemented; final pin values pending | Final pinned plan and mainnet profile, distinct from RC |
| Reward receiving addresses and custody | Awaiting owner decision | Public destinations plus custody/recovery evidence |
| Independent reproduction and review | No accepted independent record located yet | Named reproducer, signed report, independent crypto/wallet review |
| Dependency audit | rustls updated to 0.23.45 for RUSTSEC-2026-0285; 44 pool/TLS tests pass and cargo-audit reports zero vulnerabilities | Final build audit plus review of remaining informational dependency warnings |
| Windows/Linux release packages | Pending mainnet configuration | Clean installs, signature/checksum verification, matching runtime identity |
| Wallet preparation before activation | Encrypted creation with backup, restore, public address display and launch-wait UI implemented | Native custody tests plus rendered fixture checks; final signed-package rehearsal pending |
| Seeds, discovery, explorer | RC evidence needs mainnet rehearsal | Independent node results and mainnet service configuration |
| Pool payout and reorg lifecycle | Evidence collection pending | Mature-reward payout and reorg/restart reconciliation logs |
| Storage capacity | Existing unpruned proof load needs a mainnet plan | Measured growth and provisioned capacity/retention decision |
| Recovery and update | Rehearsal pending | Backup/restore, interrupted append, restart, upgrade/rollback results |
| Final launch rehearsal | Pending | Exact intended packages, future-round start, delayed-beacon handling, fresh-wallet transfers |
| Source release 24 hours early | Not yet executed | Public source and matching package timestamps at agreed release time |

OTC completion is deferred until mainnet and is not part of launch activation.
Carry forward successful unchanged RC evidence; repeat affected checks and the
final end-to-end launch rehearsal. Do not mark this checklist complete merely
because the component tests pass.

## Reproducible local checks

```powershell
$env:CARGO_BUILD_JOBS = '4'
cargo test --locked -p cmfd-launch
cargo clippy --locked -p cmfd-launch --all-targets -- -D warnings
cargo run --locked -p cmfd-launch -- schedule
cargo test --locked -p cmfd-node --lib --features production-v4-testnet rcnet_candidate::
cargo test --locked -p cmfd-node --lib --features production-v4-testnet mainnet_runtime::
python -m unittest discover -s scripts/tests -p test_mainnet_launchers.py -v
python -m unittest discover -s scripts/tests -p test_runtime_bootstrap_integrity.py -v
```

The launch tests include a real historical BLS signature, every signature-byte
mutation, old-round substitution under a future local clock, strict document
bounds, and independently calculated SHA-256 vectors. They do not claim to
possess or test the future October 3 signature.

Beacon acquisition tests passed natively on Windows and Linux. The ignored
`child_probe` is a subprocess fixture invoked by the deadline and output-limit
tests, not a skipped readiness check. The launcher suite uses local stubs,
including generated Windows console executables; it proves ordering and failure
behavior without mining or contacting a pool. These checks do not substitute
for the final signed-package launch rehearsal.

Wallet preparation checks: 81 frontend tests and 32 ProductionV4 desktop library
tests passed (the explicit hardware-only mining test was not run). Wrong
passphrases, another network and altered encrypted-key headers are rejected.
Offline creation/restore expose no node, peer manager or mining manager and do
not create a block log. Strict desktop Clippy passes with default and V4 features.
Playwright exercised the actual app at 1440x1000 and 390x844 using simulated
Tauri responses: create/backup, address/QR copy, and launch-ready display; no
console errors or horizontal overflow. Those UI fixtures do not demonstrate a
live mainnet, native file-picker behavior, or the future activation signature.
