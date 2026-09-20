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
evidence, actual mainnet package builds and release finalization, and the real launch
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
| Plan approval binding | Dedicated requests, signature verification, package binding and candidate pin generation implemented | Actual role approvals, reviewed source history and final pin application |
| Dependency audit | rustls updated to 0.23.45 for RUSTSEC-2026-0285; 44 pool/TLS tests pass and cargo-audit reports zero vulnerabilities | Final build audit plus review of remaining informational dependency warnings |
| Full cross-platform CI | Proof-worker fault-fixture race reproduced and corrected; targeted Windows/Linux suites pass | Completed successful full run on the final source, not only selected jobs |
| Windows/Linux release packages | Native assembler and four package layouts implemented; actual builds await final configuration | Clean installs, signature/checksum verification, matching runtime identity |
| Four-package release consistency | Offline archive/source/receipt reconciliation implemented | Actual four-archive preflight report followed by independent reproduction and signing |
| Mainnet release finalization | Generic finalizer dispatches mainnet assets through exact-pin, plan-signature and signed-reproduction checks | Real independently built archives and signed evidence, then final checksums/signature |
| Wallet preparation before activation | Encrypted creation with backup, restore, public address display and launch-wait UI implemented | Native custody tests plus rendered fixture checks; final signed-package rehearsal pending |
| Seeds, discovery, explorer | Live RC seed checked healthy September 19; isolated mainnet service templates staged, not deployed | Independent node results and mainnet service configuration |
| Pool payout and reorg lifecycle | Isolated real-chain maturity/payout/restart tests pass; deep-reorg funding-loss handling remains incomplete | Agreed loss policy, corresponding adversarial tests, and actual packaged mature-reward payout/recovery logs |
| Storage capacity | Live seed has about 274 GiB free; larger archival capacity versus pruning awaits owner decision | Measured growth and provisioned capacity/retention decision |
| Model download availability | Primary host returned HTTP 200 and expected Content-Length for all 40 parts on September 19; GitHub fallback has only 4 model-bank parts | Full download/hash check during packaged rehearsal and a complete independent solo-input mirror |
| Recovery and update | Offline CLI backup/restore/tail-repair rehearsal passes on Windows/Linux; mainnet storage tools now authenticate launch identity | Final signed-package and service-identity rehearsal, upgrade/rollback results |
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

Wallet preparation checks: 82 frontend tests and 33 ProductionV4 desktop library
tests passed (the explicit hardware-only mining test was not run). Wrong
passphrases, another network and altered encrypted-key headers are rejected.
Offline creation/restore expose no node, peer manager or mining manager and do
not create a block log. Strict desktop Clippy passes with default and V4 features.
Playwright exercised the actual app at 1440x1000 and 390x844 using simulated
Tauri responses: create/backup, address/QR copy, and launch-ready display; no
console errors or horizontal overflow. Those UI fixtures do not demonstrate a
live mainnet, native file-picker behavior, or the future activation signature.

Package assembly now uses the exact clean source commit and validates each
native executable's prelaunch identity against the same plan. The wallet has a
distinct prelaunch schema so this does not masquerade as an activated-chain
attestation. Four deterministic archive layouts (Windows/Linux runtime and miner)
include the launch helper, both mining workers, authenticated input catalogs,
and user instructions. Twelve assembler tests cover mixed identities, legacy RC
wallets, changed schedules, wrong architectures, missing workers, downloader path
traversal, process output/time limits, staging side effects and no-overwrite
publication. These use fixture executables, not mainnet approval records. A real
Rust-generated test plan also agreed with the Python canonical/digest checks and
artifact catalog; its test destinations are not final reward decisions.

The previous CI wallet failure was a delayed dialog-focus callback interrupting
typing. The callback now preserves focus inside the dialog, with an explicitly
delayed-frame regression and rendered interaction check. Full CI must still be
observed on the resulting commit; local test results are not a CI-success claim.
Visual QA also found that the selected custody-action tab referenced an undefined
color token; it now uses the existing dark-ink token for readable contrast.
The Linux desktop CI job also built RC5 successfully but then attempted to
normalize a hard-coded RC4 AppImage path. Desktop artifact paths and packaging
arguments now derive from matching Cargo/Tauri/npm versions instead of an old
literal. The resulting CI job still needs to complete before claiming success.

The release-set preflight streams the four archives without extraction or
executing their contents. It checks exact frozen-source files, canonical archive
framing and permissions, receipt hashes and native role identities. It rejects
mixed activation evidence, different mining workers or same-platform launch
helpers, duplicated executable roles, preloaded beacons and extra files. It also
rechecks archive hashes after the whole reconciliation. Its report explicitly
does not claim independent reproduction or release approval. Real mainnet
archives, independent build evidence and signed finalization remain pending.

The new verifier exposed a portable-mode issue: archives assembled on Windows
did not mark extensionless Linux workers as executable. Canonical archive modes
now explicitly cover the launch helper, miner and both GPU workers; existing
published RC archives have not been changed.

Mainnet plan approvals now use distinct subject/role-payload schemas and the
existing dedicated V4 activation authorities/namespaces. Requests bind the exact
canonical plan bytes, review commit, qualification subject/binding and committed
trust policy, including the trusted SSH verifier digest. The tool does not sign
or choose reviewers. Packages include MAINNET-APPROVALS.json and reject a manifest
whose hash, proof qualification binding or signer descriptors disagree with the
compiled prelaunch identity. Changes after the reviewed source commit are limited
to the two mainnet pin files; other source changes require fresh review.
Real temporary OpenSSH keys exercised signature verification, rewritten-payload
replay rejection, role swaps and verifier substitution. These disposable test
keys do not constitute actual mainnet approvals or independent review. Final pin
application, real signed evidence and release signing remain pending.
Validation for this binding layer: eight mainnet approval tests using temporary
SSH keys and 33 assembly/preflight tests pass on Windows and Linux. The existing
V4 approval tests still pass (one Windows symlink test is skipped), as do the
existing release-integrity/bootstrap suites. Seven focused mainnet runtime tests
and strict node/miner/wallet Clippy checks pass. The actual mainnet build still
rejects the absent final pins; no fixture key or approval has been installed.

The pin-candidate generator now re-verifies both mainnet signatures, checks the
reviewed proof target against its signed qualification digest, rejects RC
single-producer targets and arbitrary Rust, and renders the two mainnet includes
outside the source tree. Eight tests pass on Windows and Linux, including the
CLI, interrupted-publication cleanup and compilation against the actual release
struct definitions. This uses synthetic qualification data and disposable keys;
it is not an actual mainnet pin/application or qualification run.

The ordinary release finalizer previously skipped network activation checks for
non-RC labels. Mainnet markers now select a dedicated gate instead. It validates
the committed trust policy, freshly verifies plan signatures, compares applied
source pins with exact reviewed candidates and rechecks the four archives. A
separate independently signed build statement binds those archives and their
public review evidence. Statement preparation never signs or asserts that the
caller is independent; the real reproducer must make that attestation.
The release-gate tests use synthetic packages and
disposable keys, including the normal finalizer/verify CLI, checksum/SBOM
generation, role substitution, unsigned statements, altered source pins,
different reproduced binaries and late archive replacement.
All nine pass on Windows and Linux. The legacy 153-test release-integrity suite
also passes (three platform-specific skips on Windows); plan approval and pin
generation regressions remain green.
No actual release metadata or approvals have been generated for mainnet.

The readiness branch now queues a newer CI run instead of cancelling its current
one. Other branches/PRs retain the existing cancellation behavior. No test was
removed or shortened; only workflow concurrency changed, allowing periodic
private checkpoint pushes without discarding an active proof-test run.

Current local evidence: 19 release-set preflight tests and 12 assembler tests
pass on Windows and Linux, including the real CLI against a temporary frozen
Git fixture. The existing 153-test release-integrity suite passes on Linux;
Windows passes 150 with three filesystem/platform-specific skips. These remain
fixture-based packaging checks, not approval of actual mainnet builds.
On CI commit `83c24f3`, both desktop jobs, wallet tests, MSRV, proof-codec and
node-shutdown jobs passed, but the full Rust job failed in the
`persistent_fault_worker` response-classification fixture. Pinning that fixture
to one CPU reproduced the failure locally: its child flushed an error frame and
exited immediately, so the parent's liveness check correctly returned
`DispatchedRequest(Process(WorkerExited))` instead of the expected protocol or
worker-reported error. The fixture now waits for parent teardown after sending
the fault response, and explicitly closes each worker after the assertion input
is collected. The expected error variants and production liveness checks are
unchanged. A deterministic regression separately confirms that a buffered
success response from an already exited worker is rejected.

Windows validation also exposed an overlong test-only profile moniker: its
diagnostic label produced a 258-character cleanup filename for a six-digit PID.
The fixture now uses the production moniker shape and tests both the current PID
and `u32::MAX`. It still proves that existing registrations are neither adopted
nor deleted, and that only the fixture's owned registrations are removed.
Production profile generation, cleanup-ledger encoding and access rules did not
change.

After these repairs, Linux passes 70 library tests and 17 worker integration
tests; Windows passes 96 library tests and 16 worker integration tests. The
standalone fault matrix passes on both platforms and in three consecutive Linux
single-CPU runs. Two opt-in CUDA hardware tests per platform were not run; these
results are process/transport regression evidence, not a new GPU qualification.
Strict Clippy passes on Windows and Linux with the CI-pinned Rust 1.94.1.
The initial Linux check used the host's Rust 1.98.0 and hit newer lint rules in
unchanged proof-acceleration code; the release toolchain and lint policy were
not changed to accommodate that unrelated host-toolchain drift.
Both fault classification and the exited-worker regression are now included in
the shorter Windows/Linux CI jobs rather than being discovered only after the
long workspace proof suite. At the latest check on `d049be9`, all jobs except
the still-running full Rust job had passed. Full CI on the repaired source
remains required; no running qualification job was cancelled.

## Offline recovery identity and CLI rehearsal

Inspection and partial-tail repair previously used the compiled profile directly.
For mainnet that profile contains the unactivated zero genesis, whereas node
startup uses the verified beacon-derived genesis. A healthy first block could
therefore be rejected as having an unknown parent. The same entry points also
allowed an unauthenticated public Mainnet profile to inspect an empty log or
repair a partial first record. Unauthenticated inspection and repair were both
reproduced with disposable fixtures before the repair.

The storage commands now resolve and require the same authenticated mainnet
profile as node startup, before taking a data lock or opening a block log. No
genesis override or caller-supplied authority was added. Six storage checks pass
on Windows and Linux with ProductionV4 enabled, covering rejected bare profiles
without file changes, correct resolved-parent scanning, exact tail quarantine,
and refusal of checksum corruption. A real future mainnet certificate is not
available yet; these checks do not claim to exercise the October 3 signature.

The new offline CLI rehearsal also passes on both platforms. It creates a
disposable encrypted wallet and three-block reference chain, checks that a live
data-directory lock blocks backup, restores to a separate path containing spaces,
rejects a wrong passphrase and overwrite, preserves the exact interrupted bytes,
and replays the repaired chain without a copied checkpoint. Receiving address,
chain tip, height, consensus fingerprint, UTXO count, original source log and
restored encrypted wallet bytes are retained/checked. No network service or GPU
is used. Strict node Clippy checks pass with the pinned Rust 1.94.1.

Runtime package layouts now include RECOVERY.md and STORAGE-RECOVERY.md from the
frozen source; all 33 assembly/preflight checks pass on Windows and Linux. These
are fixture archives, not newly published mainnet binaries. Operators must still
rehearse the final signed packages under the intended service identity, including
permissions, full backups, restart, and upgrade/rollback. Existing RC services,
keys and chain data were not changed.

## Pool payout lifecycle evidence and remaining loss-policy gate

The payout reconciliation review found a temporary mempool input conflict was
being treated as permanent abandonment. That released reserved miner credit
even though the original signed payout could become valid again when the
conflicting mempool transaction disappeared. The new regression failed with
`abandoned` instead of `prepared` before the repair. Both submission paths now
retain the exact prepared transaction and its reserved credit for this transient
case. This does not change payout amounts, fees, or existing on-chain transfers.
Previously abandoned journal entries are not automatically reopened: the old
format does not retain enough information to infer why they were abandoned.

The new conflict/restart test uses two mature funding outputs, a real signed
conflicting transaction, durable preparation, repeated reconciliation, node and
ledger restart, and canonical confirmation of the original payout. It verifies
that no second payout is journaled or paid. The maturity lifecycle test submits
an ordinary share and a winning share over pinned TLS, advances the actual local
chain to one confirmation before maturity, restarts the node and ledger,
changes only the future fee/window, reaches maturity, and confirms the exact
payout across further restarts. The original block's allocation and fee remain
frozen and its credit is applied once.

The 46-test pool suite passes on Windows and Linux; enabling ProductionV4 adds
five worker/protocol checks, with all 51 passing on both platforms. Strict
ProductionV4 node Clippy checks also pass on both with Rust 1.94.1.
These tests use disposable
keys and the tiny reference proof with the real node, transaction signatures,
pool transport and durable accounting. They are not a ProductionV4 GPU proof
qualification or a rehearsal of the final signed mainnet packages. They also
do not supply independent review or evidence of a live RC pool payout.

**Unresolved mainnet gate:** once a PPLNS block has already been distributed,
block reconciliation updates its orphan/confirmation status but does not revoke
that reward's credited balance. A deep reorganization can therefore leave
unbacked credit available for automatic payment. The existing legacy-credit
reorg test does not cover this funding relationship. The owner has been asked
whether to pause automatic payouts for review or recover the shortfall from
future earnings; neither policy has been silently selected or deployed. The
chosen behavior must cover already-paid rewards, payouts whose funding returns,
restart persistence, and reorganization below maturity, and must be implemented
and tested before mainnet approval. The mempool-conflict repair does not close
this separate funding-loss gate.

## Read-only seed and capacity check (September 19)

The established RC seed at `173.249.35.251` was checked without changing its
services or files. At 21:51 UTC it was active, reported healthy storage at
height 92, and had a 1,106,437,356-byte block log. The data filesystem had
294,038,712,320 bytes available (about 274 GiB) out of 310,911,414,272 bytes.

The new read-only storage tool derives a sizing scenario from the current
12,025,320-byte proof, 16 MiB block limit, 1 MiB undo limit, 88-byte record
overhead and 60-second target spacing. Proof payload alone projects to
16.1272 GiB/day. Using maximum-sized records with a 1.25 record multiplier,
a 20 GiB reserve and an additional copy of node model inputs gives a 30-day
scenario requiring 990,515,338,869 available bytes. The observed host is short
by 696,476,626,549 bytes in that scenario, reaching the reserve in about 8.29
days. These are planning assumptions, not a hard arrival/disk-usage bound;
checkpoints, backups and unrelated growth can require more space.

Separate mainnet systemd templates use their own account, directories,
credentials and ports. They authenticate the plan and wait for the exact beacon
before node startup. A startup reserve check and a five-minute read-only storage
timer are included. The timer reports pressure but does not stop a running node
or prevent external disk consumption. No service, firewall, account or storage
purchase has been applied. Operator capacity, alert delivery, the real sandbox
and restart behavior still need qualification before deployment.
The mainnet unit was confirmed `not-found` and its proposed TCP ports had no
listeners. The RC service PID and September 12 start time remained unchanged
throughout the audit. Nine storage/service tests pass on Linux; Windows passes
eight and skips the Linux-only systemd parser check. The expanded 31 package
tests still pass. Syntax checks use executable stubs and are not a live-service
rehearsal.
