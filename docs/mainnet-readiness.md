# October 3 mainnet readiness

## Fixed schedule

- Source and matching packages: **2026-10-02 17:00:00 UTC**, noon CDT.
- Mainnet mining: **2026-10-03 17:00:00 UTC**, noon CDT.
- Local zone: `America/Chicago`; the dates are in daylight time, UTC-05:00.
- The preparation window is exactly 86,400 seconds.

## Source baseline

### September 25 pool credential compatibility

Real systemd testing found that the pool passed an ACL-backed credential path
to the wallet's stricter passphrase-file reader. The service now makes private,
service-owned runtime copies, matching the seed template's approach, without
relaxing wallet permissions. See the [reproduction and scoped test evidence](mainnet-pool-credential-qualification-20260925.md).
This fix must be included in the newly reviewed source and final packages;
no running pool or mainnet service was started or upgraded by the check.

### September 23-24 qualification checkpoint

The owner has completed both separately encrypted reward wallets and selected
one replacement release signer. The approved public plan, first plan signature
and generated mainnet pins were applied in `4c06f975bab1e76fdda8f80dc352d24e65f44168`.
Windows/Linux node, miner, launch helper and wallet binaries were each built twice;
both native build sets matched byte-for-byte. All four archives passed offline
cross-platform preflight after Linux archive staging was moved off drvfs.

**Those candidate archives are withheld, not approved for publication.** An actual
proof-worker startup check found the bundled worker accepted only the older test
network IDs. Signed private checkpoint `45601234aece4a7c4ee17d6f91c64e5d669628f4`
fixes it using the exact shared mainnet pin, preserves per-template network binding,
and adds a read-only worker identity check to Linux assembly. Unknown or malformed
IDs remain rejected. CI now chooses the actual mainnet feature/configuration for
1.0.0 instead of feeding that version to RC-only packaging scripts.

The fixed worker's two Rust network tests and all six actual server/one-shot
startup probes passed without model or CUDA work. Native SM89 and SM120 images
were inspected. This is not complete-proof GPU qualification or evidence of
support for older GPU generations. The Python mainnet suite ran 126 tests on
each OS; each had seven platform/environment skips and no failures. Full-proof
CPU verification was rerun against the exact Python sources at `4560123` and
passed every algebra, opening, Merkle, boundary, digest and target check.

The updated source still needs fresh owner approval/pins, rebuilt final archives,
hardware proof and brief final-package checks, final release signatures, and
mainnet infrastructure cutover. No mainnet service was started. Existing reward
destinations, starting difficulty, signer and October 2/3 schedule are unchanged.
The six-hour GPU-dropout waiver remains in force.

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
`CMFD/MAINNET/LAUNCH-PLAN/V2` followed by a zero byte and compact serialized
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
consensus `mainnet_network_id.inc.rs`. Initial values were applied after owner
approval; the corrected source now requires refreshed approval and release pins.
Builds reject absent
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

**Mainnet integration remains incomplete.** Initial signed pins and internally
reproduced packages exist, but the affected worker/package fixes require refreshed
approvals, final builds, release finalization, and the brief final-package smoke
check. The extended GPU dropout rehearsal
was waived by the owner. The runtime
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
| Mainnet network/consensus identity | Approved identity applied in the first candidate; corrected worker accepts its exact compiled pin | Refreshed source approval/pins and final package checks |
| Starting difficulty | Owner approved the 5× RC initial target and RC minimum on September 23 after waiving the extended live 20→5→1 run. Isolated full-proof and recovery tests passed; live dropout response remains unmeasured. | Bind the exact approved targets in the final plan, pins and packages; preserve the waiver and never present simulated data as a live result |
| Reward receiving addresses and custody | Owner completed the distinct-password setup September 23. Both public destinations and the exact plan are committed; all four encrypted-file hashes match the authenticated setup report. | Off-host backup retention remains unconfirmed; see [custody setup](mainnet-reward-custody.md#owner-setup-completed-september-23-2026) |
| Build reproduction and validation reporting | Owner declined seeking an external cryptographer; validation must be described as internal | Reproducible build records and accurate test/approval evidence, without claiming an external cryptographic audit |
| Plan approval binding | One owner signer selected; first signature verified and pins applied; full internal proof reverified after affected source fixes | Renew approval for corrected source, then apply exact generated pins |
| Dependency audit | rustls fix retained; September 25 review updated explorer tooling and backported the GLib iterator fix with an optimized regression. [Dependency review and maintenance items](mainnet-dependency-review-20260925.md). | Final frozen-build audit and native-package checks; retain the documented maintenance follow-up |
| Full cross-platform CI | All 14 jobs passed on d8116f56a18f5ef18a64761afb6c15196952660f in run 35926944704. The 4c06f97 run exposed RC-only packaging of version 1.0.0; 4560123 corrects profile selection and awaits CI. | Completed successful full run on the final source, not only selected jobs |
| Windows/Linux release packages | First eight native binaries each rebuilt identically; candidate withheld for the proof-worker correction | Rebuild corrected signed source, clean installs and final identity verification |
| Four-package release consistency | Both initial four-archive sets passed actual preflight and byte comparison; not release-approved | Repeat for corrected worker/final source, then owner signing |
| Mainnet release finalization | Generic finalizer checks exact pins, owner plan signature and an owner-signed internal-build statement | Two internally built archive sets and accurate signed evidence, then final checksums/signature |
| Wallet preparation before activation | Encrypted creation with backup, restore, public address display and launch-wait UI implemented | Native custody tests plus rendered fixture checks; final signed-package rehearsal pending |
| Seeds, discovery, explorer | Live RC seed checked healthy September 19; isolated mainnet service templates staged, not deployed | Independent node results and mainnet service configuration |
| Pool payout and reorg lifecycle | Persistent holds, funded offline reconciliation and dashboard reporting implemented and tested; live rollout remains pending | Packaged mature-reward payout/recovery rehearsal and authorized service upgrade |
| Storage capacity | Live seed has about 274 GiB free; larger archival capacity versus pruning awaits owner decision | Measured growth and provisioned capacity/retention decision |
| Model download availability | Full 61.2 GB solo-input set verified from primary; public Devnet-16 release now exposes all 40 manifest-named parts with matching published sizes, and mainnet fallback launchers select it | Authenticate a complete miner-role download from the fallback and rehearse the exact package |
| Recovery and update | Offline CLI backup/restore/tail-repair rehearsal passes on Windows/Linux; mainnet storage tools now authenticate launch identity | Final signed-package and service-identity rehearsal, upgrade/rollback results |
| Final-package smoke check | Pending; owner waived only the extended six-hour GPU dropout run | Start the exact candidate package, verify node identity/connectivity and a test transaction; keep historical/mocked beacon checks separate from the actual future round |
| Source release 24 hours early | Not yet executed | Public source and matching package timestamps at agreed release time |

OTC completion is deferred until mainnet and is not part of launch activation.
Carry forward successful unchanged RC evidence; repeat affected checks and the
brief final-package smoke check. Do not mark this checklist complete merely
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

The original two-signer pin-candidate generator re-verified both mainnet signatures, checked the
reviewed proof target against its signed qualification digest, rejects RC
single-producer targets and arbitrary Rust, and renders the two mainnet includes
outside the source tree. It is superseded by the September 23 one-signer policy
below. Eight tests passed on Windows and Linux, including the
CLI, interrupted-publication cleanup and compilation against the actual release
struct definitions. This uses synthetic qualification data and disposable keys;
it is not an actual mainnet pin/application or qualification run.

The ordinary release finalizer previously skipped network activation checks for
non-RC labels. Mainnet markers now select a dedicated gate instead. It validates
the committed trust policy, freshly verifies plan signatures, compares applied
source pins with exact reviewed candidates and rechecks the four archives. A
separate signed build statement binds those archives and their public review
evidence. The original independent-signer requirement described by this earlier
checkpoint is superseded by the explicit owner-signed internal-build policy below.
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
the then-running full Rust job had passed. That old run later failed in the same
already-repaired fault fixture; the corrected `9bdd269` checkpoint has now started
its full run. Full CI on the final source remains required; no running
qualification job was cancelled.

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

## Starting target and retarget calibration

[Starting-difficulty notes](mainnet-starting-difficulty.md) record the actual
warmup behavior and the coupled launch/floor parameter. New regression checks
confirm that adjustment begins with the short startup history and that even very
slow blocks cannot produce a target easier than the configured limit. All eight
difficulty tests pass on Windows and Linux. Historical
RC5 miner.2 console rates give search-only estimates, not a forecast for mainnet
block production. No launch target or consensus behavior was changed. Complete
proof latency, pool capacity, propagation and hash-rate-drop behavior still need
to be included when approving the final parameter.

## Remaining launch-identity consumers

A source audit of node, miner and desktop runtime genesis consumers found one
more direct use of the compiled placeholder in the node's offline keyring
tools. Stored network metadata supplied a fingerprint, but the binding combined
it with the compiled zero genesis. Mainnet bindings now resolve the authenticated
runtime first, use its actual genesis/network ID, and require the stored
fingerprint to match its derived network parameters before making a keyring or
journal binding. This reads no model inputs and adds no genesis/clock override.
RC/development metadata behavior is unchanged.

The three new decoder tests pass with ProductionV4 enabled on Windows and Linux:
resolved-genesis preservation, rejection of missing/zero launch identity and
changed fingerprints, and strict metadata framing. They use synthetic decoder
inputs, not actual launch authority or independent approvals. All 19 existing
and new offline-keyring tests and strict ProductionV4 node Clippy checks pass
on both Windows and Linux. The compile-time
DEVNET_GENESIS_HASH compatibility alias is now explicitly documented as a
template, never mainnet's activated genesis. Network-info and live RPC use node
parameters; thin-miner parameters and wallet startup already resolve the opaque
launch authority. This bounded source audit does not replace independent review
or the final signed-package rehearsal. No real keyring, anchor, policy, or OTC
application was changed.

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

**Funding-loss implementation complete; deployment gate remains:** the September
22 owner-selected policy now persists affected payout holds when a distributed
reward loses mature canonical backing, retains signed transactions/reservations,
and pauses all automatic settlement when shared funding cannot cover outstanding
credits plus fees. Offline reconciliation requires the exact inspected chain tip
and ledger generation, complete mature funding and valid outstanding signatures.
Restart/chain restoration alone does not resume payments. A write-ahead generation
guard refuses silent rollback to older payout state after interrupted storage.
No miner credit is deleted and no future-earnings levy is imposed.

Windows/Linux isolated reference-chain tests exercise actual credited/paid reward
reorgs, restoration, explicit resume, a second reorg and restart; corruption,
reservation and dashboard tests cover the surrounding boundaries. See
[the implementation and operator procedure](pool-deep-reorg-policy.md). These are
internal accounting tests, not live RC-pool or final ProductionV4 package
qualification. Package/rehearse the upgrade and obtain authorization before
changing the running service. Irrecoverable/legacy signed-payment cases remain
held for a separately reviewed recovery plan; there is no unsafe force-resume.

## Model distribution and authenticated fallback

Fresh node-role preparation was exercised against the primary download service
and, separately, the public GitHub binary repository without authentication.
Each downloaded all four model-bank parts and verified their hashes, then
assembled and authenticated the 6,442,975,416-byte MODEL-V2.bank. Its SHA-256 is
`5f9b213c3bda51b74e4ebabb26607b67385d613aa8d99af915a48ab063e17d4e`.
The bundled 6,973-byte fixed record also authenticated, with SHA-256
`ea218831aa567e486426ded77c84a5752a817329c496e3557c6d43577f0afe79`.
Native Windows hashing additionally confirmed the primary download. The real
downloads ran on the Windows host in isolated staging, not in live RC storage.
They are computation inputs, not mainnet binaries or activation approvals.

The inventory has 40 parts. GitHub's earlier RC1 release has only the four
node-model parts. The existing public Devnet-16 release exposes all 40 expected
part names and lengths; its published chunk manifest matches the local RC1
content identifiers. The mainnet launcher fallback now selects Devnet-16 while
the RC1 source catalog continues to identify the authenticated bytes. A separate
primary-host miner-role preparation downloaded the remaining files. All 36
additional parts and all assembled files passed their hashes. A separate native Windows SHA-256 readback
then checked all eight files against the input manifest, including the three
row-major codeword caches: **61,203,815,317 bytes** in total. This audit did not
rely on the normal length-only reuse rule for those caches.

An offline artifact-load smoke test with the current ProductionV4 test-profile
node also passed. It was repeated against the node-only GitHub download directory
without the solo caches; both returned the same test-profile fingerprint and
created no node storage. These are CPU-only compatibility checks, not mainnet
activation, GPU/proof qualification, release performance, or a signed-package
rehearsal. The full input set remains in isolated local staging; the running RC
installation was not changed.

An independent full miner-role download from that fallback and an exact packaged
preparation rehearsal remain launch gates. A sampled Devnet-16 part returned the
expected public size, but catalog/asset metadata alone is not a 61.2 GB byte
audit. No public assets were added, replaced or re-signed for this change.

Downloader review found that HTTP success followed by a bad hash did not try
the fallback, and that a corrupt resumed prefix could poison a healthy mirror's
response. Both preparers now authenticate before accepting a source, discard
known-invalid complete bytes, and permit one fresh retry after a corrupt resumed
prefix. Windows also captures a recovered curl failure inside the background job
so Receive-Job does not discard a subsequently authenticated fallback. All-source
failure still stops preparation; parent-side and assembled-file hash checks
remain in place. The Windows preparer now checks the bundled fixed record before
downloads and rechecks its copied output. Curl configuration files are disabled
for reproducible transport options; source overrides still work.

The reusable Windows/Linux launchers now default to the public binary repository,
not the private development repository. Eight downloader unit checks pass on both
platforms. Seven real-loopback transport cases pass on Windows (Python/curl and
native PowerShell); three run on Linux with four Windows-only cases skipped there.
All 11 existing runtime-bootstrap and 33 mainnet package/preflight checks pass on
both platforms. These bounded transport/package tests do not replace rehearsal
of the final signed packages or independent reproduction.

For review handoff, the readiness head at `a0494a1` was 508 commits ahead of
`main`, including accumulated RC development. Relative to the verified RC5
miner.2 baseline `08e63ad`, the mainnet-preparation delta was 18 commits across
106 files. That focused comparison is useful for reviewers but does not qualify
the underlying proof/consensus implementation. No reviewer was assigned and no
additional PR-triggered full CI run was started during this audit.

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
throughout the audit.

The model preparer creates a 0700 destination. When run by root during service
installation, that default prevents the unprivileged service from reading the
model. Setup now explicitly requires root-owned, service-group-readable model
directories/files while preserving non-writability and executable permissions.
The service template checks the bank and root fixed-record paths for regular-file
type and readability before copying its runtime credential or waiting for the
launch beacon, so access errors are surfaced during preparation rather than at
launch time.

Ten storage/service tests pass on Linux, including a real dropped-privilege
fixture: root-created 0700 inputs are unreadable to `nobody`; the documented
group permissions allow reads but not file or directory writes. This uses only
temporary public-data fixtures and creates no account or service. The same
isolated test is scheduled explicitly on Linux CI. Windows passes eight checks
and skips the two Linux-only cases. All 33 package/preflight checks still pass on
both platforms. The separate systemd syntax check uses executable stubs; neither
it nor the permission fixture qualifies a live service or its full sandbox.

## CI runner capacity correction (September 21)

Completed runs `35484303102` (`9bdd269`) and `35486936551` (`716c4c1`)
both have GitHub runner annotations reporting `System.IO.IOException: No space
left on device`. Their job logs were not retrievable after the runner failed.
For `716c4c1`, the step records show that default workspace tests, wallet V3
tests, Dory tests and the complete WHIR suite passed before the runner failed
at the GPU-proof test step. That is not evidence that the GPU suite passed or
that its failure was a proof rejection. All other jobs in that run succeeded,
including both desktop builds, both shutdown/recovery jobs and both codec jobs.

The former single Rust job now runs the base workspace, Dory, WHIR, GPU-proof
and ProductionV4 groups on five independent runner disks. Incremental build
caches are disabled only for those CI jobs. Initial/final disk usage is logged;
no source, tests, model files or user caches are deleted. All 46 pre-existing
validation commands from the Rust job are preserved, as are the unrelated
workflow jobs. Feature matrix failures do not cancel other matrix members.

The existing `rust` check is retained as an aggregate that requires every split
job to succeed. Local validation compared the old/new command inventories and
exercised 67 combinations of successful, failed, skipped, cancelled and missing
job results. Only the complete all-success case passes. This is workflow
validation, not a successful replacement CI run, GPU hardware qualification,
or mainnet release approval; the new full run must still finish successfully.

## AI01 pool-host qualification (September 21)

AI01 was explicitly dedicated to the pool after a fresh Vast check showed no
running, resident, on-demand or reserved rentals and no allocated customer
storage. It is unlisted, its Vast/owner-mining services are disabled, and their
files were retained. The host has an RTX 4090 (24 GB), an EPYC 7K62, 64 GB RAM
and a 2 TB SATA SSD. The separate RC pool runs as an unprivileged service with
root-owned read-only software/model inputs, systemd credentials, a private
dashboard, boot autostart and local health/disk checks. No public pool routing
or existing pool identity/ledger was migrated.

The signed RC5 node was authenticated against the previously trusted release
policy. All eight model/proving files were rehashed on AI01. SM89 replay and
proof workers were built privately from the pinned SP1/CUTLASS sources and
checked-in SP1 patch; the published RC5 full-proof worker is SM120-only.
These private workers are not new signed release artifacts.

The first test ran a separate miner on the same GPU and exhausted VRAM during
proving. A diagnostic-only example, `qualify_single_gpu_pool`, now releases its
test search worker before submitting a chain-winning nonce. It uses the normal
pool client, GPU searcher, nonce replay, full proof and block-admission paths;
it does not change targets or accept synthetic proofs. The pool GPU should be
dedicated to pool work, not shared with an additional miner.

The optimized example completed successfully at 21:37 UTC: the pool accepted
block 93, `61f446875d5dc1b4263454e5cbce9a3101cc0e7f42ba5ac7c06801583344ceff`.
The independent VPS seed reached the same height and tip. The proof was
12,025,320 bytes; the prover reported 7.349706 seconds of online proving and
0.626312 seconds for its complete CPU self-verification. These are one-run
phase measurements, not a sustained pool-throughput guarantee or the whole
mining/submission latency. The pool journal retained 170 accepted shares and
one canonical block; the temporary test client exited.

Encrypted wallet backup/restore was checked locally on AI01 and a service
restart preserved the wallet, chain and accounting. Export of encrypted wallet
key material to the operator's PC remains awaiting explicit approval. Mainnet
package qualification, public routing, off-host alert/custody arrangements,
sustained load, mature payout and deep-reorganization tests remain separate
requirements. No mainnet keys, parameters, pins or launch time were changed.

## September 23 preparation checkpoint (not launch approval)

An isolated rehearsal collector now records a 20 → 5 → 1 GPU worker drop,
full-proof phase timings, stale/job-switch activity and two-node P2P observations.
Its report fails closed on missing identity, proof, worker or peer evidence and
never selects a final difficulty policy. The physical multi-GPU run and its
independently verified GPU/host identities have **not** happened. The public RC
pool was not used for this harness.

On September 23 the owner directed us to skip the extended live 20 → 5 → 1
rehearsal. Do not pause owner miners or the old Devnet-16 pool for that run,
publish a rehearsal report, or claim measured dropout recovery. This waives
that proposed experiment, not the remaining custody, package-integrity,
storage, CI and release-approval work. The owner confirmed that the brief
final-package smoke check remains in scope.

The owner then approved the previously tested **5× RC starting difficulty with
the RC minimum** as the final parameter choice. The exact initial target is
`000ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccb` and the
pow limit is `003fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff`.
This approval does not supply reward destinations, sign release approvals,
activate mainnet, or turn the skipped dropout experiment into evidence.

The standalone pool-miner source now resolves an optional physical GPU index or
full UUID to a single CUDA-visible UUID, gives selected GPUs separate worker
names, scratch paths and logs, and holds a per-UUID process lock. Shared model
preparation waits under an OS lock instead of racing concurrent rig launchers.
The unselected single-GPU path and wallet solo worker retain their previous
behavior. Windows miner, node, launcher and input-preparation tests pass; Linux
miner/node compilation passes; a one-card WSL CUDA query accepted the full UUID.
This is a source candidate only. A six-card rig must still prove distinct
device assignment, accepted shares, reconnects and sustained operation before
any new miner package is approved.

A separate, staged Linux mainnet pool service now checks the compiled plan,
signed-package files, GPU identity, fresh TLS material, payout settings and
RC-service overlap before it can open a pool socket. Mainnet pool startup
requires the explicit `--enable-mainnet-payouts` flag; the old testnet flag
cannot activate mainnet settlement. The service has not been installed or
started. The four-package assembler/preflight now binds a reviewed dashboard
asset manifest and an exact Linux CUDA-runtime hash; real reviewed assets,
source-derived reproducibility, signed packages and live payout/reorg tests
remain outstanding.

An opt-in dual-SM89/SM120 proof-worker build path produced candidate replay and
proof binaries from the pinned SP1 source/patch and a clean pinned CUTLASS
worktree. `cuobjdump` found both architecture images in each candidate. Neither
GPU generation has run a complete proof from the final signed package; the
candidate hashes are not release identities. The older private SM89 AI01
worker and published SM120-only RC worker are not substitutes for that gate.

The earlier September 23 local checks included the mainnet Python suite on Windows and Linux
(98 tests on each, with platform-specific skips), three native Windows guided
reward-custody tests using disposable keys, 59 focused ProductionV4 pool tests,
strict node/miner Clippy and the dashboard build. They are internal component
evidence, not a green final-source CI run or an actual mainnet rehearsal. At that
checkpoint the two real reward wallets and final pins were absent; the owner
subsequently completed custody as recorded below. The separate VPS seed
had 294,014,058,496 bytes free on September 22, below the documented 30-day
unpruned sizing scenario; capacity and retention still need an operator choice.

## Owner custody and public plan checkpoint (September 23)

The owner completed the setup built from `76acf5f5f03e1fc62d5c16e08037eda4d591c8e1`.
It requires two different passwords and authenticates both wallets and their
independently encrypted backups before publishing the public report. The setup's
incomplete marker is absent, and all four 176-byte encrypted files match the
SHA-256 values in `packaging/mainnet/REWARD-CUSTODY.json`. Only that public report
and `packaging/mainnet/MAINNET-PLAN.json` were copied into source. No private key,
encrypted wallet/backup file or password is included.

The plan was regenerated from the compiled node using the public destinations
and approved targets, and matched byte-for-byte. Independent Python validation
also checked canonical encoding, derived plan/network identities, the artifact
catalog, schedule and both secp256k1 public keys. The exact plan SHA-256 is
`1dfcdfbb6739f10051f6325a3d884997cd65b468cc3594f7b03a9c83d42f3db7`;
the plan digest is
`6c839b274f6385e7f4040a715436b739612527f29bfa9bdf5d2f89de1f440b52`.
The network ID is
`4c128b19b8f663067cca1905f40993cfdbe7a4462f00b0a062d3f68d578175ec`.

These are the owner's actual candidate destinations, not fixture wallets.
The public report records native backup authentication; the later automated
check only compared ciphertext hashes and did not decrypt the wallets or obtain
their passwords. Off-host backup retention has not been confirmed. This records
completed local custody and the final parameter choice, not signed launch
authorization; both mainnet release pins remain absent.

Full cross-platform CI run
[35907290535](https://github.com/Common-Foundry-1/CommonFoundry/actions/runs/35907290535)
completed successfully on `be9ce8836581f01ec80031e4800380a361f368a3`,
including both desktop builds and the aggregate Rust check. That run predates
the distinct-password implementation and this public-plan checkpoint. Final
source CI, approvals, packages and brief package smoke remain outstanding.

## Single release signer selected (September 23)

The owner explicitly selected one release signer. The mainnet policy now uses
only the dedicated producer authority for both the exact plan approval and the
internal rebuild statement. It does not create a second key, claim an independent
reviewer or interpret an RC approval as permission to launch mainnet.

The release toolchain and native identity gate use mainnet-specific single-signer
schemas. The internal qualification helper runs the existing complete V4 verifier
with a strict statement, preserved proof, pinned model bank and fixed record. It
binds all tracked Python verifier sources and rehashes inputs after verification.
Framing-only success, omitted initial-boundary or algebra checks, changed inputs,
different signer keys/namespaces and altered plans remain rejected. Proof-of-work
consensus verification itself is unchanged.

The same owner must sign the internal rebuild record after genuinely rebuilding
and comparing the four archives. Separate build directories and byte identity
remain required, but no organizational independence is claimed. Exact plan,
network, schedule, source, artifact, dashboard and CUDA bindings remain enforced.
See [the current one-signer workflow](mainnet-plan-approvals.md). Actual proof
qualification, signing, final pins/packages and deployment remain separate from
the fixture tests of this policy change.

The initial `packaging/mainnet/APPROVAL-TRUST.json` reused the owner's dedicated
RC producer key. That pending mainnet selection was subsequently replaced with
the owner's explicit permission, as recorded below. The Windows OpenSSH verifier has SHA-256
`47f009c35523b6997aff0f0528dae84f1545465479d722292499941cd5cb83b5`
and a valid Microsoft Windows Authenticode signature at inspection. That is a
new, explicit mainnet verifier pin; it does not replace the earlier RC verifier
digest or retroactively alter RC release evidence.

## Mainnet 1.0.0 preparation and real proof verification (September 23)

The owner-signed workflow's real qualification run completed successfully on
`701c5513e2371e6b3647f4e9a8f2a56b56f0904c`. It used the exact Git-exported verifier
sources, the preserved 12,025,320-byte proof, its strict statement, the actual
6,442,975,416-byte model bank and pinned fixed record. The complete cryptographic
check passed with no remaining stages: all six relations, three opening
reductions, three BaseFold transcripts, Merkle/query folds, initial boundaries,
hash bindings and the statement's target comparison.

The canonical report is preserved as
`packaging/mainnet/MAINNET-QUALIFICATION-SUBJECT.json`, SHA-256
`d152210c6de7bf94e8747d427fafa16ff0aa8bfe9e62b701898c34e361ab2359`.
It explicitly records internal verification, not independent reproduction or
mainnet authorization. This preserved RC proof verifies the unchanged proof
system; it is not a mainnet block or verification of the future launch beacon.

Node, miner, wallet, launch helper and dashboard metadata are aligned to the
planned **1.0.0** mainnet package set. The release inventory lists the four
native runtime/miner archives and required single-owner signing evidence. These
are preparation metadata, not a published tag, release or deployed upgrade.
Final owner signing, pin application, native builds, internal rebuild comparison,
CI, package smoke and deployment remain outstanding. Existing live RC services
and public release assets remain unchanged.

## Owner-selected initial mainnet signing key

Before any mainnet release or plan signature was published, the owner explicitly
authorized replacing the pending release-signing key and signing the unchanged
launch plan with the replacement. The new Ed25519 key fingerprint is
`SHA256:hhfV/4M5XDL2hLzeX0q/IMCR4fjSq5Kb8BjMC/Zj96Q`, with principal
`commonfoundry-mainnet-owner`. The public policy and trust descriptor agree.
`packaging/mainnet/SIGNER-SELECTION.json` records this initial mainnet authority
selection; no cross-signature from the former pending key is claimed.

The owner chose a new password in a local window. The operator helper saved and
authenticated the encrypted OpenSSH key and a separately encrypted backup.
Neither a password nor private key file was added to source. The old signing
key and existing RC release authorities remain untouched. The steward/community
wallets, their passwords, the exact launch-plan bytes and the October 2/3 noon
CDT schedule are unchanged. This records key selection, not publication or
network activation; final release qualification is still required.

## Explorer resource and dense-history checks (September 25)

The [resource qualification record](explorer-resource-qualification.md) now
separates bounded synthetic index memory, consensus-valid tiny-profile recovery
and preserved full-size proof verification. Reserving one transaction location
for new IDs reduces unnecessary allocation without dropping fork history.
The valid-history fixture checks full replay, snapshot restart and recovery
after a damaged optional cache against identical state and explorer results.
This is progress on resource/recovery coverage, not completion of long-history
production startup, final-package or deployment qualification.

The local checkpoint path also supports retained branches now. It refreshes
after nonwinning appends, authenticates the complete retained log, preserves
the first-arrival equal-work winner, and checks active state/header consistency.
Targeted regressions cover cached restart, full-replay fallback, losing-branch
corruption and subsequent reorganization. This removes the linear-only
eligibility restriction; it does not turn a checkpoint into an untrusted
consensus snapshot or establish long full-size-history startup performance.
