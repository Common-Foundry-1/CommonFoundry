# ProductionV4 release-candidate gate

This is the work order and fail-closed contract for the first Common Foundry
release-candidate network. RCNet-1 is a launch rehearsal, not mainnet.

## Current status

The source tree now gives RCNet-1 the correct proof shape:

- network profile: `RCNet-1`
- consensus proof selector: `ProductionV4`
- verifier: the in-process ProductionV4 verifier
- proof and block envelopes: the ProductionV4 network-specific limits
- node, miner, wallet, and pool runtime: shared ProductionV4 feature

The canonical `CMFD_RCNET_LAUNCH_CANDIDATE_V2` and signed single-producer RC
activation are pinned into the `production-rc` profile. The activation was
approved for an experimental release candidate only: it is not an external
audit, independent reproduction, or mainnet authorization. Builds still fail
closed unless `CMFD_BUILD_SOURCE_COMMIT` names the exact source commit being
built and all pinned network, proof, verifier, artifact, and signer identities
validate.

## Frozen ProductionV4 proof surface

The following version-1 documents are the compatibility authority for the
proof system. Their current SHA-256 values are included here so an activation
record cannot silently substitute another document.

| Authority | SHA-256 |
|---|---|
| `docs/consensus/production-v4-core-spec-v1.md` | `507075fb6d22b7ac0968508b18c48a09a017806e7d4e0454b71f8ae88440df84` |
| `docs/consensus/production-v4-core-vector-v1.json` | `c885ae499a65c5bb965e08f4894a0d2768d823b0e23979958f00e3db73e0b168` |
| `docs/consensus/production-v4-proof-algebra-v1.md` | `5a686ad518a7d957b8af908fb52cd58056e63da4dab578a40d4ef097654aaf33` |

The frozen core vector binds:

- algorithm version `4` and proof version `1`
- proof-system digest
  `e849e3bfc83f8f8dd0f1fc1100879417718ba2bffb92af5cd649b61c720675a3`
- model-manifest digest
  `68f6fe674f75a363c62c275ebb11fa74aa089e9bbde5bcb952ec35b8890b575c`
- fixed-record digest
  `2efd2c4244bbd7808547b85266987544233fbe339f445135b07843aa8893d45e`
- exact transparent proof size `12,025,320` bytes
- maximum transparent payload `13,631,259` bytes
- maximum proof frame `13,631,488` bytes
- maximum block frame `16,777,216` bytes

Changing any of these is a new proof-system revision, not an RC packaging
change.

## Pinned launch candidate and remaining activation inputs

The current version-2 launch candidate binds the following immutable RCNet-1
values:

- launch root
  `748f32c069e721221b8ba17df358eb35ec0e05d93f3a31ee0c1a135c87bb7b85`
- network ID
  `3e99d45959c19c0053d8e9fef34875b57b46a8a1ce330637daddab515bc7b92d`
- virtual-genesis hash
  `a572b6ce50978511ce8771db6603a602faccf3802cf0d4791c1ce4e467ba6b71`
- virtual-genesis time `2026-09-07T17:00:00Z`
- the ProductionV4 proof selector, proof-of-work limit, consensus limits,
  monetary policy, reward public destinations, and exact model-bank and
  fixed-record identities

The compile-time release gate validates those values rather than accepting the
old placeholder identity. Selection of the public reward destinations does not
close their governance, threshold custody, recovery, or beneficial-ownership
gate. Private reward keys must not enter source, build automation, the seed
host, or release artifacts.

The canonical activation inputs are the qualified source commit and manifest
identities, the exact fresh-process Python verifier script and report
identities, the signed producer approval, and the trusted release source commit
supplied by build automation. The staged verifier evidence is named
`PRODUCTION-V4-FRESH-PROCESS-VERIFIER.py`; it must be byte-identical to the
audited `production-v4-independent-verifier.py` entrypoint bound by the report.
For activation-schema compatibility, the existing
`fresh_process_verifier_binary_sha256` field hashes this exact executable
verifier program, which is currently that Python script.
These values are pinned to the preserved qualification bundle; they must not be
filled with ad-hoc test output or invented values.

## Operational seed and service endpoints

Bootstrap peers and service ports are operational discoverability
configuration, not part of the immutable version-2 launch identity. Rotating a
seed does not change the launch root, network ID, virtual genesis, consensus
fingerprint, or ledger rules.

The currently provisioned RCNet-1 cold-start endpoint is
`173.249.35.251:19444`. In a `production-rc` node or pool invocation:

- no `--peer` and no `--no-default-seeds` selects that compiled operational
  seed and permits its public address;
- one or more explicit `--peer` arguments replace the default seed set;
  explicit public peers also require `--allow-public-peers`; and
- `--no-default-seeds` leaves the peer set empty when no explicit peer is
  supplied. The seed service uses this mode so it does not dial itself.

Peer exchange can provide additional peers after first contact, so the seed is
a cold-start aid rather than a permanent authority or consensus dependency.
The initial host handoff staged the system service without enabling it. A later
read-only check on September 19, 2026 confirmed the deployed RCNet service active,
with healthy storage and height 92. That observation is RC operational evidence,
not mainnet qualification; the October mainnet service remains separate.

The seed's 300 GB disk is suitable only for a bounded RC rehearsal. At the
measured 12,025,320-byte proof and 60-second target spacing, proof payload alone
grows by about 16.13 GiB per day; the 16 MiB block ceiling would permit about
22.5 GiB per day. Because `blocks.log` is not pruned, the observed-size budget
is approximately 15 days after operating-system, artifact, and safety
headroom, not long-term retention. A bounded retention/pruning design or a
larger storage plan remains required before long-running operation.

## Canonical activation evidence

`CMFD_PRODUCTION_V4_RC_SINGLE_PRODUCER_ACTIVATION_V1` is the RCNet-1 activation
schema. Its JSON encoding is produced only by
`canonical_production_v4_activation_evidence_json` and binds:

- exact bank and fixed-record identities
- qualification source commit
- qualification manifest SHA-256
- exact fresh-process Python verifier script SHA-256
- fresh-process verifier report SHA-256
- all three normative specification SHA-256 values
- trusted build source commit
- `RCNet-1` and `ProductionV4`

The trusted build commit is supplied by release automation through
`CMFD_BUILD_SOURCE_COMMIT`; it is not embedded as a self-referential source
constant.

## RC activation policy and later independent reproduction

The RCNet-1 pin uses an explicit single-producer approval contract. The signed
declarations state `experimental_release_candidate_only: true` and state that
independent reproduction, external audit, and mainnet authorization are false.
The finalizer accepts that contract only for the RC schema; the existing
dual-party production contract remains separate.

Before mainnet consideration, a second clean environment must reproduce:

1. The model bank and fixed artifact record from the documented inputs.
2. All byte counts, BLAKE3 digests, and SHA-256 digests.
3. The proof-system, model-manifest, and fixed-record digests.
4. Every expected value and rejection case in the canonical core vector.
5. One fresh-process known-valid proof verification and the required mutation
   rejection set.
6. The exact qualification manifest and verifier report.

The reproducer records OS, architecture, compiler versions, source commit,
commands, inputs, outputs, and hashes. For a later dual-party activation, the
original producer and independent reproducer complete the role-separated,
two-phase signature procedure in
[`production-v4-activation-approvals.md`](production-v4-activation-approvals.md).
An unsigned report, two signatures from one identity or key, or signatures over
the wrong activation phase cannot satisfy the release gate.

`scripts/production-v4-reproduction.py` packages those checks into one bounded,
fail-closed run. It authenticates the frozen specifications and core vector,
streams SHA-256 and BLAKE3 over every generated artifact, validates the fixed
record and complete model bank independently of the Rust verifier, and requires
one full cryptographic proof verification before it creates a canonical report.
The output is create-new and must be signed separately by the reproducer.

The preserved RC qualification is producer-generated and must be described as
such. It demonstrates full cryptographic proof verification for the pinned
candidate, but must not be presented as independent reproduction or an external
audit.

Without `--attest-fresh-generation`, the report is explicitly marked
`reproduction_complete: false`; that mode is useful for a producer baseline but
cannot satisfy this gate. A second operator uses a clean output directory,
passes every exact generator command through repeated `--generation-command`
arguments, and adds `--attest-fresh-generation` only after those commands have
completed in that environment.

## Build and test gates

Safe local validation uses bounded build concurrency:

```powershell
$env:CARGO_BUILD_JOBS = '4'
cargo test -p cmfd-node --lib --features production-v4
cargo test -p cmfd-node --lib --features production-v4-testnet
cargo test -p cmfd-miner --features production-v4-testnet
cargo test -p common-foundry-wallet --lib --features production-v4-testnet
cargo clippy -p cmfd-node --features production-v4-testnet --all-targets
cargo clippy -p cmfd-miner --features production-v4-testnet --all-targets
cargo clippy -p common-foundry-wallet --features production-v4-testnet --all-targets
```

The positive RC gate is also mandatory:

```powershell
$env:CARGO_BUILD_JOBS = '4'
$env:CMFD_BUILD_SOURCE_COMMIT = '<trusted lowercase source commit>'
cargo check -p cmfd-node --features production-rc
```

That command must succeed only when the trusted source commit is bound to the
pinned RC activation evidence. Missing, malformed, or mismatched activation
data must still stop the build before a node can open storage.

## RCNet-1 rehearsal acceptance

After the identity and reproduction gates pass, RCNet-1 must demonstrate:

- independently operated bootstrap and secondary nodes
- clean Windows and Linux node and wallet installation
- clean Windows and Linux miner installation
- peer discovery, catch-up, restart, and reorganization recovery
- pool share accounting, block submission, maturity, payout, and reorg recovery
- sustained load at the ProductionV4 resource envelope
- malformed and oversized network traffic rejection
- deterministic fresh-process verification of known-valid and mutated proofs
- signed, reproducible binary-only release artifacts with checksums, SBOM, and
  provenance
- documented backup, restore, update, rollback, incident, and key-rotation
  procedures

Provisioning or staging one seed host does not satisfy these items. Acceptance
requires preserved results from the independently operated node, clean package
installs, live discovery, migration, abrupt-power-loss recovery, update and
rollback rehearsals, and the applicable external cryptographic, custody, and
implementation audits. Local harness output is preparation for those runs, not
a substitute for named-operator evidence.

The operator procedures and evidence requirements are defined in
[`incident-response.md`](incident-response.md) and
[`production-key-operations.md`](production-key-operations.md). Source review
can qualify the procedures; RCNet must still execute the listed drills with
named operators, real target hosts, non-production rehearsal keys, and
preserved evidence.

Offline block-log inspection and evidence-preserving partial-tail recovery are
specified in [`storage-recovery.md`](storage-recovery.md). RCNet qualification
must exercise healthy inspection, interrupted-append quarantine and recovery,
hard refusal of checksum and record-chain corruption (including losing
branches), linear and retained-fork checkpoint restart, post-restart reorgs,
and corrupt-checkpoint fallback to full replay.

Authenticated release transition testing is specified in
[`update-rollback-qualification.md`](update-rollback-qualification.md). The
harness authenticates both binary-only releases before execution, proves
interrupted-update retention, candidate restart, rollback, and reapply, and
reauthenticates both inputs before emitting evidence. CI qualifies the harness;
the RCNet gate still requires real signed-package runs on clean Windows and
Linux hosts.

The first wallet-custody increment is specified in
[`wallet-custody.md`](wallet-custody.md): network-bound encrypted backups,
strict authenticated restore, encrypted live-key storage, data-directory
locking, RCNet plaintext-key refusal, and no-overwrite semantics. The guided
GUI now covers create/unlock, migration, backup, restore, lock, and relock. An
independent custody review remains part of the RCNet acceptance work.

Mainnet activation is a separate decision after the full rehearsal evidence,
independent audits, and launch operations review are complete.

## Deterministic pool qualification

Before the full-GPU RCNet endurance exercise, run the pool protocol,
accounting, worker-boundary, strict-lint, dashboard-test, and dashboard-build
gate in one clean source checkout:

```powershell
$commit = git rev-parse HEAD
python scripts/production-v4-pool-qualification.py `
  --source-commit $commit `
  --operator '<operator>' `
  --platform-label windows-x86_64 `
  --log-directory D:\CommonFoundry-RC1\reports\pool-windows-logs `
  --output D:\CommonFoundry-RC1\reports\pool-windows.json
```

Run the same script natively on Linux with `python3`. `--rust-only` records a
core-only result when the dashboard was already qualified from the same source
commit. The harness selects the complete host-qualified Rust 1.94.1 toolchain
used by CI instead of a machine's moving or ambiguous default. The report deliberately leaves
`full_gpu_endurance_gate_met` false; only the live RCNet pool exercise can close
that gate.
