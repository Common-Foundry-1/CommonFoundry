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

The `production-rc` feature deliberately does not contain launch identities.
It stops in `cmfd-node/build.rs` before a runnable binary is produced. At the
time of this revision the first blocker is:

```text
production RC build gate: production RC network identity pin is absent
```

This is expected. Real launch values may enter source only after the decisions
and reproduction checks below are complete.

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

## Launch identities that remain to be selected

RCNet-1 cannot be enabled until each item below has a reviewed, final value:

1. Network ID.
2. Virtual-genesis hash and timestamp.
3. Proof-of-work limit and initial difficulty policy.
4. Steward and community reward destinations with documented custody.
5. Public bootstrap address and final RC ports.
6. Exact model-bank and fixed-record byte length, BLAKE3, and SHA-256 pins.
7. Qualification source commit and qualification manifest.
8. Fresh-process verifier executable and report identities.

The current repeated-byte identifiers, development reward destinations,
development proof-of-work limit, and RFC 5737 bootstrap address are explicit
placeholders. The build gate rejects them.

## Canonical activation evidence

`CMFD_PRODUCTION_V4_ACTIVATION_V1` is the canonical evidence schema. Its JSON
encoding is produced only by
`canonical_production_v4_activation_evidence_json` and binds:

- exact bank and fixed-record identities
- qualification source commit
- qualification manifest SHA-256
- fresh-process verifier executable SHA-256
- fresh-process verifier report SHA-256
- all three normative specification SHA-256 values
- trusted build source commit
- `RCNet-1` and `ProductionV4`

The trusted build commit is supplied by release automation through
`CMFD_BUILD_SOURCE_COMMIT`; it is not embedded as a self-referential source
constant.

## Independent reproduction gate

Before launch pins are inserted, a second clean environment must reproduce:

1. The model bank and fixed artifact record from the documented inputs.
2. All byte counts, BLAKE3 digests, and SHA-256 digests.
3. The proof-system, model-manifest, and fixed-record digests.
4. Every expected value and rejection case in the canonical core vector.
5. One fresh-process known-valid proof verification and the required mutation
   rejection set.
6. The exact qualification manifest and verifier report.

The reproducer records OS, architecture, compiler versions, source commit,
commands, inputs, outputs, and hashes. The original producer and independent
reproducer sign the resulting manifest separately.

`scripts/production-v4-reproduction.py` packages those checks into one bounded,
fail-closed run. It authenticates the frozen specifications and core vector,
streams SHA-256 and BLAKE3 over every generated artifact, validates the fixed
record and complete model bank independently of the Rust verifier, and requires
one full cryptographic proof verification before it creates a canonical report.
The output is create-new and must be signed separately by the reproducer.

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

The negative RC gate is also mandatory:

```powershell
$env:CARGO_BUILD_JOBS = '4'
$env:CMFD_BUILD_SOURCE_COMMIT = '<trusted lowercase source commit>'
cargo check -p cmfd-node --features production-rc
```

Until every approved identity is present, that command must fail before a node
can open storage.

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

Mainnet activation is a separate decision after the full rehearsal evidence,
independent audits, and launch operations review are complete.
