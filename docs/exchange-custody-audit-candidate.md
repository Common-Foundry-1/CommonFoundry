# Exchange custody v0.5 audit candidate

Status: **audit candidate; no independent external audit has been completed**.

This document defines the source and evidence handed to an independent custody
auditor. It is not an audit opinion, certification, production-readiness claim,
or substitute for testing the selected HSM, operating system image, filesystem,
service identities, and recovery hardware.

## Scope

The review target is the `cmfd-node` production-v4 exchange-custody v0.5 path:

- encrypted versioned wallet keyring and explicit key lifecycle transitions;
- local/external signer routing and canonical signing packages/responses;
- action-distinct threshold approval policy;
- prepared, release-authorized, released, cancelled, and failed withdrawal
  transitions;
- authenticated append-only journal, external rollback anchor, cancellation
  tombstones, compaction, and restart recovery;
- exact plan/apply v2-to-v3 migration and archive procedures;
- RPC authentication and least-privilege filesystem checks;
- package-host ACL qualification and copy-only failure-injection rehearsal.

Consensus, peer-to-peer networking, proof generation, market operations,
exchange solvency, and third-party signer implementations are outside this
custody review except where their interfaces form a trust boundary.

## Security properties to test

1. No withdrawal is signed before an action-specific approval reaches its
   configured threshold, remains inside its signed validity window, and is
   bound to the exact policy, request, and durable journal state. Approval
   lifetime is bounded and rolling limits use durable local submission time,
   not a signer-selected historical timestamp.
2. A signing package is unavailable until `ReleaseAuthorized` is durable and
   the exact resulting anchor has been independently pinned.
3. Every local or external signature is bound to the exact package, signer
   capability, key, input, network, consensus fingerprint, genesis, policy,
   keyring anchor, prepared anchor, ReleaseAuthorized anchor, decision, and
   approval digest.
4. Missing, duplicate, reordered, replayed, foreign, malformed, oversized, or
   partially covering external signer responses fail closed.
5. Restart, torn-tail recovery, migration interruption, cancellation, and
   compaction cannot silently release reservations, revive cancelled requests,
   replace exact transaction bytes, or accept rollback/divergent history.
6. The node service cannot modify external control material and cannot expose
   exact signing-package bytes through ordinary status documents.
7. Migration and archive apply operations accept only the exact independently
   retained plan and source state that were reviewed.

## Trust boundaries and non-goals

- The integration credential routes an RPC request; it does not approve a
  custody action.
- Approval M-of-N controls authorize actions. They do not change Common
  Foundry's per-input BIP340 consensus rule.
- A threshold service may hold one aggregate BIP340 public key behind the
  external signer boundary. FROST, MuSig, MPC, vendor firmware, remote
  transport, attestation, quorum availability, and key ceremony are not
  implemented or certified here and require a separate specialist review.
- Signing-package input values are authenticated claims from node state, not
  portable UTXO proofs. A remote signer enforcing value/fee policy needs an
  independent trusted chain source or proof.
- The external anchor is independent only when a separately controlled system
  owns and persists it. A file beside node-owned data is not an independent
  rollback boundary.
- Software fault injection is not proof of physical power-loss behavior. The
  selected package, filesystem, storage/controller cache, service manager, and
  recovery procedure require target-host exercise.

## High-value adversarial review areas

- canonical encoding, length/count bounds, duplicate handling, domain
  separation, signature malleability, and signed-time semantics;
- TOCTOU windows between prepare, authorization, package export, signing,
  assembly, durable release, and transaction submission;
- stale or compromised policy/keyring/external-anchor replacement;
- crash consistency at every rename, fsync, journal append, and compaction
  boundary, including directory durability on Windows and Linux;
- legacy migration equivalence, idempotence, partial-output cleanup, and
  source/output aliasing;
- local-secret zeroization, passphrase lifetime, core dumps, swap, backups,
  logs, RPC responses, and error strings;
- ACL inheritance, owner/administrator bypass, symlink/reparse-point behavior,
  writable ancestors, packaged-service identities, and installer upgrades;
- operator ambiguity, split-brain coordinators, response replay, stale HSM
  policy, disaster recovery, and dual-control bypass.

## Reproduction baseline

These commands apply only to the separate custody audit source archive produced
by `scripts/build-exchange-custody-audit-bundle.ps1`. After verifying and
extracting that archive, run them from its single source root with the
repository MSRV or newer stable Rust. The docs/tools integration kit is not a
source tree and cannot run this baseline:

```text
cargo test -p cmfd-node --lib --features production-v4-testnet
cargo test -p cmfd-node --lib --features production-v4
cargo check -p cmfd-node --all-targets --features production-v4-testnet
cargo clippy -p cmfd-node --all-targets --features production-v4-testnet -- -D warnings
cargo fmt --all -- --check
```

Run the packaged-host ACL qualifier with the real service/control identities
and material paths. Run the rehearsal script first in `Stage`, then physically
interrupt only that isolated copy during `Exercise`; never target production
keys or the production data directory.

## Evidence interpretation

Passing unit, integration, fixture-ACL, and software failure-injection tests
means only that the checked source satisfied those tests in the recorded
environment. Production custody remains blocked until all of these are true:

- the selected external signer or aggregate-threshold system passes its own
  conformance, security, failover, ceremony, and recovery qualification;
- every packaged Windows/Linux host passes ACL qualification using its actual
  service/control identities and installed paths; Linux evidence must show
  canonical UID/GID authorities, fully enumerable dedicated-group membership,
  no extended POSIX ACLs, no inheritable, permitted, effective, or ambient
  process capabilities or set-UID credential state, and the complete
  data/control ancestor chains;
- staged live migration and physical interruption/recovery rehearsals pass on
  representative target storage;
- an independent qualified auditor reviews this source, dependencies,
  cryptographic protocol, operating procedures, and resolved findings;
- the exchange accepts the residual risks and records its production change
  approval.

One known design blocker is intentionally not hidden by the bundle: v0.5 can
archive and compact Canceled records, but it cannot yet archive finalized
Released records or roll to a new authenticated journal epoch. The RPC reports
exact bounded-capacity headroom and warns below 1,024 estimated complete
releases, but alarms do not solve eventual exhaustion. An auditor must treat a
reviewed finality/reorg policy, released-record archive, and crash-tested epoch
rollover as required production scope rather than accepting a larger bound.

The v3 terminal format also changed during unreleased candidate development.
Any earlier experimental v3 snapshot is unsupported and must not be reused.
The auditor should require evidence that no real-value state depends on the
pre-change development representation before accepting the RC migration scope.

Canonical signer responses are verified during release completion and returned
as public evidence bytes, but the journal does not retain those exact response
frames. Until journaled response commitments are implemented, the exchange must
preserve the complete response set in independently controlled immutable audit
evidence; the auditor should test that operational evidence path.

## Bundle integrity

The separate custody audit source handoff produced by
`scripts/build-exchange-custody-audit-bundle.ps1` contains
`MANIFEST.sha256`. Its archive sidecar verifies the archive only after the
sidecar itself has arrived through an authenticated independent channel; a hash
delivered beside its payload is not proof of origin.
`MANIFEST.sha256` then verifies each included file. An auditor should check both,
reject unexpected archive paths, and preserve the verified archive as the
reviewed source snapshot. The builder accepts only source-like files from the
recursively selected source trees and rejects runtime wallet, keyring,
passphrase, and linked or reparse-point files and ancestors. It has no
external-evidence input at all. Test evidence must be secret-scanned,
checksummed, and transferred as a separate artifact so an arbitrary file can
never be smuggled into the source bundle or exposed through a low-entropy
content digest.

On an isolated review host, compare the archive SHA-256 with the independently
received sidecar, list and inspect every ZIP entry before extraction, extract
into a new empty directory, and verify every manifest line against the extracted
regular file. Reject absolute paths, `..` components, links, duplicate paths,
missing files, extra files, digest mismatches, or a manifest outside the single
expected bundle root.

The exchange integration bundle produced by
`scripts/build-exchange-integration-kit.ps1` is a different, non-source
artifact. It contains `MANIFEST.json` at the archive root with each payload
length and SHA-256, declares `production_ready: false`, and has a null signature
until the release owner signs the final archive digest under the published
release policy. It does not emit the audit archive's `.sha256` sidecar. Receive
the integration archive digest through an authenticated independent channel,
reject unexpected or duplicate paths, and verify every embedded manifest entry
before use.
