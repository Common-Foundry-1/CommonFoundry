# Exchange custody v0.5 internal adversarial review

Status: **internal review candidate; not an independent external audit**.

This report records the adversarial review performed while building the
exchange-custody v0.5 candidate. It is a source-review and software-test
artifact. It is not an audit opinion, HSM certification, packaged-host
qualification, physical power-loss result, or approval to hold real value.

## Review verdict

The candidate is suitable for technical diligence and an independent external
audit. Production custody remains blocked by the open P1 gates below. An
exchange must not infer production readiness from a passing unit-test matrix or
from this report.

## Implemented security boundary

- The runtime persists `Prepared`, requires the resulting anchor to be pinned,
  persists `ReleaseAuthorized`, and requires that second anchor to be pinned
  before exporting the signing package or completing a release.
- Canonical external signer packages and responses bind the network, genesis,
  consensus fingerprint, policy, keyring, prepared and release-authorized
  anchors, exact transaction inputs, decision, approval, and signer capability.
- M-of-N approval signatures authorize actions. Consensus still requires one
  BIP340 signature for each input. Any threshold control of one spend key must
  live behind one independently reviewed aggregate external signer key.
- The encrypted keyring can move from an imported local key to a mixed
  legacy-local/external stage and then, after guarded sweep and depth checks, to
  an external-only runtime configuration. Software cannot prove that every
  backup or HSM share was destroyed.
- Rolling policy accounting uses the node's local time captured after runtime
  locks, persists that accounting time in terminal state, and rejects approval
  lifetimes longer than 900 seconds.
- v2-to-v3 migration is exact-plan/apply and charges every imported historical
  release at the bounded local cutover time. Migration fails instead of
  grandfathering old debits outside the new rolling window.
- The retained block log is fully scanned before a cached startup snapshot is
  accepted, so a changed, reordered, or deleted middle record cannot hide
  behind a matching terminal record.
- The journal, migration, cancellation, compaction, and recovery paths are
  fail-closed at their modeled interruption boundaries.

## Resolved review findings

### P1: pre-authorization signer-response replay

The external response did not originally commit to the durable
`ReleaseAuthorized` result. The response and expected signing context now bind
the release-authorization digest, including the resulting anchor and the exact
terminal decision and approval. A response made for the earlier `Prepared`
state is rejected.

### P1: signer-selected time could weaken rolling limits

Signed decision time remains audit evidence, but it no longer controls the
rolling debit window. A separate durable local accounting time is captured and
validated. Native records enforce the bounded delta, active policy events must
match their terminal records exactly, and migration debits are charged at the
local cutover watermark.

### P1: expiry could cross while waiting for a runtime lock

Release and cancellation capture current time only after the custody and live
node locks are held. This removes the pre-lock stale-time window. A deterministic
lock-contention regression remains desirable as P2 assurance.

### P1: cached startup snapshot did not cover the retained log interior

Startup now scans and authenticates the full retained block log before accepting
the cached snapshot, comparing record count, length, and terminal digest. The
tampered-middle-record regression passes.

### P1: host ACL policies did not bind every authority

The packaged-host qualifiers use explicit authority allowlists, reject
unexpected owners and effective or inherited access, reject unsafe writable
ancestors, and treat fixture qualification only as test evidence. The actual
installed Windows and Linux packages still require live qualification with
their real service and control identities.

## Open P1 production blockers

1. **Released-record retention and epoch rollover.** Canceled records can be
   authenticated, archived, and compacted. Released records cannot yet be
   archived, and the authenticated journal cannot roll to a new epoch. Capacity
   telemetry and warnings expose the finite limit but do not solve exhaustion.
2. **Mature v2 migration procedure.** If all historical v2 releases charged at
   cutover exceed one v3 rolling window, migration intentionally fails. A
   separately reviewed freeze-and-cutover procedure is not implemented. Limits
   must not be raised merely to force a migration through.
3. **Vendor signer qualification.** No HSM, MPC, FROST, MuSig, transport,
   attestation, key ceremony, quorum failover, disaster recovery, or firmware
   combination has been independently reviewed or certified against this
   protocol.
4. **Packaged target hosts.** Fixture and development-host checks do not qualify
   the exact Windows and Linux package, installer, filesystem, service account,
   control identities, upgrade path, backup agent, endpoint security software,
   or recovery environment selected by an exchange.
5. **Live and physical rehearsals.** Software copy-only fault injection is not a
   physical abrupt-power-loss test. A representative target storage/controller
   stack must pass staged live-data migration and externally witnessed abrupt
   interruption/recovery rehearsals using non-production keys.
6. **Independent review.** A qualified external auditor has not reviewed the
   custody implementation, cryptographic protocol, dependencies, operations,
   signer, target hosts, or the disposition of these findings.

## Open P2 assurance and operational findings

- Canonical signer-response bytes are verified during completion but are not
  retained in the journal. The signer/coordinator must preserve the exact
  response set in independently controlled immutable evidence until journaled
  response commitments are implemented.
- External-key retirement and quiescence hashes are operator assertions, not
  HSM-authenticated destruction attestations. The legacy wallet artifact must
  remain quarantined offline and legacy addresses must be monitored.
- Peer-only mempool transactions, future deposits to a retired address, and a
  sufficiently deep reorganization cannot be prevented by the local sweep
  checks.
- A deterministic test that holds the runtime lock across an approval-expiry
  boundary is still desirable even though the production lock/time ordering is
  correct.
- The terminal representation changed while v3 was an unreleased development
  format. Any experimental snapshot produced by the earlier v3 layout is
  unsupported and must not be reused. Before an RC, confirm that no real-value
  state depends on such a snapshot.

## Evidence required to close the external gates

- Signed protocol-conformance, negative-path, failover, ceremony, rotation, and
  recovery results for the selected HSM or aggregate threshold signer.
- Passing ACL reports from every exact packaged Windows and Linux host, with
  independently reviewed UID/GID/SID allowlists and installed paths.
- Checksummed stage, interruption, restart, rollback-anchor, and recovery
  evidence from representative storage, including a witnessed physical power
  cut rather than process termination alone.
- A reproducible source snapshot, manifest, test transcript, findings register,
  remediation retest, and signed final opinion from an independent qualified
  auditor.

Until those artifacts exist and the P1 design blockers are resolved, the
correct status is **technical-diligence candidate, not production custody**.
