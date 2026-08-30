# Production incident response

This runbook defines the minimum response for a Common Foundry RCNet or
public-value network incident. It favors preservation, independently checked
recovery, and clear operator authority. A testnet rehearsal must exercise each
playbook before mainnet activation.

## Roles and authority

Every deployment records a primary and backup for these roles:

- **Incident commander:** declares severity, owns the timeline, and approves
  recovery.
- **Chain operator:** controls bootstrap nodes, public peers, and node storage.
- **Pool operator:** controls miner admission, the payout ledger, and pool
  custody.
- **Release operator:** verifies and publishes signed binary artifacts.
- **Communications owner:** posts one consistent public status and correction
  stream.
- **Evidence recorder:** preserves hashes, logs, commands, and decisions.

One person may fill several roles during RCNet, but every role and backup must
be named before the rehearsal begins. Key custodians and quorum rules come from
[`production-key-operations.md`](production-key-operations.md); an incident
commander cannot bypass them.

## Severity

| Level | Examples | Initial objective |
|---|---|---|
| SEV-1 | divergent valid tips, invalid proof or block accepted, release-signing or fixed-reward key exposure, unauthorized payout | stop further value movement and preserve independent evidence |
| SEV-2 | widespread sync failure, bootstrap outage, persistent pool accounting fault, authenticated storage failure | contain the affected service and restore a verified path |
| SEV-3 | isolated client failure, malformed-peer burst, failed download mirror, dashboard-only fault | keep healthy services available and collect a reproducible report |

Anyone operating a public component may declare a higher severity. Lowering
severity requires the incident commander and the relevant service owner.

## First 15 minutes

1. Record UTC detection time, reporter, affected network, release version,
   binary SHA-256, network fingerprint, local height, tip, and peer/pool
   endpoint.
2. Assign the incident commander and evidence recorder.
3. Preserve the original logs and data directory. Copy evidence to a
   create-new directory; do not edit or delete the source.
4. For SEV-1, pause release publication, mining submissions, and automatic
   payouts on affected infrastructure. Prefer the graceful pool controls.
5. Compare the observation with at least one independently operated node or
   clean release package before choosing a recovery action.
6. Open a timestamped incident record and log every command, operator, result,
   and artifact hash.

Secrets never enter tickets, chat, screenshots, command-line arguments, or the
incident archive. Record only public keys, destinations, certificate pins,
key fingerprints, and secret-store references.

## Evidence bundle

An incident bundle contains:

- incident identifier, severity, roles, UTC timeline, and current status;
- exact source commit, release tag, binary identities, and signed-release
  verification result;
- network ID/fingerprint, height, tip, cumulative work, and peer observations;
- process start identity, command arguments with secrets removed, exit status,
  and resource telemetry;
- immutable copies of relevant node, pool, wallet, updater, and CDN logs;
- SHA-256 for every included file and the bundle inventory itself;
- containment and recovery decisions, approvals, and validation results.

The evidence directory is read-only after closure. Large node data or proof
artifacts may be stored separately when their paths, sizes, hashes, and custody
are recorded in the inventory.

## Playbooks

### Consensus, proof, or chain divergence

1. Stop affected miners and gracefully stop affected pools. Do not submit a
   candidate whose proof or parentage is in question.
2. Preserve at least two disagreeing node data directories and their exact
   binaries.
3. Record block bytes, proof bytes, parent, target, work, network fingerprint,
   and validation result from each independent node.
4. Reproduce verification in a fresh process using the pinned release
   verifier. Mutation or fault tests run only on copies in an isolated
   environment.
5. Resume only when the disagreement is explained, the canonical recovery
   point is independently agreed, and the corrective release passes the full
   signed update/rollback qualification.

No operator manually edits a ledger tip or marks an unverified block valid.

### P2P outage, eclipse attempt, or resource abuse

1. Preserve peer observations, connection rates, ban/reputation state, and
   host/network telemetry.
2. Keep at least two independently administered peers reachable. Temporarily
   restrict public ingress only when required to protect chain progress.
3. Confirm network fingerprint, height, tip, and cumulative work directly with
   the independent peers rather than trusting a dashboard alone.
4. Test recovery through ordinary peer discovery, catch-up, restart, and reorg
   handling before reopening broad ingress.

### Pool accounting or payout incident

1. Run `POOL-STATUS` and record its authenticated process identity and active
   log.
2. Use `STOP-POOL` for a graceful ledger-preserving stop. Do not force-kill
   unless graceful shutdown is impossible and that fact is recorded.
3. Copy `pool-data` and `pool-tls` while stopped. Keep the TLS private key out
   of the evidence bundle.
4. Reconcile accepted shares, rejected shares, blocks, maturity, reorg state,
   credits, pending payouts, and on-chain transactions.
5. Restart only after ledger authentication succeeds and the dashboard agrees
   with the node and chain. Use `RESTART-POOL` after the recovery decision.

If payout correctness is uncertain, hold payouts while continuing only those
services that cannot change balances.

### Node storage incident

Stop the node and inspect before changing storage:

```text
cmfd-node --data-dir <node-data> storage-inspect
```

Only an authenticated partial final append may use the evidence-preserving
tail repair:

```text
cmfd-node --data-dir <node-data> storage-repair-tail \
  --quarantine-output <create-new-quarantine-path>
```

Checksum, record-chain, canonical-encoding, or complete-record corruption is
not auto-repaired. Restore a verified backup or resynchronize into a fresh
directory, retain the original evidence, and compare the recovered tip with an
independent node.

### Release or distribution incident

1. Pause publication and mirror promotion; preserve the downloaded bytes and
   HTTP metadata.
2. Verify the flat directory without private source access:

```text
python scripts/release_integrity.py verify-download \
  --stage <downloaded-release-directory> \
  --allowed-signers <trusted-allowed-signers> \
  --signer-identity <release-identity> \
  --ssh-keygen <trusted-ssh-keygen-path>
```

3. Compare GitHub and mirror bytes to the signed checksum manifest. A mirror
   may be restored only from the already authenticated immutable release.
4. If the release key may be exposed, follow the emergency transition in
   [`production-key-operations.md`](production-key-operations.md). Do not
   replace an existing release asset in place and reuse its version.

### Wallet or custody incident

1. Lock the wallet and stop its embedded services.
2. Preserve encrypted backups, public destinations, transaction IDs, and
   timestamps without copying passphrases into the incident bundle.
3. Determine whether the event affects one wallet, a pool wallet, or a
   consensus-fixed reward destination.
4. Recover or rotate only through the matching procedure in
   [`wallet-custody.md`](wallet-custody.md) and
   [`production-key-operations.md`](production-key-operations.md).

## Recovery approval

Recovery requires all of the following:

- the cause and affected scope are documented;
- preserved evidence has a complete hash inventory;
- the selected binary and artifacts pass signed-release verification;
- storage, node, pool, or wallet checks for the affected surface pass;
- height, tip, work, balances, and payout state agree with an independent
  source where applicable;
- replacement credentials or keys have completed their required quorum and
  distribution steps;
- rollback remains available; and
- the incident commander and relevant service owner approve a UTC restart
  time.

## RCNet qualification

The first RCNet rehearsal must preserve evidence for at least these drills:

1. bootstrap outage and independent-peer recovery;
2. malformed and oversized peer traffic with healthy progress preserved;
3. pool graceful stop, ledger backup, restart, and reorg reconciliation;
4. interrupted block-log append with quarantine and restart;
5. corrupted signed download rejected before execution;
6. signed candidate update, rollback, and reapply;
7. planned release-key transition rehearsal using non-production keys; and
8. encrypted wallet backup and recovery into a fresh data directory.

Each drill records start/end times, operators, commands, expected and observed
results, evidence hashes, and open follow-up items. A drill closes a gate only
when its expected result is observed on the target Windows or Linux host.
