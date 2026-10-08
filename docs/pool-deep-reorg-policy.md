# Pool deep-reorganization policy

Owner decision, September 22, 2026: **pause affected automatic payouts and
reconcile the shortfall**. Do not silently recover losses from future miners'
earnings.

Implementation status: implemented in the shared node/pool source, with isolated
reference-chain tests on Windows and Linux. **Not deployed to the live RC pool.**
This is internal accounting validation, not a final signed-mainnet-package or
ProductionV4 GPU qualification.

Required behavior:

1. Detect when a reward already credited/distributed to PPLNS participants loses
   its canonical, mature backing, including after restart.
2. Persist the incident and identify the affected recipients and accounting.
3. Stop new affected automatic payments and retries without releasing reservations
   in a way that permits duplicate payments. Already-broadcast transactions cannot
   be recalled from other nodes; their actual chain/mempool state must still be
   reconciled and reported accurately.
4. Preserve earned-credit history. Do not automatically debit unrelated miners or
   apply a hidden future-earnings levy.
5. Provide a controlled operator reconciliation path, backed by a fresh chain tip,
   exact ledger state and funding checks. Restart must not clear a hold by itself.
6. Test orphaning after maturity, after credit distribution and after payment,
   chain restoration, duplicate/repeated reorg events, restart persistence and
   races with payment preparation/submission.

This decision does not change the currently running RC pool's fee, ledger or
wallet. It does not approve an actual ledger adjustment or money movement.

## Implemented behavior

- A distributed PPLNS reward that becomes orphaned, unknown, or falls below
  coinbase maturity creates a durable incident for its frozen recipients.
- Reconciliation, incidents and automatic payouts wait while the node is below
  the chain height the ledger last reconciled against, as after a restart on a
  node that is still catching up. Fewer confirmations from a node that is
  merely behind are not treated as a reorganization; the pool logs the two
  heights and resumes once the node reaches the ledger's height.
- A pool block the node no longer holds is `unknown` while the chain could
  still change at its height. Once it is at or below the prune point, or six
  coinbase maturities deep, it is treated as orphaned and retires to the
  archive like any other orphan, so blocks lost with a dropped branch do not
  stay unknown forever.
- Holds stop new payments and automatic retries to those recipients. Chain and
  mempool observations still update; already-broadcast payments cannot be recalled.
- Signed payments retain their exact bytes and credit reservations if their
  inputs disappear. Held inputs are excluded from other automatic payments.
  Legacy `abandoned` signatures are held for explicit manual review, not reused
  as permission to issue a replacement.
- During incident handling, coverage includes **all** outstanding miner credits,
  pending payment fees and one configured fee per remaining unreserved account.
  Only mature, pool-owned chain UTXOs count. Inputs committed to unrelated
  mempool transactions or exchange withdrawal reservations do not count.
  Insufficient shared funding creates a pool-wide automatic payout hold.
- Unaffected recipients can continue when the pool is fully backed. Restored
  funding or a restart alone never clears an existing hold. No credit is debited,
  no future miner levy is applied, and no fee setting is changed.
- The public dashboard shows holds, unreserved held credit and reserved pending
  payments. It does not expose operator notes or offer a resume button.

## Offline operator workflow

1. Stop the pool and all node/wallet processes using its data directory. Retain
   a complete, consistent backup first. Do not enable a second instance against
   a copied old ledger; node and ledger locks prevent same-directory concurrent use.
2. Use the **same executable, network, model/verifier flags, wallet-passphrase
   file and payout fee** as the pool service. Replace its `pool-serve` subcommand
   with `pool-payout-status`; do not retain pool-serve-only flags. These commands
   are offline and do not connect peers, sign, submit or rebroadcast payments.
3. Inspect the reported network, chain tip, ledger generation, affected recipients,
   shortfall and `blocking_signed_transactions`. A local node may be behind its
   peers: synchronize normally before stopping for final inspection, and check
   the expected network tip independently.
4. Reconcile funding and signed-payment history. A separate, explicitly authorized
   operator top-up may be needed. This command does **not** fund the wallet or
   authorize an external transfer. Sync any newly confirmed funding, stop, and
   inspect again.
5. Only after review, pass the exact inspected tip/generation to reconciliation.
   It refuses stale state, insufficient funding, invalid/conflicting signed
   payments and unresolved legacy abandoned payments. It records an operator note
   locally, resolves the existing incidents and sends nothing.
6. Restart the usual pool service. It checks backing again before settlement;
   a subsequent reorg/shortfall creates a fresh hold.

Command skeletons (replace angle-bracket placeholders; include the service's
normal global model/verifier/wallet options before the subcommand):

```text
cmfd-node --data-dir <existing-pool-data> <runtime-options> pool-payout-status --pool-payout-fee-atoms <configured-fee-atoms>

cmfd-node --data-dir <existing-pool-data> <runtime-options> pool-payout-reconcile --pool-payout-fee-atoms <configured-fee-atoms> --expected-tip <64-hex-inspected-tip> --expected-ledger-generation <inspected-generation> --note "Reviewed funding and outstanding signed payments" --acknowledge-reconciliation
```

On Windows invoke the verified `cmfd-node.exe` using PowerShell's `&` when the
path is quoted. Amounts in the report are decimal **atomic-unit strings**, not
floating-point CMFD. The tool requires an existing `pool-ledger` below the
selected node data directory; a typo does not create a new wallet/empty ledger.
A pool started with `--pool-ledger-max-bytes` needs the same value on both
commands, or they refuse the oversized snapshot exactly as `pool-serve` would.
To inspect a copy of a running pool's ledger, copy the two snapshot files
before the payout guard file, or stop the pool first: a guard copied before a
newer snapshot is refused as older than or conflicting with that snapshot.
Library integrations with custom ledger locations must retain that layout or
provide an equally locked operator workflow.

## Storage and recovery boundaries

Protected ledgers include `pool-ledger-payout-guard-v1.json`. The guard records a
write-ahead generation and snapshot checksum, is synchronized before snapshot
replacement, and requires an exact matching snapshot at restart. A missing/torn
latest snapshot or guard stops settlement instead of falling back to old payout
state. A persistence failure also stops further in-process accounting/payouts.
Old valid snapshots are migrated on open without changing credit amounts.

Keep the entire stopped `pool-ledger` directory, including the guard, together.
**Never delete the guard, mix snapshot generations, downgrade to an older pool
binary, or blindly restore an older ledger to bypass a hold.** Older binaries
do not enforce this protection. The guard detects interrupted/local partial
rollback, not malicious replacement of the entire directory with a coherent old
backup. Any backup restore must be reconciled against subsequent signed and
on-chain payment history before automatic settlement is enabled.

There is intentionally no force-clear, credit-forgiveness, replacement-payment
or automatic shortfall-recovery command. If an old signed payment is invalid
on the current branch, adding money alone does not make it safe to discard:
its original inputs might return on another reorg. That case stays paused for
a separate, reviewed recovery plan. Incidents are bounded at 4096; exceeding
that bound fails closed instead of dropping audit history.

## Evidence and remaining rollout work

Tests cover credited reward loss, funded/unfunded holds, actual paid-reward
reorgs, restart persistence, restored backing requiring explicit resume, repeated
reorgs without duplicate credit/payment, exact transaction retry, stale operator
requests, held input exclusion, legacy abandoned signatures, exclusive ledger
locking and corrupt/missing/torn persistence. Dashboard tests cover both scoped
and global holds, old API compatibility, and a fresh snapshot clearing the banner.

Still required before relying on this in service: package these changes, rehearse
the commands with the packaged ProductionV4 runtime and disposable wallets,
retain a consistent stopped backup, and perform an explicitly authorized pool
upgrade. Do not treat the source tests as evidence of a live rollout.
