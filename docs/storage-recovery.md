# Storage inspection and partial-tail recovery

Common Foundry stores accepted blocks in an authenticated append-only
`blocks.log`. Each V2 record has a checksum and commits to the complete digest
of the preceding record. The node synchronizes a record before committing its
validated state transition in memory, then deterministically rebuilds state
from the log at startup. On Unix, new data-directory, lock-file, block-log,
network-metadata, wallet-key, backup, quarantine, and repaired-log directory
entries are also synchronized so their names survive a completed operation.

An interrupted append can leave an incomplete final record. Normal startup
fails closed instead of guessing. With the node, wallet, and pool stopped, an
operator can inspect the structural record boundary without loading proof
artifacts or starting network services:

```text
cmfd-node --data-dir <node-data> storage-inspect
```

For mainnet, inspection and repair first resolve the authenticated launch
profile from the release-pinned plan and verified beacon beside the executable.
The compiled zero-genesis placeholder is never used as the first block's parent.
Keep `production-mainnet/MAINNET-PLAN.json` and the verified
`production-mainnet/LAUNCH-BEACON.json` with the matching release. If the beacon
must be reacquired after launch, use `cmfd-launch fetch --runtime <absolute-node-path>`
or restore the same public certificate from the recovery bundle. There is no
operator-supplied genesis override. Missing or invalid launch authority is
rejected before taking a data-directory lock or creating quarantine evidence.
These commands do not load model inputs or start network services themselves;
normal `status`/startup still performs the required consensus validation.

`healthy` means the log ends exactly after its last authenticated record.
`recoverable_partial_tail` identifies only an incomplete final header, block,
reversible-state delta, or checksum. A checksum mismatch, broken record-digest
chain, noncanonical block, duplicate block, or unknown parent remains a hard
error and is never classified as repairable.

Recovery is explicit and evidence preserving:

```text
cmfd-node --data-dir <node-data> storage-repair-tail \
  --quarantine-output <offline-path>/blocks.tail.quarantine
```

The quarantine path is create-new. The command copies and synchronizes the
exact partial bytes before truncating and synchronizing `blocks.log` back to
its last authenticated boundary. It holds the data-directory lock throughout,
rechecks the retained file identity and length before truncation, and performs
no action when the log is healthy. Keep the quarantine with incident records.

This repair handles only power-loss or interrupted-write tails. It does not
weaken authenticated replay, automatically discard a complete record, repair
arbitrary corruption, or replace offline backups.

## Fast-start checkpoints

After a full successful replay, the node writes a two-slot, network-bound
startup checkpoint for the canonical state and all retained branches. Every
accepted block refreshes it, including a nonwinning side-branch append that
changes the log without changing the active tip. A clean node or pool shutdown
also refreshes it; an operator can request one explicitly:

```text
cmfd-node --data-dir <node-data> storage-checkpoint
```

The checkpoint contains the canonical chain state and compact fork index,
binds the immutable network fingerprint, exact block-log length, terminal
record digest, and every cached record locator, and has a domain-separated
BLAKE3 integrity digest. Beside it the node keeps `startup-index.bin`, the
explorer's transaction and address location indexes bound to the newest
record they cover by its complete digest. It is refreshed every 64 records,
at clean shutdown and by `storage-checkpoint`.

Startup rechecks the retained log's file identity and reads and
authenticates the complete terminal record. With a valid index cache it then
reads only the records the cache does not cover, so a restart takes seconds
however long the history is. The older records are re-checked afterwards by a
background history scrub at a bounded rate: each record's header, acceptance
time, complete digest, offset and link to its predecessor must match the
cached locator. A mismatch faults storage, so the node stops accepting and
serving blocks, and moves `startup-state.*.bin` and `startup-index.bin` aside
as `*.invalid-<time>`. The next start then scans or replays the log, which
stays authoritative, and refuses a damaged record. Every block a node serves
or uses is still authenticated when it is read, before and after the scrub.
Without a valid index cache, startup scans the complete retained
record-digest chain and compares every cached locator first, as before.

When a checkpoint is not eligible, the node reconstructs the same state
through full deterministic replay. The status field `startup_snapshot_used`
reports which path opened the node; `history_scrub_complete` and
`history_scrub_verified_records` report whether every record present at
startup has been verified, by the startup scan or by the scrub.

Fork-aware loading recomputes cumulative work from retained targets, preserves
the first accepted winner on equal work, and reconstructs the active ancestry.
The restored state must agree with that winner, chain length, cumulative work
and active successor-header metadata. The last appended record need not be
on the winning branch. Corrupt losing-branch records are not ignored, and
invalid new blocks still pass through normal admission rules after restart.

This is a local crash-safe cache, not a consensus state root. It does not
protect against an attacker able to replace both node storage and the cache,
and it intentionally does not prune `blocks.log`. Use checkpoints created by
the matching local node or your own trusted backup, not untrusted third-party
state downloads. Historical serving policy, long-history bounded-startup
measurement and signed-package recovery remain separate qualification
requirements.

The [explorer resource qualification](explorer-resource-qualification.md)
separates synthetic index memory measurements, valid tiny-profile recovery
fixtures and real full-size proof checks. None alone closes the production
startup/recovery gate.

## Proof pruning

Opt-in [proof pruning](proof-pruning.md) rewrites old records without their
proofs. A pruned log also needs its `prune-anchor-<height>.bin` state file:
back the two up together. The inspection and tail-repair commands above
accept pruned logs.
