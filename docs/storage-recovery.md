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
startup checkpoint for an exact linear active-chain log. A clean node or pool
shutdown refreshes it; an operator can also request one explicitly:

```text
cmfd-node --data-dir <node-data> storage-checkpoint
```

The checkpoint contains the canonical chain state and compact fork index,
binds the immutable network fingerprint, exact block-log length, terminal
record digest, and every cached record locator, and has a domain-separated
BLAKE3 integrity digest. Startup rechecks the retained log's file identity and
the complete terminal record before using it. A missing, stale, truncated,
corrupt, wrong-network, or non-linear checkpoint is ignored and the node falls
back to full deterministic replay. The status field
`startup_snapshot_used` reports which path opened the node.

This is a local crash-safe cache, not a consensus state root. It does not
protect against an attacker able to replace both node storage and the cache,
and it intentionally does not prune `blocks.log`. Side-branch-capable
snapshots, historical serving policy, pruning, background log scrubbing, and a
long-history bounded-startup measurement remain mainnet gates.
