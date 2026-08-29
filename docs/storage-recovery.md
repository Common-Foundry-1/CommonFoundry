# Storage inspection and partial-tail recovery

Common Foundry stores accepted blocks in an authenticated append-only
`blocks.log`. Each V2 record has a checksum and commits to the complete digest
of the preceding record. The node synchronizes a record before committing its
validated state transition in memory, then deterministically rebuilds state
from the log at startup.

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
arbitrary corruption, or replace offline backups. Production snapshots,
pruning, and bounded-startup qualification remain separate mainnet gates.
