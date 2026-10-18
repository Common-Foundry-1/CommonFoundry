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
explorer's transaction location index and address history, bound to the
newest record they cover by its complete digest. Since cache format 2
(1.0.16) each address entry also holds its activity facts: transaction ID,
timestamp, kind, received atoms, received outputs and spent inputs. They are
derived from a validated or authenticated block when it is indexed, so an
address page reads no block bodies. The loader checks every address row
against the fork index and the transaction section and falls back to the
full scan on any mismatch; beyond that, the facts carry the same local trust
as the checkpoint's UTXO set. The cache is refreshed every 64 records, at
clean shutdown and by `storage-checkpoint`.

Startup rechecks the retained log's file identity and reads and
authenticates the complete terminal record. With a valid index cache it then
reads only the records the cache does not cover, so a restart takes seconds
however long the history is. The older records are re-checked afterwards by a
background history scrub at a bounded rate (96 MiB/s), newest first: each
record's header, acceptance time, complete digest, offset and link to its
predecessor must match the cached locator. A mismatch faults storage, so the
node stops accepting and serving blocks, and moves `startup-state.*.bin` and
`startup-index.bin` aside as `*.invalid-<time>`. The next start then scans or
replays the log, which stays authoritative, and refuses a damaged record.
Every block a node serves or uses is still authenticated when it is read,
before and after the scrub. Without a valid index cache, startup scans the
complete retained record-digest chain and compares every cached locator
first, as before.

### Index cache format 2: upgrade and rollback

The first 1.0.16 start on a data directory written by 1.0.15 or older loads
the format 1 `startup-index.bin` without a full scan and rewrites it as format
2 straight away. Its address entries load without facts, as hints. Until the
history scrub reaches a hint's block, an address page that shows the entry
reads and authenticates that block, as older versions did for every entry,
and then fills the facts of every key in it, so each block is read this way
at most once. The scrub decodes every record that holds hints once it passes
the checks above, and fills them. A hint record that cannot be decoded faults
storage like any other mismatch. Because the scrub runs newest first, the
entries a busy key's first pages show are filled within seconds; on an
archive node of about 17,600 blocks of 12 MB the whole pass takes about 37
minutes. On a pruning node, a prune does not mark the history verified while
hints remain, so the scrub still runs its pass over the pruned log.

The pass ends with the `retained block history verified` log line; its
`filled_address_entries` field counts the entries it filled. Like the `block
log scan progress` lines of a full scan, it goes to the daily file log
`<data-dir>/logs/cmfd-node.log.<YYYY-MM-DD>`; the console and the systemd
journal show it only with `-vv` or `CMFD_LOG=info`. A running node also
reports `"history_scrub_complete": true` from `GET /v1/status` once the pass
is done.

`pool-serve` does not run the history scrub, as before, and serves no
explorer pages, so its hints stay hints and nothing reads them. On a pruning
pool node `history_scrub_complete` therefore stays false after a prune, where
1.0.15 set it after every prune; a pool node that does not prune already
reported false after any fast start.

On an explorer origin, the hint window means that a crawler which outruns the
scrub can still make the node read up to 20 full blocks per address page under
its lock, and at worst the whole archive once more. Choose before upgrading:

- Upgrade in place, and keep address pages away from the node until the
  first scrub pass is done, except the Worker's `<tip>.1.0` supply cursor,
  which reads no blocks. Pages for busy keys are filled first, but the first
  page of a key last active long ago shows old blocks, which the scrub
  reaches last; or
- Move `startup-index.bin` aside before the first 1.0.16 start (it doubles as
  the rollback copy below). The node then rebuilds every fact with a full scan
  that logs `block log scan progress` every 1,000 records, about 30-40 minutes
  on an archive of 17,600 blocks of 12 MB, during which it serves neither RPC
  nor peers. There is no hint window afterwards.

Facts loaded from a format 2 cache get the same local trust as the startup
snapshot's UTXO set. The cache's digest catches accidental damage, and the
loader falls back to a full scan when a row contradicts its location (a
coinbase row whose txid is not that block's coinbase id, a transaction row
whose txid is not indexed at that position, impossible kinds or counts). An
edited and re-digested amount or timestamp still loads, and the scrub does
not re-derive entries that already have facts: only hints are checked against
their blocks. To rebuild every fact from the log, move `startup-index.bin`
aside before a start.

Older versions refuse format 2 and then scan the whole retained log on
startup. To keep a rollback fast:

1. Before the first 1.0.16 start, copy `startup-index.bin` aside, for example
   as `startup-index.bin.v1`. Do this on every node whose rollback must be
   fast, starting with the explorer origin.
2. Before starting 1.0.15 or older, restore that copy as
   `startup-index.bin`. The older node accepts a cache that covers fewer
   records than the log, as long as the log was not pruned in between, and
   reads only the records appended since; the longer 1.0.16 ran, the more it
   reads at that start.
3. Without the copy, the older node's full scan of an archive (about 30-40
   minutes for 17,600 blocks of 12 MB) prints no progress. It is not hung;
   do not stop it.
4. Keep the explorer Worker's `<tip>.1.0` supply cursor at least until the
   first scrub pass after the upgrade is done (the log line or status field
   above). It stays valid afterwards.

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
