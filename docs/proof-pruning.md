# Proof pruning

A Common Foundry block is about 12 MB, and almost all of that is its proof of
work. A node that has validated a block never needs that proof again, except
to serve the block to another node or to follow a reorganization through it.
Opt-in proof pruning drops the proofs of old blocks and keeps everything else:

```text
cmfd-node --data-dir <node-data> run --prune-keep-blocks 288 [other options]
```

The node keeps the newest `--prune-keep-blocks` active blocks in full. The
minimum is 288 (about 4.8 hours of blocks). Older blocks are rewritten as
pruned records of a few kilobytes that keep:

- the header (network, parent, transaction root, height, timestamp, target)
- the coinbase and every transaction
- the block ID and the size of the original block
- a proof summary: proof type, nonce, and work digest

Pruning changes nothing in consensus. Balances, deposits, transaction lookups,
the explorer, wallet history, and verbose `getblock` results stay the same.

## What a pruned node cannot do

- **Serve old blocks.** Peers syncing from the start need a full node. A pruned
  node does not advertise pruned blocks and declines requests for them without
  penalizing the peer. Seeds and relays should not prune.
- **Return raw pruned blocks.** `getblock <hash> 0` on a pruned block returns
  the error `block_proof_pruned`. Verbosity `1` and `2` still work and report
  the original block size.
- **Follow a reorganization below the prune point.** A block that builds on a
  pruned block other than the newest one is rejected with `below_prune_point`.
  This is why the keep window has a floor. It is far deeper than any
  reorganization the network has seen.
- **Get the proofs back.** Pruning is one-way. To return to a full node,
  restore a full backup or sync a new data directory from a full peer.

## When pruning runs

The node prunes at startup and then checks every 10 minutes while it runs.
A prune needs a saved chain state from a block that is already outside the
keep window. A pruning node saves one in `prune-candidates/` every 64 active
blocks, or every quarter of the keep window when that is larger. When the flag
is first turned on, the first prune therefore happens about
`--prune-keep-blocks` blocks later. After that, the node prunes once per
interval and holds between `N` and about `N` plus two intervals of full
blocks (288 to 416 at the minimum setting).

A prune rewrites the block log into `blocks.log.prune-tmp` and swaps it in
atomically. Keep enough free space for a second copy of the full blocks
that stay (around 5 GB at the minimum setting), plus a few KB per pruned
block. The rewrite runs without blocking the node; only the final swap
briefly holds it, and the swap waits for in-flight block reads to finish.
Each run prints or logs a report with the new prune height, the number of
blocks pruned, and the log size before and after.

Removing the flag stops further pruning. Blocks already pruned stay pruned,
and the node still opens and serves the log normally.

## Files

| File | Purpose |
|---|---|
| `prune-anchor-<height>.bin` | Chain state at the newest pruned block. **Required.** A pruned node refuses to start without it. Back it up with `blocks.log`. |
| `prune-candidates/*.bin` | Saved states for future prunes. Safe to delete; pruning waits for new ones. |
| `blocks.log.prune-tmp` | A prune in progress. Safe to delete while the node is stopped. |

Both state files are bound to the network and integrity-checked. A damaged
anchor stops startup instead of being guessed around. `storage-inspect` and
`storage-repair-tail` work on pruned logs.

## Reporting

`status` reports `prune_keep_blocks` and `pruned_height`, the height of the
newest pruned block. As in Bitcoin Core, exchange `getblockchaininfo` reports
`pruned`. When pruning is on or the log is pruned, it also reports
`pruneheight`, the lowest block whose raw bytes are still stored, and
`prune_keep_blocks`.

## Exchanges

An exchange node can prune. Deposits and withdrawals only read transactions,
which pruned blocks keep, and the 60-confirmation deposit rule is far inside
the minimum keep window. If your integration fetches raw blocks with
`getblock <hash> 0`, use verbosity 2 for blocks below `pruneheight`.
