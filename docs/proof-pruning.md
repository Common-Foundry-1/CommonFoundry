# Proof pruning

A Common Foundry block is about 12 MB, and almost all of that is its proof of
work. A node that has validated a block never needs that proof again, except
to serve the block to another node or to follow a reorganization through it.
Proof pruning drops the proofs of old blocks and keeps everything else. It is
on by default in the desktop wallet (see [Desktop wallet](#desktop-wallet))
and opt-in for `cmfd-node`:

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

## Desktop wallet

The desktop wallet keeps the newest 720 blocks (about 12 hours) in full and
prunes the proofs of older blocks. Balances, history, sending, receiving, and
mining work as before. Instead of growing by about 12 GB a day, the wallet's
block log levels off at roughly 6 to 9 GB of full blocks plus a few KB for
each older block.

```text
common-foundry-wallet --prune-keep-blocks 4320   # keep about three days in full
common-foundry-wallet --no-prune                 # keep every proof
```

`--prune-keep-blocks` has the same 288-block minimum as the node.
`--no-prune` stops further pruning; blocks already pruned stay pruned.

The wallet does not prune while it opens. It first checks two minutes after
it starts and then every 10 minutes. A new wallet that syncs from peers prunes
shortly after it catches up. A wallet that already holds the full chain saves
its first chain state when it first starts with pruning on, so its first
prune comes after it has seen about 720 more blocks; that can be spread over
several sessions, because saved states are kept on disk.

## Pools

`pool-serve` takes the same `--prune-keep-blocks` option; the Linux pool
service sets it from the optional `prune_keep_blocks` field in `pool.json`.
Mining jobs build on the tip, block rewards mature after 100 blocks and
payouts only check transactions, so all of them work on a pruned node. A pool
block that lost to another block and sits at or below the prune height stays
`orphaned` in the pool ledger after the prune drops it.

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
atomically. Before it starts, the node checks for free space of twice the
full blocks that stay, plus 64 KB per pruned block and a 2 GB margin. With
less, it logs a warning, skips that prune, and tries again at the next check.
The rewrite runs without blocking the node; only the final swap briefly holds
it, and the swap waits for in-flight block reads to finish. Stopping the node
or wallet during a prune discards the rewrite and leaves the block log as it
was.
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
