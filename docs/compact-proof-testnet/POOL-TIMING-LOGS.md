# Pool timing logs

The updated node records winning-proof and accepted-block timings automatically
in the pool data directory's `logs/cmfd-node.log.*` files. No diagnostic
environment variable is required. The records also appear in an info-level
console (`-vv`, as used by the pool kit). File logging remains enabled when the
console is silent or filtered.

Two events describe different stages:

- `pool proof timing` records search replay, full replay, replay handoff,
  the proof-worker request, complete backend evaluation and proof bytes. It
  means proof construction completed; receiver acceptance is recorded separately.
- `pool block accepted timing` appears only after successful node admission and
  canonical ledger finalization. It records `share_evaluation_seconds`,
  `node_submission_seconds` and `total_acceptance_seconds`, with the block ID.
  Ordinary accepted shares do not generate an accepted-block timing record.

Match events using network, height, parent and nonce. For pool latency, use
`total_acceptance_seconds`. This measures the current share-processing call,
including its verifier/batch wait, replay/proving, block checks, accounting,
node submission and tip rotation. It excludes miner nonce search, WAN travel,
initial worker startup and time before the share-processing call begins.
The component durations are contained within the total; do not add them to it.

For example, using your existing pool data directory:

```sh
grep -hE 'pool (proof timing|block accepted timing)' "$POOL_DATA"/logs/cmfd-node.log.*
```

The existing `CMFD_DROPOUT_POOL_PROOF` and `CMFD_DROPOUT_POOL_ADMISSION` stderr
records remain available for older benchmark tools when
`CMFD_DROPOUT_REHEARSAL_TELEMETRY=1` is enabled. They are no longer needed to
obtain routine pool timings. The native two-GPU prover's detailed
`CMFD_MULTI_GPU_REPORT` continues to use stderr.

This changes logging only. Proof checks, worker ordering, proof parameters,
wire format, network identity, GPU allocations and mining settings are unchanged.
