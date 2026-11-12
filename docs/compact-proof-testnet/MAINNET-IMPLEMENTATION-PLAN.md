# Mainnet compact-proof fork at height 67,535

This source implements the mainnet upgrade at **H = 67,535**, selected on
2026-11-11. Every `production-mainnet` build includes the schedule. There is no
daemon option to select another activation height. The earlier 65,535 proposal
and its fingerprint are superseded; its signed releases remain historical.

The exact identity is in [MAINNET-FINGERPRINT-67535.md](MAINNET-FINGERPRINT-67535.md)
and [MAINNET-FORK-IDENTITY-67535.json](MAINNET-FORK-IDENTITY-67535.json).

| Block height | Accepted proof | Node admission |
| --- | --- | --- |
| Below 67,535 | Existing mainnet version 1 only | Existing proof checks and required work replay |
| 67,535 onward | `CMFDDR02` version 2 only | Complete direct proof, target, transaction and block checks; no required work replay |

Version-2 packets must be strictly smaller than 6,000,000 bytes; the proof
frame cap is 6,100,000 bytes. Historical version-1 frames retain their 13 MiB
allowance. The 16 MiB block limit, network ID, launch beacon, model bank,
fixed commitments, mining calculation, rewards and transaction rules stay
pinned. The fingerprint commits both proof rules and the activation height.

## Implemented transitions

Proof selection follows each frozen block/template height, including a
reorganization across H. Wrong-era proofs fail before relation verification.
Pool jobs retain their existing stale-tip checks. The proof-worker router
switches between the inherited version-1 worker and the mainnet compact
worker, and switches back when a template returns below H. Pool clients still
submit job IDs and nonces; updated reference miner 1.0.22 accepts the exact
legacy and new fork pool identities. Version 1.0.21 recognizes the superseded
65,535 proposal and needs replacement for the new fork pool.

The node keeps required replay for historical blocks between the existing
checkpoint and H. Post-H proof-validated blocks advance the validated frontier
without being recorded as recomputed work. Historical gaps continue to hold
wallet/exchange spending and pruning. Optional offline CPU replay audits do
not change ordinary-node admission rules.

Upgraded peers advertise the legacy wire fingerprint below H and the fork
fingerprint from H onward. Connections rehandshake when crossing that boundary.
The compatibility exception permits only these two exact mainnet identities,
and only when the legacy side reports a height below H. Unknown identities and
old peers claiming post-H compatibility are rejected.

The upgraded node recognizes the exact predecessor `network.meta`, preserves
the existing wallet key, and writes `network.meta.pre-compact-67535` before
new metadata. Pre-H local state, reversible deltas and prune anchors have
narrow fingerprint compatibility. They retain structural, canonical encoding,
checksum and full-validation checks. Stale startup caches are rebuilt. An
old binary refuses the new metadata; rollback uses the untouched full backup.

## Operator testing

Use a separate directory and a stopped, complete copy of the node/pool data.
Keep the original executable, wallet key, block log, work-status files, prune
anchors, pool ledger and configuration together for rollback. Never point two
processes at the same data directory. Do not delete `blocks.log`, `wallet.key`
or `prune-anchor-*` to bypass an upgrade failure.

Confirm `cmfd-node network-info` reports fingerprint
`9009948f6eab38b5b3dcee13eda9f6ef03e0db863c435cb97c1d4c3e124eb360`.
Use the existing authenticated launch plan/beacon and fixed input bank. Build
patched pools from the public release source with `production-mainnet`; do
not carry forward the predecessor fingerprint as a hardcoded pool identity.

An old pool ledger needs an explicit **offline, copy-only** identity conversion.
Inspect `cmfd-node pool-ledger-rebind --help`: pass the stopped source archive,
a new destination, its expected generation, the exact old fingerprint and the
new binary's authenticated network-info. The converter locks and validates the
source, binds the target to this binary, and refuses an existing destination.
Check balances, payouts and generation on the copy before pool startup. The
converter does not alter node history or authorize payments.

Mainnet pool proving uses standard serial replay/proof GPU handoff. Run the
included `cmfd-mainnet-fork-prover` through the pool's proof-worker option.
One compatible GPU can prove compact blocks; setting
`CMFD_DIRECT_MULTI_GPU_DEVICES=GPU-uuid-a,GPU-uuid-b` selects the optional split
coordinator. `--shared-model` is a compact-testnet optimization and is rejected
by this mainnet router. Preserve existing pool, payout, miner and GPU settings.

`verify-fork-proof --template FILE --proof FILE` verifies a complete proof using
the authenticated mainnet inputs without opening node data. Optional
`--audit-work-threads N` independently replays the mining work. This command
checks the proof and target; it does not establish parent, transaction or full
chain admission. The `mainnet_fork_pool_fixture` example generates similarly
scoped offline fixtures through the actual pool pipeline with synthetic parents;
those fixtures must never be relayed as blocks.

## Rebuild and qualification scope

Set `CMFD_BUILD_SOURCE_COMMIT` to the exact full release commit, then build:

```sh
cargo build --release --locked -p cmfd-node -p cmfd-miner \
  --features cmfd-node/production-mainnet,cmfd-miner/production-mainnet
```

The complete compact GPU source and pinned public dependency recipe are in
`tools/compact-proof-prover/README.md`. The inherited replay/version-1 workers
must match the signed v1.0.20 distribution; package receipts record provenance.
Linux and WSL2 test packages contain no new native Windows EXE.

The release qualification receipt distinguishes exact-mainnet identity/version
tests, reduced-geometry real-chain reorg/restart tests, generic node regressions,
and full-size GPU/CPU proof tests. Generic Devnet fixture suites use
`production-v4` without a mainnet network profile; the inherited whole-suite
`production-mainnet` run contains Devnet-default fixtures that require a
mainnet launch beacon, and is not reported as green.

Publication for pool operators is a testing prerelease. Independent review of
the repaired transcript and direct-proof soundness, operator ledger/patch
testing, cross-height network rehearsal, and coordinated seed/wallet/exchange
deployment remain production activation gates. Publishing these artifacts
does not deploy them to the running network.
