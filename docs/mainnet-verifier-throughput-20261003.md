# Optional mainnet proof-verifier throughput (candidate)

This is an **availability-only candidate**, not a published or deployed
mainnet update. It starts from the signed `v1.0.0-security.1` source. The
consensus proof, target, chain-work choice, network ID, launch beacon and
monetary rules are unchanged.

`cmfd-node` retains its original one-active-verifier and five-second queue
wait unless an operator explicitly adds `--mainnet-proof-verifiers N` to
`run` or `pool-serve` on a `production-mainnet` build. `N` is bounded to
1–4. The opt-in uses the existing eight-waiter queue and a 30-second queue
wait; it never permits unbounded concurrent proofs. Other commands and
non-mainnet builds reject the flag.

This is **not** a fix merely because it compiles. Before deploying to any live
node, the final source commit needs review, native Linux and Windows builds,
regression and adversarial proof-queue tests, a measured disposable-host
throughput/memory comparison, owner signature, and public package verification.
Start conservatively on a qualified host and check accepted-height, tip,
cumulative work, queue telemetry, peer synchronization and memory pressure
against an independent node. A different height alone does not establish the
higher-work chain. Do not replace live signed binaries with an unsigned
candidate or reset a node's block log to force convergence.
