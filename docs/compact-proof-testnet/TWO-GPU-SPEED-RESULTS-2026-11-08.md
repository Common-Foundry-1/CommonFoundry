# Resident two-GPU proof results

Two different winning nonces produced complete compact proofs on Rig06.
Both passed standalone CPU verification and fresh-node admission; changing
the proof bytes caused HTTP 422 rejection without advancing the chain.
The producer emits the existing v2 packet and uses the unchanged receiver
verifier, so this optimization needs no additional consensus fork.

| Measurement | Winner 1 | Winner 2 |
| --- | ---: | ---: |
| Prepared replay | 0.0420 s | 0.0420 s |
| Complete proof-worker request | 6.0612 s | 6.0185 s |
| Replay plus proof | 6.1032 s | 6.0605 s |
| Standalone CPU verification, included above | 0.5582 s | 0.5650 s |
| Separate fresh-node admission | 1.0207 s | 0.9819 s |
| Sum of separately timed replay, proof and admission | 7.1240 s | 7.0424 s |
| Proof packet | 5,670,191 bytes | 5,683,613 bytes |

These are replayed winning-block and node-admission checks, not a continuous
live pool share-to-acceptance measurement. Cold startup, nonce search,
post-proof model reload and WAN propagation are separate measurements.
The earlier same-rig host-witness path took 16.2620 and 15.3162 seconds for
prepared replay plus proof. The new mean is **61.48% lower** with complete
producer CPU verification in both implementations.

Rig06 uses RTX 4070 Ti SUPER cards with physical 16 GiB VRAM and PCIe Gen2 x1
risers. Selected cards ran at normal 10,251 MHz memory with 230 W limits.
Proving peaks were 7.00 GiB and 7.21 GiB under a 7.25 GiB total-device guard.
The complete path peaked at 7.42 GiB under a separate 7.5 GiB ceiling, leaving
at least 512 MiB against an 8 GiB headless-device budget. A physical 8 GB
RTX 3080 mobile run is still needed before claiming that hardware qualified.

The fixed GPU service initialized once in 25.82 seconds and retained its model
across both winners. The dynamic GPU process exited after each proof. The
second winner was found by fresh GPU nonce search and reused the same fixed
worker PID. Replay model loading took 16.71 seconds initially and 16.77 seconds
after the first proof on this x1 link. That serial reload delays the next nonce
search; it is the next transfer bottleneck to remove. The five-second complete
winning-block target remains open.

The speedup comes from resident fixed weights, distributed sumcheck components,
GPU-generated trace metadata and an owned same-GPU witness snapshot. Replay
retains preactivations only; the prover reconstructs their exact cubed outputs,
saving 768 MiB of replay history. All supplied words are checked before use.
Fixed authentication trees are hashed after being copied into sealed snapshots.
First-fold equality tables are constructed at half size. Round polynomials,
challenger state and the full proof remain verifier-compatible.

Six commitments, log blowup 1, 270 queries and 16 grinding bits are unchanged.
Checks passed: 22 prover CPU tests, six GPU differential tests, 28 pool tests,
four peer tests and nine coordinator/launcher tests. The candidate includes
the previously deployed loopback self-discovery repair from commit
6633607efdc9b591792e8012892382b8f439c1e0.

Mining resumed on all six owner GPUs with unchanged command/configuration,
810 MHz memory locks, 230 W limits and a fresh accepted share. The temporary
rig payload and RAM scratch were removed; 61,775,790,931 bytes were reclaimed.
Proofs, logs, artifact identities and restoration evidence are preserved locally
in `target/compact-multigpu-speed-20261107/FINAL-EVIDENCE.tar.gz` and
`FINAL-QUALIFICATION.json`. The candidate package is local; the published
v0.3.0 assets were not changed.
