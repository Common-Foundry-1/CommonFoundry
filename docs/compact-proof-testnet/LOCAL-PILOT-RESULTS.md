# Compact proof testnet: local pilot results

The first isolated compact-proof network is running as a three-node loopback pilot: two independent nodes and one pool. It uses a new network ID, virtual genesis, ports, data directories, proof version 2, and a six-commitment direct packet. Mainnet retains its current proof rules. The pilot has now accepted three fresh GPU-proven blocks, including a block from the optimized pool build.

## What worked

| Check | Result |
| --- | --- |
| Network identity | All three participants selected `dcda3e81881e148a45970d2e7157b77f27e931e696df28468390ce79bb1e14cb` and genesis `e4d360dfffd368c83992c786a4842ed211aa2043cc6a1bc5ad487919a6f93754`. |
| Pool and worker startup | The pool authenticated the pinned 6.44 GB model bank, the release-pinned replay worker, and the direct-proof worker. Its TLS certificate was pinned by the test client. |
| First fresh block | Height 1 was accepted from a new GPU-generated 5,667,661-byte proof. Both independent nodes reached tip `9d9fee99a6ca56de0d2aaa9fe714254136c07b2e9ddee632a83fb2fc78e2e818`. The testnet payout wallet showed 35,000,000,000 immature atoms. |
| Second fresh block | Height 2 was accepted from a new 5,662,826-byte proof. The pool and first node reached tip `c4093a5fd7c561a9af71fa246739d3f61134e47bddfaaf4e0eaf8b12b771f31c`. |
| Restart catch-up | The second node was stopped at height 1, restarted from its stored chain, verified that history, downloaded height 2, and reached the same tip. Both nodes reported healthy storage. |
| Optimized pool block | Height 3 was accepted from a new 5,665,867-byte proof. The debug node and optimized node independently reached tip `34ca4c50dec5e6423342e0eb12268bf1df8334c40096abdac8dd69d35d3bd069`. |
| Owner mining | PearlMiner was restored after each short GPU window. Its scheduled-task XML and all three launcher hashes were unchanged, with fresh accepted shares after each restoration. |

## Timing and memory

The direct GPU proof stage reported **4.47, 3.84, and 4.28 seconds** for heights 1–3. All three complete packets are under the 6 MB goal. The worker reported a **9.125 GiB process peak** on the local RTX 5090; a prior complete-proof run on a 16 GB RTX 5070 Ti measured an 11,528 MiB total GPU peak.

The height-2 CPU probe took **27.20 seconds from pool connection through accepted share and block** with the initial debug node build. The same full path took **16.75 seconds** at height 3 with the optimized pool build. This includes pool replay, immutable trace snapshotting, proof generation, node verification, and response. The worker's `online_seconds` starts after the trace snapshot; heights 1 and 3 separately measured **3.21 and 3.37 seconds** to copy, seal, map, and validate the replay traces. These measurements make the next latency work concrete while the network and wallet interoperability checks are already passing.

The loopback pilot uses a zero-bit share target so one deterministic share exercises each full winning-block path. Public pool trials will set a calibrated target and report accepted-share, block, stale, propagation, and sync measurements at normal difficulty.

## Proof and test coverage

- The testnet packet is canonical version 2 with a dedicated proof-system digest and a direct-packet cap of 6,000,000 bytes. The complete proof frame is capped at 6,100,000 bytes; blocks retain the 16 MiB limit.
- The GPU worker generated each packet from fresh replay traces, checked all relations and its direct opening, and the separate nodes accepted the blocks through their independent consensus verifiers.
- The consensus suite passed 242 tests (2 existing checkpoint tests ignored), six network-profile tests passed, and the GPU worker passed 15 tests. Two saved version-2 packet fixtures also passed independent CPU verification and seven malformed-packet mutations each were rejected.

This result establishes the local interoperability pilot, including an optimized release-mode pool and peer. The next phase is the pool operator kit and a public testnet canary, with normal-difficulty mining and latency measurements.
