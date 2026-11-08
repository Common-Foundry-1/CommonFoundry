# Two-GPU compact proof qualification

One complete compact proof was generated across two GPUs and accepted by a
fresh Common Foundry proof-only node. The packet uses the existing version-2
format and verifier. This producer change requires no additional hard fork.

| Check | Result |
| --- | --- |
| Proof packet | 5,661,981 bytes / 5.66 MB |
| GPU A peak | 6.219 GiB |
| GPU B peak | 3.492 GiB |
| Per-card total-device limit | 7 GiB, sampled through NVML every 10 ms |
| Full standalone CPU verification | Passed, 0.562 seconds |
| Fresh-node acceptance | Passed, 0.978 seconds |
| Modified packet | Rejected, HTTP 422; height remained zero |
| Node work replay | None; in-process proof verification, no work rule |
| Original proof parameters | Six commitments, log blowup 1, 270 queries, 16 grinding bits |
| GPU differential | Streamed equalities matched stock proof bytes and challenger state |
| CPU regressions | 20 prover tests, 28 pool tests, seven coordinator/launcher tests passed |
| Mining restoration | Six owner GPUs, unchanged command/config hashes, 810 MHz memory and 230 W, fresh accepted share |
| Cleanup | Private RAM released; temporary rig payload removed; 61,517,938,688 bytes reclaimed |

Hardware was two RTX 4070 Ti SUPER 16 GiB cards on Rig06, both connected through
PCIe Gen2 x1 risers. The guard screens the 8 GB memory target; physical 8 GB
RTX 3080 mobile qualification remains a separate canary.

The startup-inclusive proof took 251.858 seconds. Dynamic commitment took
17.975 seconds, relations and reductions 150.868 seconds, and the final joint
BaseFold stage including its RLC request 41.834 seconds. The RLC request itself
took 32.864 seconds. This candidate starts stage processes per proof and streams
whole model banks repeatedly; those costs are part of the measured delay.
The run replayed an existing public testnet winner and submitted its new proof
to a fresh loopback node. It did not measure nonce search, a live pool share
submission, stale rate or WAN propagation.

The next performance step is to keep fixed weights resident on one proving GPU
and exchange reduced vectors between the two GPUs. This addresses repeated
whole-bank transfers while preserving the same transcript, field arithmetic,
commitments, proof parameters and full receiver verification.

The implementation supports one shared replay GPU with serial handoff, or
separate replay cards alongside the proving pair. Numeric selectors and UUIDs
are resolved to physical identities before the pool checks role overlap.

Earlier qualification attempts identified a tmpfs harness path issue and two
final-handoff metadata issues. The final full verifier passed after corrections;
mining was restored between every attempt. The original qualified v0.3.0 GPU
source and public deployment were left unchanged.
