# Dedicated pool replay residency

Included in the v0.5.2 update; older v0.5.1 kits do not have this option.

This mode removes repeated full-model reloads between ordinary shares for
GPUs dedicated to pool replay/proving. The existing serial-sharing behavior
remains the default. Proof handoff still evicts the model and holds replay's
mutex throughout proving. No proof arithmetic, parameters or validation rules
changed.

## Operator configuration

For a native Linux pool whose selected GPUs are reserved for that pool:

```sh
./START-POOL.sh --public-ip YOUR_NUMERIC_PUBLIC_IP \
  --proof-gpu 0 --replay-gpu 0 --serial-gpu --keep-replay-resident
```

The corresponding direct node option is
`--production-v4-pool-keep-replay-resident`, which requires
`--production-v4-pool-serial-gpu`. Startup reports `keep_replay_resident: true`.
Miners must run on other GPUs or hosts. Windows-to-WSL forwarding is excluded
from this new mode.

The pool claims the existing per-user CMFD miner lock for every selected physical
GPU before starting workers, then checks NVIDIA's visible compute-process list.
An occupied selected card is refused, without stopping its workload. The locks
prevent overlapping CMFD processes in the same user's state namespace. The
operator must also reserve those GPUs across containers, users and other CUDA
applications; these are advisory application locks, not an OS GPU-isolation
mechanism.

The existing `--shared-model` two-GPU mode already retains its immutable model.
It remains the measured small-per-card-memory layout and does not need this new
flag. Combining the two options is rejected. Retention does not lower the
chosen proof worker's existing VRAM requirement; the older single-GPU prover
continues to have its own memory envelope.

## Behavior and checks

In dedicated mode, successful nonwinning single-share and batched-share replay
keeps the model loaded. Before a winning proof, the unchanged handoff sends
`EVICT` and retains the replay lock so no share can reload weights during proving.
The initial model load and the first reload after a proof handoff still occur.
Avoiding those transfers entirely is the role of the shared-model two-GPU mode.

The implementation retains all replay validation, known-answer checks, full
proof verification, work-rule trust boundaries, queue limits and credit logic.
The model is reused; nonce-dependent replay is still performed for every share.

Checks passed:

- 31 backend tests, including unchanged default eviction and the retained mode's
  single/batched ordinary-share behavior.
- Proof-handoff regressions for both policies: weights are evicted and work
  replay remains blocked while the proof worker is active.
- 17 launcher/control/RPC tests, including invalid ownership-mode combinations.
- Linux and Windows ownership-lock and busy-inventory unit checks, plus the
  real Rust CLI's serial-mode requirement.
- A real Linux CLI test on Rig06 refused the already-mining assigned card before
  either worker started, leaving all six owner GPUs running.

## Real GPU backend comparison

The actual `ProductionV4PersistentPoolVerifier` was tested with the published
replay worker and authenticated 6.44 GB model on one physical 16 GiB RTX 4070 Ti
SUPER at PCIe Gen2 x1. Two nonce inputs were replayed repeatedly through both
policies. Matching inputs returned identical work digests.

| Current call | Time |
| --- | ---: |
| Default policy, ordinary share 1 | 16.8261 s |
| Default policy, ordinary share 2 | 16.7676 s |
| Dedicated policy, initial load | 16.8163 s |
| Dedicated policy, five resident shares | **0.04212-0.04262 s** |
| Dedicated policy, resident median | **0.04236 s** |
| Dedicated policy, first share after proof handoff | 16.7623 s |

At proof handoff, whole-device use fell from 6,696,206,336 bytes after resident
replay to **247,463,936 bytes**, and the replay mutex remained held. Resuming
replay after the handoff produced the same work digest. The observed peak over
the test was **6.675 GiB**, below the 7.5 GiB whole-device guard.

This was an ordinary-share and proof-handoff test. Its internal zero chain
target kept the supplied template on the nonwinning path; no fresh proof was
generated and no block was submitted. It establishes replay policy, output
equivalence, memory release and lock behavior, not a new end-to-end proof latency
or physical-8-GB-card qualification. The GPU prover binaries were unchanged.
Squid's specific A4000 configuration was not modified or independently measured.

## Restoration and evidence

All six owner GPUs returned to their original command/configuration, 810 MHz
memory locks and 230 W limits. Fresh accepted shares were observed, including
accepted share 26 with zero rejects at cleanup. The watchdog and test services
are inactive. Private RAM scratch and **6,498,037,925 bytes** of rig scratch were
removed after local evidence verification. No external tester time was used.

Evidence: `target/compact-replay-resident-20261108/EVIDENCE.tar.gz`, SHA-256
`9cb18d088447797d99aa2b108054b69c0e48e014093fd212c2bb8e07692df7e9`.
The measured backend test, occupied-GPU CLI result, exact artifact identities and
restoration records are retained in that archive. `FINAL-REPORT.json` and
`CLEANUP-RECEIPT.json` hold the local summary and cleanup readback.
