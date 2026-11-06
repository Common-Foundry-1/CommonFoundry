# RAM witness and replay optimization: qualified local testnet run

The optimized local pool accepted two fresh compact-proof blocks, heights 5
and 6. Its pool evaluation fell from **18.01 seconds** in the earlier v0.2.0
run to **7.47 and 7.14 seconds**, an average reduction of **59.4%**. Including
local node admission, the new path took **7.90 and 7.56 seconds**, versus
18.48 seconds in the earlier run.

| Measurement | Earlier v0.2.0 run | Height 5 | Height 6 |
| --- | ---: | ---: | ---: |
| Full replay and witness export | 8.702 s | 0.923 s | 0.945 s |
| Copy, seal and validate witness | 3.649 s | 0.190 s | 0.193 s |
| Complete proof-worker request | 9.073 s | 5.890 s | 5.518 s |
| Online proving within that request | 4.460 s | 5.013 s | 4.764 s |
| Pool evaluation through proof ready | 18.013 s | 7.474 s | 7.137 s |
| Local node admission after evaluation | 0.465 s | 0.422 s | 0.422 s |
| Packet bytes | 5,683,962 | 5,661,321 | 5,664,164 |

Witness files now use a private **2 GiB tmpfs**, with capacity, ownership,
permissions, free-space and host-RAM checks. Replay reuses a bounded 16 MiB
pinned export buffer. Ordinary tmpfs files are copied into owned memfds with
all required kernel seals before canonical field validation; mutable RAM files
are never used as the prover's immutable input directly.

An explicit serial mode gives the miner, pool replay and prover sequential
ownership of the shared GPU. The miner yields its model before submitting each
share; the pool evicts its model after checking ordinary shares and retains
the replay lease through proving. The prover streams one 2 GiB fixed bank at a
time and completes stream-ordered frees before returning its DONE response.
The same fixed data, relations, transcript, field/hash suite, six commitments,
BaseFold 1/270/16 parameters, target checks and node verifier remain in use.

The successful run stayed inside the **13 GiB incremental workload guard**.
The sampled workload peak was **12,873 MiB (12.57 GiB)**, leaving about
3.43 GiB below a 16 GiB workload budget. The internal CUDA sampler recorded
7.50 and 7.25 GiB above its already-prepared trace baseline; those figures are
not whole-process peaks. The host workload measurement is the budget evidence.
Available WSL RAM stayed above 7.02 GiB, with a 4 GiB abort reserve. The
dedicated RAM mount was unmounted and removed afterward.

This was an RTX 5090 **32 GB** test with 7001 MHz memory and the owner's
520 W profile. It is a bounded workload screen, not a fresh physical-16-GB-card
qualification. Total device usage peaked at 16.39 GiB including the roughly
3.82 GiB desktop baseline. The earlier run recorded 480 W while owner mining
was stopped, so these samples are not a power-matched benchmark.

The exact replay self-tests passed, and complete witness files from mainnet
fixtures 43424 and 43425 matched the published replay worker byte for byte.
The local gates passed 23 pool tests, seven miner tests, seven launcher tests
and 16 prover tests, including immutable snapshots, mutable tmpfs inputs,
noncanonical words, missing seals, malformed lengths and transcript controls.

The existing published Windows v0.2.0 verifier checked the optimized chain,
and the public Proxmox audit seed independently reached height 6. A separate
published node downloaded the same tip with in-process proof verification,
`work_rule: null`, verified history and healthy storage:
`116dbb07624ea4353e322bcd5d394e2760e303257dd7e1b7c78ce7a885b9389f`.
Propagation was verified through native Windows because WSL's LAN route was
unavailable during the final check; WAN propagation is outside the table.

The five-second complete-path goal remains open. Online proving now accounts
for 4.76–5.01 seconds of the qualified run. The faster 6.53-second experiment
with all fixed banks retained was not selected because it exceeded the
workload VRAM guard.

Owner mining was restored through the unchanged `PearlMiner` task. WildRig NG
1.0.0s reported six accepted shares, zero rejects, 99% GPU use, 7001 MHz memory
and the original 520 W power limit. All benchmark GPU processes, CPU nodes,
listeners, RAM leases and restore watchdogs were stopped.

The local candidate archive SHA-256 is
`0f21e73e73ac391897f65d5a847f7b0bbc1d39fb9e66c15b1991bb8ce3286fd4`.
It records a dirty research source state; it was not published by this test.
Exact measurements and source hashes are in
[the result record](RAM-WITNESS-RESULTS-2026-11-06.json). The GPU source changes
are preserved as [a reviewable patch](ram-witness-gpu.patch) with
[before/after identities](ram-witness-gpu-source.json). Detailed local logs and
the tested runtime patch are under `target/compact-public/ram-witness-20261105`.
