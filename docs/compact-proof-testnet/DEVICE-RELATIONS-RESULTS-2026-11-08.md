# GPU-resident relations and overlapping openings

Keeping reduced relation matrices and sumcheck inputs on the GPU improved the
relations/openings stage by **30.8%** for two matching standalone winners.
Two fresh live pool blocks reached full local acceptance in **8.520 and
8.274 seconds**, an additional **8.1%** improvement over the witness-pipeline
candidate on the same Rig06 hardware. Both live blocks passed node admission.

| Matching standalone winner | Previous pipeline | Device relations |
| --- | ---: | ---: |
| Relations/openings, winner 1 | 2.9016 s | 1.9162 s |
| Relations/openings, winner 2 | 2.7956 s | 2.0290 s |
| Native proof including producer CPU verification, winner 1 | 5.1928 s | 4.1874 s |
| Native proof including producer CPU verification, winner 2 | 4.9872 s | 4.2265 s |

| Separate live two-block samples | Previous pipeline | Device relations |
| --- | ---: | ---: |
| Pool evaluation, block 1 | 8.3133 s | 7.5566 s |
| Node admission, block 1 | 0.9634 s | 0.9634 s |
| **Full local acceptance, block 1** | **9.2767 s** | **8.5200 s** |
| Pool evaluation, block 2 | 8.0649 s | 7.3311 s |
| Node admission, block 2 | 0.9369 s | 0.9427 s |
| **Full local acceptance, block 2** | **9.0018 s** | **8.2738 s** |

The standalone comparison uses the same two nonce/template inputs and exact
relation transcripts. The live comparison uses separate two-block samples,
so its percentages are descriptive measurements rather than a statistical
throughput guarantee. Startup, nonce search and WAN propagation are excluded
from live acceptance latency. The new one-time worker startup was 31.1 seconds.
The five-second full-path goal remains open; the 4.19–4.23-second native proof
interval excludes replay/witness transfer and receiver admission.

## What changed

- Batch-reduced preactivations, next activations and boundary values stay in
  device memory. Matrix and boundary evaluations run on the GPU. Only the scalar
  claims required by the CPU verifier return to the host.
- A fused exact-field kernel constructs shifted matrix inputs and repeated
  layer equality weights on the GPU. Large input vectors are no longer built
  on the CPU and uploaded again.
- Fixed and dynamic opening evaluations run concurrently on their separate
  cards after their common evaluation point is fixed by the transcript.
- Each distributed sumcheck sends the fixed-card fold request before computing
  the independent dynamic-card fold. Request IDs, responses, round polynomials
  and challenge order remain checked in the original order.
- Independent opening-row reductions launch before a shared synchronization.
  Their small coefficient allocations stay alive until all kernels finish.

This removes approximately 192 MiB of intermediate host/device transfers per
proof, plus the associated CPU evaluations and vector construction. The larger
768 MiB witness handoff and cross-card fixed-weight reductions still use the
existing immutable host transport on this machine's non-peer-access x1 links.

## Exactness and security

The new GPU test compares reduced matrices, matrix evaluations, row evaluations,
boundary scalars, shifted inputs and equality inputs against the original CPU
calculations using nontrivial extension-field points, including the full
128-layer × 128-batch × 4096-column production geometry.

For both complete standalone proofs, all **2,142,912 public relation/opening
bytes** and the **14,220-byte secondary reduction** match the previous candidate
byte for byte. The final BaseFold argument can differ between otherwise
identical runs because parallel grinding may select different valid witnesses.
The CPU comparison helper decodes both canonical packets and records those
witnesses. Complete producer CPU verification and independent CPU-node
verification remain mandatory for the entire argument.

The initial rehearsal's stronger whole-packet equality check caught that
expected final-argument variability and stopped before the live pool stage.
Mining restored successfully. Inspection located the difference in the final
BaseFold argument, with identical public/secondary bytes and distinct valid
batch-grinding witnesses. The comparison was corrected to enforce exactness of
the changed stages while retaining complete verification of every final proof.
The subsequent complete rehearsal passed.

No proof parameters, transcript domains, commitment counts, verifier rules or
wire versions changed: six commitments, log blowup 1, 270 queries, 16 grinding
bits and direct-proof version 2 remain in force. All matrix, shift, cubic,
initial-boundary, capture and lift checks remain enabled. This producer
optimization requires no additional consensus fork.

## Complete qualification

- 23 native CPU tests, seven GPU differential tests and 16 controller/launcher/
  replay-RPC tests passed.
- Two standalone winning proofs passed complete producer verification. Fresh
  CPU nodes rejected both corrupted packets with HTTP 422 at height zero, then
  accepted the honest packets with HTTP 200 at height one. Their work rule was
  absent and proof verification ran in process.
- Two consecutive live pool blocks were mined by a separate GPU client,
  proved, and accepted. Packets were 5,679,523 and 5,665,321 bytes.
- Replay batches of 2, 32 and 64, batch digests and full replay after the large
  batch remained exact. Both standalone final vectors also matched the
  unchanged independent replay executable.
- Both workers persisted, one shared model remained resident, and zero model
  bytes reloaded after startup. Post-proof search resumed without model reload.

Rig06 used physical 16 GiB RTX 4070 Ti SUPER cards on PCIe Gen2 x1 risers, with
a separate same-model GPU miner. The complete test peaked at **6.775 GiB on
dynamic card A, 7.463 GiB on model card B and 6.834 GiB on the test miner**.
The 7.5 GiB whole-device guard sampled every 10 ms and included the new GPU
differential test. Physical 8 GB RTX 3080 mobile qualification remains separate.

All six owner GPUs returned to their unchanged mining command/configuration,
810 MHz memory locks and 230 W limits. A fresh accepted share was observed
after restoration; the cleanup readback showed accepted share 10 with zero
rejects. Test processes and services exited. Private RAM scratch and
**61,597,200,446 bytes** of rig scratch were removed after the evidence was
copied locally and hash-verified.

The evidence archive is
`target/compact-relations-device-20261108/FINAL-EVIDENCE.tar.gz`, SHA-256
`b0b4eba1bb999eb9bc0afd02e1e709ae3d6dfef214fa97bcf4b121f6e5efd849`.
`FINAL-QUALIFICATION.json` records the exact artifacts, source hashes, both
rehearsals, comparisons, measurements, restoration and cleanup. The earlier
benchmark directories remain unchanged. This candidate is local; no release,
mainnet service or public testnet seed was updated.

## Build and next target

`tools/compact-multigpu/prepare-device-relations.py` builds a separate overlay in
`target/compact-relations-device-20261108`. Use the pinned CUDA/Rust environment
and the matching controller/worker. Enable `CMFD_DEVICE_RELATIONS=1` alongside
`CMFD_WITNESS_PIPELINE=1` and the existing shared-model pool configuration. The
original CPU-intermediate path remains available when the new flag is omitted.

The remaining full-path costs include roughly 2.4–2.5 seconds of replay/witness
handoff on the x1 links, about two seconds of relations/openings, about
1.1 seconds of joint BaseFold and roughly 0.95 seconds of receiver admission.
Producer CPU verification remains included in proving. Further gains must
preserve those checks and the memory envelope.

## Squid's seed report

A fresh, package-verified published v0.4.0 CPU node synced from height 0 to 65
through `209.145.48.36:23444` in **50.9 seconds**, reaching the seed's exact tip.
The public endpoint also returned the expected network identity and height in
a fresh handshake. The seed was healthy at accepted/audited height 65, with
no ban events in the preceding two-hour journal window. The public relay
allowed TCP 23444, had no explicit firewall rule for the reported tester IP, and its
fail2ban service was inactive.

These observations establish current public-route operation from our network;
Squid's private LXC/host network was not inspected. Rig06's successful GPU tests
also use driver 580.178.04. His reported PCIe 4.0 x16/x4 topology should help
the transfer component compared with our Gen2 x1 risers; his complete latency
and physical 8 GB memory use still need measurements on his hardware.
