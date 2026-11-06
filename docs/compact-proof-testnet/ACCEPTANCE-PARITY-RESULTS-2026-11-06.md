# Compact pool acceptance: measured two-second reduction

Three fresh winning blocks averaged **5.742 seconds**
through complete local acceptance, versus **7.727
seconds** in the preceding qualified RAM-witness run. This saves **1.985
seconds (25.7%)**. Both runs used the same RTX
5090 at 7001 MHz memory and the owner's 520 W profile. These are fresh challenges
in separate runs, using the same timing endpoint.

| Block height | Full replay/export | Proof-worker request | Node admission | Full local acceptance | Proof bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| 17 | 0.249 s | 4.557 s | 0.437 s | **5.883 s** | 5,691,162 |
| 18 | 0.210 s | 4.393 s | 0.426 s | **5.684 s** | 5,650,178 |
| 19 | 0.213 s | 4.373 s | 0.419 s | **5.659 s** | 5,680,662 |

The first live block took **5.883 seconds**; subsequent blocks averaged
**5.672 seconds**. The timing includes pool-side share
replay, witness export, immutable input checks, complete proving and mandatory
node verification. Winning-nonce search, one-time startup and WAN propagation
are outside this endpoint. The five-second full-path goal remains open by about
0.74 seconds on this card.

The selected workload peaked at **12.72 GiB**,
inside the 13 GiB guard. Available WSL RAM stayed above
6.84 GiB with a 4 GiB abort reserve.
This is a bounded workload measurement on a 32 GiB card; it is not a new
physical-16-GiB-card qualification. Total GPU usage includes the desktop and is
recorded separately in the JSON and raw telemetry.

Replay now exports directly into kernel-sealed RAM, retaining every canonical
field-word check. A separate standby witness is prepared during proving; the
two slots use at most 3 GiB of host RAM. The prover rotates two fixed banks,
reuses CPU equality weights, and joins the independent initial-boundary check
after overlapping it with GPU proving. Pool-worker mode follows its existing
self-check setting; the authoritative node still verifies every complete proof,
and standalone qualification retains its full CPU self-check.

Two compiled known answers run before the pool opens, followed by model
eviction. They grant no work-check qualification or release-pin exception.
Eager CUDA module loading removes most first-use kernel loading from the live
path. The two checked startup replays took
6.66 seconds in total.
Without these startup measures an intermediate first request took 15.88 seconds;
all intermediate trials are retained in the result record. The slower mapped
model-loader experiment was discarded.

The packet codec, transcript, six commitments, field/hash suite and BaseFold
log blowup 1, 270 queries and 16 grinding bits are unchanged. No additional consensus change is introduced
by these runtime optimizations.

Checks passed: 17 prover tests, 25 pool tests, seven miner tests, nine launcher
tests and all 48 coordinated-forgery cases. Replay witnesses from fixtures
43424/43425 matched the published worker byte for byte; writes and truncation
of the sealed handoff were rejected. The final CPU-only node rejected a forged
proof with HTTP 422 and accepted its honest control. A separate node downloaded
the measured chain to height 19 over P2P, matching its tip with in-process proof
verification, healthy storage and no work-replay rule.

The candidate remains local and unpublished. Its archive SHA-256 is
5054315af260ed6ef03444e9d500514106ddc4180c0313cb98bce201c770466b. Exact timings, binary identities and intermediate
trials are in [the result record](ACCEPTANCE-PARITY-RESULTS-2026-11-06.json).
The GPU changes are preserved in [the patch](acceptance-parity-gpu.patch) and
[source identities](acceptance-parity-gpu-source.json); apply using
git apply --unidiff-zero against LF-normalized baseline text. Reconstruction was checked against normalized
source hashes; exact tested source and binary hashes are recorded separately.
Detailed logs and the tested runtime patch are in
target/compact-public/acceptance-parity-20261106.

Owner mining was restored through the unchanged PearlMiner task and settings:
eight fresh accepted shares, zero rejects, 99% GPU use and the original
7001 MHz / 520 W readback. Test processes, RAM mounts, listeners and restore
watchdogs were cleared; unselected candidate packages freed 625,567,559 bytes.
The verified mining and cleanup evidence is embedded in the result record.
Mainnet and public relay services were unchanged.
