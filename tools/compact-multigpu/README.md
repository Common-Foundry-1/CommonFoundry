# Two-GPU compact proving

## GPU-resident relations candidate

The latest local candidate keeps reduced relation matrices and sumcheck inputs
on the GPU and overlaps independent work across A and B. On Rig06 it reduced
relations/openings by **30.8%**, from 2.80–2.90 seconds to 1.92–2.03 seconds for
matching winners. Two real local pool blocks reached complete acceptance in
**8.520 and 8.274 seconds**, another 8.1% improvement over the witness pipeline.
Peak total device use remained 6.775 / 7.463 GiB under the 7.5 GiB guard.
The five-second full-path goal remains open.

Use `prepare-device-relations.py` for the separate
`target/compact-relations-device-20261108` overlay. With its matching worker,
set `CMFD_DEVICE_RELATIONS=1` alongside `CMFD_WITNESS_PIPELINE=1` and the existing
shared-model configuration. Both changed-stage transcripts match the previous
implementation exactly; every complete final proof still passes the full CPU
verifier. See
[`DEVICE-RELATIONS-RESULTS-2026-11-08.md`](../../docs/compact-proof-testnet/DEVICE-RELATIONS-RESULTS-2026-11-08.md)
for the comparisons, hardware scope, checks and restored mining state.

## Pipelined witness candidate

The new research overlay overlaps witness export on GPU B with upload on GPU A.
It publishes 48 immutable, kernel-sealed 16 MiB chunks, validates every supplied
field word and reconstructs the exact activations on A. A nonce/template-bound
capture is consumed once. Both workers and the single resident model persist.

On the same Rig06 Gen2 x1 links, two real pool blocks reached local acceptance
in **9.277 and 9.002 seconds**, compared with **12.079 and 11.566 seconds** for
the v0.4.0 shared-model baseline. This is a 22.7% reduction in mean acceptance
time. The complete path remains above five seconds. Peak total device use
stayed below 7.5 GiB per card on physical 16 GiB cards; physical 8 GB mobile
cards have not yet been measured. Proof bytes, transcript and security
parameters are unchanged. See
[`WITNESS-PIPELINE-RESULTS-2026-11-08.md`](../../docs/compact-proof-testnet/WITNESS-PIPELINE-RESULTS-2026-11-08.md)
for timings, checks and the next bottleneck.

This candidate requires the newly built shared-model worker and matching
controller. It is enabled explicitly with `CMFD_WITNESS_PIPELINE=1` alongside
the existing `--shared-model` configuration below. The published v0.4.0 kit
does not contain this optimization. Omitting the environment variable retains
the sequential host-witness path.

## Shared resident model

The shared-model mode keeps one immutable 6 GiB model on GPU B for both replay
and fixed-proof reductions. GPU A handles dynamic proving. Replay decodes one
layer into a 16 MiB GPU buffer, so no second model allocation or post-proof
model reload is needed. Both workers persist across winners.

```sh
./START-POOL.sh --public-ip YOUR_POOL_IP \
  --proof-gpus 0,1 --replay-gpu 1 --serial-gpu --shared-model \
  --ram-witness-dir /run/cmfd-witness
```

The first GPU is the dynamic prover; the second owns the shared model and
replay. The private replay socket is created automatically inside pool scratch.
The measured configuration uses private RAM-backed witness files. For the
launcher, use a private 2 GiB tmpfs mount owned by the pool user; the existing
`--ram-witness-dir` checks enforce that setup.
Omitting it uses disk scratch and changes the reported I/O performance.
Its owner-only lease prevents duplicate services and safely recovers an
abandoned socket after interruption. Temporary worker files stay in that
private scratch directory. This mode needs native Linux and NVIDIA CUDA;
NVLink and GPU peer access are not required.

On Rig06's PCIe Gen2 x1 risers, post-proof replay resumed in **0.11-0.13 s**,
replacing the prior **16.77 s** model reload. A real local pool accepted two
consecutive blocks in **12.08 s and 11.57 s**, including pool evaluation and
node admission. The witness export and upload across those x1 links take
about **4.7 s**; they are now the main transfer bottleneck. The five-second
complete-path target remains open. See `PROOF-QUALIFICATION.json` for the
separate phases, startup exclusions and hardware details.

The complete shared path stayed below **7.5 GiB total per card**, including
driver overhead. Qualification used physical 16 GiB RTX 4070 Ti SUPER cards;
the physical 8 GB RTX 3080 mobile canary remains the next hardware check.
Both complete standalone proofs and the live blocks passed full verification.
Batch sizes 2, 32 and 64, batch digests, and a full replay after a large batch
matched exactly. The proof format and security parameters are unchanged.

## Reference mode with GPU witness handoff

The resident-worker candidate generated two different winning proofs in
**6.06 and 6.02 seconds**, with **0.042 seconds** of prepared replay per winner.
Both proofs passed the full standalone CPU verifier. Packets were
**5,670,191 and 5,683,613 bytes**, using the existing consensus-v2 format.
The receiver uses the existing complete proof verification; this producer
optimization requires no additional hard fork.

On the same Rig06 PCIe Gen2 x1 risers, the previous resident implementation took
about 11 seconds for proving and 4.3-5.1 seconds to export replay witnesses. The
new GPU handoff removes that large host transfer. Fixed weights remain resident
on GPU B, while GPU A constructs the dynamic commitments and final joint proof.
Only reduced vectors and sumcheck round messages cross between the two cards.
NVLink is not required.

Proving peaked at **7.00 GiB on A and 7.21 GiB on B**, within a 7.25 GiB
total-device guard. The complete path, including replay and driver overhead,
peaked at **7.42 GiB**, within a separate 7.5 GiB limit. These measurements used
physical 16 GiB RTX 4070 Ti SUPER cards; the physical 8 GB RTX 3080 mobile canary
is the next hardware check. The five-second target remains open.

The fixed service took **25.82 seconds** to initialize once and was reused for
both winners. Timing above excludes cold model loading, nonce search, live pool
share submission and WAN propagation. Node admission is measured separately in
the qualification report. The original streaming prototype's 251.86 seconds
included worker startup and is not a steady-state comparison.

After each proof, the serial layout reloads the replay model before nonce
search resumes. This took **16.77 seconds on Rig06's x1 link**, measured
separately from submission latency. Faster links or a future shared resident
model handoff are the next steps for that mining interruption.

## Reference mode configuration

For two cards, the measured configuration is:

```sh
./START-POOL.sh --public-ip YOUR_POOL_IP \
  --proof-gpus 0,1 --replay-gpu 0 --serial-gpu --gpu-witness
```

`--gpu-witness` transfers the captured preactivations directly between processes
on GPU A. The prover takes an owned device snapshot, checks every supplied field
word, and reconstructs the exact cubed activations. It closes imported views
before acknowledging replay-buffer release. This saves 768 MiB of replay
history and avoids exporting the full witness through host RAM.

The node resolves numeric selectors and UUIDs to physical GPUs before checking
role overlap. Serial replay must share GPU A, the first proving selector.
GPU B stays reserved for its resident fixed weights. The dynamic process on A
exits before completion is returned, allowing replay to reload its model.
Closing the coordinator also closes B; parent-death guards stop orphan workers.

Separate replay cards remain supported without `--gpu-witness`, for example:

```sh
./START-POOL.sh --public-ip YOUR_POOL_IP \
  --proof-gpus 0,1 --replay-gpu 2 --replay-gpu 3
```

That layout uses the host-witness path and has not been qualified against the
new complete-path 8 GB budget. Use the measured serial GPU-witness configuration
for the 8 GB canary.

Keep `coordinator.py`, `cmfd-direct-multigpu-prover`, and the compiled
`cmfd-direct-multigpu-worker` together. The optional GPU witness also requires
the candidate `cmfd-v4-replay` and node. Each proof has a ten-minute deadline,
device-memory monitoring and a host-RAM reserve check. Set
`CMFD_MULTI_GPU_LOG_DIR` to retain stage logs outside private scratch.
The coordinator itself never changes miners, clocks, power limits or services.

## Verification and build

The proof retains six commitments, log blowup 1, 270 queries and 16 grinding
bits. Distributed sumchecks preserve all round polynomials and sampled
challenges. GPU differential tests compare complete proof bytes, endpoints
and challenger state against the stock SDK. All generated qualification proofs
also pass the independent full CPU verifier.

`prepare-resident.py` creates an isolated overlay in
`target/compact-multigpu-speed-20261107`; the qualified v0.3.0 source is preserved.
`prepare-shared-model.py` builds the new overlay separately in
`target/compact-witness-pipeline-20261108` using the same pinned environment,
preserving the qualified v0.4.0 shared-model build. An optional
`CMFD_COMPACT_BUILD_DIRECTORY` must name a direct child of the repository's
`target` directory.
Build with the existing pinned CUDA/Rust environment. The older
`prepare-candidate.py` streaming implementation remains a reference.

Linux CPU checks:

```sh
python3 -B -m unittest discover -s tools/compact-multigpu -p 'test_*.py'
cargo test --locked -p cmfd-node --features direct-proof-testnet --lib production_v4_pool::
```

The native GPU tests are ignored by default. Run the built test executable
with `--ignored --test-threads=1` only on an explicitly reserved GPU. The local
candidate package and qualification hashes are separate from published v0.3.0.
