# Isolated 20 → 5 → 1 GPU recovery rehearsal

This is an **operator-staged measurement**, not a difficulty approval or a
mainnet activation tool. The earlier two-block, one-GPU 5x qualification had no
P2P socket and did not test loss of fleet hash rate. The statistical pre-screen
found a long one-GPU tail; this run is intended to collect actual full-proof,
multi-GPU, two-host evidence before a final recovery-policy decision.

`scripts/mainnet_dropout_rehearsal.py` never starts/stops services, controls
GPUs, sends blocks, changes consensus, or opens a public listener. It polls an
isolated pool dashboard and an independent P2P node through **loopback-only**
HTTP or local SSH tunnels. It accepts no non-loopback or redirect URL. A maximum
six-hour run records create-new samples, then analyzes retained process logs.
The report's `final_setting_approved` and `mainnet_activation_approved` fields
are always false, even when `measurement_complete` is true.
It also keeps `physical_gpu_identity_verified` and
`separate_host_identity_verified` and `exact_package_identity_verified` false;
those require independently retained hardware, host, and release evidence.

## Prerequisites and boundaries

1. Build a disposable ProductionV4 candidate with the actual 5x initial target
   `000ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccb`
   and RC easiest target
   `003fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff`.
   Give it a **distinct isolated network identity and genesis**. Do not use the
   public RC pool, an existing wallet/ledger, or the future live mainnet data
   directory. This repository does not yet contain final mainnet pins or signed
   packages; consequently this harness alone cannot close the exact-package
   gate. Record package hashes, source commit, model/fixed-artifact identities,
   commands, and startup output separately.
2. Put node B on another host, with its own empty data directory and authenticated
   verifier artifacts. Connect node B and the pool node over real P2P. Keep node
   B RPC and the pool dashboard bound to loopback. For a remote collector, use
   two independent SSH loopback forwards, for example local `29443` to node B
   `/v1/status` and local `29446` to the pool `/api/v1/pool`. The pool's P2P
   service is not an RPC service; the dashboard is its status source here.
3. Run **one uniquely named pool worker per physical GPU**, with an externally
   retained mapping from worker name to GPU UUID/host. Confirm that all 20 are
   actually running, owner-controlled, and not rented. Worker names or reported
   FW/s alone are not proof of GPU identity. Ensure isolated pool connection
   limits allow the intended host distribution; do not change the public RC
   service for this test.
4. Set `CMFD_DROPOUT_REHEARSAL_TELEMETRY=1` on the candidate pool and every miner
   **before** starting them, retaining their original stderr logs. It adds
   diagnostic lines only for chain-winning search, exact replay/proof, node
   submission, and job switches. It is not an admission shortcut, and these
   unsigned logs remain operational evidence rather than cryptographic proof.

## Configure and capture

Create a JSON config outside the source checkout with this shape, replacing
identities and worker names with the exact isolated deployment. All 20 names
must be distinct; the five survivors must be a subset of the 20, and the final
one a subset of the five. The example's identity placeholders deliberately
fail validation until replaced.

```json
{
  "schema": "CommonFoundry/DropoutRehearsalConfig/v1",
  "node_b_url": "http://127.0.0.1:29443/v1/status",
  "pool_url": "http://127.0.0.1:29446/api/v1/pool",
  "network_id": "REPLACE_WITH_ISOLATED_NETWORK_ID_64_LOWERCASE_HEX",
  "consensus_fingerprint": "REPLACE_WITH_ISOLATED_FINGERPRINT_64_LOWERCASE_HEX",
  "initial_target": "000ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccb",
  "pow_limit": "003fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  "minimum_phase_seconds": 300,
  "maximum_transition_seconds": 60,
  "phases": [
    {"gpu_count": 20, "minimum_blocks": 2, "workers": ["gpu00", "gpu01", "gpu02", "gpu03", "gpu04", "gpu05", "gpu06", "gpu07", "gpu08", "gpu09", "gpu10", "gpu11", "gpu12", "gpu13", "gpu14", "gpu15", "gpu16", "gpu17", "gpu18", "gpu19"]},
    {"gpu_count": 5, "minimum_blocks": 2, "workers": ["gpu00", "gpu01", "gpu02", "gpu03", "gpu04"]},
    {"gpu_count": 1, "minimum_blocks": 2, "workers": ["gpu00"]}
  ]
}
```

Start the collector **at height zero**, after pool/node B startup and model
authentication, but before the first miner connects. It checks both identities,
both 5x genesis targets, pool genesis tip, and storage health. The first sample
may contain zero workers; the 20-GPU phase starts only once the exact cohort is
connected. Sample at one second unless endpoint cost calls for a larger interval.

```text
python3 scripts/mainnet_dropout_rehearsal.py capture \
  --config /absolute/isolated-5x.json \
  --output /absolute/new-evidence-dir \
  --seconds 21600 --interval 1
```

The command does **not** cause the dropout. Once all 20 mapped GPUs are mining,
observe at least the configured dwell and two accepted blocks. Stop 15 known
workers (not customer workloads); observe the exact five for the same minimum;
then stop four and observe the final one. Capture the actual action times and
GPU readback independently. Keep the nodes and pool running throughout. A
transition may briefly show intermediate counts but must settle within the
configured maximum; a rebound or skipped phase fails the report. Ctrl-C writes
an interrupted capture receipt and cannot be mistaken for a complete run.

Analyze with the original pool log and **all** miner logs. Repeat `--miner-log`
for each process; the result path must not exist.

```text
python3 scripts/mainnet_dropout_rehearsal.py analyze \
  --capture /absolute/new-evidence-dir \
  --pool-log /absolute/pool.stderr.log \
  --miner-log /absolute/gpu00.stderr.log \
  --miner-log /absolute/gpu01.stderr.log \
  ... \
  --output /absolute/new-dropout-report.json
```

Use an actual Python 3 executable (`python.exe` on Windows) if `python3` is not
on the path. Retain the create-new `CONFIG.json`, `SAMPLES.jsonl`, `CAPTURE.json`,
raw process logs and the SHA-256-linked report together. Never substitute
hand-written timing values for process output.

## What the report means

For each phase the report separates:

- median **reported aggregate GPU search FW/s** and a winner worker's own job
  reported work units/search seconds; this is not a network block-production
  rate. The miner counts a scheduled CUDA batch as work even if a winning
  nonce is identified within it; do not mislabel those units as exact attempts;
- pool exact search replay, full replay and proof-worker durations and proof
  bytes, plus complete pool evaluation wall time, separate from pool
  node-submission duration (which includes bounded
  admission/ledger work, not just pure CPU verification);
- node A block-tip first observation and node B's independent same-tip first
  observation, plus a contemporaneous successful P2P peer observation and
  node B's reported verifier mode/queue;
- pool stale-share counter change, superseded-job telemetry from miner logs,
  sampled verification queue, first-block delay after each step, and observed
  block intervals;
- first 10/60 interval means and first rolling 60-interval ≤90-second window
  **only if** enough real blocks were observed. `null` means not observed; two
  blocks per phase cannot establish long-run recovery.

Polling limits propagation precision to roughly a sample interval plus endpoint
response time. The script refuses skipped heights because an unseen intermediate
tip cannot be assigned a defensible P2P latency. Missing proof, search, P2P,
worker, identity, target, queue, or log evidence keeps `measurement_complete`
false. An exact-package, independently reproduced and signed launch rehearsal,
custody review, and a consciously selected recovery policy remain separate
mainnet gates; this tool cannot approve them.

The first block observed just after a dropout may reflect a winning share
already in flight before the drop. A miner job-switch log includes reported work units for
the *whole* prior job and cannot be assigned exclusively to a post-drop phase;
the report therefore counts switches but does not mislabel those units as
phase-local stale work.
