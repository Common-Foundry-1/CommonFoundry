# Common Foundry standalone CUDA miner

`cmfd-miner` is a separate command-line miner for dedicated NVIDIA mining
rigs. Normal `mine` mode is a thin client: it asks a configured Devnet node for
a complete mining template, searches the immutable proof-of-work challenge,
and returns the finished block to that node. It does not download the chain or
maintain a second node database. Multiple independent preparation workers keep
each selected GPU supplied with nonce batches.

## Supported GPUs

The packaged CUDA 12.9 fat library contains these native images:

| Architecture | CUDA target | Representative cards |
| --- | --- | --- |
| Volta | `sm_70` | Tesla V100, Titan V, Quadro GV100 |
| Turing | `sm_75` | GeForce RTX 20 series |
| Ampere | `sm_86` | GeForce RTX 30 series |
| Ada | `sm_89` | GeForce RTX 40 series |
| Blackwell | `sm_120` | GeForce RTX 50 series |

A `compute_70` PTX image is included for forward compatibility. CUDA Toolkit
12.9 is intentional: it can compile both Volta and Blackwell, whereas CUDA 13
removed offline compilation support for Volta. The miner package uses the
static CUDA runtime, so testers need a compatible NVIDIA driver but do not need
to install the CUDA Toolkit.

## Multi-GPU behavior

- With no `--device` options, every detected GPU with compute capability 7.0
  or newer is selected.
- Repeat `--device` to choose a subset, for example `--device 0 --device 2`.
- Each worker owns a separate CUDA context and model allocation on its assigned
  GPU. By default, the miner divides available host threads across the selected
  GPUs, capped at 16 workers per GPU.
- Worker contexts and resident model bytes are created once, then retained
  across block-template changes. Every new template still runs a differential
  canary before nonce search begins. This is lifecycle infrastructure for the
  bounded Devnet v2 profile; it does not activate the production V3 proof.
- `--workers-per-gpu 0` selects that automatic mode. Set an explicit value from
  1 through 16 to reduce host power use or tune a particular rig.
- Worker `i` begins at batch `i`; later batches advance by `total worker count ×
  batch size`. This keeps nonce ranges disjoint across every GPU and worker.
- The displayed rig rate is the sum of complete ForgeMatrix nonce evaluations
  from every worker.
- Every statistics report includes rig and per-GPU hashrate, NVIDIA-reported
  power draw, hashes per watt, temperature, fan, utilization, graphics and
  memory clocks, and VRAM use. Session uptime, attempted nonces, accepted
  blocks, and stale-job rebuilds are also shown.
- One displayed `H/s` is one complete ForgeMatrix nonce evaluation per second.
  It is not an INT8 operation count.
- NVIDIA sensors are read through `nvidia-smi`, which ships with the driver.
  Unsupported sensors display `N/A`; telemetry failure never stops mining.
  Hashes per watt divides the interval hashrate by the instantaneous power
  sample taken for that report.
- CUDA is a candidate generator. Rust independently recomputes a below-target
  candidate before it can be submitted as a block.

## Windows quick start

The Windows ZIP includes:

- `cmfd-miner.exe`
- `cmfd-forgematrix-v2-miner.dll`
- `cmfd-forgematrix-v2-miner.dll.build-receipt`
- `cmfd-forgematrix-v2-opencl.dll` and its `.build-receipt` (unless omitted)
- `LIST-GPUS.bat`
- `START-MINER.bat`

Run `LIST-GPUS.bat`, then launch `START-MINER.bat`. Its defaults try a GUI
wallet on the same computer first and the community bootstrap second, so the
peer settings normally need no editing. Leave `GPU_INDEXES` blank to use every
supported card automatically. Copy the 64-character address from the wallet's
**Receive** page into `PAYOUT_ADDRESS` before starting. The connected node owns
the chain and creates each payout-bound template. `WORKERS_PER_GPU=0` is the
recommended automatic high-throughput setting.

Release packaging requires the exact candidate commit as an external input and
rejects native libraries whose adjacent build receipt does not match it. The
receipt prevents accidental input mixing but does not authenticate the builder;
see [Release identity guards](release-integrity.md).

## Direct commands

List devices:

```text
cmfd-miner devices
```

Mine with every supported GPU and the community bootstrap:

```text
cmfd-miner mine --miner <64-character-wallet-receive-address> --peer 127.0.0.1:18444 --peer 107.214.187.2:18444 --allow-public-peers
```

Select GPUs 0, 1, and 3:

```text
cmfd-miner mine --miner <64-character-wallet-receive-address> --peer 127.0.0.1:18444 --device 0 --device 1 --device 3
```

Change the live-statistics interval from its five-second default:

```text
cmfd-miner mine --miner <64-character-wallet-receive-address> --peer 127.0.0.1:18444 --stats-seconds 10
```

Limit host preparation to four workers per selected GPU:

```text
cmfd-miner mine --miner <64-character-wallet-receive-address> --peer 127.0.0.1:18444 --workers-per-gpu 4
```

The standalone miner currently performs continuous solo mining. The node
selects the parent, transactions, timestamp, target, and coinbase outputs. The
miner changes only the proof nonce, fully verifies a CUDA candidate in Rust,
and submits the complete canonical block. It prints `BLOCK ACCEPTED` only after
at least one configured node answers `Accepted` or `AlreadyKnown`.

The miner checks its source node every two seconds. A changed parent cancels
the current GPU job and fetches fresh work. A temporary disconnect pauses GPU
work and retries the preferred node followed by the configured failover nodes.
After a block is found, `Busy` is not a rejection. While a compatible node
still reports the candidate's exact parent as its tip, the miner retains and
retries the byte-identical block, proof, and block ID across reconnects. It
does not fetch a fresh template solely because a node returned `Busy`. Each
connection repeats the network and consensus handshake and each response must
name the submitted block. The retry is interruptible by shutdown and has one
20-minute total budget, including connect, handshake, and response time. A tip
change increments stale-submission telemetry and rebuilds work; budget expiry
increments abandonment telemetry and logs the abandoned block ID. Shutdown is
polled during short bounded connect attempts and every handshake, request, and
response I/O wait, so an unreachable or silent peer cannot hold the miner open.
Transport disconnects and peer protocol errors (including malformed frames or
the wrong response block ID) have separate counters and diagnostics; neither
is counted as a cryptographic block rejection.

`--miner` (or `PAYOUT_ADDRESS` in the packaged launch file) selects the coinbase
payout destination. It does not identify or locate a node. `--peer` selects the
node that receives blocks. One outbound miner-to-node peer configuration is
enough; the wallet/node does not also need to list the miner as a peer.

For diagnostics, `cmfd-miner full-node` preserves the former embedded-node
mode with its own data directory and P2P listener. Normal rig operation should
use `cmfd-miner mine` or the packaged launcher.
