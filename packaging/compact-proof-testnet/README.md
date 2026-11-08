# Common Foundry Compact Proof Testnet - v0.5.0

Welcome! This canary lets pools and miners exercise the new self-contained block proof, around 5.7 MB in our first public block. It keeps the ForgeMatrix workload and the existing field, hash, and BaseFold parameters. Ordinary nodes verify the complete proof without rerunning the miner's matrix computation. The public seed at `209.145.48.36:23444` also replays work as an optional audit comparison.

v0.5.0 makes shared-model two-GPU proving faster with pipelined witness transfer
and GPU-resident relation inputs. Our complete local pool acceptance improved
from v0.4.0's 11.57-12.08 seconds to **8.27-8.52 seconds** on the same PCIe Gen2 x1
rig. Peak device memory remained **6.77 / 7.46 GiB**, with full proof verification
and unchanged security parameters. Post-proof replay resumes without reloading
the model. These measurements used physical 16 GiB cards under a 7.5 GiB guard;
physical 8 GB mobile testing is the next canary.

Existing testnet keys, chain data, inputs, ledger and TLS certificates carry
forward. This is the same network and v2 proof format.

## What you need

Use x86-64 Linux with glibc 2.35 or newer (Ubuntu 22.04 or newer), Python 3.10+, curl, and sha256sum. GPU roles need a working NVIDIA driver and CUDA 12 runtime (`libcudart.so.12`). This prover includes RTX 30, 40, and 50 architecture targets. Our physical 16 GB proof testing used an RTX 5070 Ti; please include your GPU model in feedback.

A pool's first input download is about **61.2 GB**. Allow **150 GB free disk** during first preparation for input chunks, assembled files, and scratch, and **32 GB system RAM**, with 64 GB useful for running several roles. A pool miner or CPU node downloads only the **6.44 GB model bank**. Downloads resume and authenticate against bundled SHA-256 manifests. Existing inputs can be reused with `--inputs /absolute/path/to/inputs`.

The shared-model test also ran on a 16 GB system. More host RAM is useful for
busy pools and extra roles; the worker checks available RAM throughout proving.

Inputs and node/pool/miner data default to `~/.local/share/commonfoundry-compact-testnet1`, so extracting an updated kit keeps your authenticated inputs and chain. If you used v0.1.0's in-package data directory, pass its existing path with `--inputs` and `--data-dir` when starting v0.2.0.

## Start a pool

Extract the archive, enter its directory, and verify it against the separately supplied archive checksum:

```bash
./VERIFY-PACKAGE.sh
./START-POOL.sh --public-ip YOUR_NUMERIC_PUBLIC_IP
```

The first start prepares inputs, creates dedicated testnet storage and a pool TLS certificate, then prints your complete `cmfd+tls://...?...` miner URL. Forward TCP **23444** for peers and **23445** for miners to the pool host. `--bind-ip` selects the local listen address. Share the printed miner URL with testers; it includes the exact certificate pin.

Reserve the proof GPU for pool workers and run mining clients on other GPUs or rigs. Pools with separate devices can use `--replay-gpu 0 --proof-gpu 1`; this is a useful layout for 16 GB proof cards. The prover keeps its memory guard active. The default operator fee is zero for this canary. Add `--enable-payouts` to exercise automatic testnet payouts after coinbase maturity (100 blocks). Ctrl+C gracefully stops the pool; rerunning the same command preserves the testnet ledger and certificate.

The reference pool uses Common Foundry's certificate-pinned pool protocol. Operators using another pool stack can first run this reference instance, then coordinate their own integration with us.

### Two-GPU shared resident model

Create the bounded RAM mount described below, then run:

```bash
./START-POOL.sh --public-ip YOUR_NUMERIC_PUBLIC_IP \
  --proof-gpus 0,1 --replay-gpu 1 --serial-gpu --shared-model \
  --ram-witness-dir /dev/shm/cmfd-pool-witness
```

GPU 0 handles dynamic proving; GPU 1 keeps one model for replay and fixed-proof
reductions. Reserve both cards for the pool; miners connect from other GPUs or
hosts. No NVLink or direct GPU peer access is needed. `MULTI-GPU.md` contains
the measured modes, device selection, memory budget and restart behavior.

Two live blocks reached pool evaluation plus local node admission in 12.08 and
11.57 seconds on Rig06's PCIe Gen2 x1 risers. About 4.7 seconds was witness
export/upload over those links; the five-second complete-path goal remains open.
The existing single-GPU prover and its previously measured profile remain
available. These are distinct hardware/mode measurements.

### RAM witnesses and one proof/replay GPU

Pools can keep witness files in a dedicated **2 GiB tmpfs** with
`--ram-witness-dir /dev/shm/cmfd-pool-witness`. The launcher checks its capacity,
free space, private ownership and permissions, and available host RAM. Create
the mount as the same user that runs the pool:

```bash
mkdir -m 700 /dev/shm/cmfd-pool-witness
sudo mount -t tmpfs -o size=2G,mode=0700,uid="$(id -u)",gid="$(id -g)",nosuid,nodev,noexec tmpfs /dev/shm/cmfd-pool-witness
./START-POOL.sh --public-ip YOUR_NUMERIC_PUBLIC_IP --ram-witness-dir /dev/shm/cmfd-pool-witness
```

The prover still copies regular witness files into immutable kernel-sealed
buffers and checks every field word. The proof parameters and node verification
remain the same. After stopping the pool, unmount this exact directory and
remove the empty mount point.

For one GPU serving both pool replay and proof generation, add
`--replay-gpu 0 --proof-gpu 0 --serial-gpu`. This releases replay's model before
proving and prevents replay from reloading it until proving finishes. Other
mining clients can use their own GPU. A miner sharing the proof GPU can add
`--yield-gpu-on-share` to `START-MINER.sh`: it releases its model before each
share, waits for checking/proving, and reloads before its next search. This
serial setup avoids keeping two search models on one device. Separate replay
and proof GPUs allow shares to keep running during proving.

Add `--sealed-witness` to the serial GPU command to transfer replay output
directly into immutable RAM buffers. This mode prepares the next witness while
the current proof runs, uses at most **3 GiB of host RAM** for the two witness
slots, and checks two known answers before opening the pool. It keeps every
field-word check, proof parameter and complete node-verification check.

## Connect a miner

Create a dedicated testnet payout key and copy the displayed public address:

```bash
./NEW-ADDRESS.sh --key "$PWD/testnet-payout.key"
./START-MINER.sh --pool 'COMPLETE_URL_FROM_POOL' --address YOUR_TESTNET_ADDRESS --worker rig01 --gpu 0
```

The miner reports accepted shares and discovered blocks. It uses the pool's compact prover when a winning share is found. Ctrl+C stops it.

## Run an independent node

```bash
./START-NODE.sh
curl http://127.0.0.1:23443/v1/status
./COLLECT-DIAGNOSTICS.sh --output testnet-diagnostics.json
```

Node verification runs on the CPU; it needs no GPU or CUDA runtime. Restart it, let it catch up, and compare its height and tip with another participant. The `/v1/wallet` and `/v1/explorer` endpoints show testnet rewards and chain activity.

## What to send us

Please share your GPU, driver, RAM, miner/pool versions, accepted and rejected shares, block counts, full winning-share-to-block time, peak VRAM, propagation/catch-up observations, and relevant log excerpts. The diagnostics collector includes build identity, node status, and GPU telemetry; it does not collect wallet keys or TLS private keys. Pool logs print proof-stage timings and packet sizes.

The initial public target is seven leading zero bits and adjusts with the chain's 60-second target spacing. Pool shares default to four leading zero bits. The proof-only and audit nodes use the same network identity and packet rules. Existing v0.1/v0.2 testnet data and inputs carry forward into v0.3.0.

The latest tested RAM/serial profile averaged **5.74 seconds** through complete local acceptance on an RTX 5090 (7001 MHz memory, 520 W), with three blocks at 5.88, 5.68 and 5.66 seconds. Proofs measured **5.65–5.69 MB**, and the incremental GPU workload peaked at **12.72 GiB** under its 13 GiB guard. This is the latest 32 GiB-card measurement; please include your hardware and peak memory in reports. The included qualification record identifies the exact measured GPU workers and timing scope.
