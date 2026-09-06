# RCNet-1 pool miner

The RCNet-1 miner connects only to a certificate-pinned `cmfd+tls` pool. The
pool independently replays every submitted share and constructs the complete
ProductionV4 proof only for chain-winning work.

## Requirements

- NVIDIA GPU supported by the packaged `cmfd-v4-replay` worker
- current NVIDIA driver
- about 14 GB of free disk during first setup, when downloaded parts and the
  assembled authenticated model bank coexist; about 8 GB after setup
- Windows: WSL2 with Ubuntu 22.04 and NVIDIA CUDA support
- the pool operator's complete `cmfd+tls://IP:PORT?pin=...` URL
- a 64-character RCNet-1 wallet receive address

On Windows, double-click `START-MINER.bat`. On Linux, run `./start-miner.sh`.
The first run downloads four authenticated model-bank parts, reconstructs the
6.4 GB bank, verifies its SHA-256 digest, and then starts the persistent GPU
worker. Interrupted downloads resume automatically.

The TLS pin authenticates the pool endpoint. Keep the full URL intact and do
not substitute an unpinned address.

## Miner 2 GPU update

The miner-only `v0.1.0-rc.5-miner.2` release improves GPU batching on RTX 40/50
series and hashes each final activation in one CPU operation. It preserves
RCNet-1, the model, proof rules, and pool protocol. Wallet and node RC5 remain
compatible. The miner does not change GPU clocks or power limits.

Native worker images cover CUDA SM 7.5, 8.6, 8.9 and 12.0, with compute-7.5
PTX fallback. Physical checks cover RTX 4070 Ti SUPER, RTX 5070 Ti and RTX 5090.
Physical RTX 20/30-series and 8 GB card qualification remain pending; an
embedded GPU image alone is not hardware qualification. Measurements and
their limits are in the included `PERFORMANCE-ADA.md` and
`PERFORMANCE-BLACKWELL.md`.

Extract updates into a new directory and stop the previous miner before
starting the new one. Preserve your wallet address, complete pinned pool URL,
and worker name. You may copy an existing authenticated `inputs/MODEL-V2.bank`
into the new package's `inputs` directory; setup verifies it before use.
Keep the previous package for rollback.
