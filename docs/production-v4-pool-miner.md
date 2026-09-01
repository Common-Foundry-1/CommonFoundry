# RCNet-1 pool miner

The RCNet-1 miner connects only to a certificate-pinned `cmfd+tls` pool. The
pool independently replays every submitted share and constructs the complete
ProductionV4 proof only for chain-winning work.

## Requirements

- NVIDIA GPU supported by the packaged `cmfd-v4-replay` worker
- current NVIDIA driver
- about 8 GB of free disk for the authenticated model bank and scratch files
- Windows: WSL2 with Ubuntu 22.04 and NVIDIA CUDA support
- the pool operator's complete `cmfd+tls://IP:PORT?pin=...` URL
- a 64-character RCNet-1 wallet receive address

On Windows, double-click `START-MINER.bat`. On Linux, run `./start-miner.sh`.
The first run downloads four authenticated model-bank parts, reconstructs the
6.4 GB bank, verifies its SHA-256 digest, and then starts the persistent GPU
worker. Interrupted downloads resume automatically.

The TLS pin authenticates the pool endpoint. Keep the full URL intact and do
not substitute an unpinned address.
