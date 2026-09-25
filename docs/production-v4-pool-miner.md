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

## One process per GPU (source template for a future package)

These launcher changes are not retroactive to already signed RC archives.
For a future package built from this source, run one launcher per physical GPU.
On Linux, set `CMFD_GPU=0` and `CMFD_GPU=1` in separate terminals. On Windows,
set `GPU=0` and `GPU=1` in separate copies of `START-MINER.bat`. A full GPU UUID
from `nvidia-smi --query-gpu=index,uuid --format=csv,noheader` can be used
instead of an index. The pool miner rejects malformed, unavailable, or multi-GPU
selectors; a missing selector defaults to GPU zero. It pins each replay worker
by the selected full UUID, which CUDA sees as ordinal zero. It logs the
selected physical card's telemetry,
appends `.gpuN` to the pool worker name, and gives each GPU its own scratch
directory and launcher log. With no selector, the existing single-GPU GPU-0
behavior and worker name remain unchanged.
An OS lock keyed by full UUID blocks a second miner on the same physical card,
even if one used its index and the other its UUID or a different package copy.

The shared model-bank setup is serialized by an OS file lock. Later launchers
wait with progress messages and then revalidate the first copy's authenticated
bank. The one-hour timeout fails closed; a crash releases the lock so setup can
be resumed. Do not copy partially assembled input files. This topology has
launcher and stub tests; physical multi-GPU mining and accepted pool shares
still require a separate rig qualification before release. A single-card WSL
CUDA smoke check observed the same full GPU UUID on Windows and WSL and one
visible CUDA device when selected by UUID; that does not prove two-card
assignment or end-to-end share acceptance.

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

## Mainnet compatibility build

The current source restores native replay/search images for Volta (SM70),
Turing/RTX 20 (SM75), Ampere (SM80/86), Ada/RTX 40 (SM89), Hopper (SM90), and
RTX 50 (SM120), plus compute_70 PTX. Volta uses exact signed INT8 DP4A rather
than unavailable SM75 INT8 Tensor Core instructions. Newer native cards retain
their existing Tensor Core backends. Model, field arithmetic, work digest,
proof rules and pool protocol do not change.

These source changes do not update previously signed downloads. They need a
fresh build, native/PTX inspection, differential tests, full-model/proof checks,
and release signatures before distribution. Physical older-card qualification
must be reported separately from forced-PTX testing on a newer card.

The resident-model 32-lane search allocates about 6.45 GiB before driver/display
overhead. A 6 GB GPU cannot fit this path; 8 GB is a capacity target, not a claim
that every 8 GB board/driver configuration has been tested. Pool clients need
only the replay/search worker. Full solo proving has separate GPU requirements.
