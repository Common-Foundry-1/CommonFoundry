# Common Foundry RCNet-1 runtime bootstrap

This package is the small, downloadable companion to the RCNet-1 wallet. It
contains the native wallet and node, the pinned ProductionV4 manifests, and a
resumable downloader for the approximately 6.4 GB model bank. The bank is not
duplicated in this archive so the release stays practical to download.

## Windows

Extract the archive to a writable directory, then run `START-WALLET.bat`.
The first run downloads four authenticated parts from the immutable RCNet input
distribution, assembles `production-v4/MODEL-V2.bank`, verifies its exact
length and SHA-256 digest, and starts the wallet. Interrupted transfers resume
from the `.parts` directory.

## Linux

Extract the archive, make the launcher executable if needed, and run
`./start-wallet.sh`. `curl` and Python 3 are required for the authenticated
download.

Keep at least 8 GB free in the extraction directory. Do not edit or replace the
manifest, fixed record, or downloaded bank: the wallet and node reject files
that do not match the compiled RCNet-1 identities.

The model-bank parts are served from `downloads.commonfoundry.ai` with the
public RC1 GitHub release as a fallback. The RC1 label identifies the immutable
ProductionV4 input set; the wallet and node binaries in this package are RC5.

## Optional GPU mining setup

Wallet use still needs only the model bank. To enable Mining, close the wallet
and run `PREPARE-MINING.bat` on Windows or `./prepare-mining.sh` on Linux.
This downloads the hash-pinned replay/proof workers and all fixed proving inputs
into `production-v4/`. Allow at least 85 GB free for the approximately 61 GB
input set, temporary downloads, and proving scratch files. Interrupted input
downloads resume. No GPU mining or large downloads start merely by opening a tab.

The initial packaged workers target NVIDIA RTX 50-series GPUs (CUDA SM 12.0);
the hardware qualification is on an RTX 5090. Windows needs WSL2 Ubuntu-22.04
and CUDA 12.8 in that distribution. Linux needs CUDA 12.8. Other GPU architectures
are not qualified by this release. The downloader does not install drivers,
WSL, or CUDA for you.

Reopen the wallet, unlock it, then select Mining and Start Solo Mining. The
wallet searches nonces, builds proofs, and submits blocks through the embedded
node's consensus verifier. Stop prevents new work/submissions and lets the current
GPU operation finish. RCNet mining cannot begin before its configured genesis.

RC5 enforces a minimum burn of 0.1 CMFD per transaction. All RCNet nodes and
pool operators must upgrade together. Empty RC4 chain directories migrate their
network metadata while retaining `network.meta.rc4` and the existing wallet key.
Directories containing old-rule blocks are not automatically reset or migrated.
