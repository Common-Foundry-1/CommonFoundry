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
ProductionV4 input set; the wallet and node binaries in this package are RC3.
