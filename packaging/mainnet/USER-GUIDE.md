# Common Foundry mainnet packages

Source and packages are scheduled for October 2, 2026 at noon US Central
(17:00 UTC). Mining is scheduled for October 3 at the same time. Both dates
use CDT, not winter CST.

Extract the complete archive to a folder you can write to. Keep its files
together. Verify the release signatures and SHA256 checksums before running it.
The embedded MAINNET-PACKAGE.json records the producer's package inventory and
native identity checks; it is not an independent approval or a signature.
production-mainnet/MAINNET-APPROVALS.json identifies the plan-review records
bound into the compiled release. Full signed review evidence and the release
checksum signature must be verified through the published release materials.

## Wallet and node

Windows: double-click START-WALLET.bat. Linux: run ./start-wallet.sh.
The launcher prepares approximately 6.4 GB of shared model inputs. Linux needs
Python 3, curl and the GTK/WebKit desktop runtime; Windows needs WebView2.
A GPU and WSL are not required for receiving, sending or validating blocks.

Before activation, the GUI lets you create an encrypted wallet and separate
encrypted backup, restore a backup, and copy your receiving address for miner
configuration. Keep the backup and its passphrase separately. No private key
is held unlocked during preparation. After the launch certificate is verified,
choose Unlock and connect. A delayed certificate means waiting for the same
announced round, not switching to another chain or starting early.

For a headless node, use START-NODE.bat or ./start-node.sh and supply the absolute
path to your wallet passphrase file outside data-mainnet. The launcher waits
for activation before starting the node. On Linux, that file must be readable
only by its owner (0600). Forward only the mainnet P2P port TCP 29444 when you
want inbound peers. RPC uses localhost:29443. Do not reuse RC data directories.

Runtime archives include [RECOVERY.md](RECOVERY.md) for offline backup and
restore, and [STORAGE-RECOVERY.md](STORAGE-RECOVERY.md) for interrupted-log repair.
Rehearse a restore into a separate directory before relying on the backup.

## Mining

The standalone miner connects to your chosen mainnet pool. Fill in the wallet
address, certificate-pinned pool URL and worker name in START-MINER.bat, or run
./start-miner.sh on Linux and answer its prompts. It prepares the pool-search
model inputs, waits for the authenticated launch certificate, then connects.
Windows GPU mining uses WSL2 Ubuntu-22.04 with NVIDIA support. Linux GPU mining
needs a compatible NVIDIA driver. Normal wallet operations do not require them.

For a multi-GPU rig, run one miner process per GPU. List the physical indices
and full UUIDs with `nvidia-smi --query-gpu=index,uuid --format=csv,noheader`.
Set a different `GPU` in each Windows BAT copy, or start separate Linux
terminals with `CMFD_GPU=0 ./start-miner.sh` and
`CMFD_GPU=1 ./start-miner.sh`. Full `GPU-...` UUIDs also work and are preferable
when GPU enumeration may change. The miner verifies the selector against
`nvidia-smi`, passes that exact GPU UUID to the CUDA replay process, and reports
power and temperature for that physical GPU. Selected processes get distinct
`.gpuN` pool-worker names, scratch directories, and logs under `work/logs`.
Leaving GPU blank preserves the original single-GPU default (GPU 0 and the
unsuffixed worker name). A user-scoped lock keyed by physical GPU UUID stops
the same card from starting twice under index/UUID aliases or separate package
copies; a second lock prevents sharing one scratch directory.
If two copies attempt to prepare the shared model bank simultaneously, later
copies wait with periodic progress reports, then revalidate the completed bank.
The wait is capped at one hour; a timeout never uses partial inputs. A crash
releases the OS lock, so rerun the launcher to resume authenticated setup.

Wallet solo mining additionally needs approximately 61 GB of model inputs.
Close the wallet, run PREPARE-MINING.bat (Windows) or ./prepare-mining.sh (Linux),
then reopen it. The GPU workers are included in the package; the preparation
script does not download an arbitrary newer worker. Additional scratch space
and chain storage are needed beyond these model-input sizes.

The ForgeMatrix model catalogs retain their original RC1 provenance labels.
These are reusable, hash-checked computation artifacts, not an RC network
configuration. The separate production-mainnet/MAINNET-PLAN.json and the
compiled executable pins define the mainnet identity and rules. RC balances do
not move into this new chain.

Keep the system clock accurate. The beacon response is accepted only for the
fixed launch round and verified against the compiled public key. If an existing
LAUNCH-BEACON.json is invalid, the software reports it without overwriting it.
Preserve diagnostics when asking for help; never send a wallet key, backup
passphrase, or passphrase file to support.
