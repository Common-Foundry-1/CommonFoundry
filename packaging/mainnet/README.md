# Mainnet launchers

These source launchers are for the final signed mainnet packages; they do not
convert an RC package into a mainnet package. Final packaging must stage the
mainnet binaries, the authenticated MAINNET-PLAN.json, cmfd-launch, and the
existing authenticated model-input preparation tools under the names below.

- Runtime package: cmfd-node, wallet, cmfd-launch, and
  `PREPARE-RUNTIME.ps1` / `prepare-runtime.sh` plus the model chunk manifest and
  fixed record. The preparation tool takes an explicit destination directory.
- Miner package: cmfd-miner, cmfd-launch, replay worker, and the existing
  `PREPARE-V4-INPUTS.ps1` / `PREPARE-V4-INPUTS.sh` and authenticated manifests.
- Each package contains `production-mainnet/MAINNET-PLAN.json`. The future
  beacon is downloaded as `production-mainnet/LAUNCH-BEACON.json` after launch.

All launchers validate the package identity before downloads, prepare the
model inputs. Node/miner launchers then run the cancellable beacon helper;
the wallet opens immediately for offline encrypted-key creation, backup, restore,
and authenticated address display. Its own cancellable background worker acquires
the certificate, and an explicit unlock starts the node only after activation.
The preparation view never reports a live balance, connected node, or mining.
Windows miners stay
in the visible console. Fill out START-MINER.bat or answer its prompts; Linux
accepts wallet/pool arguments or CMFD_WALLET_ADDRESS and CMFD_POOL_URL.
Standalone nodes request the path to their existing wallet passphrase file;
CMFD_WALLET_PASSPHRASE_FILE can supply it without a prompt. Keep that file
outside the node's data directory. The wallet GUI retains its normal encrypted
wallet creation/unlock flow, with a separate backup required for new wallets.

The helper uses system curl (Windows System32 or /usr/bin/curl), without a
shell, redirects, or curlrc. It requests only quicknet round 32747812 from the
three pinned drand.sh relays. The node/miner reports its release-pinned plan
before any relay request. Responses have byte and time bounds. An old round,
invalid signature, relay timeout, or malformed response cannot start mining.

Use Ctrl+C to stop waiting. A verified cached beacon is reused. Publication
uses a synced temporary file and no-overwrite persistence; interruption before
publication does not expose a partial LAUNCH-BEACON.json. Invalid existing files
are preserved and reported instead of silently overwritten. A crash may leave
an unused temporary file, which is never treated as a certificate. This is
process-interruption protection, not a claim of power-loss qualification.

The final mainnet package builder, manifests, approval pins, and full launch
rehearsal remain required. Source launcher tests are not packaged qualification.
