# Mainnet launchers

The committed `MAINNET-PLAN.json` and `REWARD-CUSTODY.json` are the public output
of the owner's custody setup. The September 27 replacement retained the exact
Steward key and replaced the Community key and release signer after the owner
reported the other passwords unavailable. The new Community destination derives
a new mainnet network identity; the earlier pending packages are superseded.
They bind the two reward destinations, 5x RC starting difficulty and October 3
17:00 UTC launch. They contain no wallet keys or passwords and are not launch
approvals. Do not regenerate or replace them with fixture destinations. See
`docs/mainnet-reward-custody.md` for verification and remaining backup retention.

These source launchers are for the final signed mainnet packages; they do not
convert an RC package into a mainnet package. Final packaging must stage the
mainnet binaries, the authenticated MAINNET-PLAN.json, cmfd-launch, and the
existing authenticated model-input preparation tools under the names below.

- Runtime package: cmfd-node, wallet, cmfd-launch, and
  `PREPARE-RUNTIME.ps1` / `prepare-runtime.sh` plus the model chunk manifest and
  fixed record. The preparation tool takes an explicit destination directory.
- Miner package: cmfd-miner, cmfd-launch, replay worker, and the existing
  `PREPARE-V4-INPUTS.ps1` / `PREPARE-V4-INPUTS.sh` and authenticated manifests.
- HiveOS package: the same native Linux miner and workers, with the custom-miner
  callbacks described in `hiveos/README.md`. Its archive root and installation
  directory are `commonfoundry-mainnet-hiveos`, with no version subdirectory.
- Each package contains `production-mainnet/MAINNET-PLAN.json`. The future
  beacon is downloaded as `production-mainnet/LAUNCH-BEACON.json` after launch.

All launchers validate the package identity before downloads and prepare the
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

## Native package assembly

`scripts/package_mainnet.py` assembles the runtime (wallet + node) and standalone
miner archives on each native platform and the Linux HiveOS archive. It requires an exact clean frozen source
commit, matching package versions, a canonical plan, mainnet-feature binaries,
the launch helper, both Linux GPU workers, a reviewed built pool-dashboard tree,
and an exact-hash-pinned Linux x86-64 CUDA 12 runtime library. It does not build
the executables or dashboard. All five archives carry the same dashboard assets
and `lib/libcudart.so.12` so the Linux pool and WSL mining workers use one
reconciled runtime set. The Linux runtime also carries the separate mainnet
pool service templates; none is installed automatically.
Use Python 3.11 or newer and install the pinned dependencies from
scripts/requirements-release-integrity.txt. This is a packaging-host requirement,
not an additional Windows wallet-user requirement.

Example argument shape for Windows, with real absolute paths and the finalized
version/commit supplied by the operator:

```powershell
py -3 scripts/package_mainnet.py --platform windows-x86_64 --kind runtime `
  --commit $FrozenCommit --version $MainnetVersion --plan $ApprovedPlan `
  --approval-manifest $VerifiedPlanApprovals `
  --output $OutputDirectory --node $NodeBinary --wallet $WalletBinary `
  --launch $LaunchBinary --replay-worker $ReplayWorker --relation-worker $RelationWorker `
  --dashboard-dist $ReviewedPoolDashboardDist --dashboard-manifest $ReviewedDashboardManifest `
  --cuda-runtime $VerifiedLinuxCudaRuntime --cuda-sha256 $ReviewedCudaRuntimeSha256
```

For a miner archive, use `--kind miner --miner $MinerBinary` instead of the node
and wallet arguments. On Linux use python3 and `--platform linux-x86_64`.
The HiveOS archive uses `--platform linux-x86_64 --kind hiveos --miner $MinerBinary`.
The source node/wallet/miner versions must match; RC versions are not accepted.
Linux staging uses the native temporary filesystem so Windows-mounted output
directories cannot silently mark configuration files executable. Set `TMPDIR`
to a native Linux filesystem if the default temporary directory is mounted from
Windows; package assembly rejects incorrect executable modes.

Linux assembly also queries the proof worker's read-only `network-info` command
using the staged CUDA runtime. Its mainnet network ID must match the approved
plan. A successful ELF/architecture check alone cannot qualify an older RC-only
worker for mainnet. The reconciled Windows/WSL packages carry those same worker
bytes; complete proof and hardware qualification remain separate checks.

The assembler executes only read-only native identity/version commands, with
bounded output and deadlines. Node/miner `mainnet-launch-info` must agree with
the wallet's distinct `CMFD_WALLET_PRELAUNCH_IDENTITY_V1` wrapper. None of these
checks needs the future beacon or the downloaded model bank. The exact source
catalog bytes are retained as artifact provenance and checked against the plan.
Linux workers are bundled even in the Windows package, where mining uses WSL2.
The dashboard manifest is canonical JSON of the form
`{"schema":"CMFD_MAINNET_POOL_DASHBOARD_ASSETS_V1","source_commit":"<40-hex-commit>","files":{"index.html":{"bytes":123,"sha256":"<64-hex>"},"assets/index-<build-hash>.js":{"bytes":456,"sha256":"<64-hex>"}}}`
with a record for **every** dist asset. The manifest must be reviewed against a
reproducible build of the frozen source; source-commit binding alone does not
prove that the JavaScript was built from that source. The assembler rejects
missing/extra files, symlinks, hashes or sizes that differ from the manifest,
and unexpected asset paths. No archive can be assembled without the explicit
dashboard tree, manifest, library path and library SHA-256. The CUDA library
must be a non-symlink Linux x86-64 ELF shared object, copied byte-for-byte.
Its hash and the entire asset tree are bound by each package receipt.

NVIDIA's [CUDA Toolkit EULA](https://docs.nvidia.com/cuda/eula/) lists Linux
`libcudart.so` as redistributable in Attachment A, subject to the agreement's
distribution conditions. Supply an authorized, unmodified CUDA runtime object
and review the applicable terms before publication; the packager's ELF/hash
checks do not establish provenance or license compliance. Do not package the
CUDA Toolkit as a stand-alone product or infer GPU/driver compatibility from
an ELF header. Exact-package testing on the target GPU remains required.

Every archive includes production-mainnet/MAINNET-APPROVALS.json. Its digest,
qualification binding and signer authority descriptors must match the compiled
prelaunch identity, not merely a caller-supplied label. Source history after the
manifest's reviewed commit may change only mainnet_release_pin.inc.rs and
mainnet_network_id.inc.rs; other changes require fresh review.

All package files are hashed into MAINNET-PACKAGE.json. Archive metadata is
normalized to the frozen commit's timestamp, and existing outputs are never
overwritten. The receipt explicitly does not grant release approval. Final
cross-platform reconciliation, owner approval, signing/checksum inventory,
and full signed-package launch rehearsal remain required. Fixture archive tests
are not qualification of actual mainnet binaries.

## Offline five-package preflight

After both native platforms assemble their runtime and miner archives and Linux
also assembles the HiveOS archive, use
`scripts/verify_mainnet_packages.py` with the same `--repo`, `--commit`,
`--version`, and `--plan`, plus absolute paths for `--windows-runtime`,
`--windows-miner`, `--linux-runtime`, `--linux-miner`, `--linux-hiveos`, the reviewed
`--dashboard-manifest`, the reviewed `--cuda-sha256`, and a new `--output` report.
This requires Python 3.11+ and the same pinned dependencies as assembly.

The verifier does not execute or extract packaged files. It checks canonical
ZIP/USTAR/gzip structure, bounded member sizes, exact source-script bytes,
executable and CUDA-library architectures and permissions, plan bytes,
dashboard asset manifest/hash/size matches, and producer receipt hashes.
The five native identity records must agree, all packages on a platform must
have the same launch-helper binary, and all five must contain identical Linux/WSL
workers, dashboard assets and CUDA runtime. Extra files (including wallet keys or a preloaded beacon), missing roles,
symlinks, duplicate members, noncanonical trailers and changed archives fail.

The output binds the five archive hashes and explicitly remains unapproved and
not independently reproduced. It is input to internal rebuild comparison, review
and final signing, not a substitute for those steps. It never uploads anything.

Linux runtime packages also include isolated mainnet systemd templates and
SERVICE-SETUP.md. They are not automatically installed or enabled. The bundled
mainnet-storage-readiness.py is a read-only capacity planner/reserve check;
it never prunes data. The existing RC seed and its credentials must remain
untouched while preparing the separate mainnet directories and service account.

Final publication additionally requires the owner-signed internal-build statement
and the mainnet-specific checks in the standard release finalizer. See
docs/mainnet-plan-approvals.md in the source checkout for exact evidence filenames
and the preparation/signing sequence. Neither archive assembly nor an unsigned
preflight report authorizes a public release.
