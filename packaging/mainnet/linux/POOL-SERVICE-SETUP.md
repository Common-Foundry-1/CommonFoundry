# Staged Linux mainnet pool service

These are service templates; extracting an archive does not install or enable
a pool. Mainnet runtime packages include the pool-service files, dashboard,
CUDA runtime and workers. Verify the exact signed package and four-archive
preflight, final mainnet plan, approved reward destinations, pool economics and
the mainnet payout CLI before installation. Qualify the actual host service
before enabling it. No RC certificate, wallet, ledger, P2P seed,
port, or service account may be reused.

## Deliberately separate identity

| Purpose | Mainnet pool only |
|---|---|
| Account/group | `commonfoundry-mainnet-pool` (nologin; `video`/`render` GPU access) |
| Root-owned release copy | `/opt/commonfoundry-mainnet-pool/releases/<version>`; `current` points there |
| Configuration and fresh certificate | `/etc/commonfoundry-mainnet-pool/pool.json`, `pool-cert.der` |
| Root-only input credentials | `/etc/commonfoundry-mainnet-pool/wallet-passphrase`, `pool-key.der` |
| Temporary service-owned credentials | `/run/commonfoundry-mainnet-pool/wallet-passphrase`, `pool-private-key` (0600; directory 0700) |
| Pool state and encrypted wallet | `/var/lib/commonfoundry-mainnet-pool/data` |
| GPU worker scratch | `/var/lib/commonfoundry-mainnet-pool/scratch` |
| Miner TLS / P2P / loopback dashboard | TCP `29445` / `29454` / `29446` |

The mainnet seed node template uses a different account and data directory.
Its default public P2P port is `29444`; the pool connects to an explicitly
approved numeric mainnet seed on that port and advertises its own `29454` P2P
listener. The pool does not fall back to an RC seed or compiled default seed.
External reachability on TCP `29445` and `29454` requires independently checked
firewall/NAT rules; the seed's `29444` rule is separate. Opening public ports,
DNS, NAT, dashboard reverse proxy, backup export, and
monitoring are separate operator changes; this template performs none of them.
The launcher refuses to start while either RC pool unit or AI01 owner ZCL/XMR
miner unit is active; it does not silently stop those services. The operator
must make an explicit RC cutover decision before mainnet pool sockets open. A
staged service can wait for the beacon while RC still serves; it checks again
after the beacon and refuses to exec the node if RC is still active or the
approved pool GPU still has a compute process. It never stops that process.

## Before any service installation

1. Independently verify the exact signed mainnet runtime package, source,
   launch plan, approvals, hashes and release receipts. Make a **separate
   copy** into the root-owned release directory, not a hardlink to RC files.
   The `current` link must resolve inside that installation's `releases`
   directory. The service user may read but never replace binaries, model
   inputs, plan, config, TLS certificate, dashboard assets or parent entries.
2. Prepare the **full miner-role ProductionV4 input set** into that release's
   `production-v4` directory using its signed `prepare-runtime.sh` with role
   `miner`. A node-only preparation omits the fixed-bank inputs needed by the
   pool proof worker. Keep the seven large input files and both copies of the
   fixed-record file root-owned, group-readable and not group-writable. The
   launcher hashes all eight catalog entries on every start and compares the
   bank and record again to the pinned mainnet launch plan. It does not download
   anything during service startup.
3. Supply the correct Linux ProductionV4 replay/proof workers for the dedicated
   GPU. The current AI01 RTX 4090 needs SM89-capable workers, not an untested
   architecture substitution. Independently verify their SHA-256 values, the
   CUDA 12 runtime copied to `lib/libcudart.so.12`, and the exact GPU UUID.
   Prove a full block and restart on this hardware with the intended package.
4. Create a **new** pool wallet passphrase and a **new** DER TLS certificate
   and private key. Do not copy the RC encrypted wallet or RC TLS files.
   Store only the passphrase and private key as root-only files in `/etc`; the
   unit passes them through systemd `LoadCredential`, then copies them as 0600
   files into its private `RuntimeDirectory` before running the pool launcher.
   This handles systemd versions that expose credentials with a named-user ACL
   and a 0440 mode mask without weakening the wallet's 0600 requirement. The
   runtime copies disappear when the service stops; keep the original root-only
   files in `/etc`. Never put credentials in environment values or command-line
   arguments. The launcher rejects a redirected/nonprivate runtime directory
   or a group/world-accessible credential. Record hashes of the
   existing RC encrypted `wallet.key`, TLS private key and certificate into
   the three `forbidden_rc_*` fields without copying those secrets into the
   mainnet installation. The known AI01 public RC certificate fingerprint is
   also rejected by code. The first start refuses nonempty unmarked pool data;
   later starts bind the data to one plan/network/certificate marker and reject
   a byte-identical RC encrypted wallet. A newly re-encrypted copy of an RC
   signing key cannot be detected by a file hash: independently compare the
   pool reward destinations before launch.
5. Supply a reviewed, immutable mainnet dashboard directory. The assembler
   requires a frozen-source dashboard manifest and carries the exact asset
   tree in all four archives.
   Hash its `index.html` from the approved asset set and verify the full tree
   against the final package receipt and independent reproduction evidence.
6. Fill every field in `mainnet-pool.json.example` with **final approved**
   values and install it as root-owned `pool.json` under `/etc`. No RC defaults
   are inherited: the share target, minimum payout, payout burn, operator fee,
   PPLNS window, worker thread count, public address, seed, node/worker hashes,
   network ID and plan digest are all mandatory. The file cannot contain
   placeholders. It must name the exact private bind IP of this host and a
   public numeric IP that routes to TCP `29445`. The expected certificate hash
   becomes the miner URL pin. `automatic_payouts` must be explicitly true; the
   launcher uses the **mainnet-specific** `--enable-mainnet-payouts` flag, never
   `--enable-testnet-payouts`. A runtime without that flag fails closed.
   The burned payout fee must meet the exact minimum in the pinned launch
   plan, and the payout threshold must exceed that fee; a lower value is
   rejected before the beacon wait or pool startup.

The service's release copy includes its own `production-mainnet/MAINNET-PLAN.json`.
To let the launch helper publish the verified future beacon without granting
write access to the pinned plan, use the same root-owned sticky-directory
pattern described in `SERVICE-SETUP.md`: directory root:service-group mode
`1770`, plan file root:service-group mode `0440`. Only that directory and the
dedicated state directory are writable through the systemd sandbox. CUDA needs
device access, so this unit does not use `PrivateDevices=true`; it instead runs
as the dedicated unprivileged account with only `video`/`render` groups and a
read-only filesystem outside those two paths. Review actual device access and
systemd sandbox behavior on AI01 before launch.

The GPU character devices also need an explicit device-filter allowlist.
`ProtectClock=true` implies a clock-device rule and can make the default device
policy deny NVIDIA access even when the account belongs to video/render. Keep
that protection enabled and create a root-owned mode-0644 drop-in at
`/etc/systemd/system/commonfoundry-mainnet-pool.service.d/20-nvidia-devices.conf`.
For a single approved GPU at `/dev/nvidia0`, use:

```ini
[Service]
DevicePolicy=closed
DeviceAllow=/dev/nvidia0 rw
DeviceAllow=/dev/nvidiactl rw
DeviceAllow=/dev/nvidia-uvm rw
DeviceAllow=/dev/nvidia-uvm-tools rw
```

Confirm the device index maps to the configured GPU UUID. On another host,
allow only its intended GPU nodes; do not copy a broad wildcard or change
global device permissions. Reload systemd and test NVIDIA visibility and a
complete proof as the actual service account with the same restrictions.
An unrestricted shell query alone does not qualify the service sandbox.

The dual-arch candidate proof worker dynamically requires the packaged
`libcudart.so.12` plus host `libstdc++`, `libgcc_s`, glibc and the NVIDIA driver;
the replay worker requires the standard host libraries. The mainnet package
does not bundle a GPU driver. Inspect dynamic dependencies and run a complete
proof under the actual service identity on the target driver before release.

## How startup is gated

The unit calls `cmfd-node mainnet-launch-info` before the Python wrapper. The
wrapper repeats that native check, requires the exact final network/plan IDs,
hashes the static runtime and full model set, checks credentials and GPU UUID,
then invokes `cmfd-launch fetch --runtime ... --wait`. No pool socket opens
before the signed future-round beacon is available. Once the helper returns,
the wrapper requires the beacon sidecar and execs the mainnet node; the node
independently verifies the beacon and compiled plan before opening state.
`TimeoutStartSec=infinity` allows waiting for the exact round rather than
substituting a fallback. A failure exits without starting the pool. Shutdown
uses `SIGINT` and a 240-second grace period for ledger-preserving cleanup.

The offline tests (`scripts/tests/test_mainnet_pool_service.py`) exercise the
configuration, separate paths/ports, exact artifact hashes, copied-RC-state
rejection, marker binding and command construction without contacting a pool
or starting a service. Passing them is **not** a live startup, payout, TLS,
share, reorg, recovery, or mainnet launch qualification. Before enabling any
unit, verify it with `systemd-analyze verify` on the target Linux system and
repeat the exact-package pool tests, mature payout and deep-reorg reconciliation
under the approved final plan. Preserve an off-host encrypted wallet backup and
test restoration without copying the RC wallet.
