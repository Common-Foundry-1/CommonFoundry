# Staged Linux mainnet pool service

These are service templates; extracting an archive does not install or enable
a pool. Mainnet runtime packages include the pool-service files, dashboard,
CUDA runtime and workers. Verify the exact signed package and five-archive
preflight, final mainnet plan, approved reward destinations, pool economics and
the mainnet payout CLI before installation. Qualify the actual host service
before enabling it. No RC certificate, wallet, ledger, P2P seed,
port, or service account may be reused.

## New operator or RC migration

`has_previous_rc_installation` in `pool.json` says whether you ever ran a
Common Foundry RC (RCNet) pool whose key or wallet could be copied to this
host. The example ships it as a placeholder that the launcher refuses, so
you must choose:

- **New operator, no RC pool:** set it to `false` and leave both RC file
  hashes `null`:

  ```json
  "has_previous_rc_installation": false,
  "forbidden_rc_private_key_sha256": null,
  "forbidden_rc_wallet_file_sha256": null
  ```

  Use JSON `false` and `null`, not quoted strings. Do not invent hashes,
  create dummy RC files or hash an empty file. If either field holds a value
  while the setting is `false`, the launcher refuses to start: a hash next to
  a "no RC installation" declaration contradicts it, and the launcher does
  not guess which one you meant.
- **RC migration:** set it to `true` and record the hashes of your old RC
  files as described in step 4. A `pool.json` without this field is treated
  as `true`, so existing configurations keep their checks unchanged.

In both cases `forbidden_rc_certificate_sha256` still needs a real hash: keep
the supplied known RC certificate hash, or for a migration use your RC
certificate's hash (step 4). Every `expected_*` field needs the real value for
your new mainnet files. The first start still requires an empty data
directory. A `false` setting is recorded in the deployment marker, so the pool
data stays bound to the setting it first started with and the launcher refuses
to start if it later changes in either direction. Do not delete a deployment
marker or wallet data to get around a check.

If your pool already started with placeholder RC hashes because an
older launcher required them, leave `has_previous_rc_installation` out and keep
those values: its deployment marker refuses a switch to `false`. A pool started
with `false` cannot go back to the launcher shipped in 1.0.15 or an older
release, which refuses its `pool.json` and marker.

If you installed the October 2 fresh-install launcher patch (the
`30-fresh-install.conf` drop-in with a separate copy at
`/usr/local/lib/commonfoundry/mainnet-pool-service.py`, also updated by the
`v1.0.0-pool.1` updater), the service still runs that copy, not the launcher in
your release. The `has_previous_rc_installation` and RC hash values in
`pool.json` and the deployment marker carry over unchanged. Before starting
this release, remove
`/etc/systemd/system/commonfoundry-mainnet-pool.service.d/30-fresh-install.conf`,
run `systemctl daemon-reload`, and check that
`systemctl show commonfoundry-mainnet-pool.service -p ExecStart` names
`/opt/commonfoundry-mainnet-pool/current/mainnet-pool-service.py`. Remove any
`idle_gpu_search` key from `pool.json`; this launcher refuses it. You can then
delete the separate copy.

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
   unit names them in systemd `LoadCredential`, and a privileged
   (`ExecStartPre=+`) step copies them as service-owned 0600 files into its
   private `RuntimeDirectory` before running the pool launcher. systemd 249
   (Ubuntu 22.04) fills the credential directory only for `ExecStart=`, so the
   copy reads the `/etc` files directly. The copy lines name the service user,
   group and source paths literally: a drop-in that overrides `User=`, `Group=`
   or a credential path must override those lines as well. The runtime copies
   disappear when the service stops; keep the original root-only files in
   `/etc`. Never put credentials in environment values or command-line
   arguments. The launcher rejects a redirected/nonprivate runtime directory
   or a group/world-accessible credential. When migrating from an RC pool
   (`has_previous_rc_installation` `true`), record hashes of its encrypted
   `wallet.key`, TLS private key and certificate into the three
   `forbidden_rc_*` fields without copying those secrets into the mainnet
   installation. A new operator with no RC pool sets the private key and
   wallet fields to `null` instead (see "New operator or RC migration"
   above). The known AI01 public RC certificate fingerprint is
   also rejected by code. The first start refuses nonempty unmarked pool data;
   later starts bind the data to one plan/network/certificate marker (for a
   new operator, also the `false` setting) and reject a byte-identical RC
   encrypted wallet. A newly re-encrypted copy of an RC
   signing key cannot be detected by a file hash: independently compare the
   pool reward destinations before launch.
5. Supply a reviewed, immutable mainnet dashboard directory. The assembler
   requires a frozen-source dashboard manifest and carries the exact asset
   tree in all five archives.
   Hash its `index.html` from the approved asset set and verify the full tree
   against the final package receipt and independent reproduction evidence.
6. Fill every field in `mainnet-pool.json.example` with **final approved**
   values and install it as root-owned `pool.json` under `/etc`. No RC defaults
   are inherited: the share target, minimum payout, payout burn, operator fee,
   PPLNS window, worker thread count, public address, seed, node/worker hashes,
   network ID and plan digest are all mandatory. The file cannot contain
   placeholders; replace the `has_previous_rc_installation` placeholder with
   `true` or `false` as described above. It must name the exact private bind
   IP of this host and a public numeric IP that routes to TCP `29445`. The
   expected certificate hash becomes the miner URL pin. The optional
   `mainnet_relays` list names up to
   eight relay nodes (`numeric-ip:29444`) or other pools' P2P listeners
   (`numeric-ip:29454`) that the pool node also treats as
   static peers: a found block is announced to them first and block frames to
   them are compressed. The optional `prune_keep_blocks` (at least `288`)
   turns on proof pruning: the pool node keeps full blocks only for that many
   newest blocks and drops the proofs of older ones, keeping their
   transactions (see `docs/proof-pruning.md`). `720` keeps about 12 hours.
   Leave it out to keep every proof. The optional `share_batch_size` (1 to
   `64`) lets the pool check that many shares in one GPU replay instead of one
   at a time, and `share_batch_wait_ms` (1 to `1000`, default `100`) caps how
   long a share waits for its batch. Leave both out to keep one-at-a-time
   checks; measure before turning batching on (see `docs/devnet-0.md`).
   The optional `replay_gpus` list (1 to 16 distinct GPU UUIDs, which may
   include `gpu_uuid`) runs one replay worker per listed GPU so shares are
   checked on all of them; every listed GPU must be present and idle at
   start. Leave it out to check shares on `gpu_uuid` alone.
   The optional `proof_resident_banks` (`true`/`false`) keeps the encoded model
   banks on the proof GPU between proofs: about 1 s faster per proof for about
   6.4 GiB more VRAM, so leave it off on 16 GB cards. With the banks preloaded
   (the default) the proof worker also stages each block's traces in about
   1.6 GiB of locked RAM, which saves about 2 s per proof; set
   `CMFD_V4_PROOF_PINNED_TRACES=0` in the service environment to turn that off.
   The optional `proof_gpu` (one GPU UUID) runs the proof worker on that GPU
   instead of `gpu_uuid`; a proof needs about 7 GiB of free VRAM, so on 16 GB
   cards it must not also be in `replay_gpus`.
   The optional `max_connections` (1 to `4096`, node default `256`) and
   `max_connections_per_source` (1 to `256`, node default `64`) change the
   miner connection limits; the official miner uses one connection per GPU,
   and the per-source limit caps the GPUs behind one public address.
   The optional `bonus_rate_bps` (1 to `10000`) and `bonus_sponsor` (the
   sponsor's `cmfd1...` address or 64-character lowercase hex x-only key,
   which must differ from
   the pool's own reward destination) turn on a sponsor-funded mining bonus:
   every mature block's PPLNS credits earn that many basis points more from a
   reserve the sponsor fills by sending CMFD from that key to the pool's
   wallet key (see `docs/production-v4-pool.md`, "Bonus reserve"). Both or
   neither must be present. The optional `bonus_scan_from_height` (at least
   `0`, needs both) is the first height scanned for sponsor transfers and
   only applies until the pool ledger has recorded its first scan; without
   it, scanning starts at the chain tip when the bonus is first enabled, so
   fund the reserve after that start or set the funding block's height here.
   `automatic_payouts` must be explicitly true; the
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

## Block checks and the first start (from 1.0.16)

The pool node re-executes the work of every new block above the release
checkpoint before it accepts the block or moves its template to it. It uses an
idle replay worker for this only while that worker runs the release's
`cmfd-v4-replay` file, whose SHA-256 must equal `expected_replay_worker_sha256`
from the new `MAINNET-PACKAGE.json`; otherwise it checks blocks on its CPU, and
each new block then waits one CPU check before the pool moves to it, which
costs orphaned blocks. Before taking miners, check that the node's startup
lines show `work_checks_use_replay_workers: true` and `"gpu_qualified": true`,
and that `/v1/status` shows `work_rule.independent_engines: true` and
`work_rule.alarms.engine_failures: 0` (see `docs/production-v4-pool.md`).

On the first start after an upgrade the pool hands out no work until it has
checked every block it stored since the release checkpoint: minutes with the
release replay worker, hours on the CPU. Miners cannot connect until then.
Progress is in `/var/lib/commonfoundry-mainnet-pool/data/logs/cmfd-node.log.<date>`
("checking stored blocks"). **Do not restart the service to hurry it**:
progress is kept, but every start loads the model bank and repeats the engine
self-checks. Before that start, copy `startup-index.bin` in the data directory
aside (for example as `startup-index.bin.v1`), so a rollback to an older
release does not rescan the whole log (see `docs/storage-recovery.md`).

The packaged unit has `RestartPreventExitStatus=3 4`. Exit status 3 means the
node halted block admission because a block on its chain does not match its
work, and waits for an operator: read the log, which names the block and the
next step, rather than running `systemctl reset-failed` and restarting in a
loop. Exit status 4 means the node refused to start for a reason a restart
does not change: its stored chain differs from the chain the release pins at
or below the checkpoint (the journal names the `cmfd-node
storage-quarantine-block` command to run with the service stopped), that
conflict is on a block already pruned and the node needs a resync from an
empty data directory, its work-status store cannot be opened (its permissions
or a read-only file system), or a release file is not the pinned one. Fix what
the journal (`journalctl -u commonfoundry-mainnet-pool`) names, then run
`systemctl reset-failed commonfoundry-mainnet-pool` and start the service. A
full disk or a failed read or write is not status 4; the unit restarts after
those. A unit of your own should carry the same line.

Blocks reach a pool fastest from the other pools and the project's relays.
List the relays in `mainnet_relays` (up to eight entries):
`88.198.110.195:29444` first and `209.145.48.36:29444` second, rather than
depending on the seed alone. Another pool's P2P listener can go in the same
list as `numeric-ip:29454`, which connects the two pools directly; a pool that
runs `cmfd-node pool-serve` itself adds it with `--peer`.

The file log is written at debug level, rolls daily and is never deleted.
Remove old files with a daily job or a logrotate rule, for example
`find /var/lib/commonfoundry-mainnet-pool/data/logs -name 'cmfd-node.log.*' -mtime +14 -delete`.

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
unit, verify it with `systemd-analyze verify` on the target Linux system, check
once on that host's systemd that the privileged copy lines leave service-owned
0600 files in the runtime directory (for example with a renamed test copy of the
unit whose `ExecStart=` is a harmless command), and
repeat the exact-package pool tests, mature payout and deep-reorg reconciliation
under the approved final plan. Preserve an off-host encrypted wallet backup and
test restoration without copying the RC wallet.
