# Mainnet seed service setup

These are staged templates, not an installed or enabled mainnet service. Keep
the existing RC service, keys, ports and data directory unchanged. Use separate
mainnet release, configuration, runtime and data directories:

- `/opt/commonfoundry-mainnet/releases/<version>` and root-owned `current` link
- `/etc/commonfoundry-mainnet/wallet-passphrase` (root-owned, 0600)
- `/var/lib/commonfoundry-mainnet` (dedicated service user, 0700)
- `/run/commonfoundry-mainnet` (systemd runtime directory, 0700)

Create the dedicated unprivileged `commonfoundry-mainnet` account before
installation. Verify the signed release, four-package preflight and final
mainnet plan before copying the runtime package. Prepare and authenticate the
model inputs before enabling a service. Keep the executables, Python/scripts,
model files and configuration root-owned and not writable by the service user.
Do not run the RC provisioning script on this host again; it changes host-wide
SSH, firewall and account settings.

The launch helper must publish its certificate into `production-mainnet` beside
the executable. On this Linux service deployment, make that directory
root:commonfoundry-mainnet, mode **1770** (sticky). Keep MAINNET-PLAN.json
root:commonfoundry-mainnet, mode **0440**. This permits the service to create its
beacon/temp files but prevents it from replacing or changing the root-owned
plan. The node additionally checks the compiled plan digest and beacon signature.
Do not make the whole release directory writable. Review these ownership/mode
settings after every release switch.

The service uses systemd credentials for the passphrase and waits for the fixed
launch certificate before starting the node. Waiting may last through the
preparation window; `TimeoutStartSec=infinity` is intentional. Stop/cancel still
works through systemd. RPC binds only to localhost:29443. Public inbound peers
use TCP 29444. Firewall changes and public reachability must be checked separately;
the template neither changes the firewall nor provisions a public seed.

## Capacity and monitoring

Run the included read-only planner against the actual data filesystem:

```sh
python3 /opt/commonfoundry-mainnet/current/mainnet-storage-readiness.py \
  --data-dir /var/lib/commonfoundry-mainnet --horizon-days 30 --reserve-gib 20
```

The default scenario uses target 60-second spacing, maximum 16 MiB block and
1 MiB undo records, 88 bytes of record framing, and a 1.25 stored-record multiplier
for side branches. This is a sizing scenario, not a hard daily limit. Actual
arrivals, checkpoints, backups and unrelated workloads can increase usage.
When forecasting before installing model files, explicitly include their extra
space using `--additional-artifact-bytes`; do not double-count files already on
disk. No history is pruned or deleted by this tool.

The startup guard only enforces the 20 GiB operational reserve plus two maximum
records, not a fresh 30-day horizon on every restart. The separate storage timer
checks every five minutes and records failure below that reserve. **It does not
stop a running node or prevent another process from filling the disk.** Connect
the failed-unit signal to operator monitoring and test its notification path.
Schedule expansion before the forecast horizon runs out. Never delete a complete
block-log suffix to recover space; use documented recovery only for an incomplete
tail, with the node stopped and evidence preserved.

Before enabling mainnet: qualify capacity and growth, verify clock synchronization,
credentials and backups, verify the systemd sandbox with real packages, rehearse
beacon waiting and a normal restart, then prove external peer discovery. These
operator checks and final release approvals remain necessary; parsing a unit file
or passing a capacity calculation is not deployment qualification.
