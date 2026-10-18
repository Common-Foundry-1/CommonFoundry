# Mainnet seed service setup

These are staged templates, not an installed or enabled mainnet service. Keep
the existing RC service, keys, ports and data directory unchanged. Use separate
mainnet release, configuration, runtime and data directories:

- `/opt/commonfoundry-mainnet/releases/<version>` and root-owned `current` link
- `/etc/commonfoundry-mainnet/wallet-passphrase` (root-owned, 0600)
- `/var/lib/commonfoundry-mainnet` (dedicated service user, 0700)
- `/run/commonfoundry-mainnet` (systemd runtime directory, 0700)

Create the dedicated unprivileged `commonfoundry-mainnet` account and matching
group before installation. Verify the signed release, five-package preflight and final
mainnet plan before copying the runtime package. Prepare and authenticate the
model inputs before enabling a service. Keep the executables, Python/scripts,
model files and configuration root-owned and not writable by the service user.
Do not run the RC provisioning script on this host again; it changes host-wide
SSH, firewall and account settings.

### Make the prepared inputs readable by the service

The input preparer creates its destination with mode 0700. If an administrator
runs it as root, the service account cannot traverse that directory until the
deployment permissions are adjusted. Do this before enabling the service, not
after the launch wait finishes.

For the separate mainnet release copy, use root:commonfoundry-mainnet ownership
with 0750 (or read-only 0550) on the release/model directories and 0640 (or 0440)
on MODEL-V2.bank and both copies of the fixed record. The node reads the record
directly under `production-v4`; the preparer also keeps a copy under
`production-v4/fixed`. Preserve executable permission on the packaged binaries
and scripts. All parent directories must permit the service account to traverse
them. The service account must not be able to replace the model, plan, binaries,
or parent directory entries.

Do not recursively change permissions on an RC installation or its shared
hardlinks. Use a separate mainnet copy. Inspect the resolved versioned release
path and ownership before applying permissions; the root-owned `current` link
should select only that verified release.

After preparation, check access as the actual service account:

```sh
sudo -u commonfoundry-mainnet test -r /opt/commonfoundry-mainnet/current/production-v4/MODEL-V2.bank
sudo -u commonfoundry-mainnet test -r /opt/commonfoundry-mainnet/current/production-v4/FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json
```

The unit also tests that these paths are regular, readable files before copying
the runtime credential or waiting for the beacon. These are accessibility checks,
not substitutes for the signed-package and artifact hash checks. The node still
authenticates the complete inputs before opening its services.

The launch helper must publish its certificate into `production-mainnet` beside
the executable. On this Linux service deployment, make that directory
root:commonfoundry-mainnet, mode **1770** (sticky). Keep MAINNET-PLAN.json
root:commonfoundry-mainnet, mode **0440**. This permits the service to create its
beacon/temp files but prevents it from replacing or changing the root-owned
plan. The node additionally checks the compiled plan digest and beacon signature.
Do not make the whole release directory writable. Review these ownership/mode
settings after every release switch.

Before starting the node, a privileged (`ExecStartPre=+`) step copies the
root-only `/etc/commonfoundry-mainnet/wallet-passphrase` into the 0700 runtime
directory as a service-owned 0600 file; the copy disappears when the service
stops. systemd 249 (Ubuntu 22.04) fills the `LoadCredential` directory only for
`ExecStart=`, so the copy reads the `/etc` file directly. That line names the
service user, group and source path literally: a drop-in that overrides `User=`,
`Group=` or the passphrase path must override the copy line as well.

The service waits for the fixed launch certificate before starting the node.
Waiting may last through the preparation window; `TimeoutStartSec=infinity` is
intentional. Stop/cancel still works through systemd. RPC binds only to localhost:29443. Public inbound peers
use TCP 29444. Firewall changes and public reachability must be checked separately;
the template neither changes the firewall nor provisions a public seed.

## Block checks (from 1.0.16)

The node re-executes the work of every new block above the release checkpoint
on its CPU before it accepts the block. For each block it reads the 6.4 GB
model bank. With the default `--work-bank auto` it holds the bank in memory
when about 8 GiB is available at start (a systemd `MemoryMax=` or container
limit counts), and otherwise reads it from disk for every block, which needs an
SSD. On a server with the memory to spare, pass `--work-bank resident`
explicitly, so a busy moment at start does not leave it streaming.
`--work-threads <n>` sets the CPU threads per block (default: half the logical
processors, at most 8). A node that needs more than about 60 seconds per block
cannot keep up with the chain; the project's relays take 6 to 28 seconds with
the bank in memory. Both options belong after `run`. To add them, use a
drop-in that clears `ExecStart=` and repeats the packaged line with the
options added, for example
`/etc/systemd/system/commonfoundry-mainnet-node.service.d/40-work.conf`:

```ini
[Service]
ExecStart=
ExecStart=/opt/commonfoundry-mainnet/current/cmfd-node --data-dir /var/lib/commonfoundry-mainnet --wallet-passphrase-file /run/commonfoundry-mainnet/wallet-passphrase run --bind 127.0.0.1:29443 --p2p-bind 0.0.0.0:29444 --allow-public-peers --no-default-seeds --work-bank resident
```

Then run `systemctl daemon-reload`. Recheck the drop-in after every release
switch, since it repeats the packaged line.

**First start after an upgrade.** Before that start, copy `startup-index.bin`
in the data directory aside (for example as `startup-index.bin.v1`) so a
rollback to an older release does not rescan the whole log (see
`docs/storage-recovery.md`). The node then opens its RPC, exchange RPC and P2P
straight away and checks every block it stored since the release checkpoint in
the background. Until it is done, the exchange RPC serves only checked blocks,
and balance, UTXO and supply reads answer the retryable `work_check_pending`.
The check takes about (blocks stored since the checkpoint) ÷ (blocks checked
per hour − 62) hours. The chain adds about 1,500 blocks a day, and a server CPU
checks roughly 130 to 600 blocks an hour, so a node upgraded one day after the
release needs from about 3 to about 22 hours. Watch it with

```sh
curl -s http://127.0.0.1:29443/v1/status
```

until `work_rule.validated_height` reaches `accepted_height`. The daily file
log `/var/lib/commonfoundry-mainnet/logs/cmfd-node.log.<date>` records the
progress as well; the journal shows only errors by default. **Do not restart
the node to hurry it:** progress is kept, but every start loads the model bank
and repeats the engine self-checks. A node set up from scratch checks every
block above the checkpoint the same way, so plan that CPU time.

At start the node prints a `work_backlog` line with `"mode": "background"`,
`blocks_left`, `validated_height` and `tip_height`. While more than 30 stored
active blocks are left above the validated height, the file log gets a warn
line with target `work_rule` about every 10 minutes (the first one 10 minutes
after the start) with `blocks_left`, `checked` (blocks checked since the
start), `checked_per_hour` (over the last 10 minutes), `eta`, `validated_height`
and `tip_height`. New blocks keep arriving meanwhile, so `eta` follows how fast
`blocks_left` fell over those 10 minutes, not `checked_per_hour`; it reads
`none at this rate` while the node checks no faster than blocks arrive. The
journal shows the `work_backlog` line, and the warn lines only when the node
runs with `-v` or more.

The packaged unit keeps `Restart=on-failure` on purpose: a node halted by the
work rule restarts and then serves its status, halted, with the steps in its
log. A `run` node has one kind of work engine, the CPU, so it does not settle
a block whose work it finds does not match: it holds
`work_rule.validated_height` below that block, reports
`work_rule.unsettled_height` and `work_rule.unsettled_block_id`, and checks the
block again every 6 hours. Compare that block id with another node and the
explorer. `cmfd-node work-reconsider` only makes the node check the block
again; if the block matches elsewhere, report it to the release maintainers.
Monitor `halted`, `engine_state`, `unsettled_height` and the gap between
`validated_height` and `accepted_height` in `/v1/status`.

A node whose stored chain at or below the checkpoint differs from the chain the
release pins refuses to start and prints the `cmfd-node
storage-quarantine-block` command to run with the node stopped.

The packaged unit has `RestartPreventExitStatus=4`. Exit status 4 means the
node refused to start for a reason a restart does not change: the stored chain
conflict above, that conflict on a block already pruned (the node then needs a
resync from an empty data directory), a work-status store that cannot be opened
(its permissions or a read-only file system), or a release file that is not the
pinned one. The journal (`journalctl -u commonfoundry-mainnet-node`) names
which. Fix it, then run
`systemctl reset-failed commonfoundry-mainnet-node` and start the service. A
full disk or a failed read or write is not status 4; the unit restarts after
those. `cmfd-node run` does not stop with status 3: a node that halts block
admission while it runs stops with status 1, restarts and serves its status,
halted, as described above. A unit of your own should carry
`RestartPreventExitStatus=4`; `3 4`, as for a pool, does no harm.

The file log is written at debug level, rolls daily and is never deleted.
Remove old files with a daily job or a logrotate rule, for example
`find /var/lib/commonfoundry-mainnet/logs -name 'cmfd-node.log.*' -mtime +14 -delete`.

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
