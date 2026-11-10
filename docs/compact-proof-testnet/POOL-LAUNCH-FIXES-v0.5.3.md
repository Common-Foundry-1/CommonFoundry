# Pool dashboard and direct launch fixes — v0.5.3 candidate

The Linux kit now includes the built pool dashboard. `START-POOL.sh` enables
it at **http://127.0.0.1:23446** and supplies the dashboard assets and advertised
TLS pool URL. Use `--dashboard-bind 127.0.0.1:PORT` to change the local port,
or `--no-dashboard` to opt out. For an LXC pool, forward that loopback port
through your existing SSH connection to view it from another machine.

Previously `--pool-dashboard-bind` alone was accepted but did not enable the
native dashboard. Native `pool-serve` now requires both
`--pool-dashboard-assets` and `--pool-public-url` when the bind option is
specified. Missing options are an argument error before node/worker startup;
an occupied port, invalid assets or invalid URL is a startup error. The config
prints the actual listener after a successful bind, and flushes it immediately.

Native `pool-serve` now accepts `--shared-model` and `--ram-witness-dir`.
`--shared-model` selects the second split proving GPU for serial replay and
sets the witness-pipeline, GPU-relations, host transport and module-loading
worker settings that previously required the launcher environment. The socket
defaults to `model.sock` under pool scratch. Legacy environment settings remain
compatible. The replay program in this layout is `cmfd-resident-replay`, and
the proof program is `cmfd-direct-multigpu-prover`.

For example, retain the usual bank, fixed-record, certificate, pool/network and
dashboard options printed by `START-POOL.sh ... --check`, and use these native
worker options for the two-card shared-model layout:

```sh
--production-v4-pool-replay-worker /path/to/kit/cmfd-resident-replay \
--production-v4-pool-replay-gpu 1 \
--production-v4-pool-proof-worker /path/to/kit/cmfd-direct-multigpu-prover \
--production-v4-pool-proof-gpus 0,1 \
--production-v4-pool-serial-gpu --shared-model \
--ram-witness-dir /dev/shm/cmfd-pool-witness \
--pool-dashboard-assets /path/to/kit/pool-dashboard \
--pool-public-url 'cmfd+tls://YOUR_NUMERIC_IP:23445?pin=YOUR_64_HEX_PIN' \
--pool-dashboard-bind 127.0.0.1:23446
```

`--ram-witness-dir` enforces the launcher's existing contract: an owned mode
0700 dedicated Linux tmpfs mount capped at 2 GiB, with at least 1.65 GB free
and 8 GiB available host RAM before startup. It conflicts with a separate
`--production-v4-pool-scratch`; there is no fallback to disk. Generic scratch
remains available through the original option.

The v0.5.1 normal proof timing and log-file changes are retained. The worker
READY/DONE protocol and reports already flush each line. `fixed_data_preload`
is selected using `/proc/meminfo` **MemAvailable**, including its reserve;
free disk space is not the selector. These launch fixes do not change the
proof format, security parameters, GPU memory guards or measured proof time.
