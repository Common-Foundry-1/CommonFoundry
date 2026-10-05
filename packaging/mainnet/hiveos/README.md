# Common Foundry for HiveOS

This is the NVIDIA mainnet custom-miner package. Packages are scheduled for
October 2, 2026 at noon Central; mining starts October 3 at noon Central.
Starting it early prepares the model and waits for the authenticated launch.

In your flight sheet, choose **Custom** and use the installation URL for
`commonfoundry-mainnet-hiveos-1.0.5.tar.gz` from the official release.

- **Wallet template:** `%WAL%` (your 64-character CMFD destination public key)
- **Pool URL:** the complete `cmfd+tls://IP:PORT?pin=...` URL supplied by the pool
- **Hash algorithm:** `forgematrix_v4`
- **Extra config:** optional JSON, for example `{"gpus":[0,2]}`

By default, the wrapper starts one worker for each NVIDIA GPU. Each worker gets
its own scratch directory and the native miner's `.gpu0`, `.gpu1`, etc. suffix. Extra config can set
`gpus`, `worker` (up to 24 characters), `model_dir`, and `state_dir`.

HiveOS installs the package directly at:

```text
/hive/miners/custom/commonfoundry-mainnet-hiveos/
```

There is no extra version directory. `h-manifest.conf`, `h-config.sh`, `h-run.sh`,
`h-stats.sh`, and the binaries are all in that directory. The archive's top-level
directory is exactly `commonfoundry-mainnet-hiveos`, which matches HiveOS's
`custom-get` name parsing.

The generated flight-sheet config is `miner.json` in the installation directory.
Model files default to `/hive/miners/custom/commonfoundry-data/production-v4`;
scratch files default to `/hive/miners/custom/commonfoundry-data/mainnet`.
Both are outside the directory that HiveOS removes during a miner upgrade.
Allow at least 15 GB of free storage for the pool-miner model and download staging.
The installer verifies model hashes before use.

Logs are under `/var/log/miner/commonfoundry-mainnet-hiveos/`. The stats callback
reports GPU work rates, temperatures, fans, accepted/rejected shares and PCI bus
numbers. Rates use ForgeWork per second, exposed through HiveOS's `hs` unit.
Stopped workers and stale logs do not continue reporting an old hashrate.

The package needs `python3`, `curl`, `jq`, NVIDIA drivers, and the same GPU/runtime
requirements as the mainnet Linux miner. The CUDA runtime is included. A mainnet
wallet address and the correct pool certificate pin are required.

For manual installation, run HiveOS's own installer with the official asset URL:

```sh
/hive/miners/custom/custom-get 'https://github.com/JustAResearcher/CommonFoundry-Binaries/releases/download/v1.0.5/commonfoundry-mainnet-hiveos-1.0.5.tar.gz'
```

That URL becomes usable when the scheduled release is published. Before launch,
configure HiveOS watchdogs to allow model preparation and the scheduled wait.
