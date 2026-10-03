# Fresh-host pool launcher update

This fixes the v1.0.0 pool service template requiring hashes of RC files on a
host that never had those files. It is a separate Python launcher patch, not a
new consensus release or a replacement for the signed v1.0.0 archives. The
published archive signatures do not cover this separate source patch.
Ordinary solo miners and miners connecting to a pool do not need it.

The patch has offline regression coverage. It does not certify your host's
GPU, full proofs, networking or payouts. Follow `POOL-SERVICE-SETUP.md` for the
remaining pool setup and validation. Do not install this on an already staged
launch-controller host: its files may be pinned by that controller.

## 1. Obtain the patch

Use the commit-specific repository link supplied with the patch announcement.
Download its source ZIP and extract it, or clone the fix branch:

```sh
git clone --depth 1 --branch codex/fresh-pool-config \
  https://github.com/Common-Foundry-1/CommonFoundry.git commonfoundry-pool-fix
cd commonfoundry-pool-fix
git rev-parse HEAD
```

Check that the printed commit matches the announcement before continuing.
For a ZIP, check that its download URL names that exact commit. Then enter
`packaging/mainnet/linux` inside that checkout or extracted folder:

```sh
cd packaging/mainnet/linux
```

## 2. Install outside the signed runtime

These steps assume you already installed the standard mainnet pool service
template and configured its GPU device drop-in. They do not start or restart
the service. Do not overwrite the launcher inside your signed runtime.

```sh
sudo install -d -o root -g root -m 0755 /usr/local/lib/commonfoundry
sudo install -o root -g root -m 0755 mainnet-pool-service.py \
  /usr/local/lib/commonfoundry/mainnet-pool-service.py
sudo install -d -o root -g root -m 0755 \
  /etc/systemd/system/commonfoundry-mainnet-pool.service.d
sudo install -o root -g root -m 0644 30-fresh-install.conf \
  /etc/systemd/system/commonfoundry-mainnet-pool.service.d/30-fresh-install.conf
```

If either destination already exists, preserve a backup and review it before
overwriting it. The drop-in changes only `ExecStart`; credential handling,
device permissions, sandboxing, runtime paths and launch-beacon checks remain.

## 3. Declare that this is a genuinely fresh installation

Edit `/etc/commonfoundry-mainnet-pool/pool.json`. Keep every other configured
value, including your actual new certificate/private-key hashes and all
runtime hashes. Add/change only these three fields:

```json
"has_previous_rc_installation": false,
"forbidden_rc_private_key_sha256": null,
"forbidden_rc_wallet_file_sha256": null
```

These are JSON fields within the existing object, not a complete config file.
Use JSON `false` and `null`, not quoted strings. Keep the supplied known RC
certificate hash in `forbidden_rc_certificate_sha256`.

For an actual RC migration, use `true` and real old-file hashes instead.
Omitting the new field preserves the old strict migration behavior. Never
delete existing wallet data or a deployment marker to force fresh mode.

## 4. Verify the service configuration

```sh
sudo systemctl daemon-reload
sudo systemd-analyze verify commonfoundry-mainnet-pool.service
sudo systemctl show commonfoundry-mainnet-pool.service -p ExecStart
```

The last command should name `/usr/local/lib/commonfoundry/mainnet-pool-service.py`.
Resolve any verification errors before starting. No service is started by
the commands above. Once the rest of your pool setup is ready, start it through
systemd, which prepares its private credentials and runtime directory:

```sh
sudo systemctl start commonfoundry-mainnet-pool.service
sudo journalctl -u commonfoundry-mainnet-pool.service -n 80 --no-pager
```

Before the approved October 3, 2026 17:00 UTC activation, waiting for the pinned
launch beacon is expected. This patch cannot enable early mainnet mining.
After activation, check actual worker connections and accepted work; a running
service alone does not prove successful mining. Do not post private keys,
wallet passphrases or unreviewed logs containing secrets when requesting help.
