# Common Foundry mainnet packages

Source and packages are scheduled for October 2, 2026 at noon US Central
(17:00 UTC). Mining is scheduled for October 3 at the same time. Both dates
use CDT, not winter CST.

Extract the complete archive to a folder you can write to. Keep its files
together. Verify the release signatures and SHA256 checksums before running it.
The published source includes `docs/mainnet-release-verification.md` and the
release checksum policy `packaging/mainnet/MAINNET-RELEASE.allowed_signers`.
Check that policy's Ed25519 fingerprint independently before using its
`verify-download` procedure on the complete release directory. The expected
fingerprint is `SHA256:cA1Tsf8hL/pxDV5WpOE3iPW3b4uDQosu1dOh//4a/fk`.
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
want inbound peers. RPC uses localhost:29443; its wallet and transaction/block
submission routes answer only requests addressed to 127.0.0.1, [::1] or
localhost, not a proxy hostname. Do not reuse RC data directories.

Runtime archives include [RECOVERY.md](RECOVERY.md) for offline backup and
restore, and [STORAGE-RECOVERY.md](STORAGE-RECOVERY.md) for interrupted-log repair.
Rehearse a restore into a separate directory before relying on the backup.

## Block checks

From 1.0.16 the wallet re-executes the work of every new block above the
release checkpoint, from the block's header and nonce, before it accepts the
block. The check runs on the CPU at below-normal priority with half the
logical processors, at most eight. Below-normal priority still uses idle
processors fully, so a wallet that runs beside a miner or other heavy work
should be started with fewer threads, for example `--work-threads 2`.

Verifying. Coins in blocks that are not checked yet show as **Verifying**.
They count in the total balance but cannot be sent or consolidated until those
blocks are checked; your own change is not held back. Solo mining waits until
the newest blocks are checked.

Catching up (`--work-check standard`, the default). After time offline, the
wallet downloads recent blocks that at least two Common Foundry relays run by
different providers list, checks the newest blocks on this computer, and keeps
checking the rest in the background. Coins in recent blocks show as Verifying
until the newest blocks are checked, and can be sent after that. If fewer than
two relays can be reached, the wallet checks every block itself, which takes
longer.

Full check (`--work-check full`). The wallet checks every block on this
computer before any coin in it shows as available, so catching up after time
offline takes longer. Add the option to a launcher only when it starts 1.0.16
or later: older versions refuse it and do not start.

Battery. The background check of older blocks pauses while the computer runs
on battery and continues when it is plugged in; the wallet says so. The newest
blocks are still checked on battery.

The first start of 1.0.16 checks the blocks the wallet stored since the
release checkpoint in the background, lowest first. After several days offline
that can take hours.

Resync chain. If the wallet's stored chain differs from the chain the release
pins, or a stored block that this computer found not to match its work holds
the check back, the wallet offers **Resync chain**. It moves the stored blocks
into a new `resync-<time>` folder inside the data directory and downloads the
whole chain again. Nothing is deleted, and your wallet key and backups stay
where they are. Until you delete that folder the chain takes about twice its
disk space; the wallet shows the folder and its size. Delete it once the
wallet has synced again. If the wallet is encrypted, unlock it again
afterwards.

## Updates

This section is about the desktop wallet; the standalone miner does not
update itself. From version 1.0.16 the desktop wallet can keep itself up to
date. Version 1.0.15 and earlier cannot, so install 1.0.16 by hand once:
download it, verify it as described at the top of this guide, extract it and
start it from its own folder. Only the mainnet release wallet updates itself.

What it does. About a minute after the wallet window opens, and then about
every 6 hours, the wallet asks GitHub for the list of Common Foundry releases.
It accepts a release only if its checksum file is signed with the release key
built into the wallet, the download matches that signed checksum, and its
signed version is newer than the one you run, on the same network. It never
installs an older version. The new version is installed in its own folder next
to the one you run; the running version is never overwritten. The updater
never moves or deletes your wallet data, keys or backups: the new version opens
the same wallet, and a newer version may change that data in a way an older one
cannot read. The 6.4 GB model bank is shared with the new version through a
hard link. When that is not possible (another drive, OneDrive, a USB or exFAT
drive), the wallet asks before it copies the file, because the copy uses that
much more disk space. The about 55 GB of solo-mining files are only linked,
never copied: where linking is not possible, wallet solo mining in the new
version asks you to run PREPARE-MINING again, in the folder the Mining tab
names, which needs that disk space again.

The switch. Open the Network tab and find the Updates card. "Update
automatically" is ON by default: the wallet downloads and installs a new
version in the background, then shows "Restart to update" and "Later". Later
starts the new version the next time you open the wallet. When the switch is
OFF, the wallet still checks and tells you that a new version is available,
but downloads nothing until you choose Download. "Check now" checks at once.
The switch is saved with your wallet data. A version that is already installed
starts at your next launch even when the switch is OFF.

Restart to update is refused while a send, backup or restore is running:
finish it, then choose Restart to update again. If you are mining, it asks
first: mining stops, and after the restart you unlock the wallet and start
mining again. If you sent a transaction that is not confirmed yet, it warns you
first, because unconfirmed transactions are kept in memory only. If one of them
does not confirm, send it again.

Turning updates off completely. Start the wallet with `--no-auto-update`, or
set the environment variable `CMFD_NO_AUTO_UPDATE` to exactly `1`. Then the
wallet does not check, does not download, and does not switch to a newer
version that is already installed: it runs exactly the version you started.
The Updates card says "Updates are turned off by a launch option"; check that
it does. A launcher of your own that starts `common-foundry-wallet.exe`
directly, for example a .bat that opens a separate wallet with `--data-dir` (a
steward or cold-storage wallet), can add `--no-auto-update` to that line, but
only when it starts 1.0.16 or later: older versions refuse the option and do
not start. START-WALLET.bat and ./start-wallet.sh pass no arguments, so use
the variable with them: in a .bat of your own, put `set "CMFD_NO_AUTO_UPDATE=1"`
on its own line (with the quotes, so no space is added to the value) before
`call START-WALLET.bat`, or run `CMFD_NO_AUTO_UPDATE=1 ./start-wallet.sh` on
Linux. Update such a wallet by hand: install the new version in its own folder
and point your launcher at it. Do not use the option or the variable to get
past the Retry or Run anyway question described below: a wallet started this
way does not ask it.

Where versions are installed. Each version gets its own folder, named like
`commonfoundry-mainnet-runtime-windows-x86_64-v1.0.17` (Linux: `linux-x86_64`),
in the same folder that holds the package folder you extracted. On Windows, if
that folder is in OneDrive, new versions go to
`%LOCALAPPDATA%\CommonFoundry\versions` instead, so they are not uploaded.
Your shortcuts, START-WALLET.bat, ./start-wallet.sh and your own launchers keep
working: the wallet you start hands over to the newest installed version that
passes its checks, with the same arguments, and waits until it closes. So while
the new version runs, you see two common-foundry-wallet processes; that is
normal. Keep the folder your shortcut or launcher points to: deleting it
breaks START-WALLET.bat. The updater keeps the running version and one
previous version. Older ones are listed under "Old versions" in the Updates
card with their full paths; "Remove old versions" deletes them after you
confirm. It never removes a folder that holds wallet data or files you added.
The updater writes a log, `.cmfd-updater.log`, in the folder that holds the
versions. Include it when you ask for help, but never send a wallet key,
backup passphrase or passphrase file.

When an update fails.
- If a download or install fails, this version keeps running and the wallet
  shows why. If it says "The next check tries again", nothing more is needed;
  otherwise choose Try again. If your antivirus removed one of its files
  (Windows Security sometimes flags the GPU workers as coin miners), it is not
  tried again until you choose Try again or start the wallet again: check the
  antivirus history, allow the file, then choose Try again.
- If the wallet says an installed update "failed its file check", a file in
  that version's folder was changed or removed after it was installed
  (antivirus software can do this). Restart to update and Retry are refused
  then: restore the file from the antivirus quarantine, or choose Reinstall so
  that a fresh copy is installed beside it (deleting that version folder also
  works). If that version had already opened your wallet data, the previous
  version waits before opening it and says the installed files are damaged;
  Run anyway then lasts only until the wallet closes, and the question comes
  back at each launch until you reinstall or remove that version.
- "Must be installed by hand" usually means that update changes the model
  bank. Install it like 1.0.16 above, and from then on start the wallet from
  the new folder (its START-WALLET.bat, or point your shortcut there): the old
  folder does not hand over to a version you installed by hand.
- If a new version fails to start before it opens your wallet data, the
  previous version starts instead and tells you why. The new version is tried
  again at later launches; after 3 failed starts it is no longer tried until
  you choose Retry in the Updates card.
- If a new version stops after it opened your wallet data, the previous
  version starts but waits before opening your data. It shows the error and
  offers Retry, or Run anyway after you type "run anyway". Run anyway is a risk:
  an older version may not read data that a newer one changed. At your next
  launches the new version is started again, up to 3 failed starts in all,
  and the previous version waits and asks again each time it fails. After
  that the new version is no longer started, and the question comes back at
  every launch until you choose. The same happens if your system blocks the
  new version from starting at all after it had opened your data. A wallet
  started with
  `--no-auto-update` or `CMFD_NO_AUTO_UPDATE=1` does not ask it and opens your
  data at once, so answer it in a normal launch first.

## Mining

The standalone miner connects to your chosen mainnet pool. Fill in the wallet
address, certificate-pinned pool URL and worker name in START-MINER.bat, or run
./start-miner.sh on Linux and answer its prompts. It prepares the pool-search
model inputs, waits for the authenticated launch certificate, then connects.
Windows GPU mining uses WSL2 Ubuntu-22.04 with NVIDIA support. Linux GPU mining
needs a compatible NVIDIA driver. Normal wallet operations do not require them.

The replay/search build targets NVIDIA Volta and RTX 20/30/40/50 generations.
Check the release's hardware-test matrix for the exact cards and drivers tested.
The model/search path needs roughly 6.45 GiB of device allocation, plus CUDA and
display overhead; 6 GB cards cannot hold it. Use a card with at least 8 GB and
sufficient free memory. Pool mining uses the replay/search worker; full solo
proving has a separate, narrower qualification matrix. A broad replay build
does not establish full-prover support on every listed GPU.

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
then reopen it. After an update, the Mining tab names the folder to run it
from. The GPU workers are included in the package; the preparation script does
not download an arbitrary newer worker. Additional scratch space and chain
storage are needed beyond these model-input sizes.

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
