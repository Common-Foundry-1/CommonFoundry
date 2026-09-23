# Preparing the two mainnet reward wallets

The owner controls both destinations: **steward** and **community**. They must
be different keys. Neither an RC receiving address nor a test fixture is selected
automatically.

Mainnet's network ID is derived from the canonical launch plan, which includes
these addresses. Encrypted wallets are bound to a network ID. The offline
`mainnet-custody-prepare` command therefore generates the keys in memory, derives
their candidate plan, and encrypts both wallets for that exact derived network.
It uses the existing wallet encryption/backup format, not new cryptography.

## Easiest Windows workflow

Use `scripts/prepare-mainnet-reward-wallets.ps1` with a trusted, hash-verified
ProductionV4 node build. A locally staged double-click launcher can supply the
executable path/hash and owner-selected targets. The setup asks for **two
different strong passwords**, each confirmed separately: one protects the
steward wallet and backup, and the other protects the community wallet and
backup. Keep both securely and separately. Losing either password prevents
recovery of that wallet from its encrypted files; there is no reset service or
recovery phrase in this setup.

The wrapper passes two length-framed passwords through an anonymous stdin pipe.
It never puts them in command arguments, logs, environment variables or
temporary files. Buffers are cleared on exit. A second native process reopens
and verifies both saved wallets with their respective passwords before success
is reported. A crash may leave partial encrypted files, but no plaintext
password file needs to be cleaned up.

For a manual invocation, substitute the verified node path and SHA-256 below:

```powershell
.\scripts\prepare-mainnet-reward-wallets.ps1 `
  -NodePath 'C:\verified-tools\cmfd-node.exe' `
  -ExpectedNodeSha256 '<verified-64-hex-sha256>' `
  -PowLimit '003fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' `
  -InitialTarget '000ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccb'
```

These targets are the owner-approved **5× RC starting / RC minimum parameter
choice** as of September 23, 2026. The extended live dropout test was waived,
so its behavior under a real hashrate drop remains unmeasured; release approval
and final plan/package binding are still separate steps.
The script requires them explicitly; it cannot silently choose a new policy.

Default output locations use a fresh timestamp/random attempt directory:

- Wallets: `%LOCALAPPDATA%\CommonFoundry\RewardWallets\<attempt>\wallets`,
  with `steward\wallet.key` and `community\wallet.key`.
- Backups: `%USERPROFILE%\CommonFoundry-Reward-Backups\<attempt>\backups`,
  with independently encrypted `steward.cmfdwallet` and `community.cmfdwallet`.
- Shareable details: the attempt's separate `public` directory, containing
  `MAINNET-PLAN.json` and `REWARD-CUSTODY.json` only.

Defaults put backups in a separate local directory, **not off this computer**.
After success, copy the encrypted backup folder to offline/off-host storage and
retain **both** passwords separately from it. Do not share wallet files, backup
files or either password. Only the public directory is intended for launch
preparation.

Windows private directories are created with protected access for the creating
account, SYSTEM and Administrators. Private files receive protected ACLs before
encrypted bytes are written. On Linux, directories use 0700 and files 0600.
Existing folders/files are not repurposed or overwritten by the native command.

## Native file-based operator workflow

The native commands also accept two separately protected password files as an
alternative to the guided stdin pipe. Supply absolute, separate, create-new
wallet/backup/public directories whose parents already exist. Keep password
files outside those directories and outside Git worktrees. On Windows their
file and containing-directory ACLs must satisfy the private-custody checks; on
Linux their modes must be 0600 or stricter.

```text
cmfd-node mainnet-custody-prepare --pow-limit <target> --initial-target <target> --wallets-directory <new-wallets> --backups-directory <new-backups> --public-directory <new-public> --steward-passphrase-file <private-file> --community-passphrase-file <private-file>

cmfd-node mainnet-custody-verify --expected-plan-digest <digest-from-reviewed-preparation> --wallets-directory <wallets> --backups-directory <backups> --public-directory <public> --steward-passphrase-file <private-file> --community-passphrase-file <private-file>
```

`--distinct-passphrases-stdin` replaces both file flags for the guided launcher.
The anonymous pipe carries the exact ASCII magic
`CMFD/REWARD-CUSTODY/TWO-PASSWORDS/V1\0`, then a little-endian 16-bit steward
password length and bytes, followed by the corresponding community length and
bytes. Each password must be 12–1024 raw UTF-8 bytes and the two must differ;
truncation, extra bytes and mixed stdin/file modes are rejected. The old
`--shared-passphrase-stdin` option is rejected; protected password files must
also contain different passwords. Never put a real password in command arguments.

## Verification and interruption handling

Preparation authenticates all four encrypted files before writing the public
plan/report. Verification checks the externally selected plan digest, the exact
network, each role's address, matching decrypted keys and independently randomized
wallet/backup ciphertext. The public report includes ciphertext hashes only.
Standard wallet-directory locks prevent concurrent node/wallet use. Verification
does not change keys or chain state, but ordinary lock files may be refreshed.

If a preparation fails, preserve the partial output. `SETUP-INCOMPLETE` is retained
once private-output publication begins, and verification refuses that attempt.
There is no force-complete or overwrite flag. Do not delete a marker to make an
incomplete setup appear successful. Review/recover the encrypted files or start
a separate unused attempt; do not replace a wallet that has received funds.

This is **candidate custody preparation, not mainnet authorization**. It does not
apply release pins, sign approvals, start a node, create a chain, publish addresses,
or transfer funds. The actual custody step remains incomplete until the owner runs
the local prompt and retains/restores the resulting backups. Tests use disposable
keys and are not the owner's wallets.

Changing launch-plan parameters changes the network ID. Do not silently reuse
wallet files encrypted for an older plan; prepare a fresh unused pair before
the final freeze or perform a separately reviewed explicit migration. Once the
final addresses/plan are published, do not rerun setup to replace them.
