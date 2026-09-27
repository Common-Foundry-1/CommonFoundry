# Preparing the two mainnet reward wallets

## Current owner custody after the September 27 replacement

The owner retained the Steward key/address and replaced the inaccessible
Community key before mainnet launch. The replacement backups were authenticated
with their new passwords; the same Steward secret was encrypted for the new
address-bound network. Older encrypted backups are preserved, not overwritten.

- Steward: `5321229f3d3e3fccb900f95c7baee2b27a929afe70f95a0bde0394dba79c9684`
- Community: `fbe36f76cad922c1c911d8cecc2eed21c853d10fb99e450fc14ac7e54bf59a3f`
- Plan: `2133726558490606e89a8fe3499f32c9a35722ed0022e09b7cd1cd30239d04af`
- Network: `88296bc39c10e8bc1dd4818d4d42412fe5f08210651110377f495da299812f62`

The updated public records are in `packaging/mainnet`. An encrypted replacement
archive was verified on the PC and AI01; this is off-host retention, not a claim
of offline physical storage. The September 23 section below is historical and
its old Community address/plan must not be used for the replacement release.

## Preparation procedure

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
or transfer funds. Component tests use disposable keys and are not evidence of
the owner's custody; the completed owner setup is recorded separately below.

Changing launch-plan parameters changes the network ID. Do not silently reuse
wallet files encrypted for an older plan; prepare a fresh unused pair before
the final freeze or perform a separately reviewed explicit migration. Once the
final addresses/plan are published, do not rerun setup to replace them.

## Owner setup completed September 23, 2026

The owner completed the guided setup using the distinct-password release utility
built from `76acf5f5f03e1fc62d5c16e08037eda4d591c8e1`. The public output is
preserved byte-for-byte in `packaging/mainnet/MAINNET-PLAN.json` and
`packaging/mainnet/REWARD-CUSTODY.json`:

- Steward: `5321229f3d3e3fccb900f95c7baee2b27a929afe70f95a0bde0394dba79c9684`
- Community: `bcd252021db8c7732cec4c2cba4b41a9d373dcbde61402e22c933751e74cc341`
- Launch plan digest: `6c839b274f6385e7f4040a715436b739612527f29bfa9bdf5d2f89de1f440b52`

The native setup report records successful authentication of both encrypted
backups. A subsequent check found no incomplete marker and matched all four
encrypted-file hashes against that report. No password or private key was read
by that subsequent check. Regeneration using the public addresses and approved
targets reproduced the exact plan bytes. CI regression checks protect this
record's identity, public-only schema and agreement with the artifact catalog.

The encrypted backups currently exist in a separate local folder. An off-host
copy and secure retention of both passwords remain operator responsibilities;
neither has been independently confirmed. Do not rerun the setup just to reopen
these wallets or create another backup. These records do not activate mainnet
or replace the outstanding signed plan and release approvals.
