# Wallet custody and recovery

Common Foundry provides an offline, authenticated backup format for the node
wallet key. The backup is encrypted with XChaCha20-Poly1305 using a key derived
from the operator's passphrase with Argon2id. Its authenticated header binds the
format version, KDF parameters, compiled network ID, and wallet destination.

The commands accept the passphrase only through a file so it is not exposed in
the process command line. The node or wallet must be stopped: both operations
take the data-directory lock, and restore refuses to overwrite an existing
`wallet.key`.

```text
cmfd-node --data-dir <wallet-data> wallet-backup \
  --output <offline-path>/wallet.cmfd-backup \
  --passphrase-file <private-passphrase-file>

cmfd-node --data-dir <fresh-or-keyless-wallet-data> wallet-restore \
  --input <offline-path>/wallet.cmfd-backup \
  --passphrase-file <private-passphrase-file>
```

Passphrases must contain 12 to 1,024 bytes. On Unix the passphrase file must be
mode `0600` or stricter. Store the encrypted backup and passphrase separately,
then test recovery into a fresh data directory and compare the reported wallet
destination before relying on the backup.

The v1 reader is deliberately strict: it accepts one exact file length and one
set of Argon2id parameters, rejects another network before writing, authenticates
all metadata and ciphertext, validates the recovered Schnorr key, and creates
the restored key with no-overwrite semantics. Restore keeps `wallet.key`
encrypted; it never writes the recovered 32-byte secret to disk.

Start the node or desktop wallet with the same private passphrase file:

```text
cmfd-node --data-dir <wallet-data> \
  --wallet-passphrase-file <private-passphrase-file> run

common-foundry-wallet \
  --wallet-passphrase-file <private-passphrase-file>
```

Supplying that option for a new data directory creates an encrypted live
`wallet.key`. Existing Devnet plaintext keys remain readable for compatibility;
they are not silently rewritten. RCNet refuses plaintext live keys and requires
the passphrase option when creating or opening its wallet. The decrypted key
exists only in process memory while the wallet is running.

The desktop wallet also provides **Wallet security** from its shield button. It
supports the same fail-closed operations without putting a passphrase in a
process command line:

- create a new encrypted wallet or unlock an existing one;
- migrate a Devnet plaintext key by creating a separate encrypted backup first,
  then atomically replacing the live key;
- create a new no-overwrite authenticated backup;
- restore into a keyless wallet data directory; and
- lock the wallet, stop its embedded services, and release the decrypted
  signing key from memory.

The interface never persists a passphrase in browser storage or wallet
settings. Backup, migration, and restore paths must be absolute. Backup and
migration leave the wallet locked so the operator explicitly unlocks it after
moving the backup to its intended offline location.

An external custody review remains required before a mainnet wallet release.
