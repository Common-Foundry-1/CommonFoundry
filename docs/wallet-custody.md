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
the restored key with no-overwrite semantics.

This first custody increment protects exported backups. The active
`wallet.key` remains the local signing key used by the embedded node. Encrypted
at-rest live storage, GUI unlock/relock, recovery UX, and external custody review
remain required before a mainnet wallet release.
