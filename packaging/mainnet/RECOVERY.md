# Mainnet backup and recovery

Use the wallet/node runtime package for these operations. They are offline
maintenance commands, not instructions to change the running RC network.
Rehearse with disposable wallets first; keep the real source data intact.

## What to retain

- A verified encrypted wallet backup and its public receiving address.
- Its passphrase under separate custody. A backup alone cannot recover a lost
  passphrase; never put the passphrase in a support log or release bundle.
- The exact signed release, checksums, MAINNET-PACKAGE.json, and the
  production-mainnet plan/approval files. After activation, also retain the
  public verified LAUNCH-BEACON.json.
- A consistent stopped copy of the complete node data directory, including
  blocks.log, network.meta and wallet.key. Preserve file ownership and access
  permissions. Cache/checkpoint files do not replace block history.
- For a pool, the matching stopped accounting ledger, saved configuration and
  TLS identity/private key. Restoring only the wallet does not reconstruct pool
  liabilities. Do not mix ledger slots from different backups.
  Include `pool-ledger-payout-guard-v1.json`; do not delete it or downgrade to a
  binary that ignores it. A guard/snapshot mismatch must stop settlement.
  A coherent old backup can still omit subsequent payments: reconcile all later
  signed/on-chain payment history before enabling payouts after a restore.

Model inputs may be downloaded and hash-verified again. They are not wallet
backups. Keep at least one independently stored copy of the encrypted backup
and verify it by restoring into a new directory.

## Make an offline wallet backup

First close every wallet, node and pool using the source data directory. For
the staged Linux service, stop commonfoundry-mainnet-node and confirm it is
inactive; separately stop any pool or manually launched process. A locked
directory must cause the backup command to fail, not trigger a force-stop.

Run as the normal wallet/service identity, with a protected passphrase file
that identity can read. A systemd runtime credential can disappear when its
service stops; arrange authorized offline access to the existing passphrase
instead of assuming the runtime path still exists. On Linux the passphrase
file must be 0600 or stricter. On Windows restrict its ACL to the intended
identity and the administrators responsible for custody.

Replace each angle-bracket placeholder with an absolute path. Quote paths
containing spaces. In PowerShell use `& 'C:\absolute\cmfd-node.exe'` in place
of `cmfd-node`; on Linux use the verified executable's absolute path.

```text
cmfd-node --data-dir <stopped-data> wallet-backup --output <new-backup-file> --passphrase-file <protected-passphrase-file>
```

The output parent must already exist. Select a new backup filename outside the
node data directory; an existing file is never overwritten. Confirm the
reported network ID and destination against the retained mainnet identity and
your receiving address. Do not use an RC backup as a mainnet wallet.

## Restore into a separate directory

Choose one recovery path:

1. **Wallet-only:** run the command below with a new data directory. Reconnect
   later to resynchronize chain history; wallet balance comes from validated
   chain data, not from the backup's displayed address.
2. **Whole-node copy:** restore the complete stopped data-directory backup to a
   new directory, preserving its encrypted wallet and permissions. Do not run
   wallet-restore over that existing wallet.key.
3. **Separate wallet and chain backups:** restore the wallet first, then copy
   the matching stopped chain data without replacing wallet.key or copying a
   live lock handle. Keep the original backup untouched and verify the network
   and tip before starting services.

```text
cmfd-node --data-dir <new-restored-data> wallet-restore --input <encrypted-backup-file> --passphrase-file <protected-passphrase-file>
```

Wrong passphrases, altered backups and another network are rejected. Existing
wallet keys are not overwritten. Before handing the directory to a service,
verify that the intended unprivileged service identity owns/can access its data
and cannot modify the executable or mainnet plan. Restore pool TLS material and
the matching accounting ledger before enabling pool settlement.

## Validate and restart

Use the exact release and mainnet plan that produced the backup. Storage
inspection/repair require its authenticated launch beacon, but no GPU or model
loading. Wallet backup/restore can be performed offline before activation.

```text
cmfd-node --data-dir <restored-data> storage-inspect
cmfd-node --data-dir <restored-data> --wallet-passphrase-file <protected-passphrase-file> status
```

`healthy` is a structural log result, not independent proof approval. `status`
opens the actual node state and needs the authenticated model inputs and launch
evidence. Compare its network ID, consensus fingerprint, height and tip with
the recorded backup. Test receive-address continuity and a controlled transfer
before switching services to restored storage.

If inspection reports `recoverable_partial_tail`, follow STORAGE-RECOVERY.md.
Only the incomplete final bytes may be quarantined and removed. Never truncate
complete records, discard a checksum failure, or delete a wallet to make startup
succeed. Preserve the original stopped copy and all quarantine evidence.

After recovery, record the binary SHA-256, source commit, network/fingerprint,
restored height/tip, backup timestamp, test results and any quarantine hash.
Do not record passphrase contents, private keys, or backup ciphertext in public
diagnostics. Complete an isolated restore/restart rehearsal under the intended
service identity before considering the deployment recovery-qualified.
