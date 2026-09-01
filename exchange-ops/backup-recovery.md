# Exchange custody backup and recovery gate

Production authorization requires a rehearsal on representative installed
hosts. A written procedure alone does not pass this gate.

## Authorities to inventory separately

- node block/index data and the exact compiled network manifest;
- encrypted wallet keyring and its independently stored rollback anchor;
- withdrawal journal slots, journal authentication key, and external anchor;
- canonical withdrawal policy and approval public keys;
- integration and withdrawal authentication files;
- HSM/remote-signer configuration, key identifiers, certificate chain, and
  vendor backup ceremony evidence;
- release binary, checksum/signature evidence, configuration, ACL report, and
  conformance report.

Never place a keyring passphrase, journal key, wallet passphrase, or HSM backup
in the audit or integration bundle. Evidence should contain only identifiers,
lengths, hashes, custody locations, and ceremony references.

## Restore acceptance criteria

1. Start from a clean replacement host under the intended service identity.
2. Verify the release and `network-info` against independently retained pins.
3. Restore each authority from its designated custodian; prove the node service
   cannot modify external anchors or offline/HSM material.
4. Open the keyring and journal only with exact matching anchors. Any rollback,
   cross-network, policy, keyring, or commitment mismatch must fail closed.
5. Reconcile the active chain and mempool, then drain deposit events from the
   exchange's last committed cursor. Replayed cursors must be idempotent.
6. Query every nonterminal withdrawal and reconcile its reserved inputs,
   terminal approval, transaction id, mempool state, and confirmations.
7. Execute one controlled deposit, removal/reorg, release, cancellation, and
   restart. Do not reuse rehearsal keys for value-bearing custody.
8. Save a signed operator record containing host, binary, source commit,
   manifest hashes, start/end anchors, results, exceptions, and approvers.

Restore time and recovery-point objectives remain exchange/operator decisions;
they are not implied by the software tests.
