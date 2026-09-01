# Exchange node upgrade and rollback procedure

1. Suspend new withdrawal preparation and wait for an exchange-defined safe
   state. Record all nonterminal request ids and the current journal, keyring,
   deposit-cursor, network, and consensus pins.
2. Verify the candidate release checksum/signature, source commit, compiled
   `network-info`, configuration inventory, and migration requirements.
3. Run candidate compatibility, ACL, backup-restore, and conformance tests on a
   clone that cannot broadcast to the production network.
4. Stop the service cleanly and prove exclusive access to the data directory.
   Retain the exact prior binary and configuration. Never copy live custody
   secrets into the release or audit bundle.
5. Apply only an explicit documented migration. Persist proposed anchors beyond
   the node's authority before acknowledging the migrated state.
6. Start the candidate with deposits and withdrawals administratively paused.
   Verify network identity, storage health, deposit cursor continuity, journal
   relationship, keyring generation, policy id, and signer possession.
7. Re-enable deposits, then withdrawals, only after independent reconciliation.
8. If validation fails, stop. Roll back only when the older binary is documented
   to understand the resulting state. Never force an older binary across an
   irreversible schema or anchor transition.

An interrupted-update and rollback/reapply rehearsal must be performed on the
packaged candidate. Passing source-tree unit tests is not installed-host proof.
