# Pool ledger migration across a consensus fingerprint change

`pool-ledger-rebind` is an offline, copy-only converter for a guarded
`format_version: 2` pool ledger. It does not change the source directory,
send a payment, or start a pool. Normal `pool-serve` still rejects a ledger
whose network ID or consensus fingerprint does not match its node.

The command requires a stopped source pool. It takes the exclusive
`pool-ledger.lock`; an active pool makes it fail. It verifies the expected
generation, the guard's exact snapshot digest, the version 2 payload checksum,
the compiled network ID, and that the requested target fingerprint matches
this binary's authenticated `network-info` output. It writes the same payload, including payout
transaction records and accounting totals, to a new directory with the new
fingerprint and a matching new guard. It copies the archive byte for byte and
reports its BLAKE3 digest. A ledger with retired history and no archive is
rejected. A partially written staging directory is never published as the
requested output directory.

Before running it, retain a consistent stopped backup of the full original
node data and `pool-ledger` directory. Determine both fingerprints and the
source generation from the reviewed old and new binaries. Run the converter
from the new binary with an output path that does not exist:

```text
cmfd-node pool-ledger-rebind \
  --source-ledger <stopped-old-data>/pool-ledger \
  --output-ledger <new-staging-data>/pool-ledger \
  --source-fingerprint <64-hex-old-fingerprint> \
  --target-fingerprint <64-hex-new-fingerprint> \
  --expected-generation <inspected-generation> \
  --pool-ledger-max-bytes <old-pool-ledger-limit>
```

Use the actual path separator and line continuation for the operator's shell.
The prepared ProductionV4 model bank and fixed record are required for
`network-info`; an arbitrary target fingerprint is rejected.
Keep the original ledger, guard, both snapshots, and archive together. Review
the command's digests and the new directory with the exact fork binary, then
run offline payout status and reconcile any holds or old signed payments
against the new chain before enabling automatic settlement. Rebinding a
fingerprint does not prove that an old signed transaction is valid on the new
branch or that the fork activation is ready. It does not choose an activation
height or replace a consensus upgrade test. A changed fingerprint also blocks
existing node `network.meta` at startup and old-fingerprint peer handshakes;
this pool-only converter is not a complete node upgrade path.
