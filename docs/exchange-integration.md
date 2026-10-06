# Exchange integration preview

For transaction-by-hash lookup, explicit address balances, and the restricted
Singapore HTTPS transport, see [integration queries](exchange-integration-queries.md).

Status: **exchange integration preview**. The chain, deposit, and legacy
withdrawal contract remains v0.4. An explicit v0.5 custody candidate can be
activated only after offline journal/keyring migration. Neither mode is a
claim of drop-in Bitcoin compatibility or production custody readiness.

For an implementation-first handoff, begin with the machine-readable
[Exchange Integration Kit v1](../exchange-kit/START-HERE.md). It contains the
OpenRPC contract, JSON Schemas, complete examples, stable error catalog, and
preview compatibility policy. This guide remains the detailed operational and
security reference.

The preview gives an exchange a small familiar surface while keeping Common
Foundry's actual wire data explicit:

- dedicated, opt-in `POST /` JSON-RPC listener;
- loopback-only binding enforced by the node;
- HTTP Basic credentials loaded from a private file, never a CLI argument;
- canonical raw block reads and canonical transaction broadcast;
- active-chain height, tip, confirmations, peer-observed sync state, and
  mempool inspection;
- a durable, labelled, watch-only event index for block-included active-chain key
  outputs, including explicit removal events after a reorganization;
- capability discovery through `getexchangeinfo` and atomic registration of
  1-1,000 watch destinations per batch;
- an optional authenticated withdrawal journal keyed by the exchange's
  `request_id`, with separate prepare, external-anchor, and release steps;
- a separate, method-scoped credential for withdrawal planning and release;
- integer `*_atoms` strings for every monetary amount; and
- explicit `key` and `inference_channel` output locks instead of pretending
  they are Bitcoin scripts.

The integration credential never selects inputs or signs. `sendrawtransaction`
can broadcast already-signed canonical bytes. v0.4 withdrawal signing is
absent unless the operator supplies a second credential file, a dedicated
journal-authentication key file, and an external anchor file. That credential
can use only `preparewithdrawal`, `releasewithdrawal`, `getwithdrawal`, and
`getwithdrawaljournalinfo` in v0.4. The separately activated v0.5 contract adds
threshold-approved release/cancellation policy and an encrypted keyring that
routes inputs to local keys or authenticated external signer identities. The
external protocol can front an HSM or a service controlling an aggregate
BIP340 threshold key, but no vendor adapter, transport, or threshold
implementation is certified by this repository.

## RCNet connectivity status

The `CMFD_RCNET_LAUNCH_CANDIDATE_V2` network identity and signed RC-only
ProductionV4 activation are pinned in source. That does not make the network or
this custody preview production-ready. The public seed remains disabled until
the exact frozen RC package is installed and the two-node connectivity
rehearsal passes.

RCNet bootstrap is deliberately operational rather than consensus-bound. When
the qualified build exists, a node started without `--peer` or
`--no-default-seeds` uses the compiled cold-start seed
`173.249.35.251:19444`. Supplying one or more `--peer` values replaces that
default; explicit public peers require `--allow-public-peers`.
`--no-default-seeds` disables the compiled default when no explicit peer is
supplied and is the correct setting for the seed service itself. Peer exchange
can expand the reachable set after first contact, so rotating the operational
seed does not change the network ID, virtual genesis, or consensus rules.

The seed host and service have been provisioned, but the service remains
disabled until a release-gated binary and authenticated ProductionV4 artifacts
are installed. Treat the endpoint as unavailable until an independently run
node proves reachability, handshake, discovery, catch-up, and restart. An
exchange deployment should use its own nodes and explicit peer/readiness policy
rather than treating one project seed or an unauthenticated peer-height report
as a trusted checkpoint.

The current seed has a 300 GB disk and the node does not prune `blocks.log`.
The measured 12,025,320-byte proof at one block per minute consumes about 16.13
GiB per day before other block data; the 16 MiB block ceiling is about 22.5 GiB
per day. This is a short RC rehearsal budget (approximately 15 days at measured
proof size after system, artifact, and safety headroom), not a long-term
exchange-retention design.

## Starting the endpoint

Create a private UTF-8 file containing exactly `username:password`. The
username must contain 1-64 visible ASCII bytes, and the password at least 16.
One final LF or CRLF is accepted. On Linux, the node rejects group- or
world-readable files; use mode `0600` or stricter. On Windows, give only the
node service account access with NTFS permissions.

Windows PowerShell example for the current account (the password is randomly
generated and is not printed). This deliberately refuses an existing file or
directory, removes inherited access from the empty directory before writing
the secret, and deletes the secret if its final ACL cannot be applied:

```powershell
$authParent = Join-Path $env:LOCALAPPDATA 'CommonFoundry'
$authDirectory = Join-Path $authParent 'exchange-rpc-private'
$authPath = Join-Path $authDirectory 'cmfd-exchange-rpc.auth'
if (Test-Path -LiteralPath $authPath) { throw "Refusing to overwrite $authPath" }
if (Test-Path -LiteralPath $authDirectory) { throw "Use a new dedicated directory: $authDirectory" }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
New-Item -ItemType Directory -Force -Path $authParent | Out-Null
New-Item -ItemType Directory -Path $authDirectory | Out-Null
& icacls.exe $authDirectory /inheritance:r /grant:r "${identity}:(OI)(CI)(F)"
if ($LASTEXITCODE -ne 0) { throw 'Failed to protect the exchange RPC authentication directory.' }
$secret = [byte[]]::new(32)
$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
try { $rng.GetBytes($secret) } finally { $rng.Dispose() }
$password = [BitConverter]::ToString($secret).Replace('-', '').ToLowerInvariant()
try {
  [IO.File]::WriteAllText(
    $authPath,
    "exchange:$password",
    [Text.UTF8Encoding]::new($false)
  )
  & icacls.exe $authPath /inheritance:r /grant:r "${identity}:(R)"
  if ($LASTEXITCODE -ne 0) {
    Remove-Item -LiteralPath $authPath -Force -ErrorAction SilentlyContinue
    throw 'Failed to restrict the exchange RPC authentication file ACL.'
  }
} finally {
  [Array]::Clear($secret, 0, $secret.Length)
  $password = $null
}
```

Do not use Windows PowerShell 5.1 `Set-Content` without an explicit encoding;
its default UTF-16 output is intentionally rejected by the node.

The endpoint is disabled by default. The bind and integration-auth options are
required together. PowerShell:

```powershell
.\cmfd-node.exe --data-dir <node-data> run `
  --exchange-rpc-bind 127.0.0.1:38101 `
  --exchange-rpc-auth-file <absolute-private-auth-file>
```

Withdrawal signing remains disabled unless a second, different credential, a
dedicated journal key, and a separately controlled anchor file are also
supplied:

```powershell
.\cmfd-node.exe --data-dir <node-data> run `
  --exchange-rpc-bind 127.0.0.1:38101 `
  --exchange-rpc-auth-file <absolute-private-integration-auth-file> `
  --exchange-rpc-withdrawal-auth-file <absolute-private-withdrawal-auth-file> `
  --exchange-withdrawal-journal-key-file <absolute-private-32-byte-key-file> `
  --exchange-withdrawal-anchor-file <absolute-external-anchor-file>
```

Create the second file with the same private-file procedure, but use a separate
directory, random password, and username such as `withdrawal`. The node rejects
identical integration and withdrawal credentials. The integration credential
cannot call withdrawal methods, and the withdrawal credential cannot call
chain, deposit, or raw-broadcast methods. An exchange service that needs both
surfaces must hold and route the two credentials separately.

The preceding creation example leaves each file under the provisioning
identity's control. That is sufficient only for the legacy preview boundary.
For v0.5, transfer both credentials to confidential external-secret paths
outside `--data-dir`: the dedicated node service may read them but must not own,
write, replace, or control any replacement-relevant ancestor. The v0.5 loader
uses a retained file handle, rejects symlinks/reparse points and identity races,
and validates the full Unix ownership/mode or Windows DACL chain. Keep the two
files in separately controlled directories. An offline provisioner may own its
staging copies, but those copies are not valid runtime controls until the
handoff and read-only service ACL are complete.

The journal key file contains exactly 32 random bytes, not hexadecimal text.
It is independent of the Basic-authentication password, wallet passphrase, and
wallet private key. Use an absolute path to a regular, non-symlink file. On
Unix, restrict it to the owner with mode `0400` or `0600`; on Windows, give only
the node service account read access. The key is loaded at startup and is used
for keyed BLAKE3 authentication of withdrawal-journal v2 or v3. Rotating an HTTP
credential does not rotate this key. Journal-key rotation is an offline custody
migration problem; this preview implements no journal-key rotation command.

For the v0.5 packaged-host profile, hand the generated and backed-up key into a
separate service-owned, owner-only path outside `--data-dir`; it is a node
secret, not an operator/anchor-owned external authorization control. The live
ACL qualifier verifies that ownership and location explicitly.

Generate it with the node's create-new command; the key bytes are never printed
and an existing output is never overwritten:

```powershell
.\cmfd-node.exe exchange-withdrawal-keygen `
  --output C:\exchange-custody\withdrawal-journal.key
```

The anchor file must be outside the node data directory. It is controlled and
atomically replaced by the exchange coordinator; the node only reads it. After
each successful withdrawal mutation, store the exact returned `anchor` object
in this file. Keeping it under the node data directory, or under the same
rollback authority, does not provide an independent rollback boundary. The
anchor is authorization state even though it is not a secret: grant write
access only to the exchange coordinator and read access to the node service.
Use reliable local storage, not a network share or removable device; unavailable
external storage blocks withdrawal handling until the anchor can be read.
An absent anchor path is accepted only while the local v2 journal has no
withdrawal records, and `preparewithdrawal` remains disabled until the empty
journal's bootstrap anchor is present. Once any request is recorded, a missing,
malformed, or unrelated file is a fail-closed startup error.

Linux shell:

```bash
./cmfd-node --data-dir <node-data> run \
  --exchange-rpc-bind 127.0.0.1:38101 \
  --exchange-rpc-auth-file <absolute-private-integration-auth-file> \
  --exchange-rpc-withdrawal-auth-file <absolute-private-withdrawal-auth-file> \
  --exchange-withdrawal-journal-key-file <absolute-private-32-byte-key-file> \
  --exchange-withdrawal-anchor-file <absolute-external-anchor-file>
```

The startup JSON reports `exchange_rpc`,
`exchange_rpc_api: "chain-preview-v0.4"`, and
`exchange_rpc_withdrawals: true|false` when it is active. A non-loopback
bind is refused. Keep the endpoint behind the exchange's local service account
or a mutually authenticated private proxy; this preview does not provide TLS.
The credential is loaded once when the listener starts. To rotate it, replace
the file securely and restart the node; the old credential remains active until
that listener stops. A node permits only one exchange RPC listener at a time so
the deposit and withdrawal stores always have one writer.

Example request:

```bash
curl --fail-with-body --user 'exchange:REDACTED' \
  --header 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":"sync-1","method":"getblockchaininfo","params":[]}' \
  http://127.0.0.1:38101/
```

Do not place real credentials in shared shell history. The read-only
conformance tool accepts the credential file directly, requires both expected
network pins, sanitizes remote errors, and writes create-new evidence. The
packaged path is shown below; use `scripts\exchange_conformance.py` from a
source checkout:

```powershell
$networkInfo = .\cmfd-node.exe network-info | ConvertFrom-Json
python .\tools\exchange_conformance.py live `
  --endpoint http://127.0.0.1:38101/ `
  --authentication-file $authPath `
  --expected-network-id $networkInfo.network.network_id `
  --expected-consensus-fingerprint $networkInfo.consensus.consensus_fingerprint `
  --output C:\exchange-evidence\contract-conformance.json
```

The endpoint remains loopback-only Basic authentication without server
authentication, so protect the host and port against hijacking. A passing
report proves only the declared contract checks; it never means deposits or
custody are production ready.

## JSON-RPC contract

This is a deliberately strict JSON-RPC 2.0-shaped subset, not full JSON-RPC or
Bitcoin Core compatibility. Requests require `jsonrpc: "2.0"`, a non-null
string or numeric ID, an `application/json` content type, and positional
parameter arrays. JSON-RPC 1.0/omitted versions, missing or null IDs, named
parameters, batches, notifications, boolean block verbosity, and `text/plain`
requests are rejected in v0.4.

```json
{"jsonrpc":"2.0","id":"request-123","method":"getblockcount","params":[]}
```

Success echoes the exact ID:

```json
{"jsonrpc":"2.0","id":"request-123","result":123}
```

Errors include a stable machine code and retry hint:

```json
{
  "jsonrpc":"2.0",
  "id":"request-123",
  "error":{
    "code":-32005,
    "message":"transaction input conflicts with the first mempool spend",
    "data":{"code":"mempool_input_conflict","retryable":false}
  }
}
```

Batch requests and notifications are rejected in v0.4. Authentication failures
return HTTP 401; authenticated JSON-RPC errors return HTTP 200.

| Method | Parameters | Result |
|---|---|---|
| `getexchangeinfo` | `[]` | Exact API/network pins, enabled custody mode and methods, encodings, index health/capacity, and an explicit non-production status |
| `getblockchaininfo` | `[]` | Network pins, height/tip/work, storage health, active and recently reachable peers, conservative sync state, warnings; `pruned`, plus `pruneheight` and `prune_keep_blocks` on a [pruned node](proof-pruning.md) |
| `getblockcount` | `[]` | Active tip height |
| `getbestblockhash` | `[]` | Active tip ID |
| `getblockhash` | `[height]` | Active-chain ID at the height |
| `getblock` | `[hash, verbosity=1]` | Canonical block-frame hex at `0` (`block_proof_pruned` below `pruneheight` on a pruned node); block with txids at `1`; block with explicit transaction objects at `2` |
| `gettxoutsetinfo` | `[]` | Active-chain height, best block, unspent-output count and `total_amount_atoms`, the total supply (every minted coin minus burned fees) |
| `getrawmempool` | `[verbose=false]` | Txid array, or txid-keyed size and `fee_atoms` records |
| `sendrawtransaction` | `[transaction_hex]` | Accepted txid; an identical transaction already in this mempool returns the same txid |
| `registerwatchdestination` | `[label, destination_hex]` | Immutable watch registration after the complete active-chain history has been indexed |
| `registerwatchdestinations` | `[[{label, destination_hex}, ...]]` | Atomic, ordered, exact-retry-idempotent registration of 1-1,000 watches after one active-chain history scan |
| `getwatchdestination` | `[label]` | Existing immutable watch registration |
| `getdepositevents` | `[after_cursor, limit=100]` | Block-included active-chain deposit additions and reorganization removals after an exclusive decimal-string cursor |
| `preparewithdrawal` | `[request_id, destination_hex, amount_atoms, fee_atoms]` | Durably reserves and records one unsigned idempotent plan; it neither signs nor broadcasts; withdrawal credential only |
| `releasewithdrawal` | `[request_id]` | Requires the configured anchor file to match that Prepared request, signs, durably records Released bytes, then permits broadcast; withdrawal credential only |
| `getwithdrawal` | `[request_id]` | Pure observation of durable phase, exact transaction, and live chain/mempool status; withdrawal credential only |
| `getwithdrawaljournalinfo` | `[]` | Current/external anchors, storage health, and exact record/tombstone/commitment capacity with a below-1,024-release warning; withdrawal credential only |

### Explicit v0.5 custody contract

The optional v0.5 path leaves every chain and deposit method above unchanged,
but replaces the v0.4 withdrawal backend after an explicit offline v2-to-v3
migration. It adds these withdrawal-credential-only operations:

| Method | Parameters | Result |
|---|---|---|
| `getwithdrawalsigningpackage` | `[request_id, signed_approval_object]` | After the exact `ReleaseAuthorized` anchor is externally pinned, returns the exact base64 package, its two digests, consensus signing digest, approval-action anchor, and verified release-authorization envelope |
| `getwithdrawalapprovalpayload` | `[request_id, action, decision_id, authorized_at_unix_seconds, expires_at_unix_seconds]` | Result wrapper containing nested `approval_document`, its exact base64 bytes, and the distinct approval signing digest |
| `releasewithdrawal` | `[request_id, signed_approval_object, external_signer_responses?]` | First call durably authorizes and returns; after the returned anchor is externally pinned, an exact retry signs locally or verifies the ordered canonical response array, durably records exact bytes, and submits |
| `cancelwithdrawal` | `[request_id, signed_approval_object]` | Action-distinct threshold verification and durable cancellation before reservation release |

The v0.5 versions of `preparewithdrawal`, `getwithdrawal`, and
`getwithdrawaljournalinfo` return the expanded v3 evidence. Every v3 method
name is treated as withdrawal-sensitive even on a v0.4 or disabled listener,
so the integration credential cannot use unsupported-method probing to cross
the credential boundary. Archive, compaction, migration, keyring, and policy
operations are deliberately absent from RPC. There is no implemented v0.5
general policy, keyring, or journal-key rotation command; never replace one in
place. The offline tools provide only a create-new transition from the exact
single-key imported keyring to one external Active key while retaining the
legacy local key as Retired for migration, followed by a guarded external-only
runtime finalization that removes that secret and atomically rotates the v3
journal anchor. The finalizer proves a confirmed active-chain sweep, zero
legacy-key chain/local-mempool outputs, and binds—but does not authenticate—
operator retirement and external-mempool assertions. Any later rotation
requires a separately designed and qualified migration.

Copy `result.approval_document`, add the strictly public-key-sorted threshold
signatures to that nested object, and pass it—not the whole result wrapper—as
`params[1]` of `releasewithdrawal` or `cancelwithdrawal`:

```text
signed_approval = copy(result.approval_document)
signed_approval.signatures = sorted_threshold_signatures
params = [request_id, signed_approval]
```

Generate the payload's `decision_id` as a fresh globally unique nonzero 32-byte
value and never reuse it, even after compaction. The wrapper's
`signing_digest` is the approval digest, while the nested
`transaction_signing_digest` is the consensus transaction digest. Approvers
sign the raw 32 approval-digest bytes with BIP340, not its hex text, JSON, or
base64 representation. Set expiry no more than 900 seconds after authorization;
rolling limits are charged at the node's durable local submission time, not a
caller-selected signed timestamp; withdrawal status reports that time as
`accounted_at_unix_seconds`. The binary signing-package layout, both package-digest
domains, the exact approval digest concatenation, a full request example, and
golden vectors are specified in
[Exchange custody v0.5](exchange-custody-v0.5.md). v0.5 exports the
provider-neutral package only after durable authorization and accepts a
strictly ordered optional array of canonical external signer responses on the
completion call. Status methods expose package digests, never exact signable
bytes. Each response and its second per-input signature binds the returned
post-transition `release_authorization_digest`, so a Prepared package cannot
be pre-signed and replayed after authorization. See the custody guide for the
response frame, independently pinned authorization envelope, and signer-side
requirements.

The optional reference signer additionally requires a BIP340-authenticated
trusted-context envelope from an out-of-band pinned authority. That context
binds transaction intent, signer capabilities/key set, approval roster, and
the Prepared, approval-action, and ReleaseAuthorized anchors. It is an
integration aid only: it has no independent chain proof of package input
values, persistent anti-replay ledger, vendor HSM transport, or installed-host
power-loss qualification.

After v3 activation, a persisted v3 marker or detected v3 slot keeps native
wallet mutation locked even if a restart omits the v3 flags. `cmfd-node status`
and the startup document's nested `status` report
`exchange_custody_v3_wallet_state` as `unclaimed`, `required`, or `active`;
custody deployment must require `active` plus top-level
`exchange_rpc_custody: "v3"`. A failed custody startup provides no listener,
but its public message distinguishes an external anchor that `is ahead of` the
authenticated journal from one that `diverges from` it. A compatible,
replay-safe ancestor can start for observation; mutations say the anchor
`is behind` until the coordinator pins the exact current state. All three
retain the machine
classification `exchange_custody_v3_anchor_mismatch`; recovery must follow the
separate evidence-based cases in the custody guide.

The offline `pin-exchange-withdrawal-anchor.ps1` helper accepts successful
`chain-preview-v0.5` responses as well as v0.4. Save and verify the complete RPC
response first, then use the helper to validate and atomically advance the
coordinator-controlled anchor.

In migration evidence, top-level `migration_decision_id` and
`migration_approval_digest` are operator-supplied nonzero reference metadata
bound into the migration plan, journal, and receipt; the node does not verify a
signature represented by either field. Per-record `signed_approval` objects are
threshold-verified, and operator confirmation of the full `plan_digest` is the
explicit cutover authorization.

Each migrated Released v2 record carries an externally retained, canonical
release approval payload with a policy-valid threshold signature set created
against the exact pinned v2 source anchor before cutover. Manual or
reorganization replay resubmits that same payload with a valid threshold
signature set, and the runtime replays only the already authenticated
transaction bytes; it cannot mint a fresh terminal approval payload for the
migrated record.

See [Exchange custody v0.5](exchange-custody-v0.5.md) for the exact migration,
activation, approval, anchor, crash-recovery, and canceled-record compaction
procedure.

IDs are lowercase 64-character hex. Timestamps are Unix seconds. `nonce` and
all monetary values are strings when their exact integer representation matters.
Transaction outputs identify `value_atoms`, `spendable_height`, `lock_type`,
and either `destination_hex` or `channel_id`. `destination_hex` is currently a
raw 32-byte x-only Schnorr public key, not a checksummed display address.
Coinbase is a separate block field rather than an ordinary transaction; its
`outpoint_txid` and each output's `n` form the exact outpoint an indexer needs.

Height zero is the immutable virtual-genesis anchor. `getblockhash(0)` returns
its ID, and `getblock` verbosity 1 or 2 returns a clearly marked synthetic
`virtual: true` document so height-based scanners retain their normal linkage.
Raw verbosity 0 returns `block_not_found` because the anchor has no canonical
frame. The first persisted block is height one.

`getblockchaininfo.initialblockdownload` deliberately remains true throughout
v0.4. `peer_observation_caught_up`, `peer_observation_tip_match`, and
`verificationprogress` summarize successful observations from the last 60
seconds, but P2P heights are unauthenticated and advisory. A production exchange
must define an external checkpoint or trusted multi-node readiness policy before
enabling deposits; one peer observation is not proof that no higher chain
exists.

## Durable deposit event workflow

`registerwatchdestinations [[{label, destination_hex}, ...]]` atomically stores
1-1,000 immutable mappings after checking their complete active-chain history
and one durable commit. The node's full-history address index lists the blocks
that pay or spend each key, so only those blocks are read; a freshly generated
key reads none. It rejects the entire batch before persistence if any entry is
invalid, conflicts with an existing mapping, or duplicates another batch label
or destination. Results preserve input order, and an exact retry returns the
same mappings. `registerwatchdestination [label, destination_hex]` is the
one-at-a-time compatibility form and uses the same validation and durable path.
Each mapping connects an exchange label to one raw 32-byte x-only Schnorr public
key. A successful response means the node has checked active-chain history from
height one and durably published all matching events.
The label must contain 1-128 visible ASCII bytes. The destination must be
exactly 64 lowercase hexadecimal characters and decode as a valid key.
Retrying the exact same label and destination is idempotent. Reusing a label
for a different destination returns `watch_label_conflict`; reusing a
destination under a different label returns `watch_destination_conflict`.

Labels are stored as plaintext. Use pseudonymous internal account or deposit
identifiers, never customer names, email addresses, or other personal data.
Registering a destination proves only that the node is observing it; it does
not prove that the exchange possesses the corresponding private key. Verify
key generation, backup, and signing independently before accepting deposits.

`getwatchdestination [label]` returns the stored mapping or `watch_not_found`.
Registrations cannot be changed or removed in this preview. The same Basic
credential currently authorizes chain reads, transaction broadcast, and watch
registration. Limit it to a dedicated integration service. Withdrawal signing
uses the separate withdrawal credential and cannot be reached with this one.

Both registration and lookup return the same immutable shape, so an exact
registration retry has the same result even after the chain advances:

```json
{
  "api_version":"chain-preview-v0.4",
  "label":"account-001",
  "destination_hex":"<64 lowercase hex>",
  "registered_at_height":123,
  "registered_at_tip":"<64 lowercase hex>"
}
```

`getdepositevents [after_cursor, limit]` is a nondestructive, at-least-once
feed. `after_cursor` is the last completely processed cursor, encoded as a
decimal string; use `"0"` for the first poll. `limit` may be 1 through 1000.
The response includes the network and consensus pins, the deposit index's
active-chain tip, immutable `events`, `next_cursor`, `high_watermark`, and
`has_more`. Cursors in requests and responses are decimal strings so clients
do not lose precision. A cursor beyond the durable high watermark is rejected
rather than silently skipped.

Each event contains `cursor`, `added_cursor`, `kind`, `label`,
`destination_hex`, `txid`, `vout`, `value_atoms`, `spendable_height`,
`coinbase`, `blockhash`, `blockheight`, and `blocktime`. Cursor and monetary
fields are decimal strings. For an addition, `added_cursor` equals `cursor`;
for a removal, it identifies the original addition.

For each polling cycle, retain the first returned `high_watermark`, stage each
event in cursor order, then request again using `next_cursor` until that
watermark has been reached. Do **not** expose a credit while draining those
pages: a historical addition can be followed by its removal on the next page.
For each later page in that cycle, set `limit` to the smaller of 1000 and
`captured_high_watermark - next_cursor` using checked unsigned arithmetic;
defer newer events to the next cycle.
After reaching the captured watermark, derive balances from the staged event
log, verify every credit candidate is still on the reported active chain (for
example, `getblockhash(blockheight) == blockhash`), and only then apply the
exchange's confirmation policy. An output is not even eligible to spend in the
next block until `indexed_tip.height + 1 >= spendable_height`; use checked
arithmetic and never release customer credit or liquidity before that condition
holds. Persist each staged event and its cursor atomically so a retry is
harmless. Poll again for events appended after the captured watermark.

`deposit_added` records are emitted only for matching key outputs in blocks on
the active chain. They are never emitted from the mempool. If those blocks are
later orphaned, the index emits immutable `deposit_removed` records that refer
back to the corresponding addition; it does not edit or delete the earlier
record. A removed outpoint that later re-enters the active chain receives a new
addition cursor. Consumers must therefore make both event kinds idempotent by
cursor and preserve the complete audit trail.

The index reports the containing block and current indexed tip, but it does not
decide when funds are safe to credit. The exchange owns its confirmation,
checkpoint, and multi-node policy. Only after draining the captured event
watermark and proving the addition remains active should it compute
confirmations from the indexed tip and the event's block height. Delay customer
credit until both the chosen threshold and `spendable_height` condition hold,
and still apply a removal event if a deeper reorganization crosses it. Mempool
visibility is useful only for display and risk monitoring; it must never create
an exchange balance.

`getdepositevents` synchronizes before serving every page. Any index, capacity,
or storage error therefore blocks even historical reads by design. Treat every
such error as a hard deposit-credit stop, preserve the last committed exchange
cursor, alert the operator, and resume only after the same request succeeds.

## Durable withdrawal workflow

Version 0.4 deliberately separates transaction preparation from broadcast. A
successful preparation is not permission to pay. The exchange must first pin
the returned journal state outside the node data directory, then make a
separate release call.

Before the first withdrawal, call `getwithdrawaljournalinfo []`. For a genuinely
new, empty v2 journal, persist its returned `anchor` object as the bootstrap
anchor. On every later startup, use this method to compare the journal's current
anchor with the configured external anchor file. Treat any relationship other
than the documented healthy current-or-descendant state as a hard custody stop;
the method reports state but never repairs, rewrites, releases, signs, or
broadcasts anything.

The withdrawal protocol is exactly three steps:

1. Call
   `preparewithdrawal [request_id, destination_hex, amount_atoms, fee_atoms]`.
   The node durably records the exact selected inputs and output plan, advances
   it to Prepared, and returns its request and signing digests, reservations,
   and `anchor`. It does not sign, submit, or relay the transaction;
   `txid` and `transaction_hex` are null while Prepared.
2. Durably store the complete response with the exchange withdrawal row. Then
   verify that its request ID, destination, amount, fee, request digest,
   signing digest, and reserved inputs match the exchange's approved database
   row. Only after that comparison succeeds, atomically replace the separately
   controlled anchor file with the exact returned `anchor` object. Do not
   reconstruct, normalize, or hand-edit it.
3. Call `releasewithdrawal [request_id]`. The node rereads the configured anchor
   file and requires it to match that request's current Prepared state exactly.
   Only then does it sign the fixed plan. It durably records the exact signed
   bytes and advances the record to Released before its first broadcast
   attempt. Persist the complete release response and atomically replace the
   anchor file again with the new returned `anchor`.

After first saving the complete RPC response in the exchange database or
durable response file, the included helper validates monotonicity and performs
the same-directory atomic anchor replacement:

```powershell
.\scripts\pin-exchange-withdrawal-anchor.ps1 `
  -ResponseFile C:\exchange-custody\prepare-response.json `
  -AnchorPath C:\exchange-custody\withdrawal-anchor.json
```

It is offline and never calls RPC. It refuses rollback, same-generation
divergence, key or journal-instance changes, and concurrent replacement.

Choose the request ID in the exchange database before step 1 and never reuse it
for another withdrawal. It must contain 1-128 visible ASCII bytes. The
destination must be a valid 32-byte Schnorr key encoded as 64 lowercase
hexadecimal characters. Amount and fee are canonical unsigned decimal strings:
use `"0"`, not `"00"`, and note that the amount must be nonzero. The supplied
fee must meet the node's relay minimum for the resulting transaction.

An exact preparation retry returns the same unsigned plan, reservations,
digests, and Prepared anchor; it still does not sign or broadcast. Reusing the
request ID with a different destination, amount, or fee returns
`withdrawal_request_conflict`. Validation and funding failures before the
Intent is durably published do not bind the request ID. If preparation succeeds
but its response is lost, retry the same request. Do not prepare a different
request against a stale anchor.

An exact release retry is also idempotent. If the Released publication committed
but the response or first broadcast was lost, retrying the same request returns
the same signed transaction and current anchor. Only a durably Released record
is eligible for startup reconciliation or byte-identical rebroadcast. A
Prepared record can never broadcast, including after a crash or restart.

`getwithdrawal [request_id]` is observation only. It returns the durable phase,
exact transaction identity, and current chain/mempool observations without
signing, releasing, broadcasting, rebroadcasting, or changing journal state.
Poll it until the exchange's confirmation policy is met. Mempool, confirmed,
and conflicted observations can change after a reorganization; the durable
Prepared/Released decision does not.

If an already Released withdrawal becomes `broadcast_pending` after eviction
or a reorganization, retry `releasewithdrawal` with the same request ID. That
call may rebroadcast only the exact durably stored bytes; polling
`getwithdrawal` alone intentionally does not alter node state.

Every successful mutation returns an `anchor` object. Persist it exactly. On a
prepare retry, require the request fields, request digest, signing digest, and
reserved inputs to remain identical, with no txid or signed bytes. On a release
retry, additionally require the txid and canonical transaction bytes to remain
byte-for-byte identical. The v2 journal uses a keyed BLAKE3 commitment chain
authenticated by the dedicated 32-byte journal key. Its physical snapshot
generation and semantic anchor progression are distinct: file-copy generations
are not withdrawal authorization.

The node authenticates both write-through journal slots, the initialization
marker, the journal ancestry, and the configured external anchor before any RPC
or P2P service starts. A missing or wrong key, corrupt or missing initialized
journal, whole-directory rollback, divergent history, invalid external anchor,
or network, consensus, genesis, wallet, instance, or ancestry mismatch fails
startup closed. An external anchor may be an ancestor of recoverable current
state, but `releasewithdrawal` still requires the file to equal that request's
exact current Prepared anchor.

Withdrawal-journal v1 is not accepted by v0.4 withdrawal mode. There is no
automatic or in-place migration. Preserve all v1 files and their original
binary; do not delete, rename, or edit the journal to force startup. A future
separately qualified migration procedure is required before such state can be
used with v0.4.

Do not run another automated payout engine against the same custody wallet.
The node wallet excludes withdrawal-journal inputs from ordinary sends and
consolidation, but this preview does not qualify cross-journal recovery with the
pool payout subsystem. It also has no cancellation or abandonment method;
manual deletion or editing of journal files is unsafe.

## What still gates an exchange wallet

The current node now has durable full-history watch-only events for explicitly
registered key destinations and a durable idempotent withdrawal journal. It
still has one signing key in legacy v0.4; explicit v0.5 migration adds a
multi-key provider-neutral custody boundary, but no certified vendor provider.
Neither path has a node-generated deposit-key or checksummed address-derivation
pool. The native development RPC also has unauthenticated loopback
wallet-spending routes.
Do not expose or use those routes for exchange custody, and do not infer
production custody security from authentication on this integration listener.

Implementation order:

1. **Completed for the preview:** a durable watch-only index keyed by
   `(txid, vout)`, with labelled destinations, block cursors, atomic
   common-ancestor rewind, and explicit removed-deposit events. It never
   credits mempool observations.
2. **Completed for the preview:** a keyed v2 withdrawal journal with durable
   input reservations, separate Prepare and Release transitions, exact-byte
   replay, a separately controlled external anchor, separate authorization,
   and restart/reorganization tests.
3. **Implemented behind explicit v3 migration:** authenticated encrypted
   keyring import and its narrowly scoped import-to-external transition,
   action-specific threshold approvals, signed-time limits, durable
   cancellation, exact signing-package verification, externally pinned
   authorization-before-signing ordering, guarded external-only keyring/journal
   finalization, and canceled-record compaction.
4. **Implemented as an uncertified integration boundary:** keyring-routed
   local/external signing, multi-provider response assembly, and custody keys
   distinct from the node's local wallet key.
5. **Still required for production custody:** vendor-specific HSM/remote or
   aggregate-threshold signer qualification, target-host packaged ACL and
   physical power-loss qualification, backup/restore rehearsal, and an
   independent external custody audit.

The complete v0.5 activation and recovery contract is in
[Exchange custody v0.5](exchange-custody-v0.5.md). It is opt-in and never
rewrites v0.4 state automatically.

The packaged Windows/Linux service-account and path boundary has a separate
[live ACL qualification gate](exchange-custody-acl-qualification.md). Run that
gate from the installed `cmfd-node` under the exact non-root/non-elevated
service identity. Only installed-host evidence with `host_qualified: true`
qualifies a machine; dry fixture output always remains non-host evidence. On
Windows, the gate also requires an exact per-artifact authority allowlist and
rejects protected owner/read/write authority assigned to an unlisted SID;
SYSTEM, Administrators, and TrustedInstaller count only when explicitly named
in the live configuration.

Steps 1-4 make this an **exchange integration candidate**, but the public label
remains **exchange integration preview** until the interface and operating
model receive external review. Production custody readiness still requires
step 5 and an exchange-specific deployment review.

Other v0.4 limitations:

- the general mempool remains volatile across node restarts; the withdrawal
  journal restores reservations and may rebroadcast only exact transactions
  that were durably Released;
- `sendrawtransaction` is still raw broadcast, not withdrawal idempotency; use
  `preparewithdrawal`, external persistence, and `releasewithdrawal` with a
  durable exchange request ID for custody payouts;
- watched deposit keys are not spendable unless they are the node wallet's one
  key. There is no keyring, address derivation, internal change-key rotation,
  approval policy, withdrawal limit, multisig, HSM, or offline signer;
- the RCNet wallet key is encrypted at rest but is unlocked in this node process
  while signing is enabled;
- Released-withdrawal reconciliation occurs at startup and during release
  handling, not in `getwithdrawal` and not in a continuously running background
  worker;
- only one non-Released request may exist at a time. There is no cancel or
  abandon operation, so a caller with the withdrawal credential can reserve
  funds and stop later prepares, but cannot sign or release without the
  exchange-controlled Prepared anchor. Recovery from an unwanted Prepared
  request is an offline operator procedure in this preview;
- the withdrawal journal has no compaction or archival procedure. It rewrites
  bounded full snapshots and permanently caps history at 65,536 records and 64
  MiB, so capacity and write latency must be monitored;
- this listener handles at most four bounded requests concurrently and returns
  HTTP 503 when all four worker slots are occupied;
- each registration reads the blocks that touch its keys synchronously, and
  updates rewrite a bounded full snapshot under one index lock. The published
  caps are safety ceilings, not production-scale qualification; onboard at a
  controlled rate until a batched, append-only/WAL-backed store replaces this
  preview implementation;
- two write-through snapshot slots plus an initialization marker protect both
  deposit and withdrawal state from corruption and ordinary file loss. The
  separately controlled v0.4 withdrawal anchor additionally detects withdrawal
  rollback of the entire node data directory. The deposit index has no matching
  external rollback anchor, so keep the exchange database authoritative for
  watch registrations and deposit cursors;
- withdrawal-journal v2 uses keyed BLAKE3 authentication, while the deposit
  index still uses an unkeyed integrity digest. The journal key does not encrypt
  metadata and does not protect against compromise of the running signer. The
  external anchor is independent only when the exchange coordinator controls it
  outside the node's rollback and write authority;
- general confirmed transaction lookup by txid is absent; deposit discovery is
  limited to registered key destinations and the immutable event feed;
- no `getnewaddress`, `listsinceblock`, `listunspent`, `gettxout`,
  `sendtoaddress`, or `sendmany`; and
- the legacy v0.4 path still treats Windows auth-file ACLs as an operator gate;
  the opt-in v0.5 custody path applies its retained-handle, reparse-safe,
  confidential external-secret boundary to both RPC authentication files and
  runtime passphrases, and validates complete ancestor ACL/ownership chains for
  its external controls.
