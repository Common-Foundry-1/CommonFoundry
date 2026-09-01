# Common Foundry Exchange Integration Kit v1

Status: **integration preview**. This kit describes the RPC implemented by the
current pre-release source. It is not a production-custody certification,
Bitcoin Core compatibility claim, independent audit opinion, or claim that a
release-gated RCNet binary is available today.

## Read this first

Common Foundry exposes a loopback-only, Basic-auth-protected, JSON-RPC
2.0-shaped interface. It deliberately separates two credentials:

| Credential | Permitted surface |
|---|---|
| Integration | Chain reads, mempool reads, raw transaction broadcast, watch registration, and deposit events |
| Withdrawal | Prepare, approve, authorize, sign, cancel, release, and observe withdrawals |

The listener has no TLS and refuses a non-loopback bind. Put any remote access
behind an exchange-controlled mutually authenticated private proxy. Never give
the node write authority over the independently pinned withdrawal anchor.
Loopback plus Basic auth authenticates the client to the listener; it does not
authenticate the listener to the client. A hostile local process that wins the
configured port could receive the credential before public network/fingerprint
checks run. Production deployment must qualify service/port ownership and OS
ACL isolation, or use a pinned mutually authenticated local proxy.

The current result-version split is intentional:

- chain and deposit objects report `chain-preview-v0.4`;
- v3 custody objects report `chain-preview-v0.5`.

Pin the exact API version, `network_id`, and `consensus_fingerprint`. Do not
credit deposits or enable withdrawals merely because the listener responds.

RCNet-1's version-2 network identity is pinned, but the `production-rc` build
remains fail-closed while canonical ProductionV4 activation evidence is absent.
The operational seed at `173.249.35.251:19444` is staged, not live: its service
must remain disabled until the qualified binary and authenticated artifacts are
installed and externally tested. See the
[RCNet connectivity status](../docs/exchange-integration.md#rcnet-connectivity-status)
before planning a live exchange node.

## Kit contents

| Artifact | Purpose |
|---|---|
| [`openrpc.json`](openrpc.json) | Machine-readable method and positional-parameter contract |
| [`schemas/exchange-rpc.schema.json`](schemas/exchange-rpc.schema.json) | Draft 2020-12 request, response, and domain-object schemas |
| [`schemas/example-transcript.schema.json`](schemas/example-transcript.schema.json) | Validator for the checked-in illustrative transcripts |
| [`schemas/error-catalog.schema.json`](schemas/error-catalog.schema.json) | Validator for the machine-readable error catalog |
| [`errors.json`](errors.json) | Stable (`error.code`, `error.data.code`) routing catalog and handling class |
| [`ERROR-CATALOG.md`](ERROR-CATALOG.md) | Short operator interpretation of error families |
| [`COMPATIBILITY.md`](COMPATIBILITY.md) | Preview version pinning and change policy |
| [`examples/chain-and-deposits.json`](examples/chain-and-deposits.json) | Illustrative chain and deposit transcript |
| [`examples/custody-v0.5.json`](examples/custody-v0.5.json) | Illustrative v3 custody transcript |

The distributable bundle also places two operator aids under `tools/`:

- `exchange_conformance.py` performs read-only live contract checks by default
  and emits digest-bound create-new evidence. Watch registration additionally
  requires both an explicit registration file and `--allow-registration`.
- `exchange_coordinator.py` demonstrates a single-writer,
  process-restart-safe poll/ack outbox for the deposit cursor. It intentionally
  makes no physical power-loss, confirmation, or customer-crediting claim.

The conformance report's SHA-256 binds the report bytes for integrity and
comparison only. It is not a signature, server-identity proof, external audit,
or production-readiness attestation; required recovery scenarios remain
explicitly `not_run` until executed on representative infrastructure.

An optional `cmfd-exchange-signer-reference` binary verifies and signs the
provider-neutral v0.5 package for integration testing. It reads a raw software
key and is explicitly not an HSM, remote-signing service, threshold-key
implementation, or production custody approval.

### Reference signer trust boundary

The signer does not trust the node's package document by itself. It also
requires an independently produced envelope:

```json
{
  "schema": "CMFD_EXCHANGE_SIGNER_TRUSTED_CONTEXT_ENVELOPE_V1",
  "context_base64": "<standard base64 of the exact JSON context bytes>",
  "context_digest": "<64 lowercase hex characters>",
  "signature": "<128 lowercase hex characters>"
}
```

Compute `context_digest` with BLAKE3 derive-key context
`CMFD/REFERENCE-SIGNER/TRUSTED-CONTEXT/V1` over the context byte length as a
little-endian `u64`, followed by those exact decoded bytes. Sign the raw
32-byte digest with BIP340. Pass the corresponding x-only public key through
`--context-authority-public-key`; it must be pinned through protected,
out-of-band configuration rather than learned from the node or request.

The strict decoded context binds network, consensus fingerprint, genesis,
request and policy IDs, Prepared/keyring/approval-action/ReleaseAuthorized
anchors, both package digests, transaction signing digest, signer ID,
capabilities, complete key set, assigned inputs, recipient/amount/fee/change,
and the approval threshold/roster. `approval_action_anchor` is the exact anchor
signed by approvers: it may be more than one generation after the request's
Prepared anchor because the journal is global. The ReleaseAuthorized anchor
must be its exact next generation. Once that decision is durably persisted and
independently pinned, recovery verifies the original approval interval and
signatures but does not incorrectly expire the decision a second time.

```text
cmfd-exchange-signer-reference \
  --package-document <absolute signing-package-result.json> \
  --trusted-context-document <absolute trusted-context-envelope.json> \
  --context-authority-public-key <64-lowercase-hex> \
  --secret-key-file <absolute 32-byte test-key file> \
  --output <absolute create-new signer-response.bin>
```

This executable is deliberately stateless. Its package input values are not
independent chain proofs, it has no durable anti-replay ledger, and its raw-key
file path is not a vendor HSM boundary. A production adapter must independently
authenticate input ownership/value, protect and pin the context authority plus
policy/roster, persist idempotent request-to-response state, enforce host ACLs,
and qualify its HSM/remote/threshold implementation and power-loss behavior.

All hashes, destinations, transaction bytes, credentials, timestamps, and
anchors in `examples/` are illustrative. They are structurally realistic but
are not deployment pins or reusable authorizations. Example destinations use
known compromised test keys; never send value to them.

## Minimum integration sequence

### 1. Qualify the host and start the listener

Follow the private-file, ACL, loopback-bind, and startup procedure in the
[full integration guide](../docs/exchange-integration.md#starting-the-endpoint).
Use different Basic credentials for integration and withdrawal scope. The node
rejects identical credentials and cross-scope calls.

Before continuing, independently verify the expected network and consensus
pins. Call `getexchangeinfo []` first to discover the exact enabled method
surface, custody mode, encodings, deposit-index health, and remaining capacity.
Its `production_ready` field is deliberately `false`. Then inspect
`getblockchaininfo`; `initialblockdownload` intentionally remains `true` in this
preview. Peer observations are advisory, so define an external checkpoint or
trusted multi-node readiness rule.

### 2. Integrate deposits

1. Supply unique exchange labels and valid raw 32-byte x-only Schnorr public
   keys to `registerwatchdestinations`. Each atomic batch contains 1-1,000
   exact `{label,destination_hex}` objects. Use `registerwatchdestination` for
   one-at-a-time compatibility.
2. Persist the returned immutable label/destination mapping.
3. Poll `getdepositevents` from cursor `"0"`. Commit the returned events and
   `next_cursor` in one database transaction.
4. Process `deposit_added` and `deposit_removed` as an event stream. A removed
   event refers to its original addition through `added_cursor`.
5. Apply the exchange's independent confirmation and spendability policy.

Registration completes only after the active-chain history has been scanned.
The batch is ordered, atomic, and exact-retry idempotent; duplicate labels or
destinations inside one batch are rejected. Labels are visible ASCII
identifiers, not secrets. `destination_hex` is a raw key, not a checksummed
user-facing address. Watch registrations are immutable.

### 3. Integrate withdrawals with custody v0.5

The safe release path is a two-mutation state machine:

1. `preparewithdrawal` durably records the fixed unsigned plan and reservations.
2. Persist and verify the complete response, then atomically pin its exact
   returned `anchor` outside the node's rollback authority.
3. Request `getwithdrawalapprovalpayload` with a fresh, globally unique,
   nonzero 32-byte `decision_id` and a validity window no longer than 900
   seconds.
4. Copy only `result.approval_document`, add action-authorized BIP340 signatures
   in strictly increasing public-key order, and submit that nested object to
   `releasewithdrawal` or `cancelwithdrawal`.
5. The first release call durably enters `release_authorized`. Persist, verify,
   and pin the new anchor.
6. For external keys, obtain `getwithdrawalsigningpackage`, compare its
   authorization envelope with the independently replicated pin, and collect
   canonical signer responses.
7. Retry the identical release action with the same approval and any ordered
   external signer responses. Persist the exact Released transaction and pin
   the returned anchor.
8. Poll `getwithdrawal`. If an already Released transaction becomes
   `broadcast_pending`, retry only the identical release; never prepare a
   replacement under a new request ID.

Every successful state-changing call must be durably committed by the exchange
before advancing the external anchor. A lost response is recovered by observing
the same request and retrying the same idempotent action, not by inventing a new
withdrawal.

The exact binary signer package, approval digest, migration, anchor, and
recovery contracts remain normative in
[Exchange custody v0.5](../docs/exchange-custody-v0.5.md).

## Deliberately unsupported

- Bitcoin Core RPC compatibility, JSON-RPC batches, notifications, or named parameters
- public/non-loopback exposure or built-in TLS
- checksummed display addresses or node-generated customer deposit addresses
- watch deletion or reassignment
- general transaction lookup, UTXO listing, or wallet balance RPC
- `sendtoaddress`, `sendmany`, fee estimation, or an exchange payout scheduler
- online policy, keyring, journal-key, migration, archive, or compaction RPC
- a certified vendor HSM driver, remote-signing transport, or threshold-key implementation
- released-record archive and journal epoch rollover

These boundaries should remain explicit in exchange diligence. Build workflow
around the implemented contract; do not emulate missing Bitcoin RPC methods by
guessing their semantics.

## Production gates still outside this kit

The interface and local evidence do not complete production qualification.
Deployment still requires the selected vendor HSM or threshold provider,
installed-host ACL evidence, representative live migration, physical power-loss
recovery, backup restoration, released-record rollover, and independent
external review. See the
[audit candidate](../docs/exchange-custody-audit-candidate.md) for the exact
boundary.

## What to send with an integration question

Provide the node build identifier, operating system, exact observed
`api_version`, network and consensus pins, method name, request ID, HTTP status,
complete redacted JSON-RPC error, and whether the failure persists after an
unchanged retry. Never send Basic credentials, private keys, journal keys,
keyring passphrases, or unredacted signer material.
