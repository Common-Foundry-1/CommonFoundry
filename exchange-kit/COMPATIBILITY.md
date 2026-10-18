# Compatibility and versioning policy

This policy is intentionally conservative while the RPC is labeled preview.

## Three identities must be pinned

An exchange integration is compatible only when all three match its approved
configuration:

1. the exact returned `api_version`;
2. `network_id`;
3. `consensus_fingerprint`.

The current listener has two result families: chain/deposit results use
`chain-preview-v0.4`, while v3 withdrawal results use
`chain-preview-v0.5`. This is not version negotiation and one token must not be
substituted for the other.

## Preview rules

- There is no compatibility promise between different `chain-preview-*`
  tokens. Unknown versions fail closed.
- Requests use positional arrays. Unknown top-level request fields, named
  parameters, notifications, and batches are rejected.
- Clients should send `params: []` explicitly for zero-parameter methods even
  though the current decoder defaults an omitted `params` field to an empty
  array.
- Within a pinned version, consume documented fields and tolerate additional
  response fields, but never tolerate a changed type, meaning, digest domain,
  state transition, or authorization requirement.
- Use the pair (`error.code`, `error.data.code`) for program logic. Treat
  `error.message` as diagnostic
  text, not a stable identifier.
- Never downgrade custody behavior after a v3 data directory has been enrolled.
  A detected v3 marker or slot keeps native wallet mutation locked.
- An identical idempotent request may be retried only with identical semantic
  fields. A new request ID means a new operation.

## Change classification

The following require a new API token and a new exchange qualification run:

- removing or renaming a method or field;
- changing a field's type, units, encoding, nullability, or meaning;
- changing positional parameter order or required count;
- changing cursor, confirmation, reorganization, or idempotency behavior;
- changing approval, signer-package, anchor, or transaction digest bytes;
- weakening authentication, scope separation, persistence, or fail-closed behavior.

Serving the chain only up to the node's validated height (1.0.16) kept
`chain-preview-v0.4`. Chain heights and confirmations are those a lagging node
of an earlier release could report for a shorter chain, and confirmations are
still counted the same way from the reported height. Not every answer has an
earlier equivalent. The exceptions are the retryable `work_check_pending`
(`-32030`); the transaction status `pending_check`, which clients must treat
like an unconfirmed transaction (a client that validates strictly against the
earlier schema rejects it); deposit events held, not removed, while the
validated height is below them; and a withdrawal mined above the validated
height reading `Confirmed` with 0 confirmations. These exceptions do not change
the token either: 1.0.16 keeps `chain-preview-v0.4`, and the exchange
conformance version moves to 1.3.1 instead. A client that validates strictly
against the earlier schema must therefore accept `pending_check` before its
node is upgraded. It still requires a new exchange qualification run.

Adding an optional response field may retain a token, but still requires an
updated kit revision and regression evidence. 1.0.16 adds the optional
`work_rule.bank` to `getblockchaininfo`, and its schema now also declares
`pruned`, `pruneheight` and `prune_keep_blocks`, which nodes have returned
since proof pruning was added. Adding a method does not imply
that an older node supports it; capability discovery must use a documented
method or an out-of-band release manifest, never trial calls with privileged
credentials.

## Kit revisions

`exchange-kit` documents source behavior; it does not independently version the
node protocol. A packaging release should checksum this directory together with
the exact node binary and publish the node build identity. If the kit and binary
disagree, the binary behavior and source tests reveal the implementation, but
the discrepancy is a release blocker rather than permission to improvise.
