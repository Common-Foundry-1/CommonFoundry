# Common Foundry technical fact sheet for exchange diligence

Status: integration candidate. Not a production listing, custody, audit, or
mainnet-readiness claim.

## Protocol and monetary facts

- Asset symbol used by the project: CMFD.
- Accounting: 100,000,000 atoms per CMFD.
- Nominal block target: 60 seconds.
- Bootstrap emission: five height-defined years, declining linearly from 500
  CMFD; 70% miner, 25% steward, and 5% community per block.
- Scheduled bootstrap issuance: 657,000,249.98688 CMFD.
- Tail: perpetual 5 CMFD per block, paid only to miners. Total eventual supply
  is therefore unbounded rather than capped.
- Transaction and channel-close fees are burned.
- No up-front premine is encoded; steward/community funding is visible in each
  bootstrap coinbase. “No token sale” is a project distribution statement and
  must be confirmed by the authorized project/legal representative before a
  venue submission.

The canonical source is `docs/consensus/emission.md` and the candidate's
machine-readable `cmfd-node network-info` output.

## Exchange interface

- Client-authenticated JSON-RPC 2.0 over numeric loopback HTTP; loopback does
  not authenticate the server process, and a separately managed mTLS boundary
  is required for remote transport.
- Separate integration and withdrawal Basic-auth credentials.
- Chain reads, raw block/transaction handling, mempool reads, durable
  watch-only deposit registrations, reorg-aware deposit additions/removals,
  and explicit v0.5 custody workflow.
- Amounts that can exceed JavaScript's exact integer range are canonical decimal
  atom strings. Destinations are currently 64 lowercase hexadecimal characters
  encoding 32-byte x-only secp256k1 keys; no checksummed address exists yet.
- Deposit consumption is cursor-based and at-least-once. Exchanges must persist
  and idempotently apply both addition and removal events.
- Withdrawal custody uses durable intent/prepared/release-authorized/released or
  canceled states, action-specific threshold approvals, external anchors, and
  provider-neutral BIP340 signing packages.

## Current evidence and open gates

Implemented repository-local evidence includes extensive Rust tests, a
deterministic software crash matrix, Windows/Linux ACL qualification tooling, a
reference coordinator, a conformance tool, and an audit-candidate bundle.

Open production gates include scalable spending-key enrollment for per-customer
deposit keys, a project-wide checksummed address, released-record rollover,
vendor HSM/threshold-provider qualification, installed-host ACL evidence,
representative live migration and physical power-loss rehearsal, independent
external audit, and venue acceptance.
