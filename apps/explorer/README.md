# Common Foundry Explorer

Read-only ProductionV4 chain explorer with a live forge visualization, canonical block history,
transaction activity, and block/transaction search.

## Development

Start a ProductionV4 node on its default RPC address, then run:

```powershell
npm install
npm run dev
```

Open `http://127.0.0.1:5175/`. The Vite server proxies `/v1` to
`http://127.0.0.1:22443`. Development mode displays clearly labelled preview data when that node
is unavailable; production builds fail closed instead.

## Verification

```powershell
npm run check
npm test -- --run
npm run build
npm run build:mainnet
npm run types -- --check
```

The node provides bounded read-only endpoints at `/v1/explorer`,
`/v1/explorer/block/{height-or-id}`, and `/v1/explorer/transaction/{txid}`. Transaction lookup covers
the full retained canonical history, not only the latest 4,096 blocks. The native node maintains
compact transaction locations for committed blocks and reconstructs them during the existing
authenticated block-log startup scan, including when a startup snapshot is used. The snapshot and
block-log formats are unchanged. No transaction hint from an independent cache is trusted.

Queries check current active-chain membership, so side branches do not appear as confirmations
and reorganizations do not require rewriting the location index. A confirmed result reauthenticates
its full stored block and exact transaction position/ID. A missing or orphan-only transaction reads
no block bodies; a confirmed lookup reads only the matching block. Mempool lookup remains separate.
The index itself is in memory and grows with retained transaction occurrences across forks. This
does not provide a disk-backed index for larger deployments. Memory/startup-cost qualification
and public integration of the native address API below remain preparation work.

### Native address API (public UI/routing not yet enabled)

The node now also supports read-only `GET /v1/explorer/address/{address}` and
`GET /v1/explorer/address/{address}/{cursor}`. An address is a 64-character hexadecimal key
destination. A valid but unseen address returns zero balances and empty history, not a guessed
wallet or an exchange watch registration. The response carries `X-CMFD-Network-Id` as well.

Balances use the active consensus UTXO set. `confirmed_atoms` includes both `spendable_atoms`
and `immature_atoms`; spendable means eligible at the next block height, without subtracting
mempool reservations. `balance_scope: "key_outputs"` explicitly excludes channel escrow, and
`includes_mempool: false` excludes unconfirmed transactions. Atom amounts are decimal strings.
Neither private wallet state nor the authenticated exchange's watch list is consulted.

History is newest-first, canonical-only and capped at 20 entries per page. Each entry identifies
its block and transaction/coinbase outpoint ID, confirmations, activity kind, received outputs
and spent input count. `received_atoms` counts outputs to the address, including change; it is
not a net transfer amount or a debit amount. `self` requires all inputs and outputs to belong to
the address; an outgoing payment with change is `sent`. Coinbase entries should link to their
block, since the ordinary transaction-detail endpoint does not index coinbase outpoint IDs.

Pass the returned `next_cursor` unchanged. It binds the current tip and last history position;
any tip change (extension or reorganization) returns HTTP 409 with `explorer_cursor_stale`, so
the client must restart pagination. Malformed or unrelated-address cursors return HTTP 400.
Address errors have a string `error` message plus top-level `code` and `retryable` fields;
existing non-address RPC error contracts are unchanged.
Every page reauthenticates its matching stored blocks, reading a shared block only once and
at most 20 block bodies. Empty histories read none. These native routes are not yet allowed
through the deployed Worker/tunnel or available in the frontend; integrate and qualify those
surfaces before describing public address search as available.

## Mainnet preparation

`npm run build:mainnet` builds a separate `dist-mainnet` asset tree. The mainnet
client requires the approved network ID in both the response header and snapshot
body. It never substitutes development preview data, including when run in a
development server. A failed refresh clears stale views; automatic polling does
not overlap a slow request, and manual Retry can supersede a pending request.
The network label remains visible on mobile.

The `mainnet` Wrangler environment is a distinct Worker named
`commonfoundry-mainnet-explorer`. It has no routes, workers.dev access or preview
URLs configured, so preparation does not take over the existing explorer domain.
Validate it locally with:

```powershell
npm run build:mainnet
npx wrangler deploy --env mainnet --dry-run
```

The mainnet edge requires `X-CMFD-Network-Id` from the native node on every
explorer response, including block/transaction details and not-found results.
The header is derived from that node's parameters, not a separate snapshot
request that could race an origin change. Missing, duplicate or wrong identities
are rejected before the body is forwarded. JSON responses remain streamed,
redirects are rejected, and requests have a bounded upstream timeout. These are
trusted-origin routing checks, not browser-side cryptographic proof verification.

Use a freshly qualified native release with the response header; the older
signed a8b23ec runtime does not emit it. The expected ID is pinned to
`packaging/mainnet/MAINNET-PLAN.json` by tests. Generate binding/runtime types
with `npm run types` after configuration changes rather than editing them by hand.

Before public cutover, integrate address search into the Worker/frontend and complete index resource qualification, prepare the
separate mainnet origin tunnel rule below, and qualify the actual native origin
when its launch gate permits startup. Preserve the existing RC origin and pool
rules. The new origin must expose only these anchored read-only route paths to
`http://127.0.0.1:29443`; never expose the general RPC service:

```yaml
- hostname: mainnet-explorer-origin.commonfoundry.ai
  path: ^/v1/explorer(?:$|/block/(?:[0-9]+|[0-9a-fA-F]{64})$|/transaction/[0-9a-fA-F]{64}$)
  service: http://127.0.0.1:29443
```

Validate the complete proposed tunnel configuration with the installed
`cloudflared tunnel ingress validate` and test both allowed and denied URLs with
`cloudflared tunnel ingress rule`. Keep the catch-all 404 last. Do not replace
the live routing or attach `explorer.commonfoundry.ai` to the mainnet Worker merely
because the local dry run succeeds. Mainnet publication/start dates remain
owner-controlled; no deployment command is run by the CI dry-run job.

## Devnet deployment

The public Devnet explorer is deployed as a Cloudflare Worker with static assets. Its edge handler
proxies only the three bounded explorer routes above to
`https://devnet-explorer-origin.commonfoundry.ai`; every other `/v1` route is rejected. The origin
hostname must be a Cloudflare Tunnel route whose only service is the node's loopback RPC endpoint.

```powershell
npm ci
npm run check
npm test -- --run
npm run deploy
```

Keep the node RPC bound to `127.0.0.1:22443`. Do not open that port on the router or expose the
unrestricted RPC service directly. The tunnel connector and node must run on the same trusted host.
