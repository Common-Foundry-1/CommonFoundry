# Common Foundry Explorer

Read-only ProductionV4 chain explorer with a live forge visualization, canonical block history,
transaction activity, and block/transaction/address search.

## Development

Start a ProductionV4 node on its default RPC address, then run:

```powershell
npm install
npm run dev
```

Open `http://127.0.0.1:5175/`. The Vite server proxies `/v1` to
`http://127.0.0.1:22443`. Development mode displays clearly labelled preview data when that node
is unavailable; production builds fail closed instead.

## Page links

Every page has a shareable URL that opens it directly, including when pasted into a new tab:

- `/` — overview
- `/block/{height-or-id}` — block detail
- `/tx/{txid}` (also `/transaction/{txid}`) — transaction detail
- `/address/{address}` — wallet balance and activity

Search and the back/forward buttons keep the address bar in step with the open page. The Worker's
single-page-application fallback serves the app for these paths; the page itself reads the path once the
live snapshot has loaded, so a link still opens after a transient node outage and a retry. Hashes and
addresses are case-insensitive; an unknown path falls back to the overview.

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

Overview polling keeps a bounded, process-local cache of at most12 checked block summaries and
24 confirmed transaction summaries, not block/proof bodies. A tip change or30-second expiry
reauthenticates the retained blocks before replacing that cache. Mempool, peer and status fields
are always read live. Every poll still checks retained-file identity and log length; known storage
faults refuse the response. The cache is discarded on restart and never participates in block
admission, proof verification or fork choice. Individual block/transaction/address detail reads
continue to authenticate their stored bodies.

Each authenticated read also returns immutable query-local identity and wire-size
metadata. Explorer rows reuse those checked scalars rather than hashing the full
V4 proof or serializing the block again merely to rediscover its ID/length. The
stored record still passes the same bounds, digest, version, canonical reencoding
and block-identity checks. The consensus block-ID algorithm is unchanged; mutable
public `Block` values do not acquire an unchecked ID cache.

An optional CPU-only resource test, `preserved_full_v4_explorer_read_cost`, accepts
an operator-selected preserved proof, strict statement, original candidate,
release-pinned model bank and fixed record. It is ignored by ordinary test runs.
Set `CMFD_EXPLORER_FULL_PROOF`, `CMFD_EXPLORER_FULL_PROOF_SHA256`,
`CMFD_EXPLORER_STATEMENT`, `CMFD_EXPLORER_CANDIDATE`, `CMFD_EXPLORER_BANK` and
`CMFD_EXPLORER_FIXED_RECORD` to explicit inputs. With the mainnet feature build
gate's `CMFD_BUILD_SOURCE_COMMIT` set to the checked-out commit, run:

```text
cargo test --locked -p cmfd-node --lib --features production-mainnet preserved_full_v4_explorer_read_cost -- --ignored --nocapture --test-threads=1
```

The test deliberately opens an isolated RCNet data directory, authenticates the
pinned inputs, submits the preserved block through normal CPU consensus, measures
read methods and removes its temporary chain. It starts no network service, uses
no GPU, generates no new proof and does not activate mainnet. Results are scoped
to that preserved block/build/host, not general HTTP throughput or release approval.

The `overview_cache` native tests include a bounded repeated-poll probe, print fixture/profile
labels and retained metadata payload bytes, and check expiry, reorgs, live mempool/peer changes
and storage faults. Those small-profile method-call measurements are not HTTP throughput,
whole-index memory, full-proof decode latency or production startup qualification.

Queries check current active-chain membership, so side branches do not appear as confirmations
and reorganizations do not require rewriting the location index. A confirmed result reauthenticates
its full stored block and exact transaction position/ID. A missing or orphan-only transaction reads
no block bodies; a confirmed lookup reads only the matching block. Mempool lookup remains separate.
The index itself is in memory and grows with retained transaction occurrences across forks. This
does not provide a disk-backed index for larger deployments. Memory/startup-cost qualification
and public cutover of the address API below remain preparation work.

### Address lookup (prepared; public cutover pending)

Choose **Address** in the search-type selector and enter a wallet's hexadecimal
key destination. Block/transaction search remains a separate mode because all
three identifiers can have the same64-character shape. Address lookup never uses
preview balances, including in ordinary development mode.

The prepared frontend displays confirmed/spendable/immature balances and
newer/older activity pages. It validates exact decimal totals, page bounds,
address/chain bindings and network identity before rendering. A stale cursor
automatically reloads page1; a newly observed tip refreshes the view. Connection
errors remove old balances until Retry succeeds. Versioned requests prevent an
older response from overwriting newer navigation or chain state. Reward rows link
to their block instead of the ordinary transaction endpoint.

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
at most20 block bodies. Empty histories read none. The prepared Worker includes
only these address path shapes and checks numeric cursor bounds; it still rejects
query strings, writes and general RPC. Local Workers-runtime and desktop/mobile
browser checks use labelled fixtures, not live mainnet data. The live Worker and
tunnel have NOT been switched to this version.

## Mainnet preparation

`npm run build:mainnet` builds a separate `dist-mainnet` asset tree. The mainnet
client requires the approved network ID in both the response header and snapshot
body. It never substitutes development preview data, including when run in a
development server. A failed refresh clears stale views; automatic polling does
not overlap a slow request, and manual Retry can supersede a pending request.
The network label remains visible on mobile.

The `mainnet` Wrangler environment is a distinct Worker named
`commonfoundry-mainnet-explorer`. It owns the public custom domain
`explorer.commonfoundry.ai` and has no workers.dev access or preview URLs. Merges to `main`
that touch `apps/explorer/` publish it through `.github/workflows/deploy-explorer.yml`: the job
runs the type check and tests, builds `dist-mainnet`, deploys with
`npx wrangler deploy --env mainnet`, then checks that the live site serves mainnet data (network
header, snapshot, supply and an address deep link) and rolls back to the previously live version
if it does not. It needs the repository secrets `CLOUDFLARE_API_TOKEN` (an "Edit Cloudflare
Workers" token) and `CLOUDFLARE_ACCOUNT_ID`. Validate it locally with:

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

Before public cutover, complete index resource qualification, merge the separate
mainnet origin rule in [origin-ingress.example.yml](./origin-ingress.example.yml), and qualify the actual native origin
when its launch gate permits startup. Preserve the existing RC origin and pool
rules. The new origin must expose only these anchored read-only route paths to
`http://127.0.0.1:29443`; never expose the general RPC service:

The example allows snapshot, block, transaction and address/cursor paths only.
It is an ingress-only validation fixture, not a replacement for the deployed
configuration. The Worker and node additionally enforce numeric cursor limits.

Validate the complete proposed tunnel configuration with the installed
`cloudflared tunnel ingress validate` and test both allowed and denied URLs with
`cloudflared tunnel ingress rule`. Keep the catch-all 404 last. Merging to `main` is the
publication decision; the CI dry-run job itself deploys nothing.

## Devnet deployment

The Devnet explorer is a Cloudflare Worker with static assets served only at its workers.dev
address (https://commonfoundry-devnet-explorer.benefit14snake.workers.dev). It has no custom domain, so a plain
`npm run deploy` can never move `explorer.commonfoundry.ai` off the mainnet Worker. (Run
without a terminal, Wrangler silently re-points any custom domain listed in the deployed
configuration.)
This prepared source expands its read-only allowlist to the address routes as well;
deploy only alongside the corresponding native origin and matching tunnel rule.
The RC environment points to
`https://devnet-explorer-origin.commonfoundry.ai`; every other `/v1` route is rejected. The origin
hostname must be a Cloudflare Tunnel route whose only service is the node's loopback RPC endpoint.

```powershell
npm ci
npm run check
npm test -- --run
npm run deploy
```

Nothing deploys the Devnet Worker automatically; run the sequence above by hand when needed.

Keep the node RPC bound to `127.0.0.1:22443`. Do not open that port on the router or expose the
unrestricted RPC service directly. The tunnel connector and node must run on the same trusted host.
