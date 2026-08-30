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
```

The node provides bounded read-only endpoints at `/v1/explorer`,
`/v1/explorer/block/{height-or-id}`, and `/v1/explorer/transaction/{txid}`. Transaction lookup is
currently bounded to the newest 4,096 canonical blocks; a persistent address and transaction index
is the next scale-out step before public mainnet deployment.

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
