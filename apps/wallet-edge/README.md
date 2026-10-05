# Common Foundry web wallet edge

Cloudflare Worker for `wallet.commonfoundry.ai`. It serves the wallet app built in web mode
(`apps/wallet`, `npm run build:web` → `apps/wallet/dist-web`). It also provides a narrow
same-origin API. Keys never reach the Worker: the browser generates the key, encrypts it
(the desktop `.cmfd-backup` format) and signs every transaction itself.

| Route | Backend | Purpose |
| --- | --- | --- |
| `GET /v1/explorer`, `/v1/explorer/address/{hex}`, `/v1/explorer/transaction/{hex}` | explorer origin | network status, balance, history, pending-transaction status |
| `POST /v1/wallet/utxos` | gateway `getaddressutxos` | coin selection |
| `POST /v1/wallet/transaction` | gateway `getrawtransaction` (with block hash) | amounts of sends signed elsewhere |
| `POST /v1/wallet/broadcast` | gateway `sendrawtransaction` | relay a signed mainnet frame |

The `/v1/wallet/*` routes have these protections:
- **Rate limit:** 30 requests per minute per IP.
- **Same origin only:** requests from other origins are refused.
- **Validation:** inputs are checked before anything is forwarded, and broadcast accepts only mainnet transaction frames.

Errors are classified so the browser can tell when a broadcast certainly did not reach a
mempool (4xx). Anything ambiguous (5xx) keeps the transaction's inputs reserved, and the browser
re-sends the same frame on later refreshes (`sendrawtransaction` is idempotent) until the network
acknowledges it. Gateway responses are schema-checked at the edge, and the browser caps new
outputs' lock height at the lower of the gateway's and the explorer's chain height.

## Trust model

Non-custodial: keys never leave the browser, so nobody operating this service can spend funds.
What the service *can* do if compromised: serve altered JavaScript (as with any hosted wallet;
the CSP allows no third-party script, and Worker deploys are limited to the Cloudflare account), or
misreport coin values so a send burns more fee than shown (no profit for the attacker; fees are
burned). Independent per-input value checks need a node endpoint that returns output values via
the explorer origin, planned for a later release.

## Verifying the signing code

`tools/webwallet-vectors` builds against the real consensus and node crates:
`cargo run --release -- vectors` must reproduce `apps/wallet/src/web/fixtures/rust-vectors.json`
(all but the one-off `backup` blob), `verify <frame-hex>` decodes and checks a browser-signed
frame, and `backup-verify` restores a browser-made backup with the node's own code.

## Develop

```bash
npm ci
npm run build:app      # builds ../wallet/dist-web
npm run dev            # http://127.0.0.1:8787
```

`.dev.vars` (gitignored) supplies `GATEWAY_USERNAME` / `GATEWAY_PASSWORD` for local runs. For UI
work with hot reload, run `npm run dev:web` in `apps/wallet`; it proxies `/v1` to this Worker.

## Deploy

1. DNS: `sg-rpc.commonfoundry.ai` A `13.140.66.6`, **DNS only**. Workers cannot fetch IP
   literals (Cloudflare answers 403), so the gateway needs a name.
2. On the Singapore box, expand the certificate to that name, then reload nginx (the default
   server already answers it):
   `certbot certonly --cert-name commonfoundry-singapore --expand --webroot -w /var/www/commonfoundry-acme --preferred-profile shortlived --key-type ecdsa --ip-address 13.140.66.6 -d sg-rpc.commonfoundry.ai`
3. Add a `webwallet` gateway client: put its SHA-256 password digest in `clients.json`, then restart
   `commonfoundry-mainnet-gateway`.
4. `npx wrangler secret put GATEWAY_PASSWORD` (the `webwallet` password).
5. `npm run deploy`. This builds the app, deploys the Worker and attaches the
   `wallet.commonfoundry.ai` custom domain.
6. Keep Cloudflare Web Analytics and bot-detection script injection off for this hostname.
   The CSP blocks every off-origin script, so injected scripts would only produce console errors.
