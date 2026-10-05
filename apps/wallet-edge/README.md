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
mempool (4xx). Anything ambiguous (5xx) keeps the transaction's inputs reserved.

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
