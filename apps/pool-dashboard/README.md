# Common Foundry pool dashboard

This Vite application is served by `cmfd-node pool-serve`. It is read-only: the
browser receives current and average miner-reported work rate, accepted,
rejected, and stale shares, per-worker activity, rolling 24-hour PPLNS credits,
estimated 24-hour earning pace, block accounting, operator-fee, and payout
summaries from `/api/v1/pool`. All share verification and settlement remain
inside the pool node. Work-rate telemetry and earning estimates are display
data only and never affect PPLNS weights, credit, or payouts.

Payout protection is reported by the node's optional `ledger.payout_protection`
field (older servers remain display-compatible). Active holds override the
automatic-settlement label and show the affected accounts' held unreserved
credit and pending reserved payments. Chain transaction status is not rewritten:
already-broadcast payments may still confirm. The page has no reconciliation or
resume action; those are offline node/operator commands documented in
`docs/pool-deep-reorg-policy.md`.

Build the static dashboard:

```text
npm ci
npm run check
```

The production files are written to `dist/`. Supply that directory together
with the exact TLS-pinned public pool URL:

```text
--pool-dashboard-assets /srv/cmfd/dashboard
--pool-public-url cmfd+tls://203.0.113.20:19445?pin=<certificate-sha256>
--pool-dashboard-bind 127.0.0.1:19446
```

The dashboard listener deliberately accepts only loopback addresses. Publish
it through an authenticated reverse proxy or tunnel if a public web dashboard
is wanted; expose TCP port 19445 separately for miner connections.

## Operator packages

The binary-only Windows and native Linux packages include this built dashboard,
the node and persistent proof workers, authenticated input bootstraps, and
ready-to-run launchers. See
[`docs/production-v4-pool.md`](../../docs/production-v4-pool.md) for the full
operator guide.

On native Linux, run:

```bash
chmod +x START-POOL.sh PREPARE-V4-INPUTS.sh cmfd-node cmfd-v4-replay real_bank0_relations
./START-POOL.sh 203.0.113.20 192.168.50.20
```

The first address is the public numeric address miners use. The second is the
Linux host's private LAN address; forward public TCP 19445 to it. The launcher
downloads and authenticates the ProductionV4 inputs, generates the TLS
certificate on first run, prints the pinned miner URL, starts the native
persistent CUDA replay/proof workers, enables Devnet payouts, and serves the
dashboard on `127.0.0.1:19446`. It also enables authenticated public pool
clients; the node still requires the exact certificate pin and signed
payout-key challenge from every worker.

Set `CMFD_POOL_PEER` to a static peer and
`CMFD_POOL_ALLOW_PUBLIC_PEERS=1` when the pool node should use a public peer.
`CMFD_POOL_OPERATOR_FEE_BPS` changes the default 300-basis-point operator fee,
and `CMFD_POOL_PPLNS_WINDOW_SHARES` changes the automatic rolling window.
Other supported overrides are documented directly in the launcher variables.

## Windows pool host

Double-click `START-POOL.bat` in the Windows package. Its node runs natively on
Windows and starts the supplied Linux CUDA workers through Ubuntu 22.04 under
WSL2. The node, ledger, dashboard, certificate pin, share checks, and payouts
are identical on both platforms. Both launchers enable public pool clients
because they require an explicit public numeric address when starting.
