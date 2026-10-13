# Rich list job

`cmfd-richlist.py` builds the explorer's rich list (`/richlist`, `/api/richlist`).

- It reads every block (`getblock` verbosity 2) from the hosted exchange RPC and keeps all unspent outputs in SQLite.
- It follows reorganizations with per-block undo records covering the last 1,000 blocks.
- Every 30 seconds it writes `richlist.json`: the 250 largest balances by address.
- It writes a list only when its outputs match the node's own `gettxoutsetinfo` (count and total) at the same block. The Worker serves only lists marked `verified_against_node`.

Balances are the value of each address's unspent outputs, including coinbase rewards that are not spendable yet. Outputs locked to inference channels have no address; they count toward the total but are not listed.

## Deployment (Singapore, beside the gateway)

- `useradd --system --no-create-home --shell /usr/sbin/nologin cmfd-richlist`
- Script: `/opt/cmfd-richlist/cmfd-richlist.py`
- State: `/var/lib/cmfd-richlist/state` (0700) and `/var/lib/cmfd-richlist/public` (0755). Both are owned by the service user.
- Gateway login: `/etc/cmfd-richlist/gateway.conf` (0400, service user). It holds `username=` and `password=` lines.
- Service: `cmfd-richlist.service`. It reads the gateway on `127.0.0.1:39102`, with two fetch threads during the first backfill.
- nginx: add `nginx-location.conf` to the TLS site, then run `nginx -t && systemctl reload nginx`.

The first run reads the whole chain (about 15,000 blocks in October 2026) and then keeps up block by block. To rebuild from scratch, stop the service, delete `/var/lib/cmfd-richlist/state` and start the service again. Until the rebuild finishes, the last published list stays in place.

Tests: `python -m unittest test_cmfd_richlist` (stdlib only, fake RPC).
