# Error handling

Authenticated JSON-RPC failures return HTTP 200 with `error.code`, diagnostic
`error.message`, and stable `error.data.code` plus `retryable`. Authentication
failures return HTTP 401 and may not contain a JSON-RPC body.

The machine-readable routing catalog for documented exchange workflows is
[`errors.json`](errors.json). Route on the ordered pair (`error.code`,
`error.data.code`), not message text. A data code can occur in more than one
numeric class when the calling surface gives it a different operational
meaning; the composite pair always maps to one handling rule.

| JSON-RPC code | Class | Default response |
|---:|---|---|
| `-32700` | Invalid JSON | Correct the serializer; do not retry unchanged |
| `-32600` | Unsupported request envelope | Correct version, ID, batch, or notification use |
| `-32601` | Unknown method | Stop; verify the exact pinned API/build |
| `-32602` | Invalid parameters or approval document | Correct the request; do not retry unchanged |
| `-32001` | Not found | Reconcile the requested block, watch, or withdrawal identity |
| `-32005` | Transaction admission failure | Follow `retryable`; never mutate signed transaction bytes |
| `-32006` | Funding, maturity, fee, input, or configured policy limit | Stop automated release and reconcile funds/policy |
| `-32007` | Authenticated storage, binding, signer, keyring, or custody fault | Hard custody stop; preserve evidence and inspect logs |
| `-32008` | Chain changed during index scan | Retry the identical read from the committed cursor |
| `-32009` | Idempotency, state, anchor, approval, or signer conflict | Stop and reconcile durable state; do not create a replacement |
| `-32010` | Credential scope or withdrawal availability failure | Correct routing/configuration; never share credentials |
| `-32011` | Method requires custody v3 | Stop and qualify the explicit v3 deployment |
| `-32030` | Block admission halted or work engine failed (`work_rule_halted`, `work_engine_failed`); or, for chain-state reads and `preparewithdrawal`, stored blocks above the validated height are not yet checked (`work_check_pending`) | Halted or failed: pause crediting and withdrawals and retry later, the node operator must act. Pending check: keep retrying; on the first start after an upgrade it lasts until the node has checked every block it stored since the release checkpoint, about (those blocks) ÷ (blocks it checks per hour − 62) hours, often many hours (see the [integration guide](../docs/exchange-integration.md#the-served-chain-and-the-validated-height)) |
| `-32603` | Internal invariant failure | Stop the affected workflow and preserve node logs |

`retryable: true` permits an unchanged retry after the indicated transient
condition clears. It never permits changing an anchor, request fields,
transaction bytes, approval, signer response, or cursor already committed by
the exchange.

`mempool_close_limit` (`-32005`, retryable) refuses a payment-channel close (a
settlement or a refund) because the node's mempool already holds its budget of
closes: 128 closes or 96 KiB of them, inside the general mempool limits.
Transfers, sweeps and withdrawals are never refused for it. The sender resends
the identical close later, once blocks have taken some of the waiting closes
out of the mempool.
