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
| `-32603` | Internal invariant failure | Stop the affected workflow and preserve node logs |

`retryable: true` permits an unchanged retry after the indicated transient
condition clears. It never permits changing an anchor, request fields,
transaction bytes, approval, signer response, or cursor already committed by
the exchange.
