# Inference payment channels

Status: signed off-chain state machine and consensus channel spends implemented
in the research chain.

Inference income is separate from proof-of-work rewards. The customer pays the
GPU operator that accepted the job; neither miners, stewards, nor the community fund receive
that payment.

## Flow

1. The provider signs a quote identifying the model, runtime, input, prices,
   token limits, provider key, and refund height.
2. The customer locks the quote's maximum `deposit` in a channel output.
3. The customer signs a cumulative payment state authorizing at most one
   32-output-token chunk ahead of the provider's latest signed receipt.
4. The provider streams that chunk and signs a receipt containing the delivered
   token count and rolling output digest.
5. The customer verifies the output and receipt, then authorizes the next chunk.
6. The provider closes with the newest customer-signed state. Consensus pays
   `provider_payment` directly to the provider key, returns `customer_refund` to
   the customer, and destroys `close_fee_burn`.
7. If the provider disappears, the customer can reclaim the unused deposit
   after `refund_height`; the close fee is still burned.

A node's mempool holds at most 128 channel closes (settlements and refunds),
96 KiB of them in all, inside its general limits. A close past that budget is
refused with the retryable `mempool_close_limit` (HTTP 422, JSON-RPC -32005).
Send the identical close again later, once blocks have taken some of the
waiting closes out of the mempool; nothing about the close has to change.

The signed state is cumulative, so an old state can only pay the provider less.
The provider has the newest state and therefore has the incentive and ability
to submit it. A customer's maximum exposure to nondelivery is one configured
chunk plus the close fee.

## Price calculation

All amounts use atomic CMFD units:

```text
provider_payment = base_price
                 + ceil(input_tokens  * input_price_per_1000  / 1000)
                 + ceil(output_tokens * output_price_per_1000 / 1000)

deposit = provider_payment + customer_refund + close_fee_burn
```

The `model_digest`, `runtime_digest`, and `input_digest` prevent substituting a
different quoted job. Schnorr signatures bind customer payment states and
provider delivery receipts.

## Trust boundary

The implemented receipt proves what the provider signed; it does not by itself
cryptographically prove that an arbitrary neural-network result is correct.
Customers should use deterministic runtimes, redundant providers, spot checks,
or a later verifiable-inference proof depending on job value.

`cmfd-marketplace` implements the signatures, accounting, chunk limits,
settlement, and timeout refund. `cmfd-consensus` implements the corresponding
channel UTXO and restricts it to either:

- a dual-signed settlement with exact provider and customer outputs; or
- a customer refund with the exact timeout and amount.

The channel identifier is retired after either spend, preventing a later output
from replaying an old signed state. The close fee is the exact difference
between the channel input and outputs, so the general fee-burn rule destroys it.

This remains research code, not a production payment network. Peer-to-peer job
discovery, quote transport, wallet UI, persistent chain storage, and adversarial
audit are not implemented.
