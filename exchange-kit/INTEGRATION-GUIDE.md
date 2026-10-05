# Common Foundry exchange integration guide

This guide covers the complete exchange flow: deposit addresses, deposit
detection, sweeping, withdrawals, fees and error handling. It applies to both
ways of connecting:

- **Hosted endpoint:** a private HTTPS JSON-RPC endpoint run by Common Foundry,
  with credentials issued per exchange. No node to operate.
- **Own node:** `cmfd-node run --exchange-rpc-bind 127.0.0.1:<port>
  --exchange-rpc-auth-file <file>`, reachable on loopback only. See
  [START-HERE](START-HERE.md) and the [full integration guide](../docs/exchange-integration.md).

The JSON-RPC methods and result shapes are the same on both. Keys never leave
your systems in either setup: the endpoint and the node only see public keys and
signed transactions.

## Chain facts

| Item | Value |
|---|---|
| Unit | 1 CMFD = 100,000,000 atoms; all amounts are decimal atom strings |
| Address | 64 lowercase hex characters: a BIP340 x-only public key (`destination_hex`); no checksum |
| Block target | 60 seconds |
| Coinbase maturity | 100 blocks (`spendable_height` = block height + 100) |
| Minimum fee | 0.1 CMFD (10,000,000 atoms) per transaction; the fee is burned |
| Transaction limits | 128 inputs, 128 outputs, 64 KiB encoded |

Because addresses carry no checksum, validate every customer withdrawal address
before accepting it: it must be 64 lowercase hex characters, and
`exchange-tx-sign` rejects anything that is not a valid public key.

## 1. Keys and deposit addresses

Generate one key per customer deposit address, plus one or more hot-wallet keys,
with the node binary from the signed release. This runs offline:

```sh
cmfd-node exchange-key-new --output /secure/keys/customer-000123.key
# {"status":"created","key_file":"...","destination_hex":"9f0c…","warning":"…"}
cmfd-node exchange-key-show --key /secure/keys/customer-000123.key
```

The key file holds the 32-byte secret as 64 hex characters. It is created new
(never overwritten) and owner-only on Unix. It is the only copy of the secret:
back it up under your own key-management policy. Show customers the
`destination_hex`.

Keys can also be produced by any BIP340 implementation. The node accepts any
valid x-only public key as a destination.

## 2. Detecting deposits

Register each deposit address once, then follow one event stream:

```json
{"jsonrpc":"2.0","id":1,"method":"registerwatchdestinations","params":[[
  {"label":"customer-000123","destination_hex":"9f0c…"},
  {"label":"customer-000124","destination_hex":"41aa…"}]]}
{"jsonrpc":"2.0","id":2,"method":"getdepositevents","params":["0",1000]}
```

- Batches hold 1–1,000 registrations and are atomic. Registrations are permanent
  and an exact retry is idempotent. Registering a fresh key is immediate; an
  address with history returns its past deposits as events.
- Labels are your identifiers, 1–128 visible ASCII bytes. On the hosted endpoint
  your labels are private to your credential (the limit is slightly lower; see
  `getexchangeinfo` → `hosted_endpoint.max_label_bytes`).
- Poll `getdepositevents` with the last `next_cursor` you stored, starting from
  `"0"`. Store the events and the new cursor in one database transaction. Pass
  `next_cursor` back unchanged; on the hosted endpoint cursors are endpoint-wide
  sequence numbers, so they increase but skip numbers that belong to other
  exchanges.
- `kind` is `deposit_added` or `deposit_removed`. A removal means a chain
  reorganization dropped the deposit; it names the original event in
  `added_cursor`. Reverse any credit you gave for it.

**When to credit.** An event carries `blockheight`. Compute confirmations as
`getblockcount − blockheight + 1` and credit only after your own threshold; we
suggest at least 20 confirmations (about 20 minutes). Coinbase deposits
(`"coinbase": true`) can only be spent once `getblockcount + 1 ≥ spendable_height`.

Without watch registration you can instead poll `getaddressbalance` /
`getaddressutxos` per address, but the event stream scales better and reports
reorganizations explicitly.

## 3. Sweeping and withdrawals

Spend with `exchange-tx-sign`, then broadcast the hex it prints.

1. List spendable outputs of the paying keys:
   `{"method":"getaddressutxos","params":["<hot destination_hex>",1000]}`.
   It returns only confirmed, mature outputs that no transaction in the node's
   mempool is already spending.
2. Write a request. Each input names the output, its owner and the key file;
   outputs are the payments; any remainder goes to `change_destination_hex`:

   ```json
   {
     "network_id": "88296bc39c10e8bc1dd4818d4d42412fe5f08210651110377f495da299812f62",
     "inputs": [
       {"txid": "…", "vout": 0, "value_atoms": "250000000000",
        "destination_hex": "<hot destination_hex>", "key_file": "/secure/keys/hot-1.key"}
     ],
     "outputs": [
       {"destination_hex": "<customer withdrawal address>", "value_atoms": "1500000000"}
     ],
     "change_destination_hex": "<hot destination_hex>",
     "fee_atoms": "10000000"
   }
   ```

3. `cmfd-node exchange-tx-sign --request withdrawal-42.json` prints
   `txid`, `transaction_hex`, `input_atoms`, `output_atoms`, `change_atoms` and
   `fee_atoms`. It runs offline and refuses a key that does not own its input, a
   fee below 0.1 CMFD, a request for another network, duplicated inputs, and any
   leftover without a change destination, so a typo cannot silently burn
   funds as fee.
4. Record the `txid` and `transaction_hex` against the withdrawal **before**
   broadcasting, then submit:
   `{"method":"sendrawtransaction","params":["<transaction_hex>"]}`.
5. Track it with `gettransaction [txid]`: `status` moves from `mempool` to
   `confirmed` and `confirmations` counts up.

A sweep is the same request with many deposit-key inputs (up to 128) and one
output to the hot wallet.

**Never sign a second transaction for the same withdrawal** while the first
could still confirm. To retry, resubmit the identical `transaction_hex`. It is
safe to send again:

| Result | Meaning |
|---|---|
| txid returned | accepted (or already in the mempool) |
| `transaction_already_confirmed` | already mined; nothing to do |
| `mempool_unconfirmed_input` | an input is no longer unspent: check `gettransaction`; if the transaction is not found, the input was spent by something else |
| `mempool_input_conflict` | another transaction in the mempool spends the same input |
| `mempool_fee_too_low` | fee below the minimum |

## 4. Reading the chain

`getblockcount`, `getbestblockhash`, `getblockhash [height]`,
`getblock [hash, 1|2]`, `getrawtransaction [txid, verbose]`,
`gettransaction [txid]`, `getaddressbalance [destination_hex]`,
`getaddressutxos [destination_hex, limit, cursor]`, `getrawmempool`. Transaction
lookups do not need a block hash. Parameters are positional; batches and named
parameters are not supported.

## 5. Errors and retries

Every error carries `error.data.code` and `error.data.retryable`. Retry only
when `retryable` is true, and never let a timeout trigger a new withdrawal
transaction: look the txid up first. The machine-readable catalog is
[errors.json](errors.json). On the hosted endpoint, `upstream_busy` (retryable)
means the node was momentarily at capacity.

## 6. Hosted endpoint specifics

| Item | Value |
|---|---|
| Transport | HTTPS, `POST` JSON-RPC 2.0, HTTP Basic credentials issued per exchange |
| Rate limit | 5 requests/second (burst 20) and 8 connections per IP |
| `getblock` | verbosity 1 or 2 only |
| Not available | withdrawal-custody methods (use `exchange-tx-sign` + `sendrawtransaction`) |
| Isolation | watches and deposit events are visible only to your credential |

`getexchangeinfo` reports the methods available to you and a `hosted_endpoint`
object with your client name and label limit.
