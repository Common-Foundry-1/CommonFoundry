# Android wallet: independent UTXO corroboration

The Android wallet must not sign a mainnet transaction using input values supplied only by `wallet.commonfoundry.ai`. A false value for a real outpoint can make the network burn more CMFD than the displayed fee.

## Required boundary

- The wallet gateway proposes spendable UTXOs and still checks each selected input against its confirmed transaction output.
- The explorer Worker forwards `GET /v1/explorer/utxo/{txid}/{vout}` to a **Falkenstein-only** mainnet node route. It must never use the normal explorer failover router for this path: that router can select Singapore, which hosts the wallet RPC gateway.
- The Android client requires both services to agree on the selected outpoint, value, owner, and maturity. The independent node must find it confirmed, mature, and not durably reserved, and be no more than six blocks behind the wallet snapshot. Its public lookup intentionally does not scan the mempool; a conflicting pending spend can still make the broadcast fail. The check runs at payment preparation and again immediately before signing. Any outage, malformed response, wrong network identity, or mismatch blocks sending.
- The Send screen probes the dedicated route with a nonexistent outpoint. Until it returns a network-identified 404, sending stays disabled.

This is independent **node corroboration**, not full on-device chain validation or a cryptographic UTXO proof. Compromise of both services, their shared control plane, or the Falkenstein node remains a trust risk. The app must describe that limit accurately.

## Deployment order (not yet authorized or performed)

1. Qualify and deploy a node build containing the read-only outpoint route on the Falkenstein mainnet node. Check sync, network ID, and missing/spent/immature responses locally. Preserve the existing node release and rollback procedure.
2. Add only the dedicated proof hostname/path tunnel rule shown in `apps/explorer/origin-ingress.example.yml`, pointing to the restricted Falkenstein transport. Keep the existing explorer/router, pool, and catch-all rules in place. Verify that the proof origin cannot serve node RPC or general explorer paths. Apply origin-side request limits as well, since clients could address the tunnel hostname directly and bypass the explorer Worker's per-IP limit. During a controlled canary, make only the Falkenstein proof transport unavailable and confirm that proof reads fail closed while ordinary explorer reads continue; a successful fallback to Singapore would violate this boundary.
3. Deploy the updated explorer Worker with `EXPLORER_PROOF_ORIGIN` pinned to that proof hostname. Verify wrong-network, redirect, malformed-path, unavailable-node, and source-routing behavior. Confirm ordinary explorer traffic still uses its existing origin.
4. Rebuild the Android APK from the reviewed integration commit. On an ARM64 evaluation device, test matching and deliberately mismatched inputs, both ordinary and mining-reward outputs, stale heights, unavailable proof origin, and confirmation/broadcast recovery using synthetic wallets first.
5. Complete independent security review, official release signing, APK/source verification, and authenticated checksum publication. No real CMFD transfer or production service change is implied by this document.
