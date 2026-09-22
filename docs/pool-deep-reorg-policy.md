# Pool deep-reorganization policy

Owner decision, September 22, 2026: **pause affected automatic payouts and
reconcile the shortfall**. Do not silently recover losses from future miners'
earnings.

Implementation status: selected policy, not yet implemented or activated.

Required behavior:

1. Detect when a reward already credited/distributed to PPLNS participants loses
   its canonical, mature backing, including after restart.
2. Persist the incident and identify the affected recipients and accounting.
3. Stop new affected automatic payments and retries without releasing reservations
   in a way that permits duplicate payments. Already-broadcast transactions cannot
   be recalled from other nodes; their actual chain/mempool state must still be
   reconciled and reported accurately.
4. Preserve earned-credit history. Do not automatically debit unrelated miners or
   apply a hidden future-earnings levy.
5. Provide a controlled operator reconciliation path, backed by a fresh chain tip,
   exact ledger state and funding checks. Restart must not clear a hold by itself.
6. Test orphaning after maturity, after credit distribution and after payment,
   chain restoration, duplicate/repeated reorg events, restart persistence and
   races with payment preparation/submission.

This decision does not change the currently running RC pool's fee, ledger or
wallet. It does not approve an actual ledger adjustment or money movement.
