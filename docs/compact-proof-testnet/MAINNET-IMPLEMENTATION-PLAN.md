# One mainnet hard fork: implementation track

The compact-proof testnet exercises the two changes together: a self-contained
version-2 proof with bound evaluation claims, and ordinary nodes that verify
that proof without replaying the 384-layer mining calculation. Mainnet will
activate both changes at height **H = 65,535**, selected by the owner on
2026-11-10. The fork and proof-system fingerprints are pinned in
[`MAINNET-FINGERPRINT-65535.md`](MAINNET-FINGERPRINT-65535.md). Activation still
requires the implementation and qualification below.

## Exact consensus boundary

| Block height | Accepted proof | Node admission |
| --- | --- | --- |
| Below H | Existing mainnet version 1 only | Existing proof checks and required work replay |
| H and above | `CMFDDR02` version 2 only | Complete direct proof, target, transaction and block checks; no required work replay |

The version-2 packet and its complete proof frame retain their separate
6,000,000-byte and 6,100,000-byte caps. The 16 MiB block limit, model bank,
fixed commitments, workload, rewards and transaction rules remain pinned.
Historical version-1 blocks are verified under their original rules when a
node restarts, imports history, or crosses H during a reorganization. An audit
node may replay post-H work independently; its replay result is observational
and cannot make ordinary nodes depend on that work engine.

## Code paths to complete before activation

1. Carry the pinned H, direct proof-system digest and authenticated model identity
   from `compact_mainnet_fork.rs` into the owner-signed mainnet release configuration. A build without all
   three pins must fail closed.
2. Make `PowParameters`, `ConsensusPowVerifier` and the node's block
   preverification select version 1 or 2 from the **block's height**. Apply
   the same selection to local block production and pool jobs. Reject a
   version-2 proof below H and a version-1 proof at or above H before an
   expensive verifier runs.
3. Version the network-parameter fingerprint/handshake deliberately. Today
   the fingerprint includes one proof identity and the proof-size cap, while
   the node retains one verifier. The fork-aware identity must commit to H and
   both proof rules and permit stored pre-H history to open under the upgraded
   binary. Old peers must not silently report compatibility after H.
4. Keep the pre-H 13 MiB frame allowance while decoding historical blocks;
   enforce the 6,100,000-byte frame and 6,000,000-byte direct-packet limits
   at or above H. The current wire cap is selected by network ID alone, so
   simply lowering it for mainnet would break historical catch-up.
5. Make the work gate height-aware. Preserve its current pre-H checkpoints
   and historical validation; stop requiring a replay checkpoint for post-H
   block admission, sync, pruning, wallet catch-up and exchange RPC. Keep
   the separate audit profile available for operators.
6. Ship the same activation rule in Linux and Windows node/wallet packages,
   pool workers, miners, seeds, relays and exchange images before H. Pool
   templates created below H must be retired at H so stale version-1 shares
   cannot produce a post-H block.

## Qualification before activation

- Run mixed-version peers at H-1, H and H+1, including wrong-version,
  wrong-network, wrong-digest, oversize, malformed and coordinated-evaluation
  proofs. The known 48 coordinated claim alterations must remain rejected.
- Run a reorganization across H, cold restart from a pre-H block log, snapshot
  recovery, pruned catch-up and wallet/exchange sync with proof-only admission.
- Mine fresh post-H blocks through the pool and separate CPU nodes. Compare
  proof-only nodes with an independent replaying audit node at the same tips.
- Check the shipped GPU worker on a 16 GB card, report the full share-to-block
  latency, and verify owner mining is restored after qualification.
- Obtain independent review of the transcript-binding repair and complete
  direct-proof soundness accounting. Publish the exact reviewed source,
  binaries, hashes, H and rollback procedure together.

Current testnet evidence: a GPU-proven chain through height 19, independent
CPU-only node catch-up, a public audit seed, live proof-only admission/restart,
48 coordinated attack rejections, 6,528 evaluation-limb binding checks,
and Linux/Windows package qualification. The latest full local pool/node
acceptance averaged 5.74 seconds with 5.65–5.69 MB proofs; the sampled workload
peaked at 12.72 GiB under its 13 GiB guard on the RTX 5090 test card.
Those tests establish the testnet path; the height-H mainnet implementation
and its cross-height tests remain the next engineering milestone.
