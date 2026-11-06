# One mainnet upgrade for the compact proof and evaluation binding repair

The proposed mainnet activation makes one consensus change at a single height **H**. It combines the smaller self-contained ForgeMatrix proof with the repair for the known unbound-evaluation flaw. Nodes verify the proof and ordinary block rules without independently rerunning each new block's 384-layer mining computation. One audit node can keep replaying work during the canary; replay is an operator check, not a condition for every node to accept a valid post-activation block.

Before H, mainnet keeps its existing version-1 proof and work-check policy. At and after H, a block must carry the version-2 direct packet (`CMFDDR02`), the new proof-system digest, and the complete version-2 transcript. Version-1 proofs at or above H, and version-2 proofs below H, are rejected. Mainnet's model and fixed-commitment identities, ForgeMatrix workload, field/hash suite, BaseFold 1/270/16 parameters, transaction rules, and 16 MiB block limit stay pinned. The direct packet is capped below 6,000,000 bytes.

The version-2 verifier checks all three bank relations, both boundary paths, final activation, work digest and target, original opening reductions, the shared reduction, and one six-commitment BaseFold argument. Every untrusted evaluation enters the challenge transcript before the backend samples its batch challenge. The CPU verifier uses the backend's `verify_untrusted_evaluations` API; the GPU prover emits the same canonical challenge order. The packet is self-contained and has its own network, proof-version, and statement binding.

The testnet regression uses a real public block. An intentionally unbound backend accepted 48 coordinated evaluation alterations that preserve two cheaper linear equations; the corrected complete verifier rejected all 48. Mutation of each original and shared evaluation limb changed the following challenge. The safe backend API and GPU explicit absorption produced identical transcript challenges. A proof-only node accepted the honest block, rejected a coordinated altered sibling over its block RPC with HTTP 422, and restarted at the same tip. The existing public seed separately replays each block as an audit comparison.

## One activation plan

1. Set H only after the release binaries, node and wallet packages, pool worker, and exchange/relay images carry both pre- and post-H rules. Publish the exact binaries, hashes, network fingerprint, and activation height together.
2. At H, require proof version 2, verify the entire direct packet and normal block/transaction rules, and stop making full ForgeMatrix replay a consensus admission step for new blocks. Retain an opt-in audit build for continuous comparison.
3. Test mixed-version peers around H, block propagation, chain restarts, pruning, historical v1 replay, wallet catch-up, malformed version boundaries, pool stale jobs, and GPU memory on 16 GB cards.
4. Obtain independent review of the repaired transcript and soundness accounting before setting H. The testnet provides live interoperability and attack-regression evidence for that review.

This plan changes future mainnet blocks once. Historical v1 blocks remain interpreted by their original rules; the compact proof starts at H. Published testnet v0.1.0 keeps work replay as an audit baseline. Testnet v0.2.0 makes ordinary node and wallet validation proof-only while retaining a separate audit comparison before H is chosen.
