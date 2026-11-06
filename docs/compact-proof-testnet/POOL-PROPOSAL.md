# Common Foundry compact-proof testnet update for pool operators

Pool operators,

We have reached an exciting milestone: **roughly mainnet proving/checking speed with proofs about 53% smaller**.

Our latest three compact-proof blocks reached full local pool/node acceptance in **5.88, 5.68 and 5.66 seconds**, averaging **5.74 seconds**. We have shaved **1.99 seconds (25.7%)** off the previous qualified average on the same RTX 5090. Mainnet's prepared reference on that rig measured **5.44–5.57 seconds**; the testnet number includes actual local pool/node admission, so this is an approximate comparison.

Proof packets now measure **5.65–5.69 MB**, down from mainnet's **12.03 MB**. That frees roughly **6.35 MB** within our existing **16 MiB block budget** for transactions and other block data, before other overhead.

We achieved this by exporting witnesses directly into immutable RAM, preparing buffers during proving, reusing weight data and calculations, and improving GPU startup. The latest workload peaked at **12.72 GiB VRAM** under the 13 GiB guard on our 32 GiB test card. The ForgeMatrix workload and proof-security parameters are preserved.

The evaluation-binding repair is included: ordinary nodes check the complete proof and normal block rules without redoing the mining calculation. All **48 coordinated forgery cases** were rejected, and an independent CPU-only node verified the chain through height 19. Our seed separately replays work as an audit comparison.

**v0.3.0 includes the Linux pool/miner/prover kit, Windows GUI/node preview, updated quickstarts, results and checksums.** Existing testnet chain data and downloaded inputs carry forward. The public seed remains **209.145.48.36:23444**.

Please join us and report your GPU/driver, winning-block latency, peak memory, stale rate, propagation and restart results. Feedback from 16 GiB GPUs and different pool setups will be especially useful. These testnet improvements support our plan to combine the compact proof and cheating repair into **one future mainnet hard fork**.

Thank you for helping us bring smaller proofs, more block capacity and smoother operation to Common Foundry.
