# Common Foundry Compact Proof Testnet v0.4.0

Pool operators,

We are opening up more GPU options with **two-GPU compact proving and a shared resident model**. Replay and proving now reuse the same model allocation: our next replay was ready in **0.11-0.13 seconds**, replacing a **16.77-second reload** on the same rig.

The new mode stayed within **7.46 GiB per card** while producing complete proofs around **5.7 MB**. The ForgeMatrix work, six commitments, 270 queries, 16 grinding bits and full node verification stay unchanged. Ordinary nodes verify the proof without repeating the mining computation.

Our live pool accepted two consecutive blocks with one resident model and no model transfers after startup. Full pool evaluation plus local admission took **12.08 and 11.57 seconds on PCIe Gen2 x1 risers**. About 4.7 seconds was witness transfer over those links, giving us a clear next optimization target. The existing single-GPU path remains available alongside this new mode.

**v0.4.0 includes the Linux pool/miner/prover kit, matching Windows GUI/node preview, updated quickstarts and signed checksums.** It also carries the seed self-discovery repair. Existing testnet keys, chain data, model inputs, ledger and pool TLS identity carry forward; the seed remains **209.145.48.36:23444**.

We would love pool feedback on both modes: GPU/driver and PCIe layout, winning-block latency, peak memory, stale rate, synchronization and restart behavior. The 7.46 GiB run used physical 16 GiB cards under a 7.5 GiB guard; an actual 8 GB RTX 3080 mobile pair is our next hardware canary.

These improvements continue toward one future mainnet upgrade combining compact proofs and the evaluation-binding repair. Thank you for helping us bring more GPU choices, smaller proofs and smoother pool operation to Common Foundry.
