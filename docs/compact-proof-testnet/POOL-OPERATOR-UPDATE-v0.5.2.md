# Common Foundry Compact Proof Testnet v0.5.2

Pool operators,

**v0.5.2 keeps replay ready between ordinary shares on dedicated pool GPUs.** The optional `--keep-replay-resident` native Linux mode avoids repeated full-model reloads, with ordinary checks measured at about 0.042 seconds after the initial load on Rig06. It preserves the existing eviction and replay lock before proving. The two-GPU shared-model mode already keeps its model resident.

**v0.5.1 makes pool timings visible automatically.** Proof phases and total accepted-block processing time now appear in the normal rotating logs, even with a silent console. There is no diagnostic flag to enable and no extra benchmark run required.

Our compact-proof testnet just got faster. **The v0.5.0 proving improvements cut full local pool acceptance to 8.27-8.52 seconds on PCIe Gen2 x1 risers**, compared with 11.57-12.08 seconds in v0.4.0. Pipelined transfers and GPU-resident calculations keep the two proving cards working together, with one shared model and no reload between proofs.

Proofs remain around **5.7 MB**, and measured memory stayed within **6.77 / 7.46 GiB per card**. ForgeMatrix work, all six commitments, 270 queries, 16 grinding bits and complete node verification are unchanged. Ordinary nodes verify the proof without repeating mining.

The update includes the Linux pool/miner/prover kit, matching Windows GUI/node preview, quickstarts and signed checksums. Existing keys, chain data, inputs, pool ledger and TLS identity carry forward. The public seed remains **209.145.48.36:23444**, and a fresh published node just synced through height 65 in about 51 seconds.

The optimized shared-model path is automatic when you use `--shared-model`. The existing single-GPU and other two-GPU layouts remain available. Our measurements used physical 16 GiB RTX 4070 Ti SUPER cards under a 7.5 GiB guard; feedback from physical 8 GB pairs and faster PCIe layouts is especially useful.

Operators can collect timing and memory feedback during ordinary use; no extra benchmark run is required. The five-second full-path target remains our next performance goal. These compatible testnet improvements continue toward one mainnet upgrade combining compact proofs and the evaluation-binding repair.

The residency measurement covers ordinary-share checks and proof handoff, not a new proof-generation benchmark. The last measured full local acceptance remains 5.74 seconds average on the RTX 5090 and 8.27-8.52 seconds on the two-GPU Gen2 x1 rig.
