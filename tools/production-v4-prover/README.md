# ProductionV4 GPU prover

This standalone WSL/CUDA tool is the exact prover path used for ProductionV4 Testnet-1 block 1.
It is not part of the default Cargo workspace and cannot activate another network profile.

Pinned dependencies:

- SP1 `92b8eabaea9ab7306da5826caa700adabf7445ba`, plus
  `patches/sp1-gpu-production-v4.patch`;
- CUTLASS 3.9.2 commit `ad7b2f5e84fcfa124cb02b91d5bd26d238c0459e`;
- CUDA 12.8 and `sm_120`.

Run `prepare-dependencies.sh` once in a clean Ubuntu-22.04 WSL environment, then run `build.sh`.
Both scripts fail closed if their pinned checkout identities do not match. The build emits the
three Rust tools plus `cmfd-v4-replay` and `cmfd-v4-fixed-row-cache` under `target/release`.

The online proving path is:

1. freeze a canonical template with `cmfd-miner snapshot-v4-template`;
2. derive replay coefficients with the consensus example
   `forgematrix_v4_replay_coefficients`;
3. run `cmfd-v4-replay` to produce the three dynamic traces and final activation;
4. run `real_dynamic_commitments`;
5. run `real_bank0_relations` to create and CPU-self-verify the exact proof; and
6. submit the unchanged template and proof with `cmfd-miner submit-v4-template`.

The block-1-qualified prover authenticates and maps three canonical fixed codewords, maps three
row-major fixed codewords for fast reads, and authenticates three Merkle trees. This current cache
occupies about 105 GiB. Reducing the release bundle to the row-major codewords and trees (about
54 GiB) requires a separately qualified cache-authentication change. Nodes need only the 6.4 GB
model bank and the 6,973-byte fixed record; they do not need the proving cache.
