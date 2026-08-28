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

Fast proving requires the fixed record, three row-major fixed codewords, and three authenticated
Merkle trees, occupying about 54 GiB. The row-major files are untrusted caches: every queried row
is opened against the record-pinned tree, and the finished proof is CPU-self-verified. The three
canonical codewords are needed to generate the row-major caches but not to mine. Block 1 was
re-proved successfully with all canonical codewords absent. Nodes need only the 6.4 GB model bank
and the 6,973-byte fixed record; they do not need the proving cache.

On Windows, `scripts/run-production-v4-miner.ps1` performs the complete template, replay,
commitment, proof, CPU-verification, and submission sequence. Its `Blocks` value defaults to zero,
which continues until interrupted. The current qualified binaries target compute capability 12.0
and the launcher enforces at least 15,000 MiB of reported GPU memory. It authenticates all eight
required inputs once at startup against `production-v4-testnet-1-inputs.json` before requesting a
node template.
