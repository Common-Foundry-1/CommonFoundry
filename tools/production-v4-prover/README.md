# ProductionV4 GPU prover

This standalone WSL/CUDA tool is the exact prover path used for ProductionV4 Testnet-1 block 1.
It is not part of the default Cargo workspace. The proof worker requires the caller to supply the
expected network ID explicitly and rejects any frozen template whose network ID differs.

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

RCNet-1 block-one qualification starts with an offline source-stage command. Build it with the
`production-v4-testnet` feature, not `production-rc`:

```text
cmfd-miner prepare-rcnet1-qualification-template \
  --candidate ABSOLUTE/RCNET1-LAUNCH-CANDIDATE-V2.json \
  --miner 64_LOWERCASE_HEX_XONLY_PUBLIC_KEY \
  --model-bank ABSOLUTE/MODEL-V2.bank \
  --fixed-record ABSOLUTE/FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json \
  --work-dir ABSOLUTE/NEW_EMPTY_WORK_DIRECTORY
```

The work-directory path must not exist. Before creating it, the command requires byte-exact
canonical Candidate V2 JSON and authenticates both artifact files against the compiled identities.
The fixed record is parsed only from its authenticated byte snapshot, and the model-bank hashes
cover the exact stream consumed by consensus verifier construction, so path replacement or
in-place mutation cannot substitute unpinned verifier inputs.
It constructs RCNet-1 block 1 in memory with no peer, node storage, or mempool; height, timestamp,
target, virtual genesis, reward policy, nonce, and network ID are deterministic. It writes replay
coefficients first and `RCNET1-BLOCK1-QUALIFICATION-TEMPLATE.json` last as the completion marker.
This command creates no proof, activation evidence, approval, or release pin.

The persistent and one-shot proof-worker forms are:

```text
real_bank0_relations --server EXPECTED_NETWORK_ID MODEL ARTIFACT_DIRECTORY
real_bank0_relations --network-id EXPECTED_NETWORK_ID MODEL ARTIFACT_DIRECTORY TEMPLATE TRACE_PREFIX DYNAMIC_RECORD FINAL OUTPUT
```

`EXPECTED_NETWORK_ID` is required to be exactly 64 lowercase hexadecimal characters and must be
one of the compiled ProductionV4 Testnet-1 or RCNet-1 identities. Packaged ProductionV4 miner
launchers read it from the already authenticated input manifest; node-owned pool workers pass the
full network ID from the compiled network profile.

Fast proving requires the fixed record, three row-major fixed codewords, and three authenticated
Merkle trees, occupying about 54 GiB. The row-major files are untrusted caches: every queried row
is opened against the record-pinned tree, and the finished proof is CPU-self-verified. The three
canonical codewords are needed to generate the row-major caches but not to mine. Block 1 was
re-proved successfully with all canonical codewords absent. Nodes need only the 6.4 GB model bank
and the 6,973-byte fixed record; they do not need the proving cache.

On Windows, `scripts/run-production-v4-miner.ps1` performs the complete template, replay,
commitment, proof, CPU-verification, and submission sequence. Its `Blocks` value defaults to zero,
which continues until interrupted. The current qualified binaries target compute capability 12.0
and the launcher enforces at least 15,000 MiB of reported GPU memory. Before requesting a node
template, the launcher authenticates the model bank, fixed record, and Merkle trees against
`production-v4-testnet-1-inputs.json`. The row-major proving files are length-checked and reused as
untrusted caches; their opened rows and the complete candidate proof remain independently checked.
The launcher also strictly validates the manifest's lowercase 32-byte network ID and supplies it
to the proof worker, which compares it with every frozen template before proving. Before validation
can pass or a prover can start, each launcher also runs `cmfd-miner network-info` and requires its
canonical compiled identity to select ProductionV4 and the same network ID as the authenticated
input manifest. This identity command does not open CUDA, node storage, or proving artifacts.
