# p3-merkle-tree 0.6.3 supplied first-layer hook

This directory vendors the source published as `p3-merkle-tree` version
`0.6.3`.

Upstream SHA-256 values before modification:

- `src/merkle_tree.rs`:
  `da3750bcca864ca3f051fa58154e8ba2ab21bb3acff6aef3c5f72475aafe51a1`
- `src/mmcs/batch.rs`:
  `29649bd96c6ce558ecf66d90ad60d4accf4ad77cbc2e6501f3e1d18d84a9c3d1`
- `Cargo.toml`:
  `588eb5d6144b7893e28fe2217fe9562386b619eb623ba3b783c12531f2702917`

The functional patch adds one prover-side hook to
`MerkleTreeMmcs`: `commit_with_first_digest_layer`. The caller supplies exactly
one unpadded digest per physical row of the tallest matrices. The vendored
implementation adds the normal default zero-digest padding, then uses the
unchanged upstream compression, mixed-height injection, cap, opening, and
verification logic for the rest of the tree.

The hook intentionally does not verify the supplied leaf digests. It is for an
accelerated prover whose completed proof is still checked by the ordinary CPU
verifier.

Focused tests compare commitments and opening proofs against the original
commit path for equal-height matrices, mixed-height matrices, and a
non-power-of-two height requiring padding. A rejection test pins the requirement
that callers must not pre-pad the supplied layer.

The normalized published `Cargo.toml` also adds `p3-baby-bear = 0.6.3` as a
test-only dependency. The upstream source tests already import that crate, but
the dependency is absent from the normalized package manifest; adding it lets
this vendored crate's complete upstream test suite run standalone.

Upstream: <https://github.com/Plonky3/Plonky3>

Package release: `p3-merkle-tree 0.6.3`

License: MIT OR Apache-2.0. Common Foundry redistributes this copy under MIT;
see `LICENSE-MIT` in this directory.
