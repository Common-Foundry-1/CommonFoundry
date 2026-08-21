# p3-fri 0.6.3 generic input-LDE storage

This directory vendors the source published as `p3-fri` version `0.6.3`.

Upstream SHA-256 values before modification:

- `src/two_adic_pcs.rs`:
  `bb09d59ca698780b63d943728983f8e476cdce01abe1972d8205e15776d5e776`
- `src/prover.rs`:
  `d4d486300cd34dbb68f75543c03bd689cdb6a84251ec68eb013426988a916400`
- `tests/pcs.rs`:
  `8e7b15b7302ba8f9a8fdc51a7e1b42b2316bdb791a2d11897cc8c22f7e5b2c23`
- `Cargo.toml`:
  `0975af90649f157d5f13ffba6a0eb38da23475c6f1cdbd62c0be28bc2d4b46b7`

The functional patch makes only the prover's retained input-LDE matrix type
generic:

- `TwoAdicFriPcs` has a fifth parameter, defaulted to
  `RowMajorMatrix<Val>`. Existing four-parameter type aliases and
  `TwoAdicFriPcs::new` retain their original behavior.
- `FriLdeMatrix` describes storage whose logical rows are the exact physical
  bit-reversed LDE rows committed by the input MMCS. It supplies domain views
  and the uncommon full re-evaluation materialization path.
- `TwoAdicFriPcs::new_with_lde` selects custom storage.
- `TwoAdicFriPcs::commit_bit_reversed_ldes` accepts LDEs already produced in
  that storage, avoiding a conversion through `RowMajorMatrix`.
- `prove_fri` and its input-opening helper are generic only over the input LDE
  matrix. FRI fold-round matrices remain the upstream `RowMajorMatrix` type.
- Opening precomputes adjusted barycentric weights only through the largest
  polynomial-height prefix used for each point, rather than duplicating its
  full LDE-height inverse-denominator vector. The adjusted weights, inverse
  denominators, and coset are explicitly released before the FRI phase.
- Non-binary FRI rounds fold each matrix row directly into the output vector.
  The implementation factors the old whole-domain inverse powers into one
  output-height row vector plus arity-only shared layers and uses stack scratch
  for log arities through 4. It no longer copies the full matrix or allocates a
  second half-height extension vector.

The verifier, proof structs, commitments, transcript order, query indices, and
serialized proof format are unchanged. The focused test commits identical
physical LDEs through default and wrapped storage, compares commitments,
exercises prefix and re-evaluation domain reads, opens through the generic
prover data, and verifies the resulting proof with the default CPU PCS type.
An additional mixed-height test checks that every bounded adjusted-weight
vector exactly equals the prefix produced by the previous full-vector
calculation, including a point repeated at different matrix heights.
Differential tests compare direct folding with the previous whole-matrix
formula for log arities 1 through 4 across edge and seeded-random vectors. A
seeded arity-16 fixture also compares the complete serialized FRI proof bytes
from the direct and reference folding implementations.

A disk-backed implementation must authenticate and validate its artifact
before constructing the matrix. `p3_matrix::Matrix` row access is infallible,
so later storage or I/O failures must fail closed rather than substitute data.

The normalized published `Cargo.toml` adds the upstream test-only Plonky3
dependencies that are absent from the crates.io manifest. This allows the
vendored source tests to compile when the workspace routes all `p3-fri`
dependencies to this copy. It also adds `serde_json` as a test-only dependency
for the deterministic complete-proof byte differential.

Workspace integration requires both entries below in the root manifest:

```toml
[workspace]
exclude = [
    # existing entries...
    "third_party/p3-fri-0.6.3-out-of-core",
]

[patch.crates-io]
p3-fri = { path = "third_party/p3-fri-0.6.3-out-of-core" }
```

Upstream: <https://github.com/Plonky3/Plonky3>

Package release: `p3-fri 0.6.3`

License: MIT OR Apache-2.0. Common Foundry redistributes this copy under MIT;
see `LICENSE-MIT` in this directory.
