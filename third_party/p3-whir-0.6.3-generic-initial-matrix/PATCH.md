# p3-whir 0.6.3 generic initial prover matrix

This directory vendors the source published as `p3-whir` version `0.6.3`.

Upstream SHA-256 values before modification:

- `src/pcs/prover/mod.rs`:
  `4d7fb73ecb3f7b04df1b858565548b254f7356ba1fdefd63b372c6b445e203b4`
- `src/pcs/tests.rs`:
  `78618581fe644ef521a39bb147e16aef2e11f8b9c257f03a7db854cc07cb4297`
- `Cargo.toml`:
  `5e2edbae11fbf3754a30085389e68a38c7087a704d14371460c6d4e070afbb2c`

The functional patch makes the prover's initial MMCS matrix type generic
inside `WhirProver::prove` and its private round state. It also exposes
`WhirProver::prove_from_sumcheck`, a checked continuation seam for an initial
sumcheck prepared from authenticated external storage. The ordinary `prove`
entry point delegates to that seam after running the unchanged layout code.
Later folded-round matrices remain the upstream dense extension-field type on
the ordinary path. The existing `MultilinearPcs` adapter and its
`WhirProverData` remain explicitly `DenseMatrix<F>`, so current callers retain
the same commit/open behavior.

The patch also exposes `FallibleWhirProverState` and
`WhirProver::try_prove_from_state`. The trait is the smallest state surface
used after the initial sumcheck: variable count, extension commitment,
multilinear evaluation, base and extension MMCS openings, sumcheck folding,
and final-polynomial materialization. Each fallible operation returns the
state backend's own error. The fallible round and final-round paths return
immediately on error; they neither retry nor switch to a dense fallback after
the challenger has advanced. An error can leave a partial proof and transcript
prefix, so callers must discard both values for that attempt. `SumcheckProver`
implements the trait with `Infallible` and the ordinary `prove` and
`prove_from_sumcheck` APIs continue to use that dense adapter.

Commitments, verifier types, proof structs, transcript order, and serialized
proof bytes are unchanged. Focused tests compare the complete commitment,
proof bytes, and next challenger sample between the ordinary and fallible
dense paths for both prefix and suffix layouts. Injected failures at extension
commitment, OOD evaluation, base opening, final-round extension opening,
intermediate sumcheck, and final-polynomial materialization verify exact error
propagation without retry.

The normalized published `Cargo.toml` adds the upstream test-only field and
hash crates imported by the source's unit tests. This lets the vendored unit
tests compile standalone.

Upstream: <https://github.com/Plonky3/Plonky3>

Package release: `p3-whir 0.6.3`

License: MIT OR Apache-2.0. Common Foundry redistributes this copy under MIT;
see `LICENSE-MIT` in this directory.
