# ProductionV4 proof algebra and message order v1

This document specifies the consensus-critical algebra, Fiat-Shamir message
order, opening-claim routing, BaseFold parameters, and transparent-proof byte
layout for ProductionV4. It extends the
[core binding specification](production-v4-core-spec-v1.md). The companion
[message-order manifest](production-v4-message-order-v1.json) is checked
against the implementation by the consensus test suite.

This specification describes the existing verifier. It does not change proof
bytes, transcript bytes, acceptance rules, or the mandatory CPU verification
path.

## Field, extension, and transcript encoding

- The base field is KoalaBear, `F = GF(0x7f000001)`.
- The extension field is `EF = F[X]/(X^4 - 3)`, represented in
  `[1, X, X^2, X^3]` coefficient order by the pinned `slop` source revision
  `92b8eabaea9ab7306da5826caa700adabf7445ba`.
- `EF` values are observed and encoded coefficient-first as four canonical
  base-field values.
- `observe_bytes(B)` observes `F::from_canonical_usize(len(B))`, followed by
  one base-field element for each byte of `B` in order.
- All points list coordinates in their stored order. No coordinate is
  implicitly reversed except the BaseFold evaluation point described below.
- `eq(x,y) = product_i ((1-x_i)(1-y_i) + x_i y_i)`.

The challenger is `KoalaBearDegree4Duplex`, the pinned Poseidon2 width-16,
digest-8 suite. It starts from its default state and first receives
`observe_bytes(transcript_statement_digest)`. The statement digest and its
14 bound inputs are specified in the core binding specification.

## Complete outer protocol order

The verifier executes these blocks in exactly this order:

1. Observe the six bank commitments as `(fixed[0], dynamic[0], fixed[1],
   dynamic[1], fixed[2], dynamic[2])` under the commitments domain.
2. Verify both relation repetitions for bank 0.
3. Verify both relation repetitions for bank 1.
4. Reduce and verify bank 0's opening claims.
5. Verify both relation repetitions for bank 2.
6. Reduce and verify bank 1's opening claims.
7. Sample and bind both public-final-activation points.
8. Reduce and verify bank 2's opening claims.

Each relation repetition is ordered `matrix`, `shift`, claim routing, then
`cubic`. Bank-opening verification is intentionally delayed by one bank so a
shift boundary from bank `b` can become an opening claim against bank `b-1`.

## Relation index and challenge points

Every matrix, cubic, or final point first observes its domain, then the bank
index, then the repetition index. A matrix or cubic point samples 26 extension
elements in `[layer(7), batch(7), output(12)]` order. A final point samples 19
extension elements in `[batch(7), output(12)]` order and uses bank index 2.

### Matrix relation

The matrix domain observes `preactivation_evaluation` and the public
coordinate-mask evaluation. Its 19-variable, degree-3 sumcheck claim is:

```text
claimed_sum = preactivation_evaluation - mask_evaluation
```

Let the sumcheck terminal point be `[terminal_layer(7), terminal_common(12)]`.
The terminal identity is:

```text
terminal_evaluation
  = weight_evaluation * input_evaluation
  * eq(claim_layer, terminal_layer)
```

After the sumcheck, `weight_evaluation` and `input_evaluation` are observed in
that order.

### Shift relation

The shift domain observes `input_evaluation`, then `boundary_evaluation`. Its
7-variable, degree-2 sumcheck claim is:

```text
claimed_sum
  = input_evaluation - eq(source_layer_point, boolean_index_0)
  * boundary_evaluation
```

For terminal point `t`, define `L_t[i]` as the multilinear Lagrange weight at
Boolean index `i`. The terminal coefficient and identity are:

```text
shift(source,t) = sum_(i=0..126) eq(source, boolean_index_(i+1)) * L_t[i]
terminal_evaluation = next_activation_evaluation * shift(source,t)
```

`next_activation_evaluation` is then observed.

### Cubic relation

The cubic point is sampled after the matrix and shift checks. The cubic domain
starts a 26-variable, degree-4 sumcheck whose claimed sum must be zero. At
terminal point `t`, with external point `r = [layer,batch,output]`:

```text
terminal_evaluation
  = eq(r,t) * (next_activation_evaluation - preactivation_evaluation^3)
```

`preactivation_evaluation` and `next_activation_evaluation` are then observed
in that order.

## Sumcheck message order

For every partial sumcheck, the first polynomial's `degree + 1` extension
coefficients are observed. Before each later polynomial, one extension
challenge is sampled; that polynomial's coefficients are then observed. One
final extension challenge is sampled after the last polynomial. The resulting
point must equal the encoded terminal point, and the last polynomial evaluated
at the final challenge must equal the encoded terminal evaluation.

The claimed sum and terminal point/evaluation are encoded in the proof but are
not separately observed by this generic sumcheck step. Relation-specific
values listed above bind the public claim before sumcheck replay.

## PCS point routing and opening claims

Fixed weight points concatenate `[layer, common, output]`; the first eight
coordinates select the fixed column and the remaining 23 select the row.
Dynamic points concatenate `[trace_kind, layer, batch, output]`; the first four
coordinates select the dynamic column and the remaining 23 select the row.
`trace_kind` is zero for preactivation and one for next activation.

Each repetition contributes five claims to its current bank in this order:

1. fixed weight evaluation;
2. dynamic preactivation from the matrix relation;
3. dynamic next activation from the shift relation;
4. dynamic preactivation from the cubic relation;
5. dynamic next activation from the cubic relation.

Each shift also produces a boundary value. For bank 0 it is checked directly
against the public initial activation. For banks 1 and 2 it is appended as an
opening claim to the preceding bank. Thus banks 0 and 1 each receive ten local
claims plus two following-bank boundary claims. Bank 2 receives ten local
claims plus two public-final-activation claims. Every bank therefore reaches
12 claims and is padded to 16 by repeating its last claim; claim order and
padding are consensus-critical.

## Opening reduction and BaseFold order

An opening reduction observes, in order:

1. `OpeningReduction/v2` via `observe_bytes`;
2. fixed commitment, then dynamic commitment;
3. claim count as one base-field element;
4. for each claim: commitment tag, column coordinates, row coordinates, value.

It samples `lambda` and uses reverse powers
`[lambda^(n-1), ..., lambda, 1]`. The 23-variable, degree-2 sumcheck claim is
the power-weighted sum of claimed values. At terminal row point `z`, the
terminal identity is the sum over claims of:

```text
power * column_evaluation(commitment, column_point) * eq(row_point,z)
```

The two column-evaluation vectors then become the BaseFold evaluation claims.
The pinned BaseFold verifier performs these transcript operations:

1. Observe `batch_grinding_witness`; require a 5-bit zero sample.
2. Sample a 9-element batching point for the 272 fixed-plus-dynamic columns.
3. Observe the FRI round count, 23.
4. For each of 23 rounds: observe the two-element univariate message, observe
   its FRI commitment, then sample `beta`.
5. Observe `final_poly`.
6. Observe `pow_witness`; require a 16-bit zero sample.
7. Sample 270 query indices, 24 bits each (`23 + log_blowup(1)`).
8. Verify component and round Merkle openings, all fold equations, the final
   constant, and the final sumcheck/FRI consistency equation.

Before the BaseFold round checks, its evaluation point is reversed because the
prover fixes the last coordinate first. The complete inner algorithm is pinned
by source revision and path
`slop/crates/basefold/src/verifier.rs::verify_mle_evaluations`.

## Transparent-proof wire layout

All ranges are half-open byte offsets. Outside the outer and nested opening
headers, every payload value is a canonical little-endian `u32` base-field
element.

| Range | Contents |
|---|---|
| `0..16` | `CMV4PF01`, `u32le(1)`, `u32le(3)` |
| `16..2,097,168` | 524,288 public final-activation fields |
| `2,097,168..5,406,552` | bank 0 |
| `5,406,552..8,715,936` | bank 1 |
| `8,715,936..12,025,320` | bank 2 |

Each 3,309,384-byte bank is `dynamic_commitment[32]`, two 4,672-byte relation
repetitions, then one 3,300,008-byte opening. Each opening begins with
`CMV4BF01`, `u32le(1)`, `u32le(16)`, followed by the opening sumcheck, fixed
column evaluations, dynamic column evaluations, 23 BaseFold univariate
messages, 23 FRI commitments, two component openings, 23 query-phase
openings, `final_poly`, `pow_witness`, and `batch_grinding_witness`.

The independent
[`production-v4-wire-conformance.py`](../../scripts/production-v4-wire-conformance.py)
tool checks exact length, every header, outer/bank/opening boundaries, and
every canonical field encoding without importing the production Rust decoder.
It is a structural conformance checker, not a cryptographic proof verifier:

```text
python scripts/production-v4-wire-conformance.py transparent-proof.bin --json
python scripts/production-v4-wire-conformance.py --self-test
```
