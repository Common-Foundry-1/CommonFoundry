# ProductionV4 core binding specification v1

This document freezes the core public bindings used by ProductionV4. The
companion [canonical vector](production-v4-core-vector-v1.json) provides one
machine-readable input and every expected digest. Together they give an
independent implementation a compact starting point for compatibility work.

This first specification slice covers block-to-proof binding, public-output
binding, work derivation, the transcript statement, artifact identities, and
wire boundaries. The complete proof-algebra and BaseFold message-order
specification remains a separate mainnet milestone.

## Encoding conventions

- `u32le(x)` and `u64le(x)` are fixed-width unsigned little-endian integers.
- A `[32]` value contributes its 32 raw bytes without a length prefix.
- A canonical KoalaBear field value contributes `u32le(value)` and must be
  strictly less than `0x7f000001`.
- `BLAKE3-DK(context, bytes)` means BLAKE3 derive-key mode using the UTF-8
  context string and the exact concatenated byte stream shown below.
- Concatenation order is normative; no field is optional.

## Proof-system identity

The v1 proof-system digest is:

`e849e3bfc83f8f8dd0f1fc1100879417718ba2bffb92af5cd649b61c720675a3`

It commits the algorithm and proof versions, KoalaBear field and extension,
384-layer production geometry, fixed and dynamic layouts, BaseFold parameters,
relation topology, axis orders, transcript domains, Poseidon suite, proof codec,
and the pinned BaseFold source revision. The normative preimage inventory is
implemented by `forgematrix_v4_proof_system_digest`.

## Challenge digest

With context `CommonFoundry/ForgeMatrix/V4/Challenge/v1`, hash:

```text
u32le(1)
|| network_id[32]
|| previous_block[32]
|| transaction_root[32]
|| u64le(height)
|| u64le(timestamp)
|| target[32]
|| u32le(algorithm_version)
|| u32le(proof_version)
|| proof_system_digest[32]
|| model_manifest_digest[32]
|| u64le(nonce)
```

## Final-activation digest

With context `CommonFoundry/ForgeMatrix/V4/FinalActivation/v1`, hash:

```text
challenge_digest[32]
|| u64le(field_count)
|| u32le(final_activation[0])
|| ...
|| u32le(final_activation[field_count - 1])
```

ProductionV4 uses exactly 524,288 final-activation fields in row-major order.

## Work digest

With context `CommonFoundry/ForgeMatrix/V4/Work/v1`, hash:

```text
u32le(1)
|| u32le(algorithm_version)
|| u32le(proof_version)
|| proof_system_digest[32]
|| model_manifest_digest[32]
|| challenge_digest[32]
|| final_activation_digest[32]
```

## Transcript-statement digest

With context `CommonFoundry/ForgeMatrix/V4/TranscriptStatement/v1`, hash:

```text
u32le(1)
|| network_id[32]
|| previous_block[32]
|| transaction_root[32]
|| u64le(height)
|| u64le(timestamp)
|| target[32]
|| u32le(algorithm_version)
|| u32le(proof_version)
|| u64le(nonce)
|| proof_system_digest[32]
|| model_manifest_digest[32]
|| challenge_digest[32]
|| final_activation_digest[32]
|| work_digest[32]
```

This digest initializes the CPU-owned BaseFold transcript.

## Artifact and wire identities

The canonical vector pins the ProductionV4 Testnet-1 network ID, model-manifest
digest, fixed-artifact-record digest, exact 12,025,320-byte transparent proof,
13 MiB complete proof-frame cap, 16 MiB complete block-frame cap, and the
derived maximum transparent-proof payload. Decoders accept only canonical
field values and exact proof topology and reject truncated, trailing,
noncanonical, or over-limit inputs.
