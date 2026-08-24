# Dory V3 production model-generation ceremony v1

Status: **frozen protocol, not yet executed or independently reviewed**.

This document specifies version 1 of the ceremony for producing the seedless
ForgeMatrix Dory V3 production model payload. Changing any normative field,
domain, encoding, acceptance rule, or phase ordering requires a new protocol
version, a new ceremony identifier, and fresh contributions. This document does
not activate Dory V3, authorize a production network, or pin a generated model
into consensus. `DORY_V3_SUITE_ACTIVATION_READY` remains `false`.

The ceremony uses full-length participant contribution streams. It deliberately
does not derive the model from a compact public seed, an XOF seed, a password,
or a short transcript value. That property matches the seedless model-bank
requirement in the [ForgeMatrix v2 research specification](forgematrix-v2.md).

## Security objective and limits

The narrow objective is to make a participant's attempt to change its
contribution after commitment, change the participant set, reorder inputs, or
substitute the final artifact publicly detectable under the collision and
second-preimage resistance of BLAKE3 and SHA-256 and the unforgeability of the
signature scheme. The ceremony assumes:

- at least one operator samples an independent, uniform, secret contribution
  and follows the protocol;
- no honest contribution leaks before the commitment set is closed;
- the public bulletin is append-only, promptly mirrored, and exposes ordering;
- operator signing keys and the local CSPRNG of at least one honest operator
  are not compromised; and
- the specified tools and independent implementations are correctly reviewed.

For every byte position, the candidate sum modulo 251, before any
output-dependent acceptance or abort decision, is exactly uniform in `Z_251`
only if at least one honest stream is independent uniform and every other
stream is fixed independently of it. The ordinary file digests used here are
computationally binding but are not a hiding-commitment construction. If
security depends on an adversary being unable to adapt its stream to honest
contribution digests, that is only a computational, random-oracle-style
assumption about the hashes, not an unconditional or information-theoretic
claim. Version 1 introduces no salted hiding commitment.

A successfully completed ceremony may be selection-biased because a later
revealer can observe earlier reveals and condition completion on aborting or
revealing. Version 1 makes that abort public; it does not restore an exact
uniform distribution over the artifacts of completed ceremonies. A file digest
also does not prove how a file was generated.

This procedure only prevents *silent* bias under those assumptions. It does
not:

- prove that the model is information-theoretically incompressible;
- prove that an operator used the claimed entropy source;
- prove one-shot sampling or stop a dishonest operator from grinding candidate
  contributions before publishing its commitment;
- guarantee that successfully completed outputs are uniformly distributed, or
  stop a final revealer from conditioning completion after seeing earlier
  reveals;
- stop all operators from colluding or using correlated/biased streams;
- prevent private leakage that is invisible to the public bulletin;
- turn the model-generation process or Dory implementation into reviewed
  cryptography; or
- satisfy the external audit and adversarial-testnet gates in
  [SECURITY.md](../../SECURITY.md).

An abort is evidence that a ceremony did not complete, not permission to patch,
drop, reorder, or replace a contribution.

## Frozen production geometry

All integer encodings in this document are unsigned little-endian unless a
field explicitly says otherwise.

| Field | Frozen value |
|---|---:|
| Dory model version | 2 |
| Model-bank format version | 2 |
| Model-bank magic | ASCII `CMFDBNK2` |
| Model-bank header bytes | 184 |
| Batch, `B` | 128 |
| Dimension, `D` | 4,096 |
| Layers, `L` | 384 |
| Weight banks | 3 |
| Layers per bank | 128 |
| Dory padded variables, `n` | 33 |
| Maximum payload byte | 250 |
| Base-input bytes, `B * D` | 524,288 |
| Bytes per layer, `D * D` | 16,777,216 |
| Weight bytes, `L * D * D` | 6,442,450,944 |
| Total payload bytes | 6,442,975,232 |
| Canonical bytes per Dory GT commitment | 576 |

The pinned lowercase-hex identities are:

```text
production_suite_digest = 6c0950d4b5dcffef9f3296f9c0718a8d5124877719b3af76b2f68b3fcb64764a
dory_setup_identity = 75fd3dacddba30682d1eabd5d8d2924466d7214b011a7ecc48ba27821cbbf612
```

The model-bank `pcs_parameter_digest` is exactly the production suite digest
above; it is not a separate caller-selected value.

The payload order is exactly the base input in row-major order, followed by
weight matrices `W_0` through `W_383`, each in row-major order. No padding,
length prefix, header, footer, or trailing byte is present in a contribution or
in the combined raw payload. Every payload byte must be in `0..=250`.

The ordered Dory commitments are the base-input commitment, weight-bank 0
commitment for layers `0..=127`, weight-bank 1 commitment for layers
`128..=255`, and weight-bank 2 commitment for layers `256..=383`. Each uses the
frozen production `n = 33` setup. The model-bank bootstrap, not a participant,
derives these commitments and all model roots.

## Roles and cardinality

The genesis record fixes these two ordered rosters:

- `N` operators, where `3 <= N <= 16`, with indices satisfying `0 <= i < N`;
  and
- `R` independent reproducer teams, where `2 <= R <= 16`, with indices
  satisfying `0 <= i < R`.

Every operator is required. There is no threshold, quorum, zero-filled input,
or subset fallback. Operator order is by the frozen index, never by arrival
time, filename, public-key order, or filesystem enumeration.

At least one reproducer must use an independently authored combiner and root
calculator that is not derived from the reference ceremony implementation.
Running the same executable on two hosts provides useful operational
redundancy, but it is not independent implementation evidence. Reproducers may
not accept roots, commitments, or output digests supplied by the organizer as
computed results.

Each operator and reproducer has:

- one 32-byte BIP340 x-only secp256k1 public key dedicated to this ceremony;
- an exact, published identity document whose ordinary BLAKE3 and SHA-256
  digests are fixed by genesis; and
- an operator-owned working directory that is not writable by another
  participant or untrusted local user.

The identity document should name the accountable operator or team, contact
method, signing-key fingerprint, hardware and operating system, and declared
tool sources. Its format is not consensus-significant; its exact bytes are.
Genesis signatures bind its two file digests.

## Hashes, signatures, and domains

`BLAKE3(file)` below means ordinary unkeyed BLAKE3 over the exact file from byte
zero through EOF. `SHA-256(file)` means ordinary SHA-256 over the same bytes.
Neither file hash has an implicit filename, length, or domain prefix.

`BLAKE3-DK(domain, bytes)` means BLAKE3 derive-key mode using the exact ASCII
domain string and exact bytes. The ceremony domains are:

```text
CMFD/FORGEMATRIX/V3/MODEL-GENERATION-CEREMONY/GENESIS/V1
CMFD/FORGEMATRIX/V3/MODEL-GENERATION-CEREMONY/CONTRIBUTION-COMMITMENT/V1
CMFD/FORGEMATRIX/V3/MODEL-GENERATION-CEREMONY/COMMITMENT-SET/V1
CMFD/FORGEMATRIX/V3/MODEL-GENERATION-CEREMONY/CONTRIBUTION-REVEAL/V1
CMFD/FORGEMATRIX/V3/MODEL-GENERATION-CEREMONY/REVEAL-SET/V1
CMFD/FORGEMATRIX/V3/MODEL-GENERATION-CEREMONY/FINAL-RECEIPT/V1
CMFD/FORGEMATRIX/V3/MODEL-GENERATION-CEREMONY/ABORT/V1
CMFD/FORGEMATRIX/V3/MODEL-GENERATION-CEREMONY/SIGNED-RECORD/V1
CMFD/FORGEMATRIX/V3/MODEL-GENERATION-CEREMONY/SIGNATURE/V1
CMFD/FORGEMATRIX/V3/MODEL-GENERATION-CEREMONY/TRANSCRIPT/V1
CMFD/FORGEMATRIX/V3/MODEL-GENERATION-CEREMONY/TRANSCRIPT-ATTESTATION/V1
```

The first seven lines map in order to record types 1 through 7. The final four
record-independent domains identify complete signed records, signature
messages, the whole transcript, and the detached transcript attestation.

The existing model-bank domains remain unchanged:

```text
CMFD/FORGEMATRIX/V2/LAYER-ROOTS
CMFD/FORGEMATRIX/V2/MANIFEST
CMFD/FORGEMATRIX/V3/DORY-MODEL-COMMITMENTS/V1
CMFD/FORGEMATRIX/V3/DORY-MODEL-IDENTITY/V1
CMFD/FORGEMATRIX/V3/DORY-MODEL-COMMITMENT-RECORD/V2
```

Each record type has the corresponding ceremony domain above. Its content
digest is:

```text
BLAKE3-DK(record_domain,
    record_type_u16le || record_version_u16le || body_bytes_u32le || body)
```

The 32-byte signature message is:

```text
BLAKE3-DK("CMFD/FORGEMATRIX/V3/MODEL-GENERATION-CEREMONY/SIGNATURE/V1",
    record_type_u16le || record_version_u16le ||
    body_bytes_u32le || content_digest[32])
```

Every signature is the canonical 64-byte BIP340 signature over that 32-byte
message. After signatures are attached, the signed-record digest is:

```text
BLAKE3-DK("CMFD/FORGEMATRIX/V3/MODEL-GENERATION-CEREMONY/SIGNED-RECORD/V1",
    exact complete framed record, including signature count and signatures)
```

All later record references use the signed-record digest, not the content
digest. Public keys must parse as valid BIP340 x-only secp256k1 keys. Invalid
keys, duplicate keys, malformed signatures, duplicate signer entries, or a
signature from the wrong roster/index are fatal. Signature bytes do not affect
the generated payload.

A roster member must sign at most one record for each required ceremony slot
and at most one detached transcript attestation for a ceremony identifier.
Observed equivocation is fatal and is published as abort evidence.

## Authoritative binary transcript

The binary transcript is authoritative. JSON, Markdown, web pages, screenshots,
and human-readable logs are projections for audit convenience only. They are
never hashed in place of the binary records and must not be parsed to determine
the payload.

### Primitive encoding

- `u8`, `u16`, `u32`, and `u64` are unsigned and little-endian.
- `[n]` is an exact fixed-length byte array.
- Counts are followed by exactly that many entries.
- No string, optional field, alignment padding, implicit default, or floating-
  point value occurs in a record body.
- Unknown versions, unknown record types, reserved signer classes, nonconsecutive
  indices, length overflow, underflow, duplicate fields, and trailing bytes are
  fatal.
- Every signed-record digest in a body must resolve to the one exact earlier
  framed record occupying the required transcript slot.

### Transcript file framing

The completed or aborted transcript file is:

```text
magic[8]       = ASCII "CMFDMGC1"
version_u16    = 1
header_bytes_u16 = 24
record_count_u32
total_file_bytes_u64
record[record_count]
EOF
```

`total_file_bytes` includes the 24-byte header and all record bytes. The
transcript digest is BLAKE3 derive-key over the complete file with the exact
transcript domain listed above. It is published alongside ordinary BLAKE3 and
SHA-256 file digests. These external file digests are not embedded in the file
because doing so would be circular.

Each record is framed as:

```text
record_type_u16
record_version_u16 = 1
body_bytes_u32
body[body_bytes]
signature_count_u16
for each signature, ordered by signer_class and then signer_index:
    signer_class_u8       # 0 = operator, 1 = reproducer
    signer_index_u16
    signature[64]
```

The completed record sequence is exactly:

1. one genesis record, type 1;
2. `N` contribution-commitment records, type 2, in operator-index order;
3. one commitment-set closure, type 3;
4. `N` contribution-reveal records, type 4, in operator-index order;
5. one reveal-set closure, type 5; and
6. one final receipt, type 6.

A completed transcript therefore has exactly `2 * N + 4` records. An aborted
transcript begins with the fully signed genesis, contains a valid prefix of the
remaining sequence, then exactly one abort record, type 7, and EOF.

The production combiner consumes an intermediate reveal-set-closed prefix with
the same header and record framing, containing exactly the first `2 * N + 3`
records through the fully signed type-5 closure and EOF. This prefix is neither
a completed nor an aborted transcript and is not eligible for the detached
transcript attestation. Its verifier requires a separately trusted expected
`ceremony_id` in addition to validating every included record and closure.
Only that anchored, exact type-5-terminal prefix may yield combiner bindings.
The generic completed/aborted transcript parser is an inspection API without an
external ceremony-identifier trust anchor and must not mint or expose a combine
capability. Any future need to combine from a completed transcript requires a
separate parser that takes and validates the independently trusted identifier.

After assembly, exact transcript bytes are closed by this detached binary
attestation:

```text
magic[8] = ASCII "CMFDMTA1"
version_u16 = 1
ceremony_id[32]
transcript_bytes_u64
transcript_derive_key_digest[32]
transcript_blake3[32]
transcript_sha256[32]
signature_count_u16 = S
for each signer, ordered by signer_class and then signer_index:
    signer_class_u8
    signer_index_u16
    signature[64]
EOF
```

Each signature is BIP340 over the 32-byte BLAKE3 derive-key digest, using the
transcript-attestation domain above, of the exact attestation byte prefix from
`magic` through the fixed `signature_count`. A completed ceremony requires
`S = N + R` and every operator and reproducer signature. An aborted transcript
requires at least one valid roster signature and should collect every available
signature.

This detached closure binds its signers to one exact transcript byte string; it
does not prevent equivocation or re-signing. Acceptance of a different
completed transcript for the same ceremony identifier would require the
required signers to sign the alternate digest, making the re-signing detectable
once both attestations are public. The attestation's own ordinary BLAKE3 and
SHA-256 are published but not recursively embedded.

### Type 1: genesis body

The genesis body is:

```text
ceremony_protocol_version_u16 = 1
model_version_u32 = 2
bank_format_version_u32 = 2
bank_header_bytes_u32 = 184
batch_u32 = 128
dimension_u32 = 4096
layers_u32 = 384
banks_u32 = 3
layers_per_bank_u32 = 128
padded_variables_u32 = 33
max_model_byte_u8 = 250
base_input_bytes_u64 = 524288
bytes_per_layer_u64 = 16777216
payload_bytes_u64 = 6442975232
commit_deadline_unix_seconds_u64
reveal_deadline_unix_seconds_u64
source_commit_sha1[20]
source_bundle_bytes_u64
source_bundle_blake3[32]
source_bundle_sha256[32]
source_bundle_policy_bytes_u64
source_bundle_policy_blake3[32]
source_bundle_policy_sha256[32]
cargo_lock_blake3[32]
cargo_lock_sha256[32]
protocol_spec_blake3[32]
protocol_spec_sha256[32]
bulletin_policy_bytes_u64
bulletin_policy_blake3[32]
bulletin_policy_sha256[32]
reference_binary_count_u16 = K
for each target_id in ascending order:
    target_id_u16
    rustc_vv_file_bytes_u64
    rustc_vv_file_blake3[32]
    rustc_vv_file_sha256[32]
    build_environment_file_bytes_u64
    build_environment_file_blake3[32]
    build_environment_file_sha256[32]
    reference_binary_blake3[32]
    reference_binary_sha256[32]
structural_analyzer_target_id_u16
structural_analyzer_blake3[32]
structural_analyzer_sha256[32]
production_suite_digest[32]
dory_setup_identity[32]
participant_count_u16 = N
for operator_index satisfying 0 <= operator_index < N:
    operator_index_u16
    operator_public_key[32]
    identity_document_bytes_u64
    identity_document_blake3[32]
    identity_document_sha256[32]
reproducer_count_u16 = R
for reproducer_index satisfying 0 <= reproducer_index < R:
    reproducer_index_u16
    reproducer_public_key[32]
    identity_document_bytes_u64
    identity_document_blake3[32]
    identity_document_sha256[32]
```

`source_commit_sha1` is the raw 20-byte Git object identifier used only as a
repository locator and audit aid. It is never the sole source identity. The
authoritative project-source input for reference builds is the exact file whose
length and ordinary BLAKE3 and SHA-256 are `source_bundle_*`.

`source_bundle_policy_*` pins the exact, separately published policy file that
defines the archive format and version, parser limits, permitted metadata, and
extraction behavior. In addition to any narrower rules in that file, the v1
policy has these minimum requirements:

- Entry names use `/` as the only separator. Every component contains only the
  portable ASCII bytes in `[A-Za-z0-9._@-]`. Backslash, colon, control bytes,
  and NUL are forbidden. This set includes every path byte tracked at the
  frozen source revision.
- Absolute names, drive-prefixed or UNC names, empty components, and components
  equal to `.` or `..` are forbidden. Exactly one terminal `/` is permitted
  only on a directory entry and is removed before component checks.
- The collision key is the entry name after removing that permitted directory
  terminator and mapping ASCII `A` through `Z` to `a` through `z`. Two entries
  with the same collision key are forbidden, whether their original names are
  byte-identical or merely case-colliding.
- A regular file and directory may not have the same collision key. A regular-
  file key followed by `/` may not prefix another entry key. Directory keys may
  prefix descendants; this is the only permitted prefix relationship.
- Only regular files and directory entries are permitted. Directory entries
  create parent directories only and contribute no source bytes or semantics.
  Symlinks, hard links, reparse points, devices, FIFOs, and every other entry
  type are forbidden. Extracted source semantics are defined solely by the
  paths and bytes of regular files.

The source bundle contains the complete source tree required for the reference
build, including `Cargo.lock`, this protocol specification, build scripts and
configuration, and any required vendored or submodule content. It excludes
secrets, `.git`, and build outputs. Its extracted `Cargo.lock` and protocol file
must match the separately pinned digests in genesis.

Before signing genesis, every operator and reproducer obtains the bundle and
policy from the public mirrors and independently checks each exact length and
both hashes. Each lists and inspects every archive entry under the pinned
policy, then extracts into a new empty private directory using a conforming
extractor. Extraction failure or an unexpected file stops the attempt before
genesis is signed and produces no protocol transcript.

The build-environment documents identify the conforming inspection and
extraction tooling, but the pinned policy is authoritative for interpretation.
Output from `git archive` may be used only when its exact bytes satisfy the
pinned format and policy; otherwise it must be repacked before hashing and
publication. Reproducibility of archive generation or repacking is not
assumed. The exact published bundle bytes, length, and two hashes are
authoritative. The bundle and policy must be independently mirrored before
genesis signatures are collected.

`K` is one or two. Target 1 is `x86_64-pc-windows-msvc`; target 2 is
`x86_64-unknown-linux-gnu`. Each target may occur at most once. The exact
`rustc -vV` output and build-environment document pin the compiler, host,
linker, build flags, and container or operating-system image used for the
distributed reference binary. Source plus `Cargo.lock` alone does not imply a
reproducible binary hash. A locally built independent binary is not expected to
hash-match unless the pinned build is proven reproducible; its hash belongs in
the reproduction report. The structural analyzer is one exact distributed
binary on one recognized target.

The bulletin-policy file identifies at least two independently controlled
public mirrors, their keys and endpoints, record/file receipt procedure, clock
source, deadline interpretation, and evidence-retention policy. All roster
members sign its exact length and dual hashes through genesis.

Both deadlines are nonzero Unix seconds and genesis validation requires
`commit_deadline_unix_seconds < reveal_deadline_unix_seconds`. The fully signed
genesis record must be receipted by every mirror named in the bulletin policy
before contribution generation or publication of any type-2 record begins.

The ceremony identifier is the type-1 content digest. It excludes signatures,
so independent implementations derive one identifier from the same genesis
body. Its signed-record digest pins the one exact signature-bearing genesis
record and is repeated in types 2 and 3. The type-1 record has exactly `N + R`
signatures: every operator followed by every reproducer. The two deadline
fields record declared deadlines but are not trusted timestamps. Deadline and
publication-order compliance are signer-attested operational facts under the
pinned bulletin policy; they cannot be derived cryptographically from the
transcript alone. A valid completed transcript proves the signed closures, not
the correctness of mirror clocks or the absence of private leakage.

### Type 2: contribution-commitment body

Each operator's commitment body is:

```text
ceremony_id[32]
genesis_signed_record_digest[32]
operator_index_u16
operator_public_key[32]
contribution_bytes_u64 = 6442975232
contribution_blake3[32]
contribution_sha256[32]
source_bytes_consumed_u64
rejected_source_bytes_u64
generation_finished_unix_seconds_u64
generator_binary_blake3[32]
generator_binary_sha256[32]
entropy_attestation_bytes_u64
entropy_attestation_blake3[32]
entropy_attestation_sha256[32]
```

`source_bytes_consumed` counts source bytes actually examined by the rejection
sampler and must equal the sum of `contribution_bytes` and
`rejected_source_bytes`. Bytes read into a local buffer but not examined after
the final acceptance are not counted and must be discarded. The record has
exactly one class-0 signature whose index and key match the body. The entropy
attestation names the local CSPRNG, operating-system API, hardware/VM boundary,
generator source revision, and generation operator. It is an exact external
file identified by its length and two digests; it must not contain a CSPRNG
seed, internal state, or other secret. It is an attestation, not proof of
entropy quality.

### Type 3: commitment-set closure body

```text
ceremony_id[32]
genesis_signed_record_digest[32]
participant_count_u16 = N
for operator_index satisfying 0 <= operator_index < N:
    operator_index_u16
    contribution_commitment_signed_record_digest[32]
```

The closure has exactly `N` class-0 signatures in index order. It may be signed
only after every exact type-2 binary record is available from multiple public
mirrors and before any contribution byte is revealed. A missing signature,
changed record, early reveal, or expired deadline aborts the ceremony.

### Type 4: contribution-reveal body

```text
ceremony_id[32]
operator_index_u16
contribution_commitment_signed_record_digest[32]
contribution_bytes_u64 = 6442975232
contribution_blake3[32]
contribution_sha256[32]
reveal_finished_unix_seconds_u64
```

The length and both file digests must equal the type-2 commitment exactly. The
record has exactly one matching class-0 signature. The contribution file is an
external artifact; it is not embedded in the transcript.

### Type 5: reveal-set closure body

```text
ceremony_id[32]
commitment_set_signed_record_digest[32]
participant_count_u16 = N
for operator_index satisfying 0 <= operator_index < N:
    operator_index_u16
    contribution_reveal_signed_record_digest[32]
```

The closure has exactly `N` class-0 signatures in index order. Each signer
attests that every revealed file has the committed exact length, ordinary
BLAKE3 digest, SHA-256 digest, allowed byte range, and exact EOF. This does not
replace each reproducer's independent verification.

### Type 6: final-receipt body

The final receipt binds the published result and the existing model-bank and
Record V2 artifacts directly:

```text
ceremony_id[32]
commitment_set_signed_record_digest[32]
reveal_set_signed_record_digest[32]
payload_bytes_u64 = 6442975232
raw_payload_blake3[32]
raw_payload_sha256[32]
base_input_blake3_root[32]
layer_roots_aggregate[32]
roots_file_bytes_u64
roots_file_blake3[32]
roots_file_sha256[32]
structural_report_bytes_u64
structural_report_blake3[32]
structural_report_sha256[32]
bank_bytes_u64 = 6442975416
bank_file_blake3[32]
bank_file_sha256[32]
manifest_file_bytes_u64
manifest_file_blake3[32]
manifest_file_sha256[32]
manifest_digest[32]
production_suite_digest[32]
pcs_parameter_digest[32]
base_commitment[576]
weight_bank_0_commitment[576]
weight_bank_1_commitment[576]
weight_bank_2_commitment[576]
pcs_commitment_root[32]
model_identity_digest[32]
setup_identity[32]
padded_variables_u32 = 33
record_v2_file_bytes_u64
record_v2_file_blake3[32]
record_v2_file_sha256[32]
record_v2_digest[32]
publisher_reproducer_index_u16 = 0
reproducer_count_u16 = R
for reproducer_index satisfying 0 <= reproducer_index < R:
    reproducer_index_u16
    combiner_binary_blake3[32]
    combiner_binary_sha256[32]
    bootstrap_report_bytes_u64
    bootstrap_report_blake3[32]
    bootstrap_report_sha256[32]
    record_ceremony_report_bytes_u64
    record_ceremony_report_blake3[32]
    record_ceremony_report_sha256[32]
    reproduction_report_bytes_u64
    reproduction_report_blake3[32]
    reproduction_report_sha256[32]
```

The four commitments are the existing canonical 576-byte GT encodings in the
specified order. They must be pairwise distinct. Their root, the manifest,
model identity, setup identity, and Record V2 digest must validate under the
frozen production suite. Both `production_suite_digest` and
`pcs_parameter_digest` must equal the pinned production suite digest.

The raw-payload, base-root, layer-root, and bank-file hashes must be nonzero.
Every final-receipt file identity must have a nonzero length and nonzero BLAKE3
and SHA-256 digests, and each combiner-binary digest must be nonzero. Every
`reproduction_report` identity has the exact `CMFDRP01` V1 length of 4,283
bytes, and those identities are pairwise distinct across the `R` reproducers.

Reproducer 0 is the canonical artifact publisher. Its raw payload, roots,
structural report, bank, manifest, and Record V2 files supply the singular file
fields above after all reproducers agree on their content. Bootstrap and Record
V2 reports remain per-reproducer because they contain host-specific paths and
timings and are not expected to be byte-identical.

The final receipt has exactly `N + R` signatures in roster order. An operator
or reproducer must not sign it until it has verified every field it claims,
including the exact external artifact lengths and hashes. Each reproduction
report identifies the host, source revision, binary hashes, commands, elapsed
times, peak resources, and all independently computed results. Those reports
are audit artifacts, not substitutes for the signed binary receipt.

### `CMFDRP01` reproduction-report V1

Each type-6 `reproduction_report` file identity names one exact canonical
fixed-width report. All integers are little-endian, `FileIdentity` means
`bytes_u64le || blake3[32] || sha256[32]` (72 bytes), and no padding or trailing
bytes are permitted. The V1 field order and cumulative end offsets are:

```text
field                                             bytes   end offset
magic = ASCII "CMFDRP01"                             8            8
version_u16le = 1                                     2           10
report_bytes_u32le = 4283                             4           14
ceremony_id[32]                                      32           46
genesis_signed_record_digest[32]                    32           78
reproducer_index_u16le                                2           80
reproducer_public_key[32]                           32          112
implementation_kind_u8                               1          113
target_id_u16le                                       2          115
source_commit_sha1[20]                              20          135
source_bundle: FileIdentity                         72          207
source_bundle_policy: FileIdentity                  72          279
cargo_lock_blake3[32]                               32          311
cargo_lock_sha256[32]                               32          343
protocol_spec_blake3[32]                            32          375
protocol_spec_sha256[32]                            32          407
reveal_set_prefix_bytes_u64le                         8          415
reveal_set_prefix_derive_key_digest[32]             32          447
reveal_set_prefix_blake3[32]                        32          479
reveal_set_prefix_sha256[32]                        32          511
commitment_set_signed_record_digest[32]             32          543
reveal_set_signed_record_digest[32]                 32          575
combiner_ordered_inputs_digest[32]                  32          607
combiner_binary: FileIdentity                       72          679
combiner_report: FileIdentity                       72          751
bootstrap_report: FileIdentity                      72          823
record_ceremony_report: FileIdentity                72          895
host_environment_report: FileIdentity               72          967
source_extraction_report: FileIdentity              72         1039
command_log: FileIdentity                           72         1111
implementation_lineage_report: FileIdentity         72         1183
raw_payload: FileIdentity                           72         1255
roots_file: FileIdentity                            72         1327
structural_report: FileIdentity                     72         1399
bank_file: FileIdentity                             72         1471
manifest_file: FileIdentity                         72         1543
record_v2_file: FileIdentity                        72         1615
base_input_blake3_root[32]                          32         1647
layer_roots_aggregate[32]                           32         1679
production_suite_digest[32]                         32         1711
pcs_parameter_digest[32]                            32         1743
base_commitment[576]                               576         2319
weight_bank_0_commitment[576]                      576         2895
weight_bank_1_commitment[576]                      576         3471
weight_bank_2_commitment[576]                      576         4047
pcs_commitment_root[32]                             32         4079
manifest_digest[32]                                 32         4111
model_identity_digest[32]                           32         4143
setup_identity[32]                                  32         4175
padded_variables_u32le                               4         4179
record_v2_digest[32]                                32         4211
combine_bytes_processed_u64le                        8         4219
combine_elapsed_micros_u64le                         8         4227
roots_elapsed_micros_u64le                           8         4235
structure_elapsed_micros_u64le                       8         4243
bootstrap_elapsed_micros_u64le                       8         4251
record_elapsed_micros_u64le                          8         4259
total_elapsed_micros_u64le                           8         4267
peak_rss_bytes_u64le                                 8         4275
peak_disk_bytes_u64le                                8         4283
```

`implementation_kind` is 0 for the pinned reference implementation and 1 for
an independent implementation; all other values are reserved and invalid.
Targets remain the genesis registry values 1 and 2. The ordered-input digest is:

```text
BLAKE3-DK("CMFD/FORGEMATRIX/V3/MODEL-REPRODUCTION/COMBINER-INPUTS/V1",
    input_count_u16le ||
    for each exact operator-order input:
        operator_index_u16le || operator_public_key[32] ||
        contribution_bytes_u64le || contribution_blake3[32] ||
        contribution_sha256[32] ||
        contribution_commitment_signed_record_digest[32] ||
        contribution_reveal_signed_record_digest[32])
```

There are three distinct authority levels. Syntax verification checks exact
length, magic, version, EOF, discriminants, nonzero file identities, frozen
production sizes and suite constants, canonical pairwise-distinct Dory
commitments, and every locally derivable commitment, manifest, model, and
Record V2 digest. Context verification additionally requires the opaque
combiner bindings from an independently anchored exact type-5 prefix and one
fresh validated-existing-payload capability. It matches the ceremony, genesis,
source, reproducer roster position and key, exact prefix, both closure digests,
every path-independent ordered-input claim, and the combined output length and
dual hashes. A completed or aborted generic transcript has no such combiner
capability and is ineligible.

The report is still not a signature, transcript, or proof that every external
file was opened. The combiner JSON is deliberately opaque: its exact
`FileIdentity` is bound, but its JSON is neither deserialized nor trusted.
Filesystem paths, durability labels, and timing/resource measurements are
operational audit data, not ceremony authority. The downstream roots,
structure, bank, manifest, Record V2, host, source-extraction, command, and
lineage file identities remain reproducer claims until their exact retained
files are independently authenticated. A type-6 signer must perform those
checks separately. Context verification covers only the transcript and freshly
validated combined-payload boundary; even its downstream final-candidate
projection remains a claim rather than semantic authority over those unopened
files. Artifact and final-candidate projections and same-candidate comparison
are exposed only from the opaque context-verified wrapper, not from a
syntax-only parsed report. This layer deliberately cannot construct a
`ReproducerReceipt`; later type-6 preparation may do that only after every
downstream artifact validator succeeds.

The exact-roster final-candidate validator is the next fail-closed boundary. It
opens every shared, report, source, and audit artifact before parsing any
`CMFDRP01`, requires exactly one ordered report for every frozen reproducer,
freshly validates the combined payload once, validates roots and the structural
report through one retained raw-payload handle, repeats the structural analysis,
and validates the bank/manifest/Record V2 chain once. It then cross-binds every
content identity, root, commitment, manifest field, and Record V2 field before
returning a non-cloneable, non-serializable aggregate. No per-reproducer result
is exposed as authority. Every supplied artifact role must use a distinct path
and retained filesystem identity; even two reproducers using byte-identical
reference binaries must provide distinct physical files. The independently
opened bank-chain validator must retain the same bank filesystem identity as
the final-candidate validator's pre-opened guard. The production entry point
additionally requires an opaque CMFDIL lineage aggregate covering every report
that declares itself independent and proving that at least one such
implementation exists. Its public constructor accepts the complete ordered
reproducer-report roster plus the consumed CMFDIL capabilities in exact
Independent-subset order. It rejects a missing, extra, reordered, wrong-roster,
wrong-ceremony, or wrong-type-5 report/capability binding and retains both each
exact CMFDRP content identity and the real CMFDIL capability. Reference reports
consume no CMFDIL capability. The report's implementation-kind byte alone is
explicitly insufficient. The final-candidate validator reauthenticates all
retained lineage evidence immediately before expensive payload validation and
again in the final guard before the bank-last check; aggregate rechecks preserve
the same bank-last ordering. This checkpoint still does not author type 6.

The keyless type-6 preparation API consumes the exact anchored type-5 prefix
and the non-cloneable retained final-candidate capability. It derives the whole
receipt internally, exposes only public signing material, and retains both
capabilities across external signature collection. Staging requires the exact
ordered `N + R` operator-then-reproducer BIP340 signatures, rederives the body
before accepting them, create-new writes and canonically reopens the record,
then rederives the body again with the bank checked last before confirming the
output. It does not sign, publish, or activate anything. No type-6 wire change
is needed: the existing `ReproducerReceipt.reproduction_report`
`FileIdentity` transitively binds these 4,283 bytes, including the opaque
combiner-report identity.

The library-only completed-transcript staging API accepts one exact retained
type-5 prefix, one canonical signed type-6 record, and an independently
obtained expected ceremony ID. It verifies the exact type-5 sequence and
anchor, the type-6 sequence link, and the ordered full-roster `N + R`
signatures, rebuilds and anchored-parses the canonical Completed transcript,
then create-new writes and canonically reopens it. Both input files and their
trusted parent handles remain retained through the output checks; both inputs
are reauthenticated immediately before the output parent is synchronized and
the file is confirmed. The report exposes the two input content identities,
the completed-transcript identity and derive-key digest, durability, and
publication-pending state. This stage authenticates the signed wire record and
the retained inputs only. It does not freshly accept external candidate,
`CMFDRP01`, or `CMFDIL01` artifacts, sign, provide an operator CLI, publish or
mirror, or activate production consensus.

### `CMFDIL01` independent-lineage approval V1

An `implementation_kind = 1` value inside `CMFDRP01` is a reproducer claim; it
is not authority that an implementation has an independent code lineage. V1
therefore requires the report's `implementation_lineage_report` `FileIdentity`
to name one exact `CMFDIL01` artifact. The lineage artifact contains no
reproduction-report identity or hash, so this binding introduces no hash or
signature cycle. The CMFDRP file identity points to CMFDIL, never the reverse.

CMFDIL is an accountable signed human approval, not a cryptographic proof of
independent authorship. It records exactly which frozen-roster people approved
specific source, build, binary, review, conformance, host, extraction, command,
type-5, and candidate identities. A dishonest or careless roster can still
approve a false lineage statement. Signers must inspect the named evidence and
are accountable for that inspection; the signatures cannot prove how code was
written or that two source trees lack a concealed common origin.

All integers are little-endian and every `FileIdentity` is
`bytes_u64le || blake3[32] || sha256[32]` (72 bytes). The fixed prefix is exactly
1,284 bytes. Each following `RecordSignature` is exactly
`signer_class_u8 || signer_index_u16le || bip340_signature[64]` (67 bytes).
There is no padding and no trailing data. The V1 prefix field order is:

```text
field                                             bytes   end offset
magic = ASCII "CMFDIL01"                            8            8
version_u16le = 1                                     2           10
declared_total_bytes_u32le                            4           14
ceremony_id[32]                                      32           46
genesis_signed_record_digest[32]                    32           78
commitment_set_signed_record_digest[32]             32          110
reveal_set_signed_record_digest[32]                 32          142
reveal_set_prefix: FileIdentity                     72          214
reveal_set_prefix_derive_key_digest[32]             32          246
reproducer_index_u16le                                2          248
reproducer_public_key[32]                           32          280
target_id_u16le                                       2          282
raw_payload: FileIdentity                           72          354
roots_file: FileIdentity                            72          426
base_input_blake3_root[32]                          32          458
layer_roots_aggregate[32]                           32          490
combiner_source_bundle: FileIdentity                72          562
combiner_build_provenance: FileIdentity             72          634
combiner_binary: FileIdentity                       72          706
roots_calculator_source_bundle: FileIdentity        72          778
roots_calculator_build_provenance: FileIdentity     72          850
roots_calculator_binary: FileIdentity               72          922
independent_lineage_review_report: FileIdentity     72          994
conformance_test_report: FileIdentity               72         1066
host_environment_report: FileIdentity               72         1138
source_extraction_report: FileIdentity              72         1210
command_log: FileIdentity                           72         1282
signer_count_u16le                                    2         1284
```

The artifact then contains exactly `signer_count` signatures. A valid artifact
requires `signer_count = N + R` and every genesis-roster operator followed by
every genesis-roster reproducer in exact index order. The minimum `N=3, R=2`
artifact is 1,619 bytes. The maximum `N=16, R=16` artifact is exactly:

```text
1284 + 67 * 32 = 3428 bytes
```

The content digest deliberately excludes only the final signer-count field and
the signatures. `bytes[0..1282]` uses half-open indexing:

```text
content_digest = BLAKE3-DK(
    "CMFD/FORGEMATRIX/V3/MODEL-REPRODUCTION/INDEPENDENT-LINEAGE-ATTESTATION/V1",
    bytes[0..1282])

signature_message = BLAKE3-DK(
    "CMFD/FORGEMATRIX/V3/MODEL-REPRODUCTION/INDEPENDENT-LINEAGE-ATTESTATION/SIGNATURE/V1",
    version_u16le || declared_total_bytes_u32le ||
    content_digest || signer_count_u16le)
```

Every roster member signs the 32-byte `signature_message` with the same
canonical BIP340 rules used by ceremony records. The declared total must equal
both the actual EOF and `1284 + 67 * signer_count`. Reserved signer classes,
wrong order, missing or extra signers, malformed signatures, and any signature
failure invalidate the artifact.

The verifier requires the independently anchored, exact reveal-set-closed
type-5 capability used to context-verify the CMFDRP report. It binds the
ceremony and three signed-record digests, exact type-5 prefix length and
ordinary BLAKE3/SHA-256 identity, its domain-separated transcript digest, the
subject reproducer and key, target, raw payload, roots file, base and layer
roots, combiner binary, and the three CMFDRP audit identities for host,
extraction, and commands. The complete CMFDIL ordinary BLAKE3/SHA-256 file
identity must equal CMFDRP's `implementation_lineage_report`. The CMFDRP kind
must be `Independent`; a reference report cannot acquire independent authority
by attaching this file. A completed type-6 transcript is not accepted in place
of the exact type-5 capability.

All CMFDIL file identities must be nonzero. Both independent source-bundle
identities are rejected if they equal the genesis reference source bundle. The
combiner and roots-calculator binary identities are rejected if either digest
reuses any genesis-pinned reference binary or the pinned structural analyzer.
These checks exclude obvious reuse; they do not establish source independence.
That conclusion remains the signed reviewers' responsibility.

The production validator accepts paths, not caller-supplied bytes. It opens the
CMFDIL artifact and all eleven post-root evidence files before parsing any of
them. All twelve paths must be pairwise-distinct normalized absolute direct
children of trusted private local directories, and their retained filesystem
identities must also be pairwise distinct. Each of the eleven evidence files
is read through its retained handle to the exact signed byte count and EOF and
must match both signed hashes. The validator repeats those complete evidence
reads, then rereads, reparses, rehashes, and identity-checks CMFDIL last. The
returned `VerifiedIndependentLineage` is opaque, non-cloneable, and
non-serializable and retains every file and parent handle. Raw-payload and
roots-file semantic authentication remains the separate final-candidate
validator's responsibility; CMFDIL binds their identities but does not open
those two large candidate artifacts.

### Type 7: abort body

```text
ceremony_id[32]
last_valid_signed_record_digest[32]
phase_u16                    # 1=post-genesis, 2=commit, 3=reveal,
                             # 4=combine, 5=analyze, 6=bootstrap,
                             # 7=reproduce, 8=finalize
reason_code_u16
evidence_file_bytes_u64
evidence_file_blake3[32]
evidence_file_sha256[32]
```

The reason-code registry for v1 is: 1 missing/late record, 2 invalid signature,
3 early/out-of-order reveal, 4 file length mismatch, 5 file digest mismatch,
6 forbidden byte, 7 roster/spec/tool mismatch, 8 structural computation or
encoding failure, 9 independent-reproduction mismatch, 10 filesystem
identity/replacement event,
11 I/O or resource failure, and 12 other fail-closed error. Reason 12 requires
public evidence explaining the error.

`phase` is signature-bound, operator-asserted incident metadata. It identifies
the operation in which the failure occurred, which need not have produced a
valid record in the retained transcript prefix. A missing first commitment may,
for example, produce a phase-2 abort immediately after genesis. Transcript
verification enforces the frozen `1..=8` registry but does not infer or prove a
phase from the valid prefix.

An abort record has one or more valid signatures from the frozen rosters,
ordered by class and index. A participant's refusal to sign an abort cannot
make a failed ceremony valid; the available signed evidence and mirrored
prefix are retained.

Type 7 is valid only after a fully signed genesis exists, so `ceremony_id` and
`last_valid_signed_record_digest` are never zero. A failure before that point
produces no protocol transcript. It should be disclosed as an ordinary signed
incident report, but a would-be genesis digest must not be presented as a
completed ceremony identifier.

## Full-length contribution generation

Each operator generates its own contribution locally after the fully signed
genesis is mirrored as required above and before publishing its type-2 record.
A correct generator performs this exact streaming rejection sampler:

1. Create a new output file; refuse an existing path, link, reparse point, or
   non-regular file.
2. Read bytes from the declared operating-system CSPRNG. Do not initialize that
   CSPRNG from ceremony data, another participant, a compact retained seed, an
   XOF seed, a password, or the final payload.
3. For each source byte in source order, append it if it is `0..=250`; discard
   it if it is `251..=255`. Do not reduce an eight-bit value modulo 251.
4. Stop after exactly 6,442,975,232 accepted bytes. Record the exact number of
   consumed and rejected source bytes.
5. Synchronize the output, close it, reopen it, scan through exact EOF, reject
   any byte above 250, and compute ordinary BLAKE3 and SHA-256 from the reopened
   file.
6. Retain the contribution privately until the commitment-set closure is fully
   signed and publicly mirrored.

If the source bytes are independent uniform bytes, conditioning on acceptance
gives each accepted value probability `1/251`. The expected number of source
bytes consumed is about 6,571,321,352, but no expected-count or histogram test
is an acceptance condition. Rejection sampling is variable length. A generator
must neither stop early nor reroll a statistically unusual but valid stream.

Each operator should use a separately built and reviewed generator where
practical. The feature-gated `dory-v3-model-contribution-generate` reference
command implements this step. One local full-scale qualification has exercised
the reference generator, but a second independently operated qualification and
an actual production contribution run have not yet been completed. No current
file should be represented as a ceremony contribution.

## Keyless type-1-through-type-5 authoring

The current source tree exposes feature-gated, keyless preparation and staging
commands for records 1 through 5. The commands pass warning-denied Windows
compilation and bounded Windows/Linux tests, including one signed `N = 3`,
`R = 2` type-5-terminal prefix staged and reparsed on each platform. This does
not constitute independent review, production-scale qualification, or a real
ceremony. The commands do not publish records, collect mirror receipts, hold
private keys, or change `DORY_V3_SUITE_ACTIVATION_READY` from `false`.

### Strict authoring plans

Every plan is an existing absolute path to at most 256 KiB of strict JSON with
exactly this outer shape:

```json
{
  "record_type": "type_N_name",
  "plan": {}
}
```

Unknown outer or inner fields, missing fields, invalid lowercase hexadecimal,
duplicate entries in prior-record or type-5 contribution-file lists,
noncanonical prior-record order, relative artifact paths, changed inputs, and
trailing or malformed signed-record bytes fail closed. All paths below are
fill-in placeholders. Plan files and every artifact named inside a plan must
already exist at absolute paths. `--record-output` and `--prefix-output` are the
opposite: each must name a new absolute path that does not exist. The direct
parent of every input and output must be owned by the ceremony operator. On
Unix its mode must be exactly `0700`; on Windows it must be on local fixed
storage, owned by the current user, with a protected operator-only DACL that
permits only that user, SYSTEM, and Administrators. Symlinks, reparse points,
and hard-linked inputs fail closed, and no parent-path component may be a
symlink or reparse point. Likewise, replace hexadecimal placeholders with exact
lowercase values; the templates are schemas, not ready-to-sign ceremony
fixtures. Windows JSON paths must escape each backslash, for example
`"D:\\cmfd\\ceremony\\records\\000-type-1-genesis.cmfd"`.

Type 1 fixes every trusted input, deadline, reference target, and ordered
roster. Reference target IDs are ordered and in `1..=2`; operator indices and
reproducer indices each begin at zero and are consecutive. The minimum roster
shown here is three operators and two reproducers:

```json
{
  "record_type": "type_1_genesis",
  "plan": {
    "commit_deadline_unix_seconds": 1789000000,
    "reveal_deadline_unix_seconds": 1789100000,
    "source_commit_sha1": "REPLACE_WITH_40_LOWERCASE_HEX",
    "source_bundle": "/srv/cmfd/ceremony/source-bundle.tar",
    "source_bundle_policy": "/srv/cmfd/ceremony/source-bundle-policy.txt",
    "cargo_lock": "/srv/cmfd/ceremony/Cargo.lock",
    "protocol_spec": "/srv/cmfd/ceremony/dory-v3-model-generation-ceremony-v1.md",
    "bulletin_policy": "/srv/cmfd/ceremony/bulletin-policy.txt",
    "reference_binaries": [
      {
        "target_id": 1,
        "rustc_vv": "/srv/cmfd/ceremony/target-1-rustc-vv.txt",
        "build_environment": "/srv/cmfd/ceremony/target-1-build-environment.txt",
        "binary": "/srv/cmfd/ceremony/target-1/cmfd-consensus"
      }
    ],
    "structural_analyzer_target_id": 1,
    "structural_analyzer_binary": "/srv/cmfd/ceremony/target-1/cmfd-consensus",
    "operators": [
      {
        "index": 0,
        "public_key": "REPLACE_WITH_OPERATOR_0_XONLY_BIP340_KEY_64_LOWERCASE_HEX",
        "identity_document": "/srv/cmfd/ceremony/operator-0-identity.txt"
      },
      {
        "index": 1,
        "public_key": "REPLACE_WITH_OPERATOR_1_XONLY_BIP340_KEY_64_LOWERCASE_HEX",
        "identity_document": "/srv/cmfd/ceremony/operator-1-identity.txt"
      },
      {
        "index": 2,
        "public_key": "REPLACE_WITH_OPERATOR_2_XONLY_BIP340_KEY_64_LOWERCASE_HEX",
        "identity_document": "/srv/cmfd/ceremony/operator-2-identity.txt"
      }
    ],
    "reproducers": [
      {
        "index": 0,
        "public_key": "REPLACE_WITH_REPRODUCER_0_XONLY_BIP340_KEY_64_LOWERCASE_HEX",
        "identity_document": "/srv/cmfd/ceremony/reproducer-0-identity.txt"
      },
      {
        "index": 1,
        "public_key": "REPLACE_WITH_REPRODUCER_1_XONLY_BIP340_KEY_64_LOWERCASE_HEX",
        "identity_document": "/srv/cmfd/ceremony/reproducer-1-identity.txt"
      }
    ]
  }
}
```

Type 2 describes the next operator commitment. `prior_records` is the exact
immutable prefix: signed type 1 followed by every earlier type-2 record in
operator-index order. `source_bytes_consumed` must equal
`6,442,975,232 + rejected_source_bytes`; the generator binary must match the
selected reference target from type 1.

```json
{
  "record_type": "type_2_contribution_commitment",
  "plan": {
    "prior_records": [
      "/srv/cmfd/ceremony/records/000-type-1-genesis.cmfd"
    ],
    "operator_index": 0,
    "contribution_file": "/srv/cmfd/ceremony/private/operator-0.bin",
    "source_bytes_consumed": 6571306075,
    "rejected_source_bytes": 128330843,
    "generation_finished_unix_seconds": 1788900000,
    "generator_target_id": 1,
    "generator_binary": "/srv/cmfd/ceremony/target-1/cmfd-consensus",
    "entropy_attestation": "/srv/cmfd/ceremony/operator-0-entropy-attestation.txt"
  }
}
```

Type 3 has no caller-supplied commitment list. Its exact list is reconstructed
from signed type-2 records. `prior_records` contains type 1 and all `N` type-2
records in canonical order:

```json
{
  "record_type": "type_3_commitment_set",
  "plan": {
    "prior_records": [
      "/srv/cmfd/ceremony/records/000-type-1-genesis.cmfd",
      "/srv/cmfd/ceremony/records/001-type-2-operator-0.cmfd",
      "/srv/cmfd/ceremony/records/002-type-2-operator-1.cmfd",
      "/srv/cmfd/ceremony/records/003-type-2-operator-2.cmfd"
    ]
  }
}
```

Type 4 describes the next operator reveal. Its immutable prefix ends at type 3
for operator 0 and then includes every earlier type-4 record for later
operators. The contribution is fully length-, range-, BLAKE3-, and SHA-256-
checked against that operator's signed type-2 commitment.

```json
{
  "record_type": "type_4_contribution_reveal",
  "plan": {
    "prior_records": [
      "/srv/cmfd/ceremony/records/000-type-1-genesis.cmfd",
      "/srv/cmfd/ceremony/records/001-type-2-operator-0.cmfd",
      "/srv/cmfd/ceremony/records/002-type-2-operator-1.cmfd",
      "/srv/cmfd/ceremony/records/003-type-2-operator-2.cmfd",
      "/srv/cmfd/ceremony/records/004-type-3-commitment-set.cmfd"
    ],
    "operator_index": 0,
    "contribution_file": "/srv/cmfd/ceremony/reveals/operator-0.bin",
    "reveal_finished_unix_seconds": 1789050000
  }
}
```

Type 5 reconstructs its reveal list from the full signed prefix. In addition,
`contribution_files` names every revealed 6,442,975,232-byte contribution in
operator-index order:

```json
{
  "record_type": "type_5_reveal_set",
  "plan": {
    "prior_records": [
      "/srv/cmfd/ceremony/records/000-type-1-genesis.cmfd",
      "/srv/cmfd/ceremony/records/001-type-2-operator-0.cmfd",
      "/srv/cmfd/ceremony/records/002-type-2-operator-1.cmfd",
      "/srv/cmfd/ceremony/records/003-type-2-operator-2.cmfd",
      "/srv/cmfd/ceremony/records/004-type-3-commitment-set.cmfd",
      "/srv/cmfd/ceremony/records/005-type-4-operator-0.cmfd",
      "/srv/cmfd/ceremony/records/006-type-4-operator-1.cmfd",
      "/srv/cmfd/ceremony/records/007-type-4-operator-2.cmfd"
    ],
    "contribution_files": [
      "/srv/cmfd/ceremony/reveals/operator-0.bin",
      "/srv/cmfd/ceremony/reveals/operator-1.bin",
      "/srv/cmfd/ceremony/reveals/operator-2.bin"
    ]
  }
}
```

Type-5 preparation does not trust the earlier type-4 summaries alone. It opens
every contribution under the trusted-filesystem boundary, scans the entire
file twice, enforces exact length, byte range, EOF, BLAKE3, and SHA-256, and
matches those results to the corresponding signed type-2 commitment. Staging
repeats preparation, so it repeats those full contribution scans before it
accepts signatures. Operators must provision time and I/O for both passes in
both operations; bypassing them does not produce a valid staged type-5 record.

### Independent ceremony-ID rule

For type 1, `--expected-ceremony-id` is forbidden on both preparation and
staging. The canonical type-1 `record_content_digest` becomes the ceremony ID.
For every type 2, 3, 4, and 5 operation, `--expected-ceremony-id` is mandatory
and must be obtained independently from the authenticated, signed, published,
and mirrored type-1 record. It must not be copied from the plan, a prior-record
prefix currently being validated, or organizer-supplied command output without
independent mirror authentication. A mismatch fails closed.

### Prepare, sign externally, and stage

Preparation authenticates the plan and every named input, reconstructs the one
canonical body, and prints the plan's dual hashes, `record_content_digest`, the
raw 32-byte `signature_message`, and every exact `required_signer` slot. Type 1
omits the ceremony-ID option:

```text
cmfd-consensus dory-v3-model-ceremony-record-prepare \
  --plan /srv/cmfd/ceremony/plans/type-1.json
```

Types 2 through 5 require the independently authenticated anchor:

```text
cmfd-consensus dory-v3-model-ceremony-record-prepare \
  --plan /srv/cmfd/ceremony/plans/type-N.json \
  --expected-ceremony-id 64_LOWERCASE_HEX_FROM_INDEPENDENT_MIRRORS
```

Every required signer independently reproduces those values, then uses an
external signer or HSM to produce a canonical BIP340 signature over the exact
32-byte message. The signer must sign the raw message; it must not hash the
message again. The ceremony tool has no private-key, seed, key-generation, or
signing option. Never place private keys in a plan, command line, working
directory, log, record file, or bulletin submission.

Staging repeats the complete preparation pass and accepts public signatures
only as `INDEX:128-lowercase-hex`. The exact signer policy is:

| Record | Required external signatures |
|---|---|
| Type 1 | every operator and every reproducer |
| Type 2 | the named operator only |
| Type 3 | every operator |
| Type 4 | the named operator only |
| Type 5 | every operator |

For the minimum three-operator, two-reproducer example, type 1 is staged as:

```text
cmfd-consensus dory-v3-model-ceremony-record-stage \
  --plan /srv/cmfd/ceremony/plans/type-1.json \
  --operator-signature 0:128_LOWERCASE_HEX \
  --operator-signature 1:128_LOWERCASE_HEX \
  --operator-signature 2:128_LOWERCASE_HEX \
  --reproducer-signature 0:128_LOWERCASE_HEX \
  --reproducer-signature 1:128_LOWERCASE_HEX \
  --record-output /srv/cmfd/ceremony/records/000-type-1-genesis.cmfd
```

Types 2 and 4 use their one named operator signature. Types 3 and 5 repeat an
operator signature for every operator. All post-genesis stages include the
independent anchor, for example:

```text
cmfd-consensus dory-v3-model-ceremony-record-stage \
  --plan /srv/cmfd/ceremony/plans/type-2-operator-0.json \
  --expected-ceremony-id 64_LOWERCASE_HEX_FROM_INDEPENDENT_MIRRORS \
  --operator-signature 0:128_LOWERCASE_HEX \
  --record-output /srv/cmfd/ceremony/records/001-type-2-operator-0.cmfd

cmfd-consensus dory-v3-model-ceremony-record-stage \
  --plan /srv/cmfd/ceremony/plans/type-3.json \
  --expected-ceremony-id 64_LOWERCASE_HEX_FROM_INDEPENDENT_MIRRORS \
  --operator-signature 0:128_LOWERCASE_HEX \
  --operator-signature 1:128_LOWERCASE_HEX \
  --operator-signature 2:128_LOWERCASE_HEX \
  --record-output /srv/cmfd/ceremony/records/004-type-3-commitment-set.cmfd
```

The type-4 and type-5 invocations have the same shapes as type 2 and type 3,
respectively, with their own plan and output paths. A missing, duplicate,
extra, wrong-class, wrong-index, malformed, or invalid signature fails closed.

The output path must be a new absolute path in a participant-controlled parent;
an existing path is never overwritten. Staging synchronizes the exact binary
record, reopens it, decodes it, verifies it equals the prepared record, and
reports its ordinary BLAKE3 and SHA-256 plus its signed-record digest. Treat the
record as immutable after staging. Every later plan must name those exact files
in canonical sequence; editing, replacing, reordering, or re-encoding one is a
fatal verification failure.

### Stage the type-5-terminal prefix

After the signed type-5 record has been independently authenticated, stage the
canonical reveal-set-closed prefix. Supply one `--record` for every immutable
record in exact type-1-through-type-5 order. For `N = 3`:

```text
cmfd-consensus dory-v3-model-ceremony-prefix-stage \
  --record /srv/cmfd/ceremony/records/000-type-1-genesis.cmfd \
  --record /srv/cmfd/ceremony/records/001-type-2-operator-0.cmfd \
  --record /srv/cmfd/ceremony/records/002-type-2-operator-1.cmfd \
  --record /srv/cmfd/ceremony/records/003-type-2-operator-2.cmfd \
  --record /srv/cmfd/ceremony/records/004-type-3-commitment-set.cmfd \
  --record /srv/cmfd/ceremony/records/005-type-4-operator-0.cmfd \
  --record /srv/cmfd/ceremony/records/006-type-4-operator-1.cmfd \
  --record /srv/cmfd/ceremony/records/007-type-4-operator-2.cmfd \
  --record /srv/cmfd/ceremony/records/008-type-5-reveal-set.cmfd \
  --expected-ceremony-id 64_LOWERCASE_HEX_FROM_INDEPENDENT_MIRRORS \
  --prefix-output /srv/cmfd/ceremony/records/REVEAL-SET-CLOSED.cmfd
```

The command verifies all signatures and sequence links, requires the exact
`2 * N + 3` record prefix ending at type 5 and EOF, create-new persists it, and
reopens and revalidates the bytes. This is the only staged prefix eligible for
the independently anchored combiner path.

Every successful record or prefix stage reports
`mirror_publication_pending true`. That is not a warning that the file is
partially written; it means local durable staging is complete but protocol
publication is not. The responsible operator must publish the exact staged
bytes and dual hashes to the append-only bulletin, obtain observable receipts
from at least two independently controlled mirrors, download and reauthenticate
each mirrored copy, check for equivocation, and retain those receipts before
advancing the ceremony. None of these authoring commands uploads, mirrors,
declares publication complete, or activates production consensus.

### Prepare and stage the detached transcript attestation

The feature-gated detached-attestation commands accept only an exact,
terminal transcript: either a completed transcript ending at the signed type-6
receipt or an aborted transcript ending at the signed type-7 record and EOF.
The type-5-terminal reveal-set prefix above is deliberately ineligible. The
library API can now assemble and reauthenticate `COMPLETED.cmfd` from the exact
prefix and signed type-6 record, but no operator CLI exists for either type-6
or completed-transcript staging. Detached attestation begins only after
equivalent library orchestration has produced the exact completed file.

Both commands require `--expected-ceremony-id`. Obtain this 32-byte anchor
independently from the authenticated, signed, published, and mirrored type-1
record; never derive it from the transcript being attested. Preparation reads
the transcript through the trusted-filesystem boundary, parses and verifies
the complete record sequence and exact EOF, and then reauthenticates the same
immutable file in a second pass. It prints the transcript file identity,
terminal status, ceremony ID, exact transcript length, derive-key digest,
ordinary BLAKE3, SHA-256, raw 32-byte `signature_message`, and every exact
`required_signer` slot. Every signer must independently reproduce and compare
those values before signing.

A completed transcript automatically requires every frozen operator followed
by every frozen reproducer: all `N + R` signatures. Supplying any
`--aborted-operator-signer` or `--aborted-reproducer-signer` selector for a
completed transcript is an error. Prepare it as:

```text
cmfd-consensus dory-v3-model-ceremony-attestation-prepare \
  --transcript /srv/cmfd/ceremony/records/COMPLETED.cmfd \
  --expected-ceremony-id 64_LOWERCASE_HEX_FROM_INDEPENDENT_MIRRORS
```

An aborted transcript requires the operator to select an explicit, nonempty
subset of the frozen roster. Repeat either selector as needed; every selected
slot must exist in the signed type-1 roster. Selector input order is arbitrary;
the tool canonicalizes slots by signer class and index. Duplicate or
out-of-roster selections fail closed. For example:

```text
cmfd-consensus dory-v3-model-ceremony-attestation-prepare \
  --transcript /srv/cmfd/ceremony/records/ABORTED.cmfd \
  --expected-ceremony-id 64_LOWERCASE_HEX_FROM_INDEPENDENT_MIRRORS \
  --aborted-operator-signer 0 \
  --aborted-reproducer-signer 1
```

The attestation message commits to the signature count but not to the signer
class/index slots themselves. Consequently, the exact aborted signer subset
selected during preparation must be repeated unchanged at staging. The stage
command verifies that every supplied signature exactly matches the subset
supplied to that invocation, but the message alone cannot prove which subset
was shown during an earlier prepare invocation. Operators must therefore retain
and compare the printed signer list out of band. Every selected signer uses an
external signer or HSM to sign the exact raw 32-byte message. Do not hash it
again. These commands accept no private key, seed, key-generation, or signing
input.

Stage a completed attestation by supplying all `N + R` public signatures. For
the minimum `N = 3`, `R = 2` roster:

```text
cmfd-consensus dory-v3-model-ceremony-attestation-stage \
  --transcript /srv/cmfd/ceremony/records/COMPLETED.cmfd \
  --expected-ceremony-id 64_LOWERCASE_HEX_FROM_INDEPENDENT_MIRRORS \
  --operator-signature 0:128_LOWERCASE_HEX \
  --operator-signature 1:128_LOWERCASE_HEX \
  --operator-signature 2:128_LOWERCASE_HEX \
  --reproducer-signature 0:128_LOWERCASE_HEX \
  --reproducer-signature 1:128_LOWERCASE_HEX \
  --attestation-output /srv/cmfd/ceremony/records/COMPLETED.cmfdmta1
```

Stage an aborted attestation with the exact same nonempty selector set used at
preparation and one external signature for each selected slot:

```text
cmfd-consensus dory-v3-model-ceremony-attestation-stage \
  --transcript /srv/cmfd/ceremony/records/ABORTED.cmfd \
  --expected-ceremony-id 64_LOWERCASE_HEX_FROM_INDEPENDENT_MIRRORS \
  --aborted-operator-signer 0 \
  --aborted-reproducer-signer 1 \
  --operator-signature 0:128_LOWERCASE_HEX \
  --reproducer-signature 1:128_LOWERCASE_HEX \
  --attestation-output /srv/cmfd/ceremony/records/ABORTED.cmfdmta1
```

Staging repeats the complete two-pass transcript authentication, reconstructs
the same identity and signing message, verifies the exact signer policy and
every external BIP340 signature, and verifies the canonical detached
attestation before writing. `--attestation-output` must be a new absolute path
inside the trusted ceremony filesystem boundary; an existing path is never
overwritten. The command synchronizes the create-new output, reopens it,
decodes and canonically re-encodes it, re-verifies it against the transcript,
and reauthenticates the transcript once more before reporting success. The
report includes the immutable transcript and attestation file identities,
attestation BLAKE3 and SHA-256, signing message, every canonical staged signer
slot and public key, signer count, durability, and
`mirror_publication_pending true`.

Local staging is not publication. Publish the exact attestation bytes and dual
hashes to the append-only bulletin, obtain and reauthenticate receipts from at
least two independently controlled mirrors, and compare all observed
attestations for equivocation. The commands neither upload artifacts nor prove
receipt timing, mirror agreement, or absence of re-signing. They do not inspect
external artifacts named by a type-6 receipt and do not change production
activation.

## Commit, reveal, and closure sequence

All publications use an append-only public bulletin with at least two
independently controlled mirrors. The bulletin publishes exact binary record
files, their ordinary BLAKE3 and SHA-256 digests, and observable receipt times.
Signatures authenticate content, not time; this publication layer is therefore
an explicit ceremony assumption.

The sequence is:

1. Publish all pinned specifications, binaries, identity documents, rosters,
   deadlines, and the genesis body. Obtain all `N + R` genesis signatures, then
   obtain a receipt for that complete signed record from every pinned mirror.
2. Only after step 1, operators generate privately. Publish type-2 commitment
   records in operator-index order. Publishing a digest is not a reveal.
3. Verify every commitment record from every mirror. Obtain the type-3 `N`-of-
   `N` closure. No contribution byte may have been published or privately
   disclosed to another operator before this closure.
4. Reveal contribution files and type-4 records strictly in operator-index
   order. Operator `i+1` must wait until operator `i`'s complete file has been
   downloaded, length-checked, dual-hashed, range-checked, and mirrored.
5. After every reveal is verified, obtain the type-5 `N`-of-`N` closure.
6. Independent reproducers combine, analyze, bootstrap, and construct Record
   V2 as specified below. They compare results before anyone signs type 6.
7. Publish and sign the type-6 receipt, assemble the exact binary transcript,
   verify exact EOF, publish its derive-key digest plus ordinary BLAKE3 and
   SHA-256, and obtain the detached `N + R` transcript attestation.

Any public out-of-order reveal is fatal. Private leakage may be undetectable and
is addressed only by operator separation, access controls, and external review.

## Canonical N-of-N combination

After the reveal-set closure, each reproducer independently opens the exact `N`
contribution files in operator-index order and verifies both committed file
hashes, exact length, byte range, and EOF. It retains those authenticated file
handles or an equivalent immutable, identity-bound snapshot for combination.
The production combiner accepts only an exact transcript prefix ending at the
fully signed type-5 record. It also requires the expected `ceremony_id` obtained
independently from the authenticated, mirrored genesis; deriving that expected
identifier from the prefix under validation would remove the organizer-intent
trust anchor and is forbidden. The command requires both that prefix file and
the explicit 32-byte expected identifier, reads the prefix through exact EOF
under the 1 MiB protocol cap, and has no path-only production entry point.
Completed and aborted transcript inspection results cannot authorize
combination.

The feature-gated reference invocation is:

```text
cmfd-consensus dory-v3-model-combine \
  --reveal-set-prefix ./REVEAL-SET-CLOSED.cmfd \
  --expected-ceremony-id <64-lowercase-hex-characters> \
  --contribution ./operator-0.bin \
  --contribution ./operator-1.bin \
  --contribution ./operator-2.bin \
  [--contribution ./operator-N.bin ...] \
  --output ./MODEL-PAYLOAD.bin
```

Each repeated contribution path is positionally checked against the matching
signed operator-index claim. Swapping paths whose signed length or digest
claims differ is a verification failure, even though addition modulo 251 is
mathematically commutative. If two operators sign byte-identical contribution
claims, their payloads are content-equivalent and local paths cannot provide
additional cryptographic attribution.

For every payload offset `j` satisfying `0 <= j < 6,442,975,232`:

```text
accumulator_u32 = 0
for operator_index i satisfying 0 <= i < N:
    accumulator_u32 += contribution_i[j]
payload[j] = accumulator_u32 mod 251
```

`N <= 16` makes the maximum pre-reduction sum 4,000, well within `u32`.
Chunking is permitted but may not change this bytewise definition. The combiner
must consume exactly the same offset from every input, reject early EOF and
trailing data, use a create-new output, synchronize it, reopen it, range-check
and dual-hash through EOF, and reauthenticate the inputs after the combine pass.

The read-only existing-payload validator returns a non-cloneable opaque
capability only after that retained-handle procedure succeeds. Its contained
operational report remains serializable for audit, but the public report value
alone is not validation authority and cannot be supplied to reproduction
authoring. The capability retains no file handle or lock after return; type-6
preparation must run this validator freshly and consume that new capability in
the same preparation flow rather than rely on an older result as ongoing path
authority.

The combined file is the raw payload supplied to the existing bootstrap. No
participant-provided root, layer digest, PCS commitment, commitment root, model
identity, or Record V2 value is accepted as input to that bootstrap.

## Frozen root and structural reports

Each reproducer emits an exact binary roots file:

```text
magic[8] = ASCII "CMFDMR01"
version_u16 = 1
ceremony_id[32]
payload_bytes_u64 = 6442975232
raw_payload_blake3[32]
raw_payload_sha256[32]
base_input_blake3_root[32]
layer_count_u32 = 384
for layer_index 0..=383:
    layer_index_u32
    layer_blake3_root[32]
layer_roots_aggregate[32]
EOF
```

The raw, base, and individual layer roots are ordinary BLAKE3. The layer-root
aggregate is exactly:

```text
BLAKE3-DK("CMFD/FORGEMATRIX/V2/LAYER-ROOTS",
    u32_le(384) ||
    for i in 0..=383: u32_le(i) || layer_blake3_root_i[32])
```

The mandatory structural analyzer emits this exact binary report only after it
has scanned the complete payload, observed exact EOF, accepted every byte, and
materialized all 385 section records:

```text
magic[8] = ASCII "CMFDSR01"
version_u16 = 1
ceremony_id[32]
payload_bytes_u64 = 6442975232
raw_payload_blake3[32]
raw_payload_sha256[32]
section_count_u32 = 385
for section in base, then W_0 through W_383:
    section_kind_u8       # 0 = base, 1 = weight layer
    section_index_u32     # 0xffffffff for base, otherwise 0..=383
    rows_u32              # 128 for base, otherwise 4096
    columns_u32 = 4096
    section_bytes_u64
    section_blake3_root[32]
    for value 0..=250:
        byte_count_u64
    constant_rows_u64
    constant_columns_u64
duplicate_row_pairs_u64
duplicate_column_pairs_u64
duplicate_layer_pairs_u64
diagnostic_mask_u32
fatal_mask_u32
EOF
```

For v1, a constant row or column is one whose entries are all equal.
The per-section `constant_rows` and `constant_columns` fields count those
indices in that section. For section `s`, define `duplicate_rows(s)` as the
number of unordered pairs `(a, b)` with `0 <= a < b < rows(s)` whose exact row
byte strings, read in ascending column index, are equal. Define
`duplicate_columns(s)` identically over column indices, with each column byte
string read in ascending row index. The global fields are exactly:

```text
duplicate_row_pairs = sum over all sections s of duplicate_rows(s)
duplicate_column_pairs = sum over all sections s of duplicate_columns(s)
```

Duplicate layers are unordered pairs `(a, b)` with `0 <= a < b < 384` whose
exact 16,777,216-byte matrix strings are equal. A root match must be confirmed
by byte comparison. Every count uses checked `u64` addition.

Early EOF, trailing bytes, a byte above 250, invalid section geometry/order, or
counter overflow produces no completed `CMFDSR01` report. The analyzer instead
emits a separately dual-hashed error-evidence file, and the ceremony publishes
an abort. It must not pad missing sections, emit partial section records, or
encode a sentinel as though the fixed report were complete.

The canonical analyzer error-evidence file is 384 through 448 bytes:

```text
magic[8] = ASCII "CMFDSE01"
version_u16 = 1
ceremony_id[32]
last_valid_signed_record_digest[32]
analyzer_target_id_u16
analyzer_binary_blake3[32]
analyzer_binary_sha256[32]
roots_file_bytes_u64
roots_file_blake3[32]
roots_file_sha256[32]
expected_payload_bytes_u64 = 6442975232
opened_payload_bytes_u64
payload_prefix_bytes_u64
payload_prefix_blake3[32]
payload_prefix_sha256[32]
subject_file_bytes_u64             # zero for report generation
subject_file_blake3[32]            # zero when subject bytes are zero
subject_file_sha256[32]            # zero when subject bytes are zero
operation_u16                      # 1=generate report, 2=validate report
stage_u16                          # 1=input authentication, 2=first analysis,
                                   # 3=second analysis, 4=report encoding,
                                   # 5=report persistence, 6=final recheck
failure_class_u16
failure_code_u16
detail_bytes_u16                   # 0..=64
reserved_u16 = 0
detail[detail_bytes]               # printable ASCII
EOF
```

File identities are `u64` length followed by ordinary BLAKE3 and SHA-256. The
failure code fixes its permitted class, stage, and deterministic length/prefix
relationships; a parser rejects inconsistent combinations. During a failing
analyzer pass, `payload_prefix` commits to every successful forward payload read
before the failure, including a successfully read forbidden or trailing byte.
It is therefore a successfully read prefix, not a claim that every committed
byte passed semantic validation. It excludes later seek-back reads used only to
confirm suspected duplicate rows, columns, or layers. An empty prefix uses the
canonical hashes of the empty byte string.

The anchored generator accepts only an exact, signature-verified transcript
prefix ending at type 5 and EOF, an independently supplied ceremony ID, and an
independently supplied digest of that signed type-5 record. The running
executable must match both analyzer-binary hashes pinned in genesis. It
authenticates the exact canonical roots artifact and its ceremony ID, then lets
the analyzer's two complete passes independently compare the payload with every
claimed root before it can succeed. This ordering is required so a forbidden
byte or payload/root mismatch can produce evidence instead of failing before
the observed analyzer runs. The command reserves distinct create-new report and
evidence paths. On a mapped failure, it
synchronizes, reopens, parses, dual-hashes, and confirms the exact `CMFDSE01`
file before returning an unsigned type-7 body and the existing transcript
signature message. It never signs, appends, or publishes a record. External
operator or HSM tooling must sign the returned message under the frozen roster
policy.

Local type-7 construction is split into three keyless, resumable operations:

1. `abort-prepare` reauthenticates the exact type-5 prefix, independent
   ceremony anchors, retained payload, roots, and `CMFDSE01` evidence, then
   prints the canonical 32-byte BIP340 raw-signing message. It accepts no key,
   seed, or private-key file.
2. `abort-record-stage` accepts only public `INDEX:128-lowercase-hex`
   operator/reproducer signature tuples. It reconstructs the body rather than
   trusting caller-supplied body fields, canonically orders the signatures,
   verifies the frozen roster policy through the full transcript verifier, and
   create-new persists one exact signed type-7 record.
3. `abort-transcript-stage` consumes that immutable signed record and
   create-new persists a complete terminal aborted-transcript snapshot. It
   reauthenticates every external input before confirming the output.

Transcript staging is not a literal append to the type-5 file. The canonical
header's record count and total length must change, so the implementation
creates a new snapshot, requires header bytes `0..12` and the original record
region to remain byte-identical, and requires the terminal bytes to equal the
staged record exactly. After a successful record-stage report, the valid record
remains available while transcript staging is retried. An abrupt process or
power loss can leave an unconfirmed final-named file because outputs are
create-new; operators must authenticate and retain or quarantine that file,
then use a fresh output path rather than overwrite it. The results
`record_staged` and `transcript_staged` describe local durable files,
not public publication. Bulletin submission, independent mirror receipts,
equivocation monitoring, and the detached transcript attestation remain
separate external steps. Because that attestation commits to the final
signature count and transcript bytes, it requires a second signing round after
the type-7 signer set is frozen.

Hashing the running executable file (`/proc/self/exe` on Linux and the path
returned by `current_exe` on other supported hosts) detects accidental binary
drift on a trusted host; it is not remote attestation and does not prove the
in-memory image against a malicious process running as the ceremony account.
The operator-private host and account boundary remains mandatory.

The abort verifier accepts only an exact signed transcript ending at type 7 and
EOF, with type 5 immediately before it. It independently checks both anchors,
authenticates the exact roots and external evidence artifacts, and requires the
type-7 phase, reason, length, BLAKE3, and SHA-256 to match the evidence. For a
reproducible retained failed payload, it also rechecks the stable file identity
and length and streams the recorded prefix twice, requiring both prefix hashes
to match; a forbidden-byte claim additionally requires such a byte in that
prefix. A mismatch in a deterministic subject claim fails closed. A transient
I/O, resource, permission, or identity claim whose recorded observation is no
longer reproducible verifies only as `attestation_only`, never as a retained
payload observation.

The inherited type-7 policy requires one or more valid signatures from either
frozen roster; it is evidence of at least one roster member's attestation, not a
threshold or full-committee vote. A pre-read, transient I/O, resource, or
identity failure may have no reproducible subject prefix and remains a signed
attestation. Deterministic subject claims gain the independent length/prefix
binding above, but external reproduction is still required to establish the
full semantic cause. Stable short or long files are reported as a generic file
length mismatch because the trusted file opener rejects their metadata before
analysis; the more specific early-EOF and trailing-byte codes describe changes
or unusual read behavior observed after opening.

The reference CLI exposes analyzer generation, keyless type-7 staging, and
final verification as:

```text
cmfd-consensus dory-v3-model-structure-generate-anchored \
  --reveal-set-prefix ABSOLUTE-TYPE5-PREFIX \
  --expected-ceremony-id LOWERCASE-64-HEX \
  --expected-last-valid-signed-record-digest LOWERCASE-64-HEX \
  --payload ABSOLUTE-PAYLOAD --roots ABSOLUTE-ROOTS \
  --structure-output NEW-ABSOLUTE-REPORT \
  --error-evidence-output NEW-ABSOLUTE-EVIDENCE

cmfd-consensus dory-v3-model-structure-abort-prepare \
  --reveal-set-prefix ABSOLUTE-TYPE5-PREFIX \
  --expected-ceremony-id LOWERCASE-64-HEX \
  --expected-last-valid-signed-record-digest LOWERCASE-64-HEX \
  --payload ABSOLUTE-PAYLOAD --roots ABSOLUTE-ROOTS \
  --error-evidence ABSOLUTE-EVIDENCE

cmfd-consensus dory-v3-model-structure-abort-record-stage \
  --reveal-set-prefix ABSOLUTE-TYPE5-PREFIX \
  --expected-ceremony-id LOWERCASE-64-HEX \
  --expected-last-valid-signed-record-digest LOWERCASE-64-HEX \
  --payload ABSOLUTE-PAYLOAD --roots ABSOLUTE-ROOTS \
  --error-evidence ABSOLUTE-EVIDENCE \
  --operator-signature INDEX:128-LOWERCASE-HEX \
  --record-output NEW-ABSOLUTE-TYPE7-RECORD

cmfd-consensus dory-v3-model-structure-abort-transcript-stage \
  --reveal-set-prefix ABSOLUTE-TYPE5-PREFIX \
  --expected-ceremony-id LOWERCASE-64-HEX \
  --expected-last-valid-signed-record-digest LOWERCASE-64-HEX \
  --payload ABSOLUTE-PAYLOAD --roots ABSOLUTE-ROOTS \
  --error-evidence ABSOLUTE-EVIDENCE \
  --signed-abort-record ABSOLUTE-TYPE7-RECORD \
  --transcript-output NEW-ABSOLUTE-TYPE7-TRANSCRIPT

cmfd-consensus dory-v3-model-structure-abort-verify \
  --aborted-transcript ABSOLUTE-TYPE7-TRANSCRIPT \
  --expected-ceremony-id LOWERCASE-64-HEX \
  --expected-last-valid-signed-record-digest LOWERCASE-64-HEX \
  --payload ABSOLUTE-PAYLOAD --roots ABSOLUTE-ROOTS \
  --error-evidence ABSOLUTE-EVIDENCE
```

An evidence-producing analyzer run exits unsuccessfully after printing
`outcome abort_evidence_prepared`; this is intentional so automation cannot
mistake a preserved incident for a completed structural report. Successful
abort verification also prints either
`subject_binding retained_payload_observation_verified` or
`subject_binding attestation_only`, so machine consumers do not confuse a
signed incident with an independently bound retained length and read prefix.

The `diagnostic_mask` bits are: bit 0 at least one constant row/column, bit 1 at
least one duplicate row/column pair, bit 2 at least one duplicate layer pair,
and bits 3..=31 reserved and required to be zero. It must agree exactly with the
counters. In a completed post-scan report, `fatal_mask` bit 0 means at least one
section's 251 histogram counts do not sum to `section_bytes`; bit 1 means a
recomputed raw, base, layer, or layer-aggregate root differs from the separately
generated roots file; and bits 2..=31 are reserved and required to be zero.
Completion requires an exact report through EOF and `fatal_mask == 0`.

The 251-bin histograms and all diagnostic counters are report-only in v1 and
have no rejection threshold. Conditioning completion on the appearance of an
otherwise valid random payload would create a selection channel and invalidate
an unqualified uniform-output claim. A nonzero diagnostic mask must therefore
be published and reviewed, but it does not permit a reroll under v1. No
operator may reject and reroll because a valid histogram or structural
diagnostic appears unusual.

These checks are the frozen minimum, not a claim that every useful structural
analysis has been identified. Rank, correlation, compression, and accelerator-
specific analyses may be published as additional reports, but after genesis
they cannot become new pass/fail rules for this ceremony. If external review
rejects the resulting candidate or requires another mandatory rule, v1 ends
publicly without an activated model. Any later protocol must use a new version,
new ceremony identifier, and disclosed rationale; it must not disguise a
post-hoc search for a preferred output.

The feature-gated reference implementation now generates and separately
validates both fixed-width artifacts through the
`dory-v3-model-roots-generate`, `dory-v3-model-roots-validate`,
`dory-v3-model-structure-generate`, and
`dory-v3-model-structure-validate` commands. Every artifact path must be an
absolute direct child of an operator-private local directory. The roots
authority is created only after the complete payload has been reproduced; a
parsed roots file alone cannot authorize a structural report. Full-length
qualification on the eventual combined payload, an independently authored
reproducer, and independent external review remain pre-ceremony blockers.

## Model-bank bootstrap and Record V2

The model-bank bootstrap and Record V2 tooling begin only after the bound
combiner has produced a combined raw payload.
Genesis pins one or both target-specific distributed reference executables.
The executable used for the canonical published artifacts must match its
target's genesis hashes. Independently built executables are recorded in
reproduction reports and must use the same verified source bundle and pinned
lockfile; their binary hashes need not match without a reproducible build
proof.

After verifying the exact genesis source-bundle policy, inspect and extract the
exact source bundle under that policy. Verify the extracted `Cargo.lock` and
protocol-specification digests again and use the new extraction root as the
working directory. A mutable repository checkout or the Git locator alone is
not an acceptable substitute. With locked dependencies, build and run on
Windows PowerShell:

```text
cargo build --release --locked -p cmfd-consensus `
  --no-default-features `
  --features dory-bls12-381-prototype

.\target\release\cmfd-consensus.exe dory-v3-model-bank-bootstrap `
  --payload .\MODEL-PAYLOAD.bin `
  --bank-output .\MODEL-V2.bank `
  --manifest-output .\MODEL-V2.manifest.json

.\target\release\cmfd-consensus.exe dory-v3-model-record-ceremony `
  --bank .\MODEL-V2.bank `
  --manifest .\MODEL-V2.manifest.json `
  --output .\DORY-V3-MODEL-RECORD-V2.json
```

On Linux:

```text
cargo build --release --locked -p cmfd-consensus \
  --no-default-features \
  --features dory-bls12-381-prototype

./target/release/cmfd-consensus dory-v3-model-bank-bootstrap \
  --payload ./MODEL-PAYLOAD.bin \
  --bank-output ./MODEL-V2.bank \
  --manifest-output ./MODEL-V2.manifest.json

./target/release/cmfd-consensus dory-v3-model-record-ceremony \
  --bank ./MODEL-V2.bank \
  --manifest ./MODEL-V2.manifest.json \
  --output ./DORY-V3-MODEL-RECORD-V2.json
```

The output names are recommendations, not semantic identifiers. All inputs use
absolute paths in the logged execution, all output paths must be absent, and
the bank and manifest paths must differ. Capture each command's exact stdout
JSON with a create-new wrapper, synchronize it, and hash its exact bytes as the
bootstrap and record-ceremony reports. Shell redirection that silently
overwrites an existing report is forbidden.

The bootstrap validates the production geometry and every payload byte,
derives the ordinary raw BLAKE3 root and all layer roots, derives the four
ordered `n = 33` Dory commitments and their commitment root, emits the
184-byte-header bank and strict manifest JSON, and reopens and authenticates
the published artifacts before success. It does not generate entropy and does
not accept caller-supplied roots or commitments.

The Record V2 command authenticates the bank through two full passes and
create-new writes the strict Record V2 JSON. Those two passes are valuable
internal defense, but they are not independent operators or independent
implementations. The canonical Record V2 is exactly these 166 bytes:

```text
record_version_u16le = 2
suite_digest[32]
manifest_digest[32]
model_identity_digest[32]
setup_identity[32]
padded_variables_u32le = 33
commitment_root[32]
```

Its protocol identity is:

```text
BLAKE3-DK("CMFD/FORGEMATRIX/V3/DORY-MODEL-COMMITMENT-RECORD/V2",
    exact 166 canonical bytes)
```

The canonical digest, rather than JSON whitespace, is the Record V2 identity.
The exact published strict JSON file is audit-only but is also dual-hashed for
distribution and recorded in type 6.

The library's existing-chain validator opens the bank, manifest, and Record V2
before parsing any of them and retains all three no-follow file handles plus
their trusted parent handles. It requires pairwise-distinct absolute normalized
direct-child paths, exact canonical pretty JSON followed by one line feed,
manifest equality across both JSON artifacts, and the pinned production setup.
Here, canonical artifact JSON means the repository's currently frozen Rust
`serde_json::to_vec_pretty` byte encoding plus that line feed; it is guarded by
known-answer tests and is not yet claimed as a language-neutral JSON profile.
It then rederives Record V2 twice through the same retained bank handle. Each
complete pass independently counts and computes BLAKE3 and SHA-256 over the
exact 6,442,975,416 bytes and exact EOF. Inter-pass and final identity rechecks,
a final reread and reparse of both small files, and a bank-last recheck are
required before the non-cloneable, non-serializable capability is returned. It
is consumed only by the capability-bound type-6 preparation and staging API;
there is no type-6 operator CLI yet. The private-workspace rule still excludes
same-user concurrent writers; in particular, a retained read handle on Unix is
not an exclusive content lock.

The bank contains the 184-byte header followed by the payload, for exactly
6,442,975,416 bytes and exact EOF. The bootstrap publishes bank and manifest as
two files and truthfully does not claim multi-file crash atomicity. After a
crash or interruption, quarantine all partial names and restart the bootstrap
with fresh absent output names; never treat the presence of one output as
completion.

## Independent reproduction and comparison

Before a type-6 receipt can be signed, every reproducer independently:

1. obtains the authoritative source bundle and source-bundle policy from more
   than one mirror, verifies both exact lengths and dual hashes, inspects and
   extracts the bundle under that policy, and checks the pinned `Cargo.lock`
   and protocol-specification files;
2. obtains all exact contribution files and binary records from more than one
   mirror;
3. validates genesis, every signature, closure, length, full-file digest,
   allowed byte, and EOF;
4. recombines the payload without accepting an expected output digest as an
   input;
5. derives the raw, base, and 384 layer roots and the root aggregate;
6. runs the frozen structural analysis;
7. runs the bootstrap and Record V2 chain, or independently implements and
   validates the same encodings and derivations; and
8. reports exact artifacts, roots, commitments, canonical record digest,
   timings, peak memory, disk use, source-bundle length and hashes, Git locator,
   extraction inspection, and executable hashes.

All reproducers must obtain byte-identical raw payloads, roots files, structural
reports, model banks, and bootstrap-derived fields. Reference implementations
must also emit byte-identical strict manifest and Record V2 JSON. An independent
implementation may use a different audit-only JSON serialization, but it must
parse the published strict JSON and derive the identical header bytes,
commitments, model identity, 166-byte canonical Record V2, and record digest.

At least two hosts and two administrators are required, and at least one
combiner/root implementation must have an independent code lineage. A mismatch
is fatal even if an organizer believes one result is probably correct. Diagnose
only after publishing an abort; do not choose the preferred output under the
same ceremony identifier.

## Abort and restart rules

The ceremony aborts on any missing or late required record, invalid signature,
roster or order change, early/out-of-order reveal, changed specification or
pinned binary, contribution replacement, wrong length, forbidden byte, hash
mismatch, exact-EOF failure, structural fatal bit, path identity event,
bootstrap or Record V2 failure, independent-reproduction mismatch, or inability
to retain the public evidence.

After abort:

- publish the type-7 record and all available evidence;
- retain and mirror the failed transcript prefix and artifact digests;
- do not patch, truncate, append to, rename as valid, or reuse any contribution;
- do not remove, replace, or reorder an operator;
- do not fill a missing contribution with zeroes or reduce `N`; and
- begin only with a new genesis, new ceremony identifier, new deadlines, and
  freshly generated full-length contributions from every operator.

Rerunning deterministic combination and verification on the same closed reveal
set is required reproduction, not a restart. Selective abort remains possible,
especially for the final revealer. Its visibility is the mitigation; v1 makes
no cryptographic claim that it prevents abort bias. Consequently, the exact
uniformity statement applies to the pre-selection candidate sum under its
independence assumptions, not to the distribution conditioned on successful
ceremony completion.

## Filesystem and operational boundary

All generation, combination, bootstrap, and Record V2 work must occur on a
local, operator-owned filesystem in a directory that other users cannot write.
Do not use a shared temp directory, network filesystem, cloud-sync directory,
or directory where an untrusted account can create links or replace names.
Reject symlinks, reparse points, non-regular files, unexpected hard links, and
cross-filesystem publication.

The existing bootstrap retains file identities and performs fail-closed
rechecks, but pathname operations cannot make a hostile shared directory fully
race-proof. The Record V2 and external ceremony tools have their own path and
crash boundaries. Directory ownership and isolation are mandatory even when a
tool reports success. Preserve read-only copies of every published artifact on
independently controlled storage.

Use create-new semantics everywhere. Synchronize file contents and, where the
platform supports it, the containing directory before publication. After long
passes, rehash retained handles and recheck that the published regular-file
link still names the authenticated file. Cleanup must never delete a path that
no longer identifies the tool's own temporary artifact.

## Resource preflight

One contribution or final raw payload is 6,442,975,232 bytes
(6.00048828125 GiB). The bank is 6,442,975,416 bytes. For the minimum `N = 3`,
the three contributions occupy 19,328,925,696 bytes (18.00146484375 GiB).
Keeping the three contributions, final payload, and bank simultaneously
requires at least 32,214,876,344 bytes (30.0024415776134 GiB), before reports,
temporary publication names, independent copies, filesystem reserve, or
backups.

For arbitrary `N`, the contributions, final payload, and bank alone require:

```text
(N + 2) * 6,442,975,232 + 184 bytes
```

At `N = 16`, that floor is 115,973,554,360 bytes (about 108.0088 GiB). The
minimum `N = 3` workspace should preflight at least 64 GiB, but that is not a
general ceremony requirement. Each workspace must preflight the formula for
its frozen `N`, then add space for temporary publication names, reports,
filesystem reserve, recovery, and any local mirrors; a 16-operator workspace
should provision at least 160 GiB before additional retained copies. The
expected CSPRNG input per contribution is about 6,571,321,352 bytes, but it is
variable and may be streamed without retention. All tools must use bounded
streaming rather than loading contributions or the payload into memory.

The bootstrap and Record V2 commands make multiple complete passes over a
roughly 6 GiB artifact and derive production `n = 33` commitments. No runtime,
RAM peak, accelerator requirement, or completion estimate is promised by this
document. Operators must run a non-ceremony qualification on the named hardware
and filesystem first, record actual resource ceilings, and provision margin
for a clean abort. A GPU is not required merely to validate or relay ordinary
node transactions; this ceremony is a separate one-time production-artifact
operation.

### Non-ceremony proof-qualification request

The feature-gated `dory-v3-qualify-request` command evaluates exactly one
caller-selected nonce against an authenticated production bank. Its strict seed
JSON contains only a complete block challenge and `nonce`; it cannot contain a
claimed final-activation digest or work digest. The command validates the
production Record V2, reauthenticates the complete bank, executes all 384 model
layers with the consensus-owned CPU path, derives both digests, enforces the
block target, removes its authenticated execution scratch, and only then
creates, syncs, reopens, and byte-checks the request output.

This command is a one-nonce evaluator, not a CPU mining loop. For an unchanged
pipeline qualification, use a fixed nonce such as `0` and a target containing
32 bytes of `255`; every computed digest then meets the target. A real mining
target needs a separate batched accelerator search, whose result must still be
replayed by the CPU verifier. The subsequent `dory-v3-qualify` command performs
its own Record V2 validation, bank authentication, and full winning-claim CPU
replay. A request generated from a single qualification payload is evidence for
the proof toolchain only. It is not a combined ceremony model or a signed
type-5 ceremony prefix.

At the frozen production geometry, request generation reads the
`6,442,975,416`-byte bank twice, performs `824,633,720,832` integer
multiply-accumulates for the selected nonce, and preflights an exact
`807,453,072`-byte authenticated execution artifact. Runtime, peak RSS, and
filesystem behavior must be measured on the qualification host rather than
inferred from these operation and byte counts.

## Implementation inventory and remaining gates

Already implemented in this repository:

- the seedless 184-byte-header model-bank V2 codec and strict manifest parser;
- streaming payload length, range, root, layer-root, and exact-EOF validation;
- deterministic transparent Dory `n = 33` setup derivation;
- derivation of the four ordered production commitments, commitment root,
  model identity, and canonical Record V2 digest;
- the feature-gated, fail-closed full-length OS-CSPRNG rejection-sampling
  contribution generator, including one successful local production-length
  qualification on 2026-08-24 that generated and twice reread all
  `6,442,975,232` bytes, range-checked every byte, and independently matched
  BLAKE3 and SHA-256 before removing the temporary artifact;
- the feature-gated exact binary transcript encoder/parser, BIP340 signature
  verifier, detached-attestation verifier, and independently anchored exact
  type-5-prefix capability;
- feature-gated keyless type-1-through-type-5 plan preparation,
  external BIP340 signature verification, create-new immutable signed-record
  staging, and type-5-terminal prefix staging, with bounded Windows/Linux
  `N = 3`, `R = 2` tests; this does not assert independent review or
  production qualification of those commands;
- feature-gated keyless detached-transcript-attestation preparation and
  create-new staging, with external BIP340 signatures, independent
  ceremony-ID anchoring, strict completed-versus-aborted signer policy, and
  trusted-filesystem reauthentication, with 14 bounded authoring tests passing
  on each Windows and Ubuntu 22.04 plus warning-denied Clippy and both new CLI
  help paths; this is not independent review or production qualification, and
  it neither authors type 6 nor stages a final completed transcript;
- the feature-gated, identity-safe streaming modular combiner bound exclusively
  to that anchored type-5-prefix capability, with three-pass signed-claim
  authentication and ceremony-bound operational reporting;
- the fixed-width `CMFDRP01` V1 reproduction-report codec, keyless
  capability-derived authoring, strict syntax and derived-field validation,
  exact type-5/sealed-combiner contextual verification, immutable artifact and
  final-candidate projections, and bounded known-answer, capability-boundary,
  mutation, context, completed, and aborted tests;
- the exact-roster retained final-candidate validator plus capability-only
  type-6 preparation and create-new signed-record staging. Every receipt field
  is projected internally, same-ceremony alternate type-5 forks are rejected,
  full-roster signatures are exact and ordered, and retained artifacts are
  rechecked with the bank last before and after canonical output reopen. A
  dedicated parser requires an exact ceremony-ID-anchored Completed transcript.
  Library-only completed-transcript staging retains and reauthenticates the
  exact type-5 prefix and signed type-6 record, verifies the exact full-roster
  sequence, and create-new reopens the canonical result before confirmation;
  it does not freshly accept the external candidate artifacts, sign, publish,
  mirror, activate, or provide an operator CLI;
- the exact `CMFDMR01` roots and `CMFDSR01` structural-report codecs,
  create-new generators, full-payload validators, and operator commands, backed
  by a shared trusted-filesystem boundary that retains and rechecks parent and
  file identities;
- the exact `CMFDSE01` structural-analyzer error-evidence codec, create-new
  persistence, independently anchored type-5 generation authority, prepared
  unsigned type-7 abort, external-signature verifier, create-new signed-record
  and successor-transcript staging, and signed type-7 evidence verifier;
- the fail-closed `dory-v3-model-bank-bootstrap` command;
- the two-pass `dory-v3-model-record-ceremony` command;
- the retained-handle existing production bank + strict manifest + Record V2
  validator, including two complete same-handle commitment derivations and
  dual whole-file identities; and
- the one-nonce, exact-CPU `dory-v3-qualify-request` generator with strict
  create-new output and an independently replaying `dory-v3-qualify` consumer.

Not implemented or not completed by this document:

- independent external review and a second independently operated full-scale
  qualification of the contribution generator;
- public append-only bulletin submission, independently mirrored expected
  ceremony-ID tooling, receipt/equivocation handling, and independent external
  review of the transcript and detached-attestation implementation;
- type-6 and completed-transcript operator CLI integration plus an
  operator-scale rehearsal of the existing library APIs;
- independent security review and an operator-scale rehearsal of the keyless
  type-1-through-type-5 authoring and prefix-staging paths;
- independent external review and a production-scale qualification of the
  reference combiner;
- external signature collection, public append-only publication, and
  independent mirroring of a locally staged type-7 abort record;
- a full-length qualification of the roots and structural-report tools on a
  production-geometry combined payload, plus an independently authored
  reproduction implementation;
- operator/reproducer rosters, public identity documents, bulletin mirrors,
  the authoritative source bundle and policy, source/binary hashes, and actual
  ceremony artifacts;
- production-scale resource measurements for the complete chain; and
- independent cryptographic review, implementation audit, structural review,
  and the remaining activation gates in `SECURITY.md`.

The next minimal implementation slice adds type-6 and completed-transcript CLI
integration around the existing library APIs, cross-platform validation, and
an operator-scale rehearsal of the keyless record and detached-attestation
authoring paths. That is followed by public
append-only transcript publication with independent mirror receipts and
production-scale roots, structure, combiner, request, and proof qualification.
The transcript, generator, combiner, and new report tools still require
independent external review before generating real contributions. A successful
run of the current bootstrap or one local generator qualification is not a
completed ceremony.

## Operator completion checklist

A ceremony is complete only when all of the following are public and mutually
consistent:

- the signed genesis and frozen ordered rosters;
- the exact authoritative source bundle and policy, their lengths and dual
  hashes, safe entry inventory, independent extraction/inspection records, and
  mirror receipts;
- `N` dual-hashed 6,442,975,232-byte contribution files and their signed commit
  and reveal records;
- signed commitment-set and reveal-set closures;
- the byte-identical combined raw payload from every reproducer;
- the exact roots file, structural report, bank, strict manifest, Record V2,
  per-reproducer bootstrap and record-ceremony reports, and reproduction
  reports;
- matching raw root, base root, all 384 layer roots, layer aggregate, four
  ordered commitments, commitment root, model identity, setup identity,
  manifest digest, and canonical Record V2 digest;
- the `N + R` signed final receipt; and
- the exact binary transcript with derive-key, ordinary BLAKE3, and SHA-256
  digests and the detached `N + R` attestation on independent mirrors.

Even then, the result is a candidate production model artifact. Production
activation remains off until external reviewers accept this protocol and its
implementations and every remaining mainnet gate is independently satisfied.
