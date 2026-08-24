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
command implements this step, but its ignored full-scale qualification and an
actual production contribution run have not yet been executed. No current file
should be represented as a ceremony contribution.

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
trust anchor and is forbidden.

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

The structural analyzer named in genesis is not yet implemented in this
repository. That is a pre-ceremony blocker.

## Model-bank bootstrap and Record V2

The existing Rust tooling begins only after a combined raw payload exists.
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

## Implementation inventory and remaining gates

Already implemented in this repository:

- the seedless 184-byte-header model-bank V2 codec and strict manifest parser;
- streaming payload length, range, root, layer-root, and exact-EOF validation;
- deterministic transparent Dory `n = 33` setup derivation;
- derivation of the four ordered production commitments, commitment root,
  model identity, and canonical Record V2 digest;
- the feature-gated, fail-closed full-length OS-CSPRNG rejection-sampling
  contribution generator, not yet executed at production length;
- the fail-closed `dory-v3-model-bank-bootstrap` command; and
- the two-pass `dory-v3-model-record-ceremony` command.

Not implemented or not completed by this document:

- full-scale execution and independent external review of the contribution
  generator;
- the exact binary record/transcript encoder, parser, signature verifier, and
  append-only publication tooling;
- the identity-bound streaming modular combiner;
- the exact roots-file and structural-report generators and validators;
- an independently authored reproduction implementation;
- operator/reproducer rosters, public identity documents, bulletin mirrors,
  the authoritative source bundle and policy, source/binary hashes, and actual
  ceremony artifacts;
- production-scale resource measurements for the complete chain; and
- independent cryptographic review, implementation audit, structural review,
  and the remaining activation gates in `SECURITY.md`.

The next minimal implementation slice is a fixture-tested ceremony toolset for
the exact binary formats, BIP340 record verification, identity-bound streaming
combiner, and frozen reports, plus full-scale qualification and review of the
create-new generator. It must be reviewed before generating real contributions.
A successful run of the current bootstrap alone is not a completed ceremony.

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
