//! Dedicated testnet direct-proof codec and CPU verifier.
//! The old three BaseFold arguments are absent from the wire and are never
//! consulted for acceptance. The v1 codec is reused only to parse its pinned
//! public relation/opening layout with zero-filled, ignored legacy slots.
use crate::forgematrix_v4_basefold::{
    ForgeMatrixV4Challenger as Challenger, ForgeMatrixV4Digest as Digest,
    ForgeMatrixV4Extension as Ext, ForgeMatrixV4Field as Felt,
    ForgeMatrixV4OpeningClaim as OpeningClaim, ForgeMatrixV4OpeningCommitment as Commitment,
    ForgeMatrixV4OpeningReductionProof as OpeningProof,
    ForgeMatrixV4TranscriptStatement as Statement, forgematrix_v4_transcript,
};
use crate::forgematrix_v4_proof::{
    ForgeMatrixV4TransparentProof, forgematrix_v4_activation_evaluation,
    forgematrix_v4_final_activation_digest, forgematrix_v4_initial_activation_evaluation,
    forgematrix_v4_mask_evaluation,
};
use crate::forgematrix_v4_proof_codec::{
    FORGEMATRIX_V4_TRANSPARENT_PROOF_BYTES, decode_forgematrix_v4_transparent_proof,
    encode_forgematrix_v4_transparent_proof,
};
use crate::forgematrix_v4_relations::{
    bind_forgematrix_v4_commitments, finalize_forgematrix_v4_bank_opening_claims,
    forgematrix_v4_cubic_opening_claims, forgematrix_v4_final_opening_claim,
    forgematrix_v4_matrix_opening_claims, forgematrix_v4_matrix_terminal_layer,
    forgematrix_v4_shift_boundary_opening_claim, forgematrix_v4_shift_boundary_point,
    forgematrix_v4_shift_opening_claim, sample_forgematrix_v4_cubic_point,
    sample_forgematrix_v4_final_point, sample_forgematrix_v4_matrix_point,
    verify_forgematrix_v4_cubic_relation, verify_forgematrix_v4_matrix_relation,
    verify_forgematrix_v4_shift_relation,
};
use anyhow::{Context, Result, bail, ensure};
#[path = "forgematrix_v4_direct_reduction.rs"]
pub mod reduction;
pub use direct::{DirectBasefoldProof, ReductionProof};
use miniz_oxide::{deflate::compress_to_vec_zlib, inflate::decompress_to_vec_zlib_with_limit};
use reduction as direct;
use slop_algebra::AbstractField;
use slop_challenger::{CanObserve, FieldChallenger};
use slop_sumcheck::partially_verify_sumcheck_proof;

pub const HEADER_BYTES: usize = 96;
pub const TOP_BYTES: usize = 16 + 2_097_152;
pub const BANK_PUBLIC_BYTES: usize = 32 + 9_344 + 5_872;
pub const LEGACY_OPENING_BYTES: usize = 3_300_008;
pub const LEGACY_PCS_BYTES: usize = LEGACY_OPENING_BYTES - 5_872;
pub const PUBLIC_BYTES: usize = TOP_BYTES + 3 * BANK_PUBLIC_BYTES;
pub const MAX_WIRE_BYTES: usize = 6_000_000;
pub const REDUCTION_BYTES: usize = 14_220;
pub const JOINT_BASEFOLD_RAW_BYTES: usize = 4_713_576;
const DIRECT_WIRE_MAGIC: &[u8; 8] = b"CMFDDR02";
const DIRECT_WIRE_VERSION: usize = 2;
// Level 1 is canonical for this research version. The full verifier still
// decompresses with an exact bound and recompresses to reject malleable wires.
const CANONICAL_ZLIB_LEVEL: u8 = 1;
const OPENING_DOMAIN: &[u8] = b"CommonFoundry/ForgeMatrix/V4/OpeningReduction/v2";

/// Read the public final vector for work-digest construction. This does not
/// authorize a block; callers must still pass the whole packet to `verify_wire`.
pub fn final_activation_digest_from_packet(
    challenge_digest: [u8; 32],
    wire: &[u8],
) -> Result<[u8; 32]> {
    ensure!(
        wire.len() >= HEADER_BYTES + TOP_BYTES && wire.len() < MAX_WIRE_BYTES,
        "direct packet length"
    );
    ensure!(
        &wire[..8] == DIRECT_WIRE_MAGIC && u32_at(wire, 0) == DIRECT_WIRE_VERSION,
        "direct packet version"
    );
    let top = &wire[HEADER_BYTES..HEADER_BYTES + TOP_BYTES];
    ensure!(
        &top[..8] == b"CMV4PF01" && u32::from_le_bytes(top[8..12].try_into()?) == 1,
        "direct public-vector codec"
    );
    crate::forgematrix_v4_execution::forgematrix_v4_final_activation_digest_from_le_bytes(
        challenge_digest,
        &top[16..],
    )
    .map_err(Into::into)
}

pub struct DirectPacket {
    pub public: ForgeMatrixV4TransparentProof,
    pub reduction: direct::ReductionProof,
    pub joint_basefold: direct::DirectBasefoldProof,
}

fn u32_at(wire: &[u8], index: usize) -> usize {
    u32::from_le_bytes(wire[8 + 4 * index..12 + 4 * index].try_into().unwrap()) as usize
}

/// Decode every retained public field using the existing exact, canonical v1
/// codec. The zero-filled legacy BaseFold slots are a parsing adapter only.
/// `verify_direct` never reads them or invokes the old opening verifier.
pub fn decode(wire: &[u8], statement: Statement) -> Result<DirectPacket> {
    ensure!(
        wire.len() >= HEADER_BYTES + PUBLIC_BYTES && wire.len() < MAX_WIRE_BYTES,
        "direct packet length"
    );
    ensure!(&wire[..8] == DIRECT_WIRE_MAGIC, "direct packet magic");
    ensure!(
        u32_at(wire, 0) == DIRECT_WIRE_VERSION
            && u32_at(wire, 1) == FORGEMATRIX_V4_TRANSPARENT_PROOF_BYTES
            && u32_at(wire, 2) == PUBLIC_BYTES
            && u32_at(wire, 3) == REDUCTION_BYTES
            && u32_at(wire, 4) == JOINT_BASEFOLD_RAW_BYTES
            && u32_at(wire, 6) == 6,
        "direct pinned header geometry"
    );
    ensure!(
        &wire[36..68] == statement.digest().as_slice(),
        "direct statement binding"
    );
    ensure!(
        wire[68..HEADER_BYTES].iter().all(|byte| *byte == 0),
        "direct reserved header"
    );
    let reduction_at = HEADER_BYTES + PUBLIC_BYTES;
    let compressed_at = reduction_at
        .checked_add(u32_at(wire, 3))
        .context("reduction overflow")?;
    let end = compressed_at
        .checked_add(u32_at(wire, 5))
        .context("compressed overflow")?;
    ensure!(end == wire.len(), "direct exact framing");

    let public_wire = &wire[HEADER_BYTES..reduction_at];
    let mut old_layout = Vec::with_capacity(FORGEMATRIX_V4_TRANSPARENT_PROOF_BYTES);
    old_layout.extend_from_slice(&public_wire[..TOP_BYTES]);
    let mut at = TOP_BYTES;
    for _ in 0..3 {
        old_layout.extend_from_slice(&public_wire[at..at + BANK_PUBLIC_BYTES]);
        old_layout.resize(old_layout.len() + LEGACY_PCS_BYTES, 0);
        at += BANK_PUBLIC_BYTES;
    }
    ensure!(
        old_layout.len() == FORGEMATRIX_V4_TRANSPARENT_PROOF_BYTES,
        "legacy layout length"
    );
    let public = decode_forgematrix_v4_transparent_proof(&old_layout)?;
    ensure!(
        encode_forgematrix_v4_transparent_proof(&public)? == old_layout,
        "noncanonical public fields"
    );

    let reduction_bytes = &wire[reduction_at..compressed_at];
    let reduction: direct::ReductionProof = bincode::deserialize(reduction_bytes)?;
    ensure!(
        bincode::serialize(&reduction)? == reduction_bytes,
        "noncanonical reduction"
    );
    let packed = &wire[compressed_at..];
    let raw = decompress_to_vec_zlib_with_limit(packed, JOINT_BASEFOLD_RAW_BYTES)
        .map_err(|_| anyhow::anyhow!("bounded BaseFold decompression"))?;
    ensure!(
        raw.len() == JOINT_BASEFOLD_RAW_BYTES
            && compress_to_vec_zlib(&raw, CANONICAL_ZLIB_LEVEL) == packed,
        "noncanonical compressed BaseFold"
    );
    let joint_basefold = direct::decode_basefold(&raw)?;
    ensure!(
        bincode::serialize(&joint_basefold)? == raw,
        "noncanonical BaseFold encoding"
    );
    Ok(DirectPacket {
        public,
        reduction,
        joint_basefold,
    })
}

/// Encode an already constructed direct proof. The three legacy BaseFold
/// fields in `public` must be zero placeholders; they are not serialized.
pub fn encode(
    public: &ForgeMatrixV4TransparentProof,
    statement: Statement,
    reduction: &direct::ReductionProof,
    joint: &direct::DirectBasefoldProof,
) -> Result<Vec<u8>> {
    let raw = encode_forgematrix_v4_transparent_proof(public)?;
    let reduction_bytes = bincode::serialize(reduction)?;
    let joint_bytes = bincode::serialize(joint)?;
    ensure!(
        reduction_bytes.len() == REDUCTION_BYTES && joint_bytes.len() == JOINT_BASEFOLD_RAW_BYTES,
        "direct proof shape"
    );
    let packed = compress_to_vec_zlib(&joint_bytes, CANONICAL_ZLIB_LEVEL);
    let mut wire =
        Vec::with_capacity(HEADER_BYTES + PUBLIC_BYTES + reduction_bytes.len() + packed.len());
    wire.extend_from_slice(DIRECT_WIRE_MAGIC);
    for value in [
        DIRECT_WIRE_VERSION,
        raw.len(),
        PUBLIC_BYTES,
        reduction_bytes.len(),
        joint_bytes.len(),
        packed.len(),
        6,
    ] {
        wire.extend_from_slice(&u32::try_from(value)?.to_le_bytes());
    }
    wire.extend_from_slice(&statement.digest());
    wire.resize(HEADER_BYTES, 0);
    wire.extend_from_slice(&raw[..TOP_BYTES]);
    let mut at = TOP_BYTES;
    for _ in 0..3 {
        wire.extend_from_slice(&raw[at..at + BANK_PUBLIC_BYTES]);
        at += BANK_PUBLIC_BYTES + LEGACY_PCS_BYTES;
    }
    wire.extend_from_slice(&reduction_bytes);
    wire.extend_from_slice(&packed);
    ensure!(wire.len() < MAX_WIRE_BYTES, "direct wire exceeds six MB");
    Ok(wire)
}

fn observe_bytes(challenger: &mut Challenger, bytes: &[u8]) {
    challenger.observe(Felt::from_canonical_usize(bytes.len()));
    for byte in bytes {
        challenger.observe(Felt::from_canonical_u8(*byte));
    }
}

/// Check the unchanged per-bank opening reduction up to its BaseFold
/// obligation. The single shared BaseFold below discharges all six obligations.
pub fn verify_public_opening(
    commitments: [Digest; 2],
    claims: &[OpeningClaim],
    proof: &OpeningProof,
    challenger: &mut Challenger,
) -> Result<()> {
    ensure!(
        claims.len() == 16
            && proof.fixed_column_evaluations.len() == 256
            && proof.dynamic_column_evaluations.len() == 16,
        "opening shape"
    );
    ensure!(
        claims.iter().all(|claim| claim.row_point.dimension() == 23
            && claim.column_point.dimension()
                == if claim.commitment == Commitment::Fixed {
                    8
                } else {
                    4
                }),
        "opening claim geometry"
    );
    observe_bytes(challenger, OPENING_DOMAIN);
    challenger.observe(commitments[0]);
    challenger.observe(commitments[1]);
    challenger.observe(Felt::from_canonical_usize(claims.len()));
    for claim in claims {
        challenger.observe(Felt::from_canonical_u8(claim.commitment as u8));
        for coordinate in claim.column_point.iter() {
            challenger.observe_ext_element(*coordinate);
        }
        for coordinate in claim.row_point.iter() {
            challenger.observe_ext_element(*coordinate);
        }
        challenger.observe_ext_element(claim.value);
    }
    let lambda: Ext = challenger.sample_ext_element();
    let mut powers = vec![Ext::one(); claims.len()];
    for index in (0..claims.len() - 1).rev() {
        powers[index] = powers[index + 1] * lambda;
    }
    let expected: Ext = claims
        .iter()
        .zip(&powers)
        .map(|(claim, power)| claim.value * *power)
        .sum();
    ensure!(
        proof.sumcheck.claimed_sum == expected,
        "opening claimed sum"
    );
    partially_verify_sumcheck_proof(&proof.sumcheck, challenger, 23, 2)
        .map_err(|error| anyhow::anyhow!("opening sumcheck: {error:?}"))?;
    let point = &proof.sumcheck.point_and_eval.0;
    let mut terminal = Ext::zero();
    for (claim, power) in claims.iter().zip(&powers) {
        let values = if claim.commitment == Commitment::Fixed {
            &proof.fixed_column_evaluations
        } else {
            &proof.dynamic_column_evaluations
        };
        let column_point = claim.column_point.iter().copied().collect::<Vec<_>>();
        let coefficients = direct::equality_table(&column_point);
        let evaluation: Ext = values
            .iter()
            .zip(&coefficients)
            .map(|(value, weight)| *value * *weight)
            .sum();
        let equality: Ext = claim
            .row_point
            .iter()
            .zip(point.iter())
            .map(|(left, right)| (Ext::one() - *left) * (Ext::one() - *right) + *left * *right)
            .product();
        terminal += *power * evaluation * equality;
    }
    ensure!(
        proof.sumcheck.point_and_eval.1 == terminal,
        "opening terminal"
    );
    Ok(())
}

pub fn verify_direct(
    statement: Statement,
    fixed: [Digest; 3],
    base: &[u8],
    packet: &DirectPacket,
) -> Result<()> {
    let proof = &packet.public;
    ensure!(
        base.len() == 524_288 && base.iter().all(|value| *value <= 250),
        "base input"
    );
    ensure!(
        proof.final_activation.len() == 524_288,
        "final activation shape"
    );
    ensure!(
        forgematrix_v4_final_activation_digest(statement.challenge_digest, &proof.final_activation)
            == statement.final_activation_digest,
        "final activation digest"
    );
    let dynamic: [Digest; 3] = std::array::from_fn(|bank| proof.banks[bank].dynamic_commitment);
    let mut challenger = forgematrix_v4_transcript(statement);
    bind_forgematrix_v4_commitments(&mut challenger, &fixed, &dynamic);
    let mut claims: [Vec<OpeningClaim>; 3] = std::array::from_fn(|_| Vec::with_capacity(16));
    for bank in 0..3 {
        for repetition in 0..2 {
            let relation = &proof.banks[bank].relations[repetition];
            let matrix_point =
                sample_forgematrix_v4_matrix_point(&mut challenger, bank, repetition)?;
            let mask = forgematrix_v4_mask_evaluation(
                statement.challenge_digest,
                bank,
                &matrix_point.layer,
                &matrix_point.batch,
                &matrix_point.output,
            )?;
            verify_forgematrix_v4_matrix_relation(
                &matrix_point,
                mask,
                &relation.matrix,
                &mut challenger,
            )?;
            let terminal = forgematrix_v4_matrix_terminal_layer(&relation.matrix)?;
            verify_forgematrix_v4_shift_relation(
                &terminal,
                relation.matrix.input_evaluation,
                &relation.shift,
                &mut challenger,
            )?;
            claims[bank].extend(forgematrix_v4_matrix_opening_claims(
                &matrix_point,
                &relation.matrix,
            )?);
            claims[bank].push(forgematrix_v4_shift_opening_claim(
                &matrix_point,
                &relation.matrix,
                &relation.shift,
            )?);
            let boundary = forgematrix_v4_shift_boundary_point(&matrix_point, &relation.matrix)?;
            if bank == 0 {
                let expected = forgematrix_v4_initial_activation_evaluation(
                    statement.challenge_digest,
                    base,
                    &boundary.batch,
                    &boundary.output,
                )?;
                ensure!(
                    relation.shift.boundary_evaluation == expected,
                    "initial boundary"
                );
            } else {
                claims[bank - 1].push(forgematrix_v4_shift_boundary_opening_claim(
                    &matrix_point,
                    &relation.matrix,
                    &relation.shift,
                )?);
            }
            let cubic_point = sample_forgematrix_v4_cubic_point(&mut challenger, bank, repetition)?;
            verify_forgematrix_v4_cubic_relation(&cubic_point, &relation.cubic, &mut challenger)?;
            claims[bank].extend(forgematrix_v4_cubic_opening_claims(&relation.cubic)?);
        }
    }
    for repetition in 0..2 {
        let point = sample_forgematrix_v4_final_point(&mut challenger, repetition)?;
        let value = forgematrix_v4_activation_evaluation(
            &proof.final_activation,
            &point.batch,
            &point.output,
        )?;
        claims[2].push(forgematrix_v4_final_opening_claim(&point, value)?);
    }
    for bank in 0..3 {
        finalize_forgematrix_v4_bank_opening_claims(&mut claims[bank])?;
        verify_public_opening(
            [fixed[bank], dynamic[bank]],
            &claims[bank],
            &proof.banks[bank].opening,
            &mut challenger,
        )?;
    }
    let roots: [Digest; 6] = std::array::from_fn(|index| {
        if index % 2 == 0 {
            fixed[index / 2]
        } else {
            dynamic[index / 2]
        }
    });
    let bank_points: [Vec<Ext>; 3] = std::array::from_fn(|bank| {
        proof.banks[bank]
            .opening
            .sumcheck
            .point_and_eval
            .0
            .iter()
            .copied()
            .collect()
    });
    let original_evaluations: [Vec<Ext>; 6] = std::array::from_fn(|index| {
        if index % 2 == 0 {
            proof.banks[index / 2]
                .opening
                .fixed_column_evaluations
                .clone()
        } else {
            proof.banks[index / 2]
                .opening
                .dynamic_column_evaluations
                .clone()
        }
    });
    let direct_statement = direct::Statement {
        shape: direct::Shape::production(),
        job: statement.digest(),
        roots,
        bank_points,
        original_evaluations,
    };
    direct::verify_reduction(&direct_statement, &packet.reduction)?
        .verify_basefold(&packet.joint_basefold)?;
    Ok(())
}

pub fn verify_wire(
    statement: Statement,
    fixed: [Digest; 3],
    base: &[u8],
    wire: &[u8],
) -> Result<()> {
    let packet = decode(wire, statement)?;
    verify_direct(statement, fixed, base, &packet)
}

/// The old v1 transparent verifier must reject a direct packet. This guard is
/// intentionally separate from `verify_wire` to avoid accidental fallback.
pub fn reject_as_v1(wire: &[u8]) -> Result<()> {
    if decode_forgematrix_v4_transparent_proof(wire).is_ok() {
        bail!("direct wire accepted as v1");
    }
    Ok(())
}
