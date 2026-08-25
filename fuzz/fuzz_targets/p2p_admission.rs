#![no_main]

use std::sync::OnceLock;

use cmfd_consensus::{
    BLOCK_VERSION, Block, BlockChallenge, BlockProof, Coinbase, ConsensusPowVerifier,
    FORGEMATRIX_V3_CANDIDATE_PROOF_TAG, ForgeMatrixV3CandidateProof, MAX_BLOCK_BYTES,
    MAX_FORGEMATRIX_V3_STRUCTURED_PROOF_BYTES, MAX_PROOF_BYTES, PowError, PowParameters,
    WIRE_HEADER_BYTES, merkle_root, v2_test_reference, validate_block_resources,
};
use cmfd_node::peer::{
    MAX_PEER_PAYLOAD_BYTES, PEER_FRAME_HEADER_BYTES, PeerFrame, PeerMessage, decode_peer_frame,
    encode_peer_frame,
};
use cmfd_node::{DEFAULT_MINING_ATTEMPTS, default_miner_destination, devnet_params};
use libfuzzer_sys::fuzz_target;

const PEER_PAYLOAD_LENGTH_OFFSET: usize = PEER_FRAME_HEADER_BYTES - size_of::<u32>();
const BLOCK_FRAME_OFFSET: usize = PEER_FRAME_HEADER_BYTES;
const BLOCK_PAYLOAD_LENGTH_OFFSET: usize =
    BLOCK_FRAME_OFFSET + WIRE_HEADER_BYTES - size_of::<u32>();
const BLOCK_PAYLOAD_OFFSET: usize = BLOCK_FRAME_OFFSET + WIRE_HEADER_BYTES;
const BLOCK_CHALLENGE_BYTES: usize = 3 * 32 + 2 * size_of::<u64>() + 32;
const PROOF_LENGTH_OFFSET: usize = BLOCK_PAYLOAD_OFFSET + size_of::<u32>() + BLOCK_CHALLENGE_BYTES;
const PROOF_PAYLOAD_OFFSET: usize = PROOF_LENGTH_OFFSET + size_of::<u32>();
const FORGEMATRIX_V3_PUBLIC_PREFIX_BYTES: usize = MAX_PROOF_BYTES
    - WIRE_HEADER_BYTES
    - MAX_FORGEMATRIX_V3_STRUCTURED_PROOF_BYTES
    - size_of::<u32>();
const V3_STRUCTURED_LENGTH_OFFSET: usize =
    PROOF_PAYLOAD_OFFSET + FORGEMATRIX_V3_PUBLIC_PREFIX_BYTES;
const V3_STRUCTURED_PAYLOAD_OFFSET: usize = V3_STRUCTURED_LENGTH_OFFSET + size_of::<u32>();
const MAX_BLOCK_PAYLOAD_BYTES: usize = MAX_BLOCK_BYTES - WIRE_HEADER_BYTES;
const MAX_PEER_FRAME_BYTES: usize = PEER_FRAME_HEADER_BYTES + MAX_PEER_PAYLOAD_BYTES;

const MODE_XOR: u16 = 1 << 0;
const MODE_TRUNCATION: u16 = 1 << 1;
const MODE_INSERTION: u16 = 1 << 2;
const MODE_SPLICE: u16 = 1 << 3;
const MODE_GROWTH: u16 = 1 << 4;
const MODE_LENGTH_FIELDS: u16 = 1 << 5;
const MODE_TRAILING_BYTES: u16 = 1 << 6;
const MODE_V3_LENGTH_FIELD: u16 = 1 << 7;
const ALL_COMMON_MODES: u16 = MODE_XOR
    | MODE_TRUNCATION
    | MODE_INSERTION
    | MODE_SPLICE
    | MODE_GROWTH
    | MODE_LENGTH_FIELDS
    | MODE_TRAILING_BYTES;

struct AdmissionHarness {
    network_id: [u8; 32],
    verifier: ConsensusPowVerifier,
    seeds: [Vec<u8>; 4],
    near_outer_limit: Box<[u8]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdmissionOutcome {
    Rejected,
    ProofRejected,
    V2Accepted,
    V3FailClosed,
}

fn harness() -> &'static AdmissionHarness {
    static HARNESS: OnceLock<AdmissionHarness> = OnceLock::new();
    HARNESS.get_or_init(|| {
        let params = devnet_params().expect("Devnet parameters must remain valid");
        let verifier = ConsensusPowVerifier::v2_reference(
            v2_test_reference().expect("the current V2 reference must remain valid"),
        );
        assert!(matches!(
            verifier.parameters(),
            PowParameters::V2Reference(_)
        ));

        let height = 1;
        let coinbase = Coinbase::new(
            height,
            params
                .monetary_policy
                .allocation(height, 0)
                .expect("height-one allocation must remain valid"),
            default_miner_destination(),
            params.rewards,
        );
        let challenge = BlockChallenge {
            network_id: params.network_id,
            previous_block: params.genesis_hash,
            transaction_root: merkle_root(&[coinbase.commitment(params.network_id)]),
            height,
            timestamp: params.genesis_timestamp + 1,
            target: params.pow_limit,
        };
        let proof = verifier
            .mine(&challenge, 0, DEFAULT_MINING_ATTEMPTS)
            .expect("the deterministic seed block must mine under the Devnet limit");
        let block = Block {
            version: BLOCK_VERSION,
            challenge,
            proof,
            coinbase,
            transactions: Vec::new(),
        };
        validate_block_resources(&block).expect("the seed block must fit every resource bound");
        verifier
            .preverify(&block.challenge, &block.proof)
            .expect("the seed block must pass the current V2 verifier");

        let mut v3_block = block.clone();
        v3_block.proof = BlockProof::V3Candidate(Box::new(ForgeMatrixV3CandidateProof {
            algorithm_version: 3,
            proof_version: 1,
            nonce: 0,
            model_manifest_digest: [0x31; 32],
            challenge_digest: [0x32; 32],
            final_activation_digest: [0x33; 32],
            work_digest: [0x34; 32],
            structured_proof: vec![0x35],
        }));
        assert!(matches!(
            verifier.preverify(&v3_block.challenge, &v3_block.proof),
            Err(PowError::WrongProofType)
        ));

        let block_frame = encode_peer_frame(&PeerFrame {
            sequence: 0,
            message: PeerMessage::Block(block.clone()),
        })
        .expect("the seed block frame must encode");
        let submit_frame = encode_peer_frame(&PeerFrame {
            sequence: 1,
            message: PeerMessage::SubmitBlock(block),
        })
        .expect("the seed submission frame must encode");
        let v3_block_frame = encode_peer_frame(&PeerFrame {
            sequence: 2,
            message: PeerMessage::Block(v3_block.clone()),
        })
        .expect("the fail-closed V3 block frame must encode");
        let v3_submit_frame = encode_peer_frame(&PeerFrame {
            sequence: 3,
            message: PeerMessage::SubmitBlock(v3_block),
        })
        .expect("the fail-closed V3 submission frame must encode");

        assert_eq!(PEER_PAYLOAD_LENGTH_OFFSET, 16);
        assert_eq!(BLOCK_PAYLOAD_LENGTH_OFFSET, 32);
        assert_eq!(PROOF_LENGTH_OFFSET, 184);
        assert_eq!(V3_STRUCTURED_LENGTH_OFFSET, 365);

        let mut near_outer_limit = vec![0_u8; MAX_PEER_FRAME_BYTES];
        near_outer_limit[..block_frame.len()].copy_from_slice(&block_frame);
        write_u32(
            &mut near_outer_limit,
            PEER_PAYLOAD_LENGTH_OFFSET,
            u32::try_from(MAX_PEER_PAYLOAD_BYTES).expect("the peer limit must fit u32"),
        );
        write_u32(
            &mut near_outer_limit,
            BLOCK_PAYLOAD_LENGTH_OFFSET,
            u32::try_from(MAX_BLOCK_PAYLOAD_BYTES).expect("the block limit must fit u32"),
        );

        let harness = AdmissionHarness {
            network_id: params.network_id,
            verifier,
            seeds: [block_frame, submit_frame, v3_block_frame, v3_submit_frame],
            near_outer_limit: near_outer_limit.into_boxed_slice(),
        };
        assert_eq!(
            exercise_admission(&harness.seeds[0], &harness),
            AdmissionOutcome::V2Accepted
        );
        assert_eq!(
            exercise_admission(&harness.seeds[1], &harness),
            AdmissionOutcome::V2Accepted
        );
        assert_eq!(
            exercise_admission(&harness.seeds[2], &harness),
            AdmissionOutcome::V3FailClosed
        );
        assert_eq!(
            exercise_admission(&harness.seeds[3], &harness),
            AdmissionOutcome::V3FailClosed
        );
        for (index, seed) in harness.seeds.iter().enumerate() {
            let expected = if index >= 2 {
                ALL_COMMON_MODES | MODE_V3_LENGTH_FIELD
            } else {
                ALL_COMMON_MODES
            };
            assert_eq!(exercise_seed_mutations(&[], seed, &harness), expected);
        }
        assert_eq!(harness.near_outer_limit.len(), MAX_PEER_FRAME_BYTES);
        assert_eq!(
            exercise_admission(&harness.near_outer_limit, &harness),
            AdmissionOutcome::Rejected
        );
        harness
    })
}

fn exercise_admission(bytes: &[u8], harness: &AdmissionHarness) -> AdmissionOutcome {
    let Ok(frame) = decode_peer_frame(bytes, harness.network_id) else {
        return AdmissionOutcome::Rejected;
    };
    let block = match &frame.message {
        PeerMessage::Block(block) | PeerMessage::SubmitBlock(block) => block,
        _ => return AdmissionOutcome::Rejected,
    };
    if validate_block_resources(block).is_err() {
        return AdmissionOutcome::Rejected;
    }

    let canonical = encode_peer_frame(&frame).expect("an accepted peer frame must re-encode");
    assert_eq!(
        canonical, bytes,
        "accepted peer frames must be byte-canonical"
    );

    let result = harness.verifier.preverify(&block.challenge, &block.proof);
    if matches!(&block.proof, BlockProof::V3Candidate(_)) {
        assert!(matches!(result, Err(PowError::WrongProofType)));
        return AdmissionOutcome::V3FailClosed;
    }
    if result.is_ok() {
        AdmissionOutcome::V2Accepted
    } else {
        AdmissionOutcome::ProofRejected
    }
}

fn input_byte(input: &[u8], index: usize, fallback: u8) -> u8 {
    if input.is_empty() {
        fallback
    } else {
        input[index % input.len()]
    }
}

fn input_u32(input: &[u8], offset: usize, fallback: u32) -> u32 {
    u32::from_le_bytes([
        input_byte(input, offset, fallback as u8),
        input_byte(input, offset + 1, (fallback >> 8) as u8),
        input_byte(input, offset + 2, (fallback >> 16) as u8),
        input_byte(input, offset + 3, (fallback >> 24) as u8),
    ])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + size_of::<u32>()]
            .try_into()
            .expect("a declared length field must be present"),
    )
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + size_of::<u32>()].copy_from_slice(&value.to_le_bytes());
}

fn exercise_candidate(candidate: &[u8], harness: &AdmissionHarness) {
    assert!(candidate.len() <= MAX_PEER_FRAME_BYTES);
    let _ = exercise_admission(candidate, harness);
}

fn normalize_envelope_lengths(candidate: &mut [u8]) {
    assert!(candidate.len() >= BLOCK_PAYLOAD_OFFSET);
    write_u32(
        candidate,
        PEER_PAYLOAD_LENGTH_OFFSET,
        u32::try_from(candidate.len() - PEER_FRAME_HEADER_BYTES)
            .expect("a bounded peer frame length must fit u32"),
    );
    write_u32(
        candidate,
        BLOCK_PAYLOAD_LENGTH_OFFSET,
        u32::try_from(candidate.len() - BLOCK_PAYLOAD_OFFSET)
            .expect("a bounded block payload length must fit u32"),
    );
}

fn exercise_length_field(
    input: &[u8],
    seed: &[u8],
    offset: usize,
    maximum: usize,
    salt: usize,
    harness: &AdmissionHarness,
) {
    let actual = read_u32(seed, offset);
    let maximum = u32::try_from(maximum).expect("a wire maximum must fit u32");
    let values = [
        0,
        actual.saturating_sub(1),
        actual.saturating_add(1),
        maximum,
        maximum.saturating_add(1),
        input_u32(input, salt, 0xa5c3_91e7),
        u32::MAX,
    ];
    for value in values {
        let mut candidate = seed.to_vec();
        write_u32(&mut candidate, offset, value);
        exercise_candidate(&candidate, harness);
    }
}

fn mutation_boundaries(is_v3: bool) -> impl Iterator<Item = usize> {
    const BOUNDARIES: &[(usize, bool)] = &[
        (4, false),
        (6, false),
        (8, false),
        (PEER_PAYLOAD_LENGTH_OFFSET, false),
        (PEER_FRAME_HEADER_BYTES, false),
        (BLOCK_FRAME_OFFSET + 4, false),
        (BLOCK_FRAME_OFFSET + 8, false),
        (BLOCK_FRAME_OFFSET + 10, false),
        (BLOCK_PAYLOAD_LENGTH_OFFSET, false),
        (BLOCK_PAYLOAD_OFFSET, false),
        (PROOF_LENGTH_OFFSET, false),
        (PROOF_PAYLOAD_OFFSET, false),
        (V3_STRUCTURED_LENGTH_OFFSET, true),
        (V3_STRUCTURED_PAYLOAD_OFFSET, true),
    ];
    BOUNDARIES
        .iter()
        .copied()
        .filter(move |(_, v3_only)| is_v3 || !v3_only)
        .map(|(offset, _)| offset)
}

fn deep_mutation_boundaries(is_v3: bool) -> impl Iterator<Item = usize> {
    const BOUNDARIES: &[(usize, bool)] = &[
        (BLOCK_PAYLOAD_OFFSET, false),
        (PROOF_LENGTH_OFFSET, false),
        (PROOF_PAYLOAD_OFFSET, false),
        (V3_STRUCTURED_LENGTH_OFFSET, true),
        (V3_STRUCTURED_PAYLOAD_OFFSET, true),
    ];
    BOUNDARIES
        .iter()
        .copied()
        .filter(move |(_, v3_only)| is_v3 || !v3_only)
        .map(|(offset, _)| offset)
}

fn exercise_seed_mutations(input: &[u8], seed: &[u8], harness: &AdmissionHarness) -> u16 {
    assert!(seed.len() <= MAX_PEER_FRAME_BYTES);
    let is_v3 = seed.get(PROOF_PAYLOAD_OFFSET) == Some(&FORGEMATRIX_V3_CANDIDATE_PROOF_TAG);
    let mut modes = 0_u16;

    let mut candidate = seed.to_vec();
    let offset = usize::try_from(input_u32(input, 0, 0x9e37_79b9)).expect("u32 must fit usize")
        % candidate.len();
    let patch_len = 1 + usize::from(input_byte(input, 4, 7) % 32);
    for index in 0..patch_len {
        let patch = input_byte(input, index + 5, 0x5b_u8.wrapping_add(index as u8)) | 1;
        candidate[(offset + index) % seed.len()] ^= patch;
    }
    exercise_candidate(&candidate, harness);
    modes |= MODE_XOR;

    for boundary in mutation_boundaries(is_v3) {
        for cut in [
            boundary.saturating_sub(1),
            boundary,
            boundary.saturating_add(1),
        ] {
            if cut < seed.len() {
                exercise_candidate(&seed[..cut], harness);
                modes |= MODE_TRUNCATION;
            }
        }
    }

    for (index, boundary) in deep_mutation_boundaries(is_v3).enumerate() {
        let width = 1 + usize::from(input_byte(input, index + 11, 1) % 4);
        let available = MAX_PEER_FRAME_BYTES - seed.len();
        let width = width.min(available);
        let mut candidate = Vec::with_capacity(seed.len() + width);
        candidate.extend_from_slice(&seed[..boundary]);
        candidate
            .extend((0..width).map(|byte| input_byte(input, index + byte + 17, 0x80 | byte as u8)));
        candidate.extend_from_slice(&seed[boundary..]);
        normalize_envelope_lengths(&mut candidate);
        exercise_candidate(&candidate, harness);
        modes |= MODE_INSERTION;
    }

    for (index, boundary) in deep_mutation_boundaries(is_v3).enumerate() {
        let width = 1 + usize::from(input_byte(input, index + 23, 1) % 4);
        let start = boundary.saturating_sub(width / 2);
        let end = start.saturating_add(width).min(seed.len());
        if start < end && seed.len() - (end - start) >= BLOCK_PAYLOAD_OFFSET {
            let mut candidate = Vec::with_capacity(seed.len() - (end - start));
            candidate.extend_from_slice(&seed[..start]);
            candidate.extend_from_slice(&seed[end..]);
            normalize_envelope_lengths(&mut candidate);
            exercise_candidate(&candidate, harness);
            modes |= MODE_SPLICE;
        }
    }

    let growth = 1 + usize::from(input_byte(input, 29, 31) % 64);
    let growth = growth.min(MAX_PEER_FRAME_BYTES - seed.len());
    let mut candidate = seed.to_vec();
    candidate.extend(
        (0..growth).map(|index| input_byte(input, index + 31, 0x40_u8.wrapping_add(index as u8))),
    );
    normalize_envelope_lengths(&mut candidate);
    exercise_candidate(&candidate, harness);
    modes |= MODE_GROWTH;

    exercise_length_field(
        input,
        seed,
        PEER_PAYLOAD_LENGTH_OFFSET,
        MAX_PEER_PAYLOAD_BYTES,
        41,
        harness,
    );
    exercise_length_field(
        input,
        seed,
        BLOCK_PAYLOAD_LENGTH_OFFSET,
        MAX_BLOCK_PAYLOAD_BYTES,
        47,
        harness,
    );
    exercise_length_field(
        input,
        seed,
        PROOF_LENGTH_OFFSET,
        MAX_PROOF_BYTES,
        53,
        harness,
    );
    modes |= MODE_LENGTH_FIELDS;

    if is_v3 {
        exercise_length_field(
            input,
            seed,
            V3_STRUCTURED_LENGTH_OFFSET,
            MAX_FORGEMATRIX_V3_STRUCTURED_PROOF_BYTES,
            59,
            harness,
        );
        modes |= MODE_V3_LENGTH_FIELD;
    }

    for width in [1_usize, 32] {
        let width = width.min(MAX_PEER_FRAME_BYTES - seed.len());
        let mut candidate = seed.to_vec();
        candidate.extend(
            (0..width)
                .map(|index| input_byte(input, index + 67, 0xd0_u8.wrapping_add(index as u8))),
        );
        exercise_candidate(&candidate, harness);
        modes |= MODE_TRAILING_BYTES;
    }

    modes
}

fuzz_target!(|bytes: &[u8]| {
    let harness = harness();
    let _ = exercise_admission(bytes, harness);
    for (index, seed) in harness.seeds.iter().enumerate() {
        let expected = if index >= 2 {
            ALL_COMMON_MODES | MODE_V3_LENGTH_FIELD
        } else {
            ALL_COMMON_MODES
        };
        assert_eq!(exercise_seed_mutations(bytes, seed, harness), expected);
    }
    exercise_candidate(&harness.near_outer_limit, harness);
});
