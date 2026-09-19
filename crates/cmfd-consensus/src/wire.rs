use blake3::Hasher;
use cmfd_marketplace::{ChannelTerms, PaymentState, Settlement, SignedPaymentState};
use thiserror::Error;

use crate::{
    Block, BlockChallenge, BlockProof, CONSENSUS_SIGNATURE_BYTES, Coinbase, ForgeMatrixProof,
    ForgeMatrixV2CompactProof, ForgeMatrixV3CandidateProof, ForgeMatrixV4CandidateProof,
    InputWitness, MAX_BLOCK_AGGREGATE_INPUTS, MAX_BLOCK_AGGREGATE_OUTPUTS,
    MAX_BLOCK_SIGNATURE_CHECKS, MAX_BLOCK_TRANSACTIONS, MAX_COINBASE_OUTPUTS,
    MAX_TRANSACTION_INPUTS, MAX_TRANSACTION_OUTPUTS, OutPoint, OutputLock, Transaction, TxInput,
    TxOutput,
};

pub const WIRE_HEADER_BYTES: usize = 16;
pub const WIRE_VERSION: u16 = 1;
pub const WIRE_HEADER_FIELDS: &str =
    "magic[4],network_magic[4],version_u16le,kind_u8,reserved_zero_u8,payload_length_u32le";
pub const TRANSACTION_KIND: u8 = 1;
pub const FORGEMATRIX_PROOF_KIND: u8 = 2;
pub const BLOCK_KIND: u8 = 3;
pub const FORGEMATRIX_V1_PROOF_TAG: u8 = 1;
pub const FORGEMATRIX_V2_PROOF_TAG: u8 = 2;
/// Reserved, fail-closed production-candidate proof tag.
pub const FORGEMATRIX_V3_CANDIDATE_PROOF_TAG: u8 = 3;
/// Reserved exclusively for ProductionV4 networks.
pub const FORGEMATRIX_V4_CANDIDATE_PROOF_TAG: u8 = 4;

pub const MAX_TRANSACTION_BYTES: usize = 64 * 1024;
/// All proof tags before V4 retain this complete-frame limit.
pub const MAX_PROOF_BYTES: usize = 256 * 1024;
/// All networks before V4 retain this complete-frame limit.
pub const MAX_BLOCK_BYTES: usize = 1024 * 1024;
pub const PRODUCTION_V4_MAX_PROOF_BYTES: usize = 13 * 1024 * 1024;
pub const PRODUCTION_V4_MAX_BLOCK_BYTES: usize = 16 * 1024 * 1024;

/// SHA-256("CMFD/PRODUCTION-V4-TESTNET/V1/NETWORK-ID").
pub const PRODUCTION_V4_TESTNET_NETWORK_ID: [u8; 32] = [
    0xb9, 0xe5, 0x5d, 0x5a, 0x5e, 0x80, 0xc8, 0xe3, 0xd7, 0x3b, 0xf8, 0x1b, 0x19, 0x9b, 0xc6, 0x43,
    0xac, 0x93, 0x67, 0x43, 0x69, 0x62, 0xc2, 0x8b, 0x6a, 0xac, 0xdc, 0x37, 0xf3, 0x80, 0x99, 0x62,
];

/// RCNet-1 identity derived by `CMFD_RCNET_LAUNCH_CANDIDATE_V2`.
pub const PRODUCTION_V4_RCNET1_NETWORK_ID: [u8; 32] = [
    0x3e, 0x99, 0xd4, 0x59, 0x59, 0xc1, 0x9c, 0x00, 0x53, 0xd8, 0xe9, 0xfe, 0xf3, 0x48, 0x75, 0xb5,
    0x7b, 0x46, 0xa8, 0xa1, 0xce, 0x33, 0x06, 0x37, 0xda, 0xdd, 0xab, 0x51, 0x5b, 0xc7, 0xb9, 0x2d,
];

pub(crate) const FORGEMATRIX_V3_PUBLIC_PREFIX_BYTES: usize = 1 + 32 + 4 + 4 + 8 + 4 * 32;
pub(crate) const FORGEMATRIX_V3_LENGTH_BYTES: usize = std::mem::size_of::<u32>();
#[cfg(feature = "dory-bls12-381-prototype")]
pub(crate) const FORGEMATRIX_V3_WIRE_PREFIX_FIELDS: &str = "v3_wire_tag_u8,network_id[32],algorithm_version_u32le,proof_version_u32le,nonce_u64le,model_manifest_digest[32],challenge_digest[32],final_activation_digest[32],work_digest[32]";
#[cfg(feature = "dory-bls12-381-prototype")]
pub(crate) const FORGEMATRIX_V3_WIRE_TAIL_FIELDS: &str =
    "structured_length_u32le,structured_bytes; exact EOF";
/// Exact V3 aggregate allowance beneath the complete 256 KiB proof-frame cap.
pub const MAX_FORGEMATRIX_V3_STRUCTURED_PROOF_BYTES: usize = MAX_PROOF_BYTES
    - WIRE_HEADER_BYTES
    - FORGEMATRIX_V3_PUBLIC_PREFIX_BYTES
    - FORGEMATRIX_V3_LENGTH_BYTES;
pub(crate) const FORGEMATRIX_V4_PUBLIC_PREFIX_BYTES: usize = 1 + 32 + 4 + 4 + 8 + 5 * 32;
pub(crate) const FORGEMATRIX_V4_LENGTH_BYTES: usize = std::mem::size_of::<u32>();
pub const MAX_FORGEMATRIX_V4_TRANSPARENT_PROOF_BYTES: usize = PRODUCTION_V4_MAX_PROOF_BYTES
    - WIRE_HEADER_BYTES
    - FORGEMATRIX_V4_PUBLIC_PREFIX_BYTES
    - FORGEMATRIX_V4_LENGTH_BYTES;

pub(crate) const FRAME_MAGIC: [u8; 4] = *b"CMFD";
pub(crate) const NETWORK_MAGIC_DOMAIN: &str = "CMFD/WIRE/NETWORK-MAGIC/V1";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WireError {
    #[error("wire input is truncated: need {needed} bytes, have {remaining}")]
    Truncated { needed: usize, remaining: usize },
    #[error("wire frame magic is not CMFD")]
    InvalidMagic,
    #[error("wire frame belongs to another network")]
    WrongNetworkMagic,
    #[error("{field} belongs to another network")]
    WrongNetworkId { field: &'static str },
    #[error("unsupported wire version {0}")]
    UnsupportedVersion(u16),
    #[error("unexpected wire kind {actual}, expected {expected}")]
    UnexpectedKind { expected: u8, actual: u8 },
    #[error("wire flags must be zero, received {0:#04x}")]
    NonZeroFlags(u8),
    #[error("{object} encoding is {actual} bytes, exceeding the {max}-byte limit")]
    SizeLimit {
        object: &'static str,
        actual: usize,
        max: usize,
    },
    #[error("wire input contains {remaining} trailing bytes")]
    TrailingBytes { remaining: usize },
    #[error("{field} count {actual} exceeds the limit of {max}")]
    CountLimit {
        field: &'static str,
        actual: usize,
        max: usize,
    },
    #[error("unknown {field} tag {tag}")]
    UnknownTag { field: &'static str, tag: u8 },
    #[error("Schnorr signature is {actual} bytes; exactly 64 are required")]
    SignatureLength { actual: usize },
    #[error("wire length arithmetic overflowed")]
    LengthOverflow,
    #[error("{field} must not be empty")]
    EmptyField { field: &'static str },
    #[error("proof tag {tag} is not valid for this network")]
    ProofTagNetworkMismatch { tag: u8 },
}

pub fn max_proof_bytes_for_network(network_id: [u8; 32]) -> usize {
    if is_production_v4_network(network_id) {
        PRODUCTION_V4_MAX_PROOF_BYTES
    } else {
        MAX_PROOF_BYTES
    }
}

pub fn max_block_bytes_for_network(network_id: [u8; 32]) -> usize {
    if is_production_v4_network(network_id) {
        PRODUCTION_V4_MAX_BLOCK_BYTES
    } else {
        MAX_BLOCK_BYTES
    }
}

fn ensure_proof_tag_for_network(tag: u8, network_id: [u8; 32]) -> Result<(), WireError> {
    let is_v4_tag = tag == FORGEMATRIX_V4_CANDIDATE_PROOF_TAG;
    let is_v4_network = is_production_v4_network(network_id);
    if is_v4_tag != is_v4_network {
        return Err(WireError::ProofTagNetworkMismatch { tag });
    }
    Ok(())
}

fn is_production_v4_network(network_id: [u8; 32]) -> bool {
    matches!(
        network_id,
        PRODUCTION_V4_TESTNET_NETWORK_ID | PRODUCTION_V4_RCNET1_NETWORK_ID
    ) || crate::mainnet_network::is_mainnet_network(network_id)
}

/// Derives the four-byte frame discriminator from all 32 bytes of a network ID.
pub fn network_magic(network_id: &[u8; 32]) -> [u8; 4] {
    let mut hasher = Hasher::new_derive_key(NETWORK_MAGIC_DOMAIN);
    hasher.update(network_id);
    let digest = hasher.finalize();
    let mut magic = [0_u8; 4];
    magic.copy_from_slice(&digest.as_bytes()[..4]);
    magic
}

pub fn encode_transaction(transaction: &Transaction) -> Result<Vec<u8>, WireError> {
    let payload = encode_transaction_payload(transaction)?;
    encode_frame(
        TRANSACTION_KIND,
        transaction.network_id,
        &payload,
        MAX_TRANSACTION_BYTES,
        "transaction",
    )
}

pub fn decode_transaction(
    bytes: &[u8],
    expected_network_id: [u8; 32],
) -> Result<Transaction, WireError> {
    let payload = decode_frame(
        bytes,
        expected_network_id,
        TRANSACTION_KIND,
        MAX_TRANSACTION_BYTES,
        "transaction",
    )?;
    decode_transaction_payload(payload, expected_network_id)
}

pub fn encode_forgematrix_proof(
    proof: &BlockProof,
    network_id: [u8; 32],
) -> Result<Vec<u8>, WireError> {
    let payload = encode_forgematrix_proof_payload(proof, network_id)?;
    encode_frame(
        FORGEMATRIX_PROOF_KIND,
        network_id,
        &payload,
        max_proof_bytes_for_network(network_id),
        "ForgeMatrix proof",
    )
}

pub fn decode_forgematrix_proof(
    bytes: &[u8],
    expected_network_id: [u8; 32],
) -> Result<BlockProof, WireError> {
    let payload = decode_frame(
        bytes,
        expected_network_id,
        FORGEMATRIX_PROOF_KIND,
        max_proof_bytes_for_network(expected_network_id),
        "ForgeMatrix proof",
    )?;
    decode_forgematrix_proof_payload(payload, expected_network_id)
}

pub fn encode_block(block: &Block) -> Result<Vec<u8>, WireError> {
    validate_block_shape(block)?;
    let network_id = block.challenge.network_id;
    let max_block_bytes = max_block_bytes_for_network(network_id);
    let max_proof_bytes = max_proof_bytes_for_network(network_id);
    let mut writer = Writer::new(payload_limit(max_block_bytes), "block");
    writer.u32(block.version)?;
    encode_challenge(&block.challenge, &mut writer)?;

    let proof = encode_forgematrix_proof_payload(&block.proof, network_id)?;
    writer.sized_bytes(&proof, max_proof_bytes, "ForgeMatrix proof")?;
    encode_coinbase(&block.coinbase, &mut writer)?;

    writer.count(
        block.transactions.len(),
        MAX_BLOCK_TRANSACTIONS,
        "block transactions",
    )?;
    for transaction in &block.transactions {
        let payload = encode_transaction_payload(transaction)?;
        writer.sized_bytes(&payload, MAX_TRANSACTION_BYTES, "transaction")?;
    }

    let payload = writer.finish();
    encode_frame(BLOCK_KIND, network_id, &payload, max_block_bytes, "block")
}

pub fn decode_block(bytes: &[u8], expected_network_id: [u8; 32]) -> Result<Block, WireError> {
    let max_block_bytes = max_block_bytes_for_network(expected_network_id);
    let max_proof_bytes = max_proof_bytes_for_network(expected_network_id);
    let payload = decode_frame(
        bytes,
        expected_network_id,
        BLOCK_KIND,
        max_block_bytes,
        "block",
    )?;
    let mut reader = Reader::new(payload);
    let version = reader.u32()?;
    let challenge = decode_challenge(&mut reader, expected_network_id)?;

    let proof_payload = reader.sized_bytes(max_proof_bytes, "ForgeMatrix proof")?;
    let proof = decode_forgematrix_proof_payload(proof_payload, challenge.network_id)?;
    let coinbase = decode_coinbase(&mut reader)?;

    let transaction_count = reader.count(MAX_BLOCK_TRANSACTIONS, "block transactions")?;
    let mut transactions = Vec::with_capacity(transaction_count);
    let mut aggregate_inputs = 0_usize;
    let mut aggregate_outputs = 0_usize;
    let mut signature_checks = 0_usize;
    for _ in 0..transaction_count {
        let transaction_payload = reader.sized_bytes(MAX_TRANSACTION_BYTES, "transaction")?;
        let transaction = decode_transaction_payload(transaction_payload, expected_network_id)?;
        add_block_resources(
            &transaction,
            &mut aggregate_inputs,
            &mut aggregate_outputs,
            &mut signature_checks,
        )?;
        transactions.push(transaction);
    }
    reader.finish()?;

    Ok(Block {
        version,
        challenge,
        proof,
        coinbase,
        transactions,
    })
}

fn encode_transaction_payload(transaction: &Transaction) -> Result<Vec<u8>, WireError> {
    validate_transaction_shape(transaction, transaction.network_id)?;
    let mut writer = Writer::new(payload_limit(MAX_TRANSACTION_BYTES), "transaction");
    writer.bytes(&transaction.network_id)?;
    writer.u32(transaction.version)?;
    writer.count(
        transaction.inputs.len(),
        MAX_TRANSACTION_INPUTS,
        "transaction inputs",
    )?;
    for input in &transaction.inputs {
        encode_input(input, &mut writer)?;
    }
    writer.count(
        transaction.outputs.len(),
        MAX_TRANSACTION_OUTPUTS,
        "transaction outputs",
    )?;
    for output in &transaction.outputs {
        encode_output(output, &mut writer)?;
    }
    Ok(writer.finish())
}

fn decode_transaction_payload(
    payload: &[u8],
    expected_network_id: [u8; 32],
) -> Result<Transaction, WireError> {
    ensure_payload_size(payload.len(), MAX_TRANSACTION_BYTES, "transaction")?;
    let mut reader = Reader::new(payload);
    let network_id = reader.array()?;
    if network_id != expected_network_id {
        return Err(WireError::WrongNetworkId {
            field: "transaction",
        });
    }
    let version = reader.u32()?;
    let input_count = reader.count(MAX_TRANSACTION_INPUTS, "transaction inputs")?;
    let mut inputs = Vec::with_capacity(input_count);
    for _ in 0..input_count {
        inputs.push(decode_input(&mut reader, expected_network_id)?);
    }
    let output_count = reader.count(MAX_TRANSACTION_OUTPUTS, "transaction outputs")?;
    let mut outputs = Vec::with_capacity(output_count);
    for _ in 0..output_count {
        outputs.push(decode_output(&mut reader)?);
    }
    reader.finish()?;
    Ok(Transaction {
        network_id,
        version,
        inputs,
        outputs,
    })
}

fn encode_forgematrix_proof_payload(
    proof: &BlockProof,
    network_id: [u8; 32],
) -> Result<Vec<u8>, WireError> {
    let mut writer = Writer::new(
        payload_limit(max_proof_bytes_for_network(network_id)),
        "ForgeMatrix proof",
    );
    match proof {
        BlockProof::V1Legacy(proof) => {
            ensure_proof_tag_for_network(FORGEMATRIX_V1_PROOF_TAG, network_id)?;
            writer.u8(FORGEMATRIX_V1_PROOF_TAG)?;
            writer.bytes(&network_id)?;
            writer.u32(proof.algorithm_version)?;
            writer.u32(proof.model_version)?;
            writer.u64(proof.nonce)?;
            writer.bytes(&proof.model_root)?;
            writer.bytes(&proof.output_digest)?;
            writer.bytes(&proof.work_digest)?;
        }
        BlockProof::V2Reference(proof) => {
            ensure_proof_tag_for_network(FORGEMATRIX_V2_PROOF_TAG, network_id)?;
            writer.u8(FORGEMATRIX_V2_PROOF_TAG)?;
            writer.bytes(&network_id)?;
            writer.u32(proof.algorithm_version)?;
            writer.u32(proof.proof_version)?;
            writer.u64(proof.nonce)?;
            writer.bytes(&proof.model_manifest_digest)?;
            writer.bytes(&proof.challenge_digest)?;
            writer.bytes(&proof.final_activation_digest)?;
            writer.bytes(&proof.work_digest)?;
        }
        BlockProof::V3Candidate(proof) => {
            ensure_proof_tag_for_network(FORGEMATRIX_V3_CANDIDATE_PROOF_TAG, network_id)?;
            if proof.structured_proof.is_empty() {
                return Err(WireError::EmptyField {
                    field: "structured production proof",
                });
            }
            writer.u8(FORGEMATRIX_V3_CANDIDATE_PROOF_TAG)?;
            writer.bytes(&network_id)?;
            writer.u32(proof.algorithm_version)?;
            writer.u32(proof.proof_version)?;
            writer.u64(proof.nonce)?;
            writer.bytes(&proof.model_manifest_digest)?;
            writer.bytes(&proof.challenge_digest)?;
            writer.bytes(&proof.final_activation_digest)?;
            writer.bytes(&proof.work_digest)?;
            check_byte_length(
                proof.structured_proof.len(),
                MAX_FORGEMATRIX_V3_STRUCTURED_PROOF_BYTES,
                "structured production proof",
            )?;
            let structured_length = u32::try_from(proof.structured_proof.len())
                .map_err(|_| WireError::LengthOverflow)?;
            writer.u32(structured_length)?;
            writer.bytes(&proof.structured_proof)?;
        }
        BlockProof::V4Candidate(proof) => {
            ensure_proof_tag_for_network(FORGEMATRIX_V4_CANDIDATE_PROOF_TAG, network_id)?;
            if proof.transparent_proof.is_empty() {
                return Err(WireError::EmptyField {
                    field: "transparent production proof",
                });
            }
            writer.u8(FORGEMATRIX_V4_CANDIDATE_PROOF_TAG)?;
            writer.bytes(&network_id)?;
            writer.u32(proof.algorithm_version)?;
            writer.u32(proof.proof_version)?;
            writer.u64(proof.nonce)?;
            writer.bytes(&proof.proof_system_digest)?;
            writer.bytes(&proof.model_manifest_digest)?;
            writer.bytes(&proof.challenge_digest)?;
            writer.bytes(&proof.final_activation_digest)?;
            writer.bytes(&proof.work_digest)?;
            check_byte_length(
                proof.transparent_proof.len(),
                MAX_FORGEMATRIX_V4_TRANSPARENT_PROOF_BYTES,
                "transparent production proof",
            )?;
            let proof_length = u32::try_from(proof.transparent_proof.len())
                .map_err(|_| WireError::LengthOverflow)?;
            writer.u32(proof_length)?;
            writer.bytes(&proof.transparent_proof)?;
        }
    }
    Ok(writer.finish())
}

fn decode_forgematrix_proof_payload(
    payload: &[u8],
    expected_network_id: [u8; 32],
) -> Result<BlockProof, WireError> {
    ensure_payload_size(
        payload.len(),
        max_proof_bytes_for_network(expected_network_id),
        "ForgeMatrix proof",
    )?;
    let mut reader = Reader::new(payload);
    let tag = reader.u8()?;
    let network_id = reader.array()?;
    if network_id != expected_network_id {
        return Err(WireError::WrongNetworkId {
            field: "ForgeMatrix proof",
        });
    }
    ensure_proof_tag_for_network(tag, expected_network_id)?;
    let proof = match tag {
        FORGEMATRIX_V1_PROOF_TAG => BlockProof::V1Legacy(ForgeMatrixProof {
            algorithm_version: reader.u32()?,
            model_version: reader.u32()?,
            nonce: reader.u64()?,
            model_root: reader.array()?,
            output_digest: reader.array()?,
            work_digest: reader.array()?,
        }),
        FORGEMATRIX_V2_PROOF_TAG => BlockProof::V2Reference(ForgeMatrixV2CompactProof {
            algorithm_version: reader.u32()?,
            proof_version: reader.u32()?,
            nonce: reader.u64()?,
            model_manifest_digest: reader.array()?,
            challenge_digest: reader.array()?,
            final_activation_digest: reader.array()?,
            work_digest: reader.array()?,
        }),
        FORGEMATRIX_V3_CANDIDATE_PROOF_TAG => {
            let algorithm_version = reader.u32()?;
            let proof_version = reader.u32()?;
            let nonce = reader.u64()?;
            let model_manifest_digest = reader.array()?;
            let challenge_digest = reader.array()?;
            let final_activation_digest = reader.array()?;
            let work_digest = reader.array()?;
            let structured_length =
                usize::try_from(reader.u32()?).map_err(|_| WireError::LengthOverflow)?;
            check_byte_length(
                structured_length,
                MAX_FORGEMATRIX_V3_STRUCTURED_PROOF_BYTES,
                "structured production proof",
            )?;
            let structured_proof = reader.bytes(structured_length)?.to_vec();
            if structured_proof.is_empty() {
                return Err(WireError::EmptyField {
                    field: "structured production proof",
                });
            }
            BlockProof::V3Candidate(Box::new(ForgeMatrixV3CandidateProof {
                algorithm_version,
                proof_version,
                nonce,
                model_manifest_digest,
                challenge_digest,
                final_activation_digest,
                work_digest,
                structured_proof,
            }))
        }
        FORGEMATRIX_V4_CANDIDATE_PROOF_TAG => {
            let algorithm_version = reader.u32()?;
            let proof_version = reader.u32()?;
            let nonce = reader.u64()?;
            let proof_system_digest = reader.array()?;
            let model_manifest_digest = reader.array()?;
            let challenge_digest = reader.array()?;
            let final_activation_digest = reader.array()?;
            let work_digest = reader.array()?;
            let proof_length =
                usize::try_from(reader.u32()?).map_err(|_| WireError::LengthOverflow)?;
            check_byte_length(
                proof_length,
                MAX_FORGEMATRIX_V4_TRANSPARENT_PROOF_BYTES,
                "transparent production proof",
            )?;
            let transparent_proof = reader.bytes(proof_length)?.to_vec();
            if transparent_proof.is_empty() {
                return Err(WireError::EmptyField {
                    field: "transparent production proof",
                });
            }
            BlockProof::V4Candidate(Box::new(ForgeMatrixV4CandidateProof {
                algorithm_version,
                proof_version,
                nonce,
                proof_system_digest,
                model_manifest_digest,
                challenge_digest,
                final_activation_digest,
                work_digest,
                transparent_proof,
            }))
        }
        tag => {
            return Err(WireError::UnknownTag {
                field: "ForgeMatrix proof",
                tag,
            });
        }
    };
    reader.finish()?;
    Ok(proof)
}

fn encode_challenge(challenge: &BlockChallenge, writer: &mut Writer) -> Result<(), WireError> {
    writer.bytes(&challenge.network_id)?;
    writer.bytes(&challenge.previous_block)?;
    writer.bytes(&challenge.transaction_root)?;
    writer.u64(challenge.height)?;
    writer.u64(challenge.timestamp)?;
    writer.bytes(&challenge.target)
}

fn decode_challenge(
    reader: &mut Reader<'_>,
    expected_network_id: [u8; 32],
) -> Result<BlockChallenge, WireError> {
    let network_id = reader.array()?;
    if network_id != expected_network_id {
        return Err(WireError::WrongNetworkId {
            field: "block challenge",
        });
    }
    Ok(BlockChallenge {
        network_id,
        previous_block: reader.array()?,
        transaction_root: reader.array()?,
        height: reader.u64()?,
        timestamp: reader.u64()?,
        target: reader.array()?,
    })
}

fn encode_coinbase(coinbase: &Coinbase, writer: &mut Writer) -> Result<(), WireError> {
    writer.u64(coinbase.height)?;
    writer.count(
        coinbase.outputs.len(),
        MAX_COINBASE_OUTPUTS,
        "coinbase outputs",
    )?;
    for output in &coinbase.outputs {
        encode_output(output, writer)?;
    }
    Ok(())
}

fn decode_coinbase(reader: &mut Reader<'_>) -> Result<Coinbase, WireError> {
    let height = reader.u64()?;
    let output_count = reader.count(MAX_COINBASE_OUTPUTS, "coinbase outputs")?;
    let mut outputs = Vec::with_capacity(output_count);
    for _ in 0..output_count {
        outputs.push(decode_output(reader)?);
    }
    Ok(Coinbase { height, outputs })
}

fn encode_input(input: &TxInput, writer: &mut Writer) -> Result<(), WireError> {
    writer.bytes(&input.previous.txid)?;
    writer.u32(input.previous.index)?;
    match &input.witness {
        InputWitness::Key {
            public_key,
            signature,
        } => {
            writer.u8(0)?;
            writer.bytes(public_key)?;
            encode_signature(signature, writer)
        }
        InputWitness::InferenceSettlement { terms, settlement } => {
            writer.u8(1)?;
            encode_channel_terms(terms, writer)?;
            encode_payment_state(&settlement.state.state, writer)?;
            encode_signature(&settlement.state.customer_signature, writer)?;
            encode_signature(&settlement.provider_signature, writer)
        }
        InputWitness::InferenceRefund { terms } => {
            writer.u8(2)?;
            encode_channel_terms(terms, writer)
        }
    }
}

fn decode_input(
    reader: &mut Reader<'_>,
    expected_network_id: [u8; 32],
) -> Result<TxInput, WireError> {
    let previous = OutPoint {
        txid: reader.array()?,
        index: reader.u32()?,
    };
    let witness = match reader.u8()? {
        0 => InputWitness::Key {
            public_key: reader.array()?,
            signature: decode_signature(reader)?.to_vec(),
        },
        1 => {
            let terms = decode_channel_terms(reader, expected_network_id)?;
            let state = decode_payment_state(reader)?;
            let customer_signature = decode_signature(reader)?.to_vec();
            let provider_signature = decode_signature(reader)?.to_vec();
            InputWitness::InferenceSettlement {
                terms,
                settlement: Settlement {
                    state: SignedPaymentState {
                        state,
                        customer_signature,
                    },
                    provider_signature,
                },
            }
        }
        2 => InputWitness::InferenceRefund {
            terms: decode_channel_terms(reader, expected_network_id)?,
        },
        tag => {
            return Err(WireError::UnknownTag {
                field: "input witness",
                tag,
            });
        }
    };
    Ok(TxInput { previous, witness })
}

fn encode_output(output: &TxOutput, writer: &mut Writer) -> Result<(), WireError> {
    writer.u64(output.value)?;
    match &output.lock {
        OutputLock::Key(owner) => {
            writer.u8(0)?;
            writer.bytes(owner)?;
        }
        OutputLock::InferenceChannel { channel_id } => {
            writer.u8(1)?;
            writer.bytes(channel_id)?;
        }
    }
    writer.u64(output.spendable_height)
}

fn decode_output(reader: &mut Reader<'_>) -> Result<TxOutput, WireError> {
    let value = reader.u64()?;
    let lock = match reader.u8()? {
        0 => OutputLock::Key(reader.array()?),
        1 => OutputLock::InferenceChannel {
            channel_id: reader.array()?,
        },
        tag => {
            return Err(WireError::UnknownTag {
                field: "output lock",
                tag,
            });
        }
    };
    Ok(TxOutput {
        value,
        lock,
        spendable_height: reader.u64()?,
    })
}

fn encode_channel_terms(terms: &ChannelTerms, writer: &mut Writer) -> Result<(), WireError> {
    writer.bytes(&terms.network_id)?;
    writer.bytes(&terms.job_id)?;
    writer.bytes(&terms.customer_key)?;
    writer.bytes(&terms.provider_key)?;
    writer.bytes(&terms.model_digest)?;
    writer.bytes(&terms.runtime_digest)?;
    writer.bytes(&terms.input_digest)?;
    for value in [
        terms.deposit,
        terms.close_fee_burn,
        terms.base_price,
        terms.input_price_per_1000,
        terms.output_price_per_1000,
        terms.max_input_tokens,
        terms.max_output_tokens,
        terms.output_chunk_tokens,
        terms.refund_height,
    ] {
        writer.u64(value)?;
    }
    Ok(())
}

fn decode_channel_terms(
    reader: &mut Reader<'_>,
    expected_network_id: [u8; 32],
) -> Result<ChannelTerms, WireError> {
    let network_id = reader.array()?;
    if network_id != expected_network_id {
        return Err(WireError::WrongNetworkId {
            field: "channel terms",
        });
    }
    Ok(ChannelTerms {
        network_id,
        job_id: reader.array()?,
        customer_key: reader.array()?,
        provider_key: reader.array()?,
        model_digest: reader.array()?,
        runtime_digest: reader.array()?,
        input_digest: reader.array()?,
        deposit: reader.u64()?,
        close_fee_burn: reader.u64()?,
        base_price: reader.u64()?,
        input_price_per_1000: reader.u64()?,
        output_price_per_1000: reader.u64()?,
        max_input_tokens: reader.u64()?,
        max_output_tokens: reader.u64()?,
        output_chunk_tokens: reader.u64()?,
        refund_height: reader.u64()?,
    })
}

fn encode_payment_state(state: &PaymentState, writer: &mut Writer) -> Result<(), WireError> {
    writer.bytes(&state.channel_id)?;
    writer.u64(state.sequence)?;
    writer.u64(state.input_tokens)?;
    writer.u64(state.authorized_output_tokens)?;
    writer.u64(state.provider_payment)?;
    writer.u64(state.customer_refund)?;
    writer.u64(state.close_fee_burn)?;
    writer.bytes(&state.previous_receipt)
}

fn decode_payment_state(reader: &mut Reader<'_>) -> Result<PaymentState, WireError> {
    Ok(PaymentState {
        channel_id: reader.array()?,
        sequence: reader.u64()?,
        input_tokens: reader.u64()?,
        authorized_output_tokens: reader.u64()?,
        provider_payment: reader.u64()?,
        customer_refund: reader.u64()?,
        close_fee_burn: reader.u64()?,
        previous_receipt: reader.array()?,
    })
}

fn encode_signature(signature: &[u8], writer: &mut Writer) -> Result<(), WireError> {
    if signature.len() != CONSENSUS_SIGNATURE_BYTES {
        return Err(WireError::SignatureLength {
            actual: signature.len(),
        });
    }
    writer.bytes(signature)
}

fn decode_signature(reader: &mut Reader<'_>) -> Result<[u8; CONSENSUS_SIGNATURE_BYTES], WireError> {
    reader.array()
}

fn validate_transaction_shape(
    transaction: &Transaction,
    expected_network_id: [u8; 32],
) -> Result<(), WireError> {
    if transaction.network_id != expected_network_id {
        return Err(WireError::WrongNetworkId {
            field: "transaction",
        });
    }
    check_count(
        transaction.inputs.len(),
        MAX_TRANSACTION_INPUTS,
        "transaction inputs",
    )?;
    check_count(
        transaction.outputs.len(),
        MAX_TRANSACTION_OUTPUTS,
        "transaction outputs",
    )?;
    for input in &transaction.inputs {
        match &input.witness {
            InputWitness::Key { signature, .. } => check_signature(signature)?,
            InputWitness::InferenceSettlement { terms, settlement } => {
                check_terms_network(terms, expected_network_id)?;
                check_signature(&settlement.state.customer_signature)?;
                check_signature(&settlement.provider_signature)?;
            }
            InputWitness::InferenceRefund { terms } => {
                check_terms_network(terms, expected_network_id)?;
            }
        }
    }
    Ok(())
}

fn validate_block_shape(block: &Block) -> Result<(), WireError> {
    check_count(
        block.coinbase.outputs.len(),
        MAX_COINBASE_OUTPUTS,
        "coinbase outputs",
    )?;
    check_count(
        block.transactions.len(),
        MAX_BLOCK_TRANSACTIONS,
        "block transactions",
    )?;
    let mut aggregate_inputs = 0_usize;
    let mut aggregate_outputs = 0_usize;
    let mut signature_checks = 0_usize;
    for transaction in &block.transactions {
        validate_transaction_shape(transaction, block.challenge.network_id)?;
        add_block_resources(
            transaction,
            &mut aggregate_inputs,
            &mut aggregate_outputs,
            &mut signature_checks,
        )?;
    }
    Ok(())
}

fn add_block_resources(
    transaction: &Transaction,
    aggregate_inputs: &mut usize,
    aggregate_outputs: &mut usize,
    signature_checks: &mut usize,
) -> Result<(), WireError> {
    *aggregate_inputs = aggregate_inputs
        .checked_add(transaction.inputs.len())
        .ok_or(WireError::LengthOverflow)?;
    check_count(
        *aggregate_inputs,
        MAX_BLOCK_AGGREGATE_INPUTS,
        "block aggregate inputs",
    )?;
    *aggregate_outputs = aggregate_outputs
        .checked_add(transaction.outputs.len())
        .ok_or(WireError::LengthOverflow)?;
    check_count(
        *aggregate_outputs,
        MAX_BLOCK_AGGREGATE_OUTPUTS,
        "block aggregate outputs",
    )?;
    for input in &transaction.inputs {
        let additional = match &input.witness {
            InputWitness::Key { .. } => 1,
            InputWitness::InferenceSettlement { .. } => 2,
            InputWitness::InferenceRefund { .. } => 0,
        };
        *signature_checks = signature_checks
            .checked_add(additional)
            .ok_or(WireError::LengthOverflow)?;
        check_count(
            *signature_checks,
            MAX_BLOCK_SIGNATURE_CHECKS,
            "block signature checks",
        )?;
    }
    Ok(())
}

fn check_terms_network(
    terms: &ChannelTerms,
    expected_network_id: [u8; 32],
) -> Result<(), WireError> {
    if terms.network_id != expected_network_id {
        return Err(WireError::WrongNetworkId {
            field: "channel terms",
        });
    }
    Ok(())
}

fn check_signature(signature: &[u8]) -> Result<(), WireError> {
    if signature.len() != CONSENSUS_SIGNATURE_BYTES {
        return Err(WireError::SignatureLength {
            actual: signature.len(),
        });
    }
    Ok(())
}

fn check_count(actual: usize, max: usize, field: &'static str) -> Result<(), WireError> {
    if actual > max {
        return Err(WireError::CountLimit { field, actual, max });
    }
    Ok(())
}

fn check_byte_length(actual: usize, max: usize, object: &'static str) -> Result<(), WireError> {
    if actual > max {
        return Err(WireError::SizeLimit {
            object,
            actual,
            max,
        });
    }
    Ok(())
}

fn payload_limit(maximum_frame_bytes: usize) -> usize {
    maximum_frame_bytes - WIRE_HEADER_BYTES
}

fn ensure_payload_size(
    payload_bytes: usize,
    maximum_frame_bytes: usize,
    object: &'static str,
) -> Result<(), WireError> {
    let total = WIRE_HEADER_BYTES
        .checked_add(payload_bytes)
        .ok_or(WireError::LengthOverflow)?;
    if total > maximum_frame_bytes {
        return Err(WireError::SizeLimit {
            object,
            actual: total,
            max: maximum_frame_bytes,
        });
    }
    Ok(())
}

fn encode_frame(
    kind: u8,
    network_id: [u8; 32],
    payload: &[u8],
    maximum_bytes: usize,
    object: &'static str,
) -> Result<Vec<u8>, WireError> {
    ensure_payload_size(payload.len(), maximum_bytes, object)?;
    let payload_length = u32::try_from(payload.len()).map_err(|_| WireError::LengthOverflow)?;
    let total = WIRE_HEADER_BYTES
        .checked_add(payload.len())
        .ok_or(WireError::LengthOverflow)?;
    let mut frame = Vec::with_capacity(total);
    frame.extend_from_slice(&FRAME_MAGIC);
    frame.extend_from_slice(&network_magic(&network_id));
    frame.extend_from_slice(&WIRE_VERSION.to_le_bytes());
    frame.push(kind);
    frame.push(0);
    frame.extend_from_slice(&payload_length.to_le_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

fn decode_frame<'a>(
    bytes: &'a [u8],
    expected_network_id: [u8; 32],
    expected_kind: u8,
    maximum_bytes: usize,
    object: &'static str,
) -> Result<&'a [u8], WireError> {
    if bytes.len() < WIRE_HEADER_BYTES {
        return Err(WireError::Truncated {
            needed: WIRE_HEADER_BYTES,
            remaining: bytes.len(),
        });
    }
    if bytes.len() > maximum_bytes {
        return Err(WireError::SizeLimit {
            object,
            actual: bytes.len(),
            max: maximum_bytes,
        });
    }
    if bytes[..4] != FRAME_MAGIC {
        return Err(WireError::InvalidMagic);
    }
    if bytes[4..8] != network_magic(&expected_network_id) {
        return Err(WireError::WrongNetworkMagic);
    }
    let version = u16::from_le_bytes([bytes[8], bytes[9]]);
    if version != WIRE_VERSION {
        return Err(WireError::UnsupportedVersion(version));
    }
    if bytes[10] != expected_kind {
        return Err(WireError::UnexpectedKind {
            expected: expected_kind,
            actual: bytes[10],
        });
    }
    if bytes[11] != 0 {
        return Err(WireError::NonZeroFlags(bytes[11]));
    }
    let payload_length = usize::try_from(u32::from_le_bytes([
        bytes[12], bytes[13], bytes[14], bytes[15],
    ]))
    .map_err(|_| WireError::LengthOverflow)?;
    ensure_payload_size(payload_length, maximum_bytes, object)?;
    let actual_payload = bytes.len() - WIRE_HEADER_BYTES;
    if actual_payload < payload_length {
        return Err(WireError::Truncated {
            needed: payload_length,
            remaining: actual_payload,
        });
    }
    if actual_payload > payload_length {
        return Err(WireError::TrailingBytes {
            remaining: actual_payload - payload_length,
        });
    }
    Ok(&bytes[WIRE_HEADER_BYTES..])
}

struct Writer {
    bytes: Vec<u8>,
    limit: usize,
    object: &'static str,
}

impl Writer {
    fn new(limit: usize, object: &'static str) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
            object,
        }
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }

    fn reserve(&self, additional: usize) -> Result<(), WireError> {
        let actual = self
            .bytes
            .len()
            .checked_add(additional)
            .ok_or(WireError::LengthOverflow)?;
        if actual > self.limit {
            let framed_actual = actual
                .checked_add(WIRE_HEADER_BYTES)
                .ok_or(WireError::LengthOverflow)?;
            let framed_limit = self
                .limit
                .checked_add(WIRE_HEADER_BYTES)
                .ok_or(WireError::LengthOverflow)?;
            return Err(WireError::SizeLimit {
                object: self.object,
                actual: framed_actual,
                max: framed_limit,
            });
        }
        Ok(())
    }

    fn bytes(&mut self, value: &[u8]) -> Result<(), WireError> {
        self.reserve(value.len())?;
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn u8(&mut self, value: u8) -> Result<(), WireError> {
        self.bytes(&[value])
    }

    fn u32(&mut self, value: u32) -> Result<(), WireError> {
        self.bytes(&value.to_le_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<(), WireError> {
        self.bytes(&value.to_le_bytes())
    }

    fn count(
        &mut self,
        count: usize,
        maximum: usize,
        field: &'static str,
    ) -> Result<(), WireError> {
        check_count(count, maximum, field)?;
        let count = u32::try_from(count).map_err(|_| WireError::LengthOverflow)?;
        self.u32(count)
    }

    fn sized_bytes(
        &mut self,
        value: &[u8],
        maximum_frame_bytes: usize,
        object: &'static str,
    ) -> Result<(), WireError> {
        ensure_payload_size(value.len(), maximum_frame_bytes, object)?;
        let length = u32::try_from(value.len()).map_err(|_| WireError::LengthOverflow)?;
        self.u32(length)?;
        self.bytes(value)
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn finish(self) -> Result<(), WireError> {
        let remaining = self.bytes.len() - self.offset;
        if remaining != 0 {
            return Err(WireError::TrailingBytes { remaining });
        }
        Ok(())
    }

    fn bytes(&mut self, length: usize) -> Result<&'a [u8], WireError> {
        let remaining = self.bytes.len() - self.offset;
        if remaining < length {
            return Err(WireError::Truncated {
                needed: length,
                remaining,
            });
        }
        let end = self
            .offset
            .checked_add(length)
            .ok_or(WireError::LengthOverflow)?;
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        let mut value = [0_u8; N];
        value.copy_from_slice(self.bytes(N)?);
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.bytes(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, WireError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, WireError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn count(&mut self, maximum: usize, field: &'static str) -> Result<usize, WireError> {
        let count = usize::try_from(self.u32()?).map_err(|_| WireError::LengthOverflow)?;
        check_count(count, maximum, field)?;
        Ok(count)
    }

    fn sized_bytes(
        &mut self,
        maximum_frame_bytes: usize,
        object: &'static str,
    ) -> Result<&'a [u8], WireError> {
        let length = usize::try_from(self.u32()?).map_err(|_| WireError::LengthOverflow)?;
        ensure_payload_size(length, maximum_frame_bytes, object)?;
        self.bytes(length)
    }
}

#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use super::*;

    const NETWORK_ID: [u8; 32] = [0x51; 32];

    fn terms() -> ChannelTerms {
        ChannelTerms {
            network_id: NETWORK_ID,
            job_id: [1; 32],
            customer_key: [2; 32],
            provider_key: [3; 32],
            model_digest: [4; 32],
            runtime_digest: [5; 32],
            input_digest: [6; 32],
            deposit: 10_000,
            close_fee_burn: 10,
            base_price: 20,
            input_price_per_1000: 30,
            output_price_per_1000: 40,
            max_input_tokens: 50,
            max_output_tokens: 60,
            output_chunk_tokens: 10,
            refund_height: 70,
        }
    }

    fn settlement() -> Settlement {
        Settlement {
            state: SignedPaymentState {
                state: PaymentState {
                    channel_id: [7; 32],
                    sequence: 8,
                    input_tokens: 9,
                    authorized_output_tokens: 10,
                    provider_payment: 11,
                    customer_refund: 12,
                    close_fee_burn: 13,
                    previous_receipt: [14; 32],
                },
                customer_signature: vec![15; CONSENSUS_SIGNATURE_BYTES],
            },
            provider_signature: vec![16; CONSENSUS_SIGNATURE_BYTES],
        }
    }

    fn transaction() -> Transaction {
        Transaction {
            network_id: NETWORK_ID,
            version: 7,
            inputs: vec![
                TxInput {
                    previous: OutPoint {
                        txid: [17; 32],
                        index: 18,
                    },
                    witness: InputWitness::Key {
                        public_key: [19; 32],
                        signature: vec![20; CONSENSUS_SIGNATURE_BYTES],
                    },
                },
                TxInput {
                    previous: OutPoint {
                        txid: [21; 32],
                        index: 22,
                    },
                    witness: InputWitness::InferenceSettlement {
                        terms: terms(),
                        settlement: settlement(),
                    },
                },
                TxInput {
                    previous: OutPoint {
                        txid: [23; 32],
                        index: 24,
                    },
                    witness: InputWitness::InferenceRefund { terms: terms() },
                },
            ],
            outputs: vec![
                TxOutput {
                    value: 25,
                    lock: OutputLock::Key([26; 32]),
                    spendable_height: 27,
                },
                TxOutput {
                    value: 28,
                    lock: OutputLock::InferenceChannel {
                        channel_id: [29; 32],
                    },
                    spendable_height: 30,
                },
            ],
        }
    }

    fn proof() -> BlockProof {
        BlockProof::V1Legacy(ForgeMatrixProof {
            algorithm_version: 31,
            model_version: 32,
            nonce: 33,
            model_root: [34; 32],
            output_digest: [35; 32],
            work_digest: [36; 32],
        })
    }

    fn v2_proof() -> BlockProof {
        BlockProof::V2Reference(ForgeMatrixV2CompactProof {
            algorithm_version: 41,
            proof_version: 42,
            nonce: 43,
            model_manifest_digest: [44; 32],
            challenge_digest: [45; 32],
            final_activation_digest: [46; 32],
            work_digest: [47; 32],
        })
    }

    fn v3_proof() -> BlockProof {
        BlockProof::V3Candidate(Box::new(ForgeMatrixV3CandidateProof {
            algorithm_version: 51,
            proof_version: 52,
            nonce: 53,
            model_manifest_digest: [54; 32],
            challenge_digest: [55; 32],
            final_activation_digest: [56; 32],
            work_digest: [57; 32],
            structured_proof: b"CMFDSA03-canonical-candidate".to_vec(),
        }))
    }

    fn v4_proof() -> BlockProof {
        BlockProof::V4Candidate(Box::new(ForgeMatrixV4CandidateProof {
            algorithm_version: 61,
            proof_version: 62,
            nonce: 63,
            proof_system_digest: [64; 32],
            model_manifest_digest: [65; 32],
            challenge_digest: [66; 32],
            final_activation_digest: [67; 32],
            work_digest: [68; 32],
            transparent_proof: b"CMFDV4-transparent-candidate".to_vec(),
        }))
    }

    fn block() -> Block {
        Block {
            version: 37,
            challenge: BlockChallenge {
                network_id: NETWORK_ID,
                previous_block: [38; 32],
                transaction_root: [39; 32],
                height: 40,
                timestamp: 41,
                target: [42; 32],
            },
            proof: proof(),
            coinbase: Coinbase {
                height: 40,
                outputs: vec![TxOutput {
                    value: 43,
                    lock: OutputLock::Key([44; 32]),
                    spendable_height: 45,
                }],
            },
            transactions: vec![transaction()],
        }
    }

    #[test]
    fn canonical_frames_and_all_payloads_round_trip() {
        let transaction = transaction();
        let encoded_transaction = encode_transaction(&transaction).unwrap();
        assert_header(
            &encoded_transaction,
            TRANSACTION_KIND,
            MAX_TRANSACTION_BYTES,
        );
        assert_eq!(
            decode_transaction(&encoded_transaction, NETWORK_ID).unwrap(),
            transaction
        );

        for (proof, tag) in [
            (proof(), FORGEMATRIX_V1_PROOF_TAG),
            (v2_proof(), FORGEMATRIX_V2_PROOF_TAG),
            (v3_proof(), FORGEMATRIX_V3_CANDIDATE_PROOF_TAG),
        ] {
            let encoded_proof = encode_forgematrix_proof(&proof, NETWORK_ID).unwrap();
            assert_header(&encoded_proof, FORGEMATRIX_PROOF_KIND, MAX_PROOF_BYTES);
            assert_eq!(encoded_proof[WIRE_HEADER_BYTES], tag);
            assert_eq!(
                decode_forgematrix_proof(&encoded_proof, NETWORK_ID).unwrap(),
                proof
            );
        }

        let v1_block = block();
        let encoded_block = encode_block(&v1_block).unwrap();
        assert_header(&encoded_block, BLOCK_KIND, MAX_BLOCK_BYTES);
        assert_eq!(
            u32::from_le_bytes(
                encoded_block[WIRE_HEADER_BYTES..WIRE_HEADER_BYTES + 4]
                    .try_into()
                    .unwrap()
            ),
            v1_block.version
        );
        assert_eq!(decode_block(&encoded_block, NETWORK_ID).unwrap(), v1_block);

        let mut v2_block = block();
        v2_block.proof = v2_proof();
        let encoded_v2_block = encode_block(&v2_block).unwrap();
        assert_eq!(
            decode_block(&encoded_v2_block, NETWORK_ID).unwrap(),
            v2_block
        );

        let mut v3_block = block();
        v3_block.proof = v3_proof();
        let encoded_v3_block = encode_block(&v3_block).unwrap();
        assert_eq!(
            decode_block(&encoded_v3_block, NETWORK_ID).unwrap(),
            v3_block
        );
    }

    #[test]
    fn framing_mutations_are_rejected_precisely() {
        let encoded = encode_transaction(&transaction()).unwrap();

        let mut bad_magic = encoded.clone();
        bad_magic[0] ^= 1;
        assert_eq!(
            decode_transaction(&bad_magic, NETWORK_ID),
            Err(WireError::InvalidMagic)
        );

        let mut wrong_network = encoded.clone();
        wrong_network[4] ^= 1;
        assert_eq!(
            decode_transaction(&wrong_network, NETWORK_ID),
            Err(WireError::WrongNetworkMagic)
        );

        let mut bad_version = encoded.clone();
        bad_version[8..10].copy_from_slice(&2_u16.to_le_bytes());
        assert_eq!(
            decode_transaction(&bad_version, NETWORK_ID),
            Err(WireError::UnsupportedVersion(2))
        );

        let mut bad_kind = encoded.clone();
        bad_kind[10] = BLOCK_KIND;
        assert_eq!(
            decode_transaction(&bad_kind, NETWORK_ID),
            Err(WireError::UnexpectedKind {
                expected: TRANSACTION_KIND,
                actual: BLOCK_KIND,
            })
        );

        let mut bad_flags = encoded.clone();
        bad_flags[11] = 1;
        assert_eq!(
            decode_transaction(&bad_flags, NETWORK_ID),
            Err(WireError::NonZeroFlags(1))
        );

        let payload_length = encoded.len() - WIRE_HEADER_BYTES;
        let mut short_declaration = encoded.clone();
        short_declaration[12..16]
            .copy_from_slice(&(u32::try_from(payload_length - 1).unwrap()).to_le_bytes());
        assert_eq!(
            decode_transaction(&short_declaration, NETWORK_ID),
            Err(WireError::TrailingBytes { remaining: 1 })
        );

        let mut long_declaration = encoded.clone();
        long_declaration[12..16]
            .copy_from_slice(&(u32::try_from(payload_length + 1).unwrap()).to_le_bytes());
        assert_eq!(
            decode_transaction(&long_declaration, NETWORK_ID),
            Err(WireError::Truncated {
                needed: payload_length + 1,
                remaining: payload_length,
            })
        );

        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            decode_transaction(&trailing, NETWORK_ID),
            Err(WireError::TrailingBytes { remaining: 1 })
        );
    }

    #[test]
    fn full_network_ids_are_checked_inside_transaction_and_block_payloads() {
        let mut encoded_transaction = encode_transaction(&transaction()).unwrap();
        encoded_transaction[WIRE_HEADER_BYTES] ^= 1;
        assert_eq!(
            decode_transaction(&encoded_transaction, NETWORK_ID),
            Err(WireError::WrongNetworkId {
                field: "transaction",
            })
        );

        let mut encoded_block = encode_block(&block()).unwrap();
        encoded_block[WIRE_HEADER_BYTES + 4] ^= 1;
        assert_eq!(
            decode_block(&encoded_block, NETWORK_ID),
            Err(WireError::WrongNetworkId {
                field: "block challenge",
            })
        );

        for proof in [proof(), v2_proof(), v3_proof()] {
            let mut encoded_proof = encode_forgematrix_proof(&proof, NETWORK_ID).unwrap();
            encoded_proof[WIRE_HEADER_BYTES + 1] ^= 1;
            assert_eq!(
                decode_forgematrix_proof(&encoded_proof, NETWORK_ID),
                Err(WireError::WrongNetworkId {
                    field: "ForgeMatrix proof",
                })
            );

            let mut block = block();
            block.proof = proof;
            let mut encoded_block = encode_block(&block).unwrap();
            let challenge_bytes = 4 + 4 * 32 + 2 * 8;
            let proof_tag_offset = WIRE_HEADER_BYTES + challenge_bytes + 4;
            encoded_block[proof_tag_offset + 1] ^= 1;
            assert_eq!(
                decode_block(&encoded_block, NETWORK_ID),
                Err(WireError::WrongNetworkId {
                    field: "ForgeMatrix proof",
                })
            );
        }

        let mut inconsistent = transaction();
        let InputWitness::InferenceSettlement { terms, .. } = &mut inconsistent.inputs[1].witness
        else {
            unreachable!();
        };
        terms.network_id[0] ^= 1;
        assert_eq!(
            encode_transaction(&inconsistent),
            Err(WireError::WrongNetworkId {
                field: "channel terms",
            })
        );
    }

    #[test]
    fn proof_tags_are_explicit_and_cannot_be_substituted() {
        let v1 = encode_forgematrix_proof(&proof(), NETWORK_ID).unwrap();
        let v2 = encode_forgematrix_proof(&v2_proof(), NETWORK_ID).unwrap();
        let v3 = encode_forgematrix_proof(&v3_proof(), NETWORK_ID).unwrap();

        let mut v1_as_v2 = v1.clone();
        v1_as_v2[WIRE_HEADER_BYTES] = FORGEMATRIX_V2_PROOF_TAG;
        assert!(decode_forgematrix_proof(&v1_as_v2, NETWORK_ID).is_err());

        let mut v2_as_v1 = v2.clone();
        v2_as_v1[WIRE_HEADER_BYTES] = FORGEMATRIX_V1_PROOF_TAG;
        assert!(decode_forgematrix_proof(&v2_as_v1, NETWORK_ID).is_err());

        let mut v2_as_v3 = v2;
        v2_as_v3[WIRE_HEADER_BYTES] = FORGEMATRIX_V3_CANDIDATE_PROOF_TAG;
        assert!(decode_forgematrix_proof(&v2_as_v3, NETWORK_ID).is_err());

        let mut v3_as_v2 = v3;
        v3_as_v2[WIRE_HEADER_BYTES] = FORGEMATRIX_V2_PROOF_TAG;
        assert!(decode_forgematrix_proof(&v3_as_v2, NETWORK_ID).is_err());

        let mut unknown = v1;
        unknown[WIRE_HEADER_BYTES] = 0xff;
        assert_eq!(
            decode_forgematrix_proof(&unknown, NETWORK_ID),
            Err(WireError::UnknownTag {
                field: "ForgeMatrix proof",
                tag: 0xff,
            })
        );
    }

    #[test]
    fn v3_candidate_frame_has_an_exact_whole_frame_cap_and_stays_fail_closed() {
        assert_eq!(
            WIRE_HEADER_BYTES
                + FORGEMATRIX_V3_PUBLIC_PREFIX_BYTES
                + FORGEMATRIX_V3_LENGTH_BYTES
                + MAX_FORGEMATRIX_V3_STRUCTURED_PROOF_BYTES,
            MAX_PROOF_BYTES
        );

        let BlockProof::V3Candidate(mut proof) = v3_proof() else {
            unreachable!();
        };
        proof.structured_proof = vec![0x5a; MAX_FORGEMATRIX_V3_STRUCTURED_PROOF_BYTES];
        let encoded =
            encode_forgematrix_proof(&BlockProof::V3Candidate(proof.clone()), NETWORK_ID).unwrap();
        assert_eq!(encoded.len(), MAX_PROOF_BYTES);
        assert_eq!(
            decode_forgematrix_proof(&encoded, NETWORK_ID).unwrap(),
            BlockProof::V3Candidate(proof.clone())
        );

        proof.structured_proof.push(0);
        assert_eq!(
            encode_forgematrix_proof(&BlockProof::V3Candidate(proof), NETWORK_ID),
            Err(WireError::SizeLimit {
                object: "structured production proof",
                actual: MAX_FORGEMATRIX_V3_STRUCTURED_PROOF_BYTES + 1,
                max: MAX_FORGEMATRIX_V3_STRUCTURED_PROOF_BYTES,
            })
        );

        let BlockProof::V3Candidate(mut empty) = v3_proof() else {
            unreachable!();
        };
        empty.structured_proof.clear();
        assert_eq!(
            encode_forgematrix_proof(&BlockProof::V3Candidate(empty), NETWORK_ID),
            Err(WireError::EmptyField {
                field: "structured production proof",
            })
        );

        let encoded_candidate = encode_forgematrix_proof(&v3_proof(), NETWORK_ID).unwrap();
        let structured_length_offset = WIRE_HEADER_BYTES + FORGEMATRIX_V3_PUBLIC_PREFIX_BYTES;
        let mut declared_oversized = encoded_candidate.clone();
        declared_oversized[structured_length_offset..structured_length_offset + 4].copy_from_slice(
            &u32::try_from(MAX_FORGEMATRIX_V3_STRUCTURED_PROOF_BYTES + 1)
                .unwrap()
                .to_le_bytes(),
        );
        assert_eq!(
            decode_forgematrix_proof(&declared_oversized, NETWORK_ID),
            Err(WireError::SizeLimit {
                object: "structured production proof",
                actual: MAX_FORGEMATRIX_V3_STRUCTURED_PROOF_BYTES + 1,
                max: MAX_FORGEMATRIX_V3_STRUCTURED_PROOF_BYTES,
            })
        );

        let mut declared_empty = encoded_candidate;
        declared_empty[structured_length_offset..structured_length_offset + 4]
            .copy_from_slice(&0_u32.to_le_bytes());
        assert_eq!(
            decode_forgematrix_proof(&declared_empty, NETWORK_ID),
            Err(WireError::EmptyField {
                field: "structured production proof",
            })
        );

        let verifier =
            crate::ConsensusPowVerifier::v2_reference(crate::v2_test_reference().unwrap());
        let wrong_network = verifier.parameters();
        assert!(matches!(
            wrong_network,
            crate::PowParameters::V2Reference(_)
        ));
        assert!(matches!(
            verifier.verify(
                &BlockChallenge {
                    network_id: NETWORK_ID,
                    previous_block: [1; 32],
                    transaction_root: [2; 32],
                    height: 1,
                    timestamp: 60,
                    target: [0xff; 32],
                },
                &v3_proof(),
            ),
            Err(crate::PowError::WrongProofType)
        ));
    }

    #[test]
    fn v4_candidate_uses_only_its_isolated_network_and_exact_larger_cap() {
        assert_eq!(max_proof_bytes_for_network(NETWORK_ID), MAX_PROOF_BYTES);
        assert_eq!(max_block_bytes_for_network(NETWORK_ID), MAX_BLOCK_BYTES);
        assert_eq!(
            max_proof_bytes_for_network(PRODUCTION_V4_TESTNET_NETWORK_ID),
            PRODUCTION_V4_MAX_PROOF_BYTES
        );
        assert_eq!(
            max_block_bytes_for_network(PRODUCTION_V4_TESTNET_NETWORK_ID),
            PRODUCTION_V4_MAX_BLOCK_BYTES
        );
        assert_eq!(
            max_proof_bytes_for_network(PRODUCTION_V4_RCNET1_NETWORK_ID),
            PRODUCTION_V4_MAX_PROOF_BYTES
        );
        assert_eq!(
            max_block_bytes_for_network(PRODUCTION_V4_RCNET1_NETWORK_ID),
            PRODUCTION_V4_MAX_BLOCK_BYTES
        );
        assert_eq!(
            WIRE_HEADER_BYTES
                + FORGEMATRIX_V4_PUBLIC_PREFIX_BYTES
                + FORGEMATRIX_V4_LENGTH_BYTES
                + MAX_FORGEMATRIX_V4_TRANSPARENT_PROOF_BYTES,
            PRODUCTION_V4_MAX_PROOF_BYTES
        );

        let proof = v4_proof();
        let encoded = encode_forgematrix_proof(&proof, PRODUCTION_V4_TESTNET_NETWORK_ID).unwrap();
        assert_eq!(
            encoded[WIRE_HEADER_BYTES],
            FORGEMATRIX_V4_CANDIDATE_PROOF_TAG
        );
        assert_eq!(
            decode_forgematrix_proof(&encoded, PRODUCTION_V4_TESTNET_NETWORK_ID).unwrap(),
            proof
        );
        let rcnet_encoded =
            encode_forgematrix_proof(&proof, PRODUCTION_V4_RCNET1_NETWORK_ID).unwrap();
        assert_eq!(
            decode_forgematrix_proof(&rcnet_encoded, PRODUCTION_V4_RCNET1_NETWORK_ID).unwrap(),
            proof
        );

        assert_eq!(
            encode_forgematrix_proof(&v4_proof(), NETWORK_ID),
            Err(WireError::ProofTagNetworkMismatch {
                tag: FORGEMATRIX_V4_CANDIDATE_PROOF_TAG,
            })
        );
        assert_eq!(
            encode_forgematrix_proof(&v3_proof(), PRODUCTION_V4_TESTNET_NETWORK_ID),
            Err(WireError::ProofTagNetworkMismatch {
                tag: FORGEMATRIX_V3_CANDIDATE_PROOF_TAG,
            })
        );

        let mut wrong_tag = encoded;
        wrong_tag[WIRE_HEADER_BYTES] = FORGEMATRIX_V3_CANDIDATE_PROOF_TAG;
        assert_eq!(
            decode_forgematrix_proof(&wrong_tag, PRODUCTION_V4_TESTNET_NETWORK_ID),
            Err(WireError::ProofTagNetworkMismatch {
                tag: FORGEMATRIX_V3_CANDIDATE_PROOF_TAG,
            })
        );
    }

    #[test]
    fn v4_candidate_accepts_measured_pcs_and_public_output_then_rejects_oversize() {
        const MEASURED_THREE_BANK_BASEFOLD_BYTES: usize = 3 * 3_296_168;
        const MEASURED_PCS_PLUS_PUBLIC_OUTPUT_BYTES: usize = MEASURED_THREE_BANK_BASEFOLD_BYTES
            + crate::FORGEMATRIX_V4_PUBLIC_FINAL_ACTIVATION_BYTES;
        const {
            assert!(MEASURED_THREE_BANK_BASEFOLD_BYTES > MAX_PROOF_BYTES);
            assert!(
                MEASURED_PCS_PLUS_PUBLIC_OUTPUT_BYTES < MAX_FORGEMATRIX_V4_TRANSPARENT_PROOF_BYTES
            );
        }

        let BlockProof::V4Candidate(mut proof) = v4_proof() else {
            unreachable!();
        };
        proof.transparent_proof = vec![0x5a; MEASURED_PCS_PLUS_PUBLIC_OUTPUT_BYTES];
        let candidate = BlockProof::V4Candidate(proof.clone());
        let encoded =
            encode_forgematrix_proof(&candidate, PRODUCTION_V4_TESTNET_NETWORK_ID).unwrap();
        assert!(encoded.len() > MAX_PROOF_BYTES);
        assert!(encoded.len() < PRODUCTION_V4_MAX_PROOF_BYTES);
        assert_eq!(
            decode_forgematrix_proof(&encoded, PRODUCTION_V4_TESTNET_NETWORK_ID).unwrap(),
            BlockProof::V4Candidate(proof)
        );

        let mut block = block();
        block.challenge.network_id = PRODUCTION_V4_TESTNET_NETWORK_ID;
        block.proof = candidate;
        block.transactions.clear();
        let encoded_block = encode_block(&block).unwrap();
        assert!(encoded_block.len() > MAX_BLOCK_BYTES);
        assert!(encoded_block.len() < PRODUCTION_V4_MAX_BLOCK_BYTES);
        assert_eq!(
            decode_block(&encoded_block, PRODUCTION_V4_TESTNET_NETWORK_ID).unwrap(),
            block
        );

        let BlockProof::V4Candidate(mut oversize) = v4_proof() else {
            unreachable!();
        };
        oversize.transparent_proof = vec![0; MAX_FORGEMATRIX_V4_TRANSPARENT_PROOF_BYTES + 1];
        assert_eq!(
            encode_forgematrix_proof(
                &BlockProof::V4Candidate(oversize),
                PRODUCTION_V4_TESTNET_NETWORK_ID,
            ),
            Err(WireError::SizeLimit {
                object: "transparent production proof",
                actual: MAX_FORGEMATRIX_V4_TRANSPARENT_PROOF_BYTES + 1,
                max: MAX_FORGEMATRIX_V4_TRANSPARENT_PROOF_BYTES,
            })
        );

        let mut declared_oversize =
            encode_forgematrix_proof(&v4_proof(), PRODUCTION_V4_TESTNET_NETWORK_ID).unwrap();
        let proof_length_offset = WIRE_HEADER_BYTES + FORGEMATRIX_V4_PUBLIC_PREFIX_BYTES;
        declared_oversize[proof_length_offset..proof_length_offset + FORGEMATRIX_V4_LENGTH_BYTES]
            .copy_from_slice(
                &u32::try_from(MAX_FORGEMATRIX_V4_TRANSPARENT_PROOF_BYTES + 1)
                    .unwrap()
                    .to_le_bytes(),
            );
        assert_eq!(
            decode_forgematrix_proof(&declared_oversize, PRODUCTION_V4_TESTNET_NETWORK_ID,),
            Err(WireError::SizeLimit {
                object: "transparent production proof",
                actual: MAX_FORGEMATRIX_V4_TRANSPARENT_PROOF_BYTES + 1,
                max: MAX_FORGEMATRIX_V4_TRANSPARENT_PROOF_BYTES,
            })
        );

        let BlockProof::V4Candidate(mut empty) = v4_proof() else {
            unreachable!();
        };
        empty.transparent_proof.clear();
        assert_eq!(
            encode_forgematrix_proof(
                &BlockProof::V4Candidate(empty),
                PRODUCTION_V4_TESTNET_NETWORK_ID,
            ),
            Err(WireError::EmptyField {
                field: "transparent production proof",
            })
        );

        let mut declared_empty =
            encode_forgematrix_proof(&v4_proof(), PRODUCTION_V4_TESTNET_NETWORK_ID).unwrap();
        declared_empty[proof_length_offset..proof_length_offset + FORGEMATRIX_V4_LENGTH_BYTES]
            .copy_from_slice(&0_u32.to_le_bytes());
        declared_empty.truncate(proof_length_offset + FORGEMATRIX_V4_LENGTH_BYTES);
        let payload_length = declared_empty.len() - WIRE_HEADER_BYTES;
        declared_empty[12..16]
            .copy_from_slice(&u32::try_from(payload_length).unwrap().to_le_bytes());
        assert_eq!(
            decode_forgematrix_proof(&declared_empty, PRODUCTION_V4_TESTNET_NETWORK_ID),
            Err(WireError::EmptyField {
                field: "transparent production proof",
            })
        );
    }

    #[test]
    fn signatures_are_fixed_width_and_nested_payloads_require_exact_exhaustion() {
        let mut invalid = transaction();
        let InputWitness::Key { signature, .. } = &mut invalid.inputs[0].witness else {
            unreachable!();
        };
        signature.pop();
        assert_eq!(
            encode_transaction(&invalid),
            Err(WireError::SignatureLength { actual: 63 })
        );

        let mut transaction_payload = encode_transaction_payload(&transaction()).unwrap();
        transaction_payload.push(0);
        assert_eq!(
            decode_transaction_payload(&transaction_payload, NETWORK_ID),
            Err(WireError::TrailingBytes { remaining: 1 })
        );

        let mut proof_payload = encode_forgematrix_proof_payload(&proof(), NETWORK_ID).unwrap();
        proof_payload.push(0);
        assert_eq!(
            decode_forgematrix_proof_payload(&proof_payload, NETWORK_ID),
            Err(WireError::TrailingBytes { remaining: 1 })
        );
    }

    #[test]
    fn declared_counts_are_rejected_before_element_allocation() {
        let mut payload = Writer::new(payload_limit(MAX_TRANSACTION_BYTES), "transaction");
        payload.bytes(&NETWORK_ID).unwrap();
        payload.u32(1).unwrap();
        payload
            .u32(u32::try_from(MAX_TRANSACTION_INPUTS + 1).unwrap())
            .unwrap();
        let encoded = encode_frame(
            TRANSACTION_KIND,
            NETWORK_ID,
            &payload.finish(),
            MAX_TRANSACTION_BYTES,
            "transaction",
        )
        .unwrap();
        assert_eq!(
            decode_transaction(&encoded, NETWORK_ID),
            Err(WireError::CountLimit {
                field: "transaction inputs",
                actual: MAX_TRANSACTION_INPUTS + 1,
                max: MAX_TRANSACTION_INPUTS,
            })
        );

        let mut too_many = block();
        too_many.transactions = vec![transaction(); MAX_BLOCK_TRANSACTIONS + 1];
        assert_eq!(
            encode_block(&too_many),
            Err(WireError::CountLimit {
                field: "block transactions",
                actual: MAX_BLOCK_TRANSACTIONS + 1,
                max: MAX_BLOCK_TRANSACTIONS,
            })
        );

        let output = block().coinbase.outputs[0].clone();
        let mut too_many_coinbase_outputs = block();
        too_many_coinbase_outputs.coinbase.outputs = vec![output; MAX_COINBASE_OUTPUTS + 1];
        assert_eq!(
            encode_block(&too_many_coinbase_outputs),
            Err(WireError::CountLimit {
                field: "coinbase outputs",
                actual: MAX_COINBASE_OUTPUTS + 1,
                max: MAX_COINBASE_OUTPUTS,
            })
        );
    }

    #[test]
    fn aggregate_and_signature_limits_match_network_consensus() {
        let refund_input = transaction().inputs[2].clone();
        let mut dense_transaction = transaction();
        dense_transaction.inputs = vec![refund_input; MAX_TRANSACTION_INPUTS];
        dense_transaction.outputs.truncate(1);
        let mut aggregate_block = block();
        aggregate_block.transactions =
            vec![dense_transaction; MAX_BLOCK_AGGREGATE_INPUTS / MAX_TRANSACTION_INPUTS + 1];
        assert!(matches!(
            encode_block(&aggregate_block),
            Err(WireError::CountLimit {
                field: "block aggregate inputs",
                actual,
                max: MAX_BLOCK_AGGREGATE_INPUTS,
            }) if actual > MAX_BLOCK_AGGREGATE_INPUTS
        ));

        let settlement_input = transaction().inputs[1].clone();
        let mut signed_transaction = transaction();
        signed_transaction.inputs = vec![settlement_input; MAX_TRANSACTION_INPUTS];
        signed_transaction.outputs.truncate(1);
        let mut signature_block = block();
        signature_block.transactions =
            vec![signed_transaction; MAX_BLOCK_SIGNATURE_CHECKS / (2 * MAX_TRANSACTION_INPUTS) + 1];
        assert!(matches!(
            encode_block(&signature_block),
            Err(WireError::CountLimit {
                field: "block signature checks",
                actual,
                max: MAX_BLOCK_SIGNATURE_CHECKS,
            }) if actual > MAX_BLOCK_SIGNATURE_CHECKS
        ));
    }

    #[test]
    fn transaction_byte_cap_is_enforced_while_encoding() {
        let settlement_input = transaction().inputs[1].clone();
        let output = transaction().outputs[0].clone();
        let oversized = Transaction {
            network_id: NETWORK_ID,
            version: 1,
            inputs: vec![settlement_input; MAX_TRANSACTION_INPUTS],
            outputs: vec![output; MAX_TRANSACTION_OUTPUTS],
        };
        assert!(matches!(
            encode_transaction(&oversized),
            Err(WireError::SizeLimit {
                object: "transaction",
                actual,
                max: MAX_TRANSACTION_BYTES,
            }) if actual > MAX_TRANSACTION_BYTES
        ));
    }

    #[test]
    fn every_truncation_and_deterministic_mutation_is_panic_free() {
        let transaction = encode_transaction(&transaction()).unwrap();
        assert_all_truncations(&transaction, |bytes| {
            decode_transaction(bytes, NETWORK_ID).map(drop)
        });

        for proof in [proof(), v2_proof(), v3_proof()] {
            let proof = encode_forgematrix_proof(&proof, NETWORK_ID).unwrap();
            assert_all_truncations(&proof, |bytes| {
                decode_forgematrix_proof(bytes, NETWORK_ID).map(drop)
            });
        }

        let mut v3_block = block();
        v3_block.proof = v3_proof();
        for block in [block(), v3_block] {
            let block = encode_block(&block).unwrap();
            assert_all_truncations(&block, |bytes| decode_block(bytes, NETWORK_ID).map(drop));
            for index in 0..block.len() {
                let mut mutated = block.clone();
                mutated[index] ^= 0x80;
                assert!(
                    catch_unwind(AssertUnwindSafe(|| decode_block(&mutated, NETWORK_ID))).is_ok(),
                    "decoder panicked after mutating byte {index}"
                );
            }
        }

        let mut state = 0x9e37_79b9_u32;
        for length in 0..512 {
            let mut arbitrary = vec![0_u8; length];
            for byte in &mut arbitrary {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                *byte = (state >> 24) as u8;
            }
            assert!(
                catch_unwind(AssertUnwindSafe(|| {
                    let _ = decode_transaction(&arbitrary, NETWORK_ID);
                    let _ = decode_forgematrix_proof(&arbitrary, NETWORK_ID);
                    let _ = decode_block(&arbitrary, NETWORK_ID);
                }))
                .is_ok(),
                "decoder panicked on {length} arbitrary bytes"
            );
        }
    }

    fn assert_header(encoded: &[u8], kind: u8, maximum: usize) {
        assert!(encoded.len() <= maximum);
        assert_eq!(&encoded[..4], b"CMFD");
        assert_eq!(&encoded[4..8], &network_magic(&NETWORK_ID));
        assert_eq!(
            u16::from_le_bytes(encoded[8..10].try_into().unwrap()),
            WIRE_VERSION
        );
        assert_eq!(encoded[10], kind);
        assert_eq!(encoded[11], 0);
        assert_eq!(
            usize::try_from(u32::from_le_bytes(encoded[12..16].try_into().unwrap())).unwrap(),
            encoded.len() - WIRE_HEADER_BYTES
        );
    }

    fn assert_all_truncations(
        encoded: &[u8],
        mut decode: impl FnMut(&[u8]) -> Result<(), WireError>,
    ) {
        for length in 0..encoded.len() {
            let result = catch_unwind(AssertUnwindSafe(|| decode(&encoded[..length])));
            assert!(result.is_ok(), "decoder panicked at prefix length {length}");
            assert!(
                result.unwrap().is_err(),
                "decoder accepted truncated prefix length {length}"
            );
        }
    }
}
