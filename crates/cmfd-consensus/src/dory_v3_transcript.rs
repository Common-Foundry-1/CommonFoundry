//! Canonical transcript derivations for the proposed Dory-native V3 path.
//!
//! These helpers own only fixed-width public transcript bytes. They do not
//! verify a proof, authenticate a model bank, or authorize chain admission.

use blake3::Hasher;
use thiserror::Error;

use crate::{
    BlockChallenge, ForgeMatrixV3CandidateProof,
    dory_bls12_381_blake3::BLS_DORY_BLAKE3_PRODUCTION_ACTIVATION_BYTES,
    dory_v3_model_record::{
        BankAuthenticatedDoryV3ModelCommitmentRecordV2, DoryV3ModelCommitmentRecordError,
    },
    dory_v3_suite::{
        DORY_V3_ALGEBRAIC_BINDING_DOMAIN, DORY_V3_ALGEBRAIC_BINDING_VERSION,
        DORY_V3_ALGORITHM_VERSION, DORY_V3_CHALLENGE_DOMAIN, DORY_V3_MASK_DOMAIN,
        DORY_V3_OUTPUT_DOMAIN, DORY_V3_POW_TYPE, DORY_V3_PRODUCTION_SUITE_DIGEST,
        DORY_V3_PROOF_VERSION, DORY_V3_WORK_DOMAIN, Digest32,
    },
};

/// Bank-authenticated fixed identities prepended to every V3 public transcript.
///
/// This value can only be constructed from the non-serializable Record V2
/// capability returned after one reader authenticates the complete model bank
/// and rederives all four ordered Dory commitments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DoryV3TranscriptContext {
    network_id: [u8; 32],
    suite_digest: Digest32,
    manifest_digest: Digest32,
    model_identity_digest: Digest32,
    model_record_digest: Digest32,
}

/// Opaque evidence that one V3 challenge digest was derived from an
/// authenticated transcript context, one block challenge, and one nonce.
///
/// The private transcript context retains every model and network identity
/// that was absorbed into the digest. Callers cannot construct this capability
/// from raw digest bytes.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DoryV3ChallengeContext {
    transcript_context: DoryV3TranscriptContext,
    digest: [u8; 32],
}

impl DoryV3ChallengeContext {
    /// Return the exact derived challenge digest.
    pub(crate) const fn digest(self) -> [u8; 32] {
        self.digest
    }

    /// Hash one canonical centered-byte activation under this exact challenge.
    #[allow(dead_code)]
    pub(crate) fn output_digest(
        self,
        activation: &[u8],
    ) -> Result<[u8; 32], DoryV3TranscriptError> {
        self.transcript_context
            .output_digest(self.digest, activation)
    }

    /// Hash the V3 work fields under this exact challenge.
    #[allow(dead_code)]
    pub(crate) fn work_digest(self, final_activation_digest: [u8; 32]) -> [u8; 32] {
        self.transcript_context
            .work_digest(self.digest, final_activation_digest)
    }

    #[allow(dead_code)]
    pub(crate) const fn transcript_context(self) -> DoryV3TranscriptContext {
        self.transcript_context
    }
}

impl DoryV3TranscriptContext {
    pub fn from_bank_authenticated_record(
        network_id: [u8; 32],
        authenticated: &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
    ) -> Result<Self, DoryV3TranscriptError> {
        if network_id == [0; 32] {
            return Err(DoryV3TranscriptError::NetworkIdentity);
        }
        let record = authenticated.record();
        record.validate()?;
        if record.suite_digest() != *DORY_V3_PRODUCTION_SUITE_DIGEST {
            return Err(DoryV3TranscriptError::SuiteDigest);
        }
        Ok(Self {
            network_id,
            suite_digest: record.suite_digest(),
            manifest_digest: record.manifest_digest(),
            model_identity_digest: record.model_identity_digest(),
            model_record_digest: record.record_digest(),
        })
    }

    pub const fn network_id(self) -> [u8; 32] {
        self.network_id
    }

    pub const fn suite_digest(self) -> Digest32 {
        self.suite_digest
    }

    pub const fn manifest_digest(self) -> Digest32 {
        self.manifest_digest
    }

    pub const fn model_identity_digest(self) -> Digest32 {
        self.model_identity_digest
    }

    pub const fn model_record_digest(self) -> Digest32 {
        self.model_record_digest
    }

    /// Derive a typed challenge capability from the exact fields frozen by the
    /// V3 suite.
    pub(crate) fn challenge_context(
        self,
        block: &BlockChallenge,
        nonce: u64,
    ) -> Result<DoryV3ChallengeContext, DoryV3TranscriptError> {
        if block.network_id != self.network_id {
            return Err(DoryV3TranscriptError::WrongNetwork);
        }
        let mut hasher = Hasher::new_derive_key(DORY_V3_CHALLENGE_DOMAIN);
        hasher.update(&DORY_V3_POW_TYPE.to_le_bytes());
        hasher.update(&DORY_V3_ALGORITHM_VERSION.to_le_bytes());
        hasher.update(&DORY_V3_PROOF_VERSION.to_le_bytes());
        hasher.update(&self.network_id);
        hasher.update(self.suite_digest.as_bytes());
        hasher.update(self.manifest_digest.as_bytes());
        hasher.update(self.model_identity_digest.as_bytes());
        hasher.update(&block.previous_block);
        hasher.update(&block.transaction_root);
        hasher.update(&block.height.to_le_bytes());
        hasher.update(&block.timestamp.to_le_bytes());
        hasher.update(&block.target);
        hasher.update(&nonce.to_le_bytes());
        Ok(DoryV3ChallengeContext {
            transcript_context: self,
            digest: *hasher.finalize().as_bytes(),
        })
    }

    /// Hash the exact challenge fields frozen by the V3 suite.
    ///
    /// This raw-digest compatibility wrapper derives the same typed challenge
    /// capability used by V3 artifact consumers and then returns its digest.
    pub fn challenge_digest(
        self,
        block: &BlockChallenge,
        nonce: u64,
    ) -> Result<[u8; 32], DoryV3TranscriptError> {
        Ok(self.challenge_context(block, nonce)?.digest())
    }

    /// Hash one canonical centered-byte final activation.
    pub fn output_digest(
        self,
        challenge_digest: [u8; 32],
        activation: &[u8],
    ) -> Result<[u8; 32], DoryV3TranscriptError> {
        if activation.len() != BLS_DORY_BLAKE3_PRODUCTION_ACTIVATION_BYTES {
            return Err(DoryV3TranscriptError::ActivationLength {
                expected: BLS_DORY_BLAKE3_PRODUCTION_ACTIVATION_BYTES,
                actual: activation.len(),
            });
        }
        if activation.iter().any(|byte| *byte > 250) {
            return Err(DoryV3TranscriptError::Activation);
        }
        let activation_len =
            u64::try_from(activation.len()).map_err(|_| DoryV3TranscriptError::LengthOverflow)?;
        let mut hasher = Hasher::new_derive_key(DORY_V3_OUTPUT_DOMAIN);
        hasher.update(&challenge_digest);
        hasher.update(&activation_len.to_le_bytes());
        hasher.update(activation);
        Ok(*hasher.finalize().as_bytes())
    }

    /// Hash the exact V3 work fields. The Record V2 model identity already
    /// binds the byte roots, ordered Dory commitments, setup, and geometry.
    pub fn work_digest(
        self,
        challenge_digest: [u8; 32],
        final_activation_digest: [u8; 32],
    ) -> [u8; 32] {
        let mut hasher = Hasher::new_derive_key(DORY_V3_WORK_DOMAIN);
        hasher.update(self.suite_digest.as_bytes());
        hasher.update(&challenge_digest);
        hasher.update(self.model_identity_digest.as_bytes());
        hasher.update(&final_activation_digest);
        *hasher.finalize().as_bytes()
    }

    /// Hash the exact algebraic-binding V2 fields frozen for the V3 suite.
    pub fn algebraic_binding(
        self,
        block: &BlockChallenge,
        proof: &ForgeMatrixV3CandidateProof,
    ) -> Result<[u8; 32], DoryV3TranscriptError> {
        if block.network_id != self.network_id {
            return Err(DoryV3TranscriptError::WrongNetwork);
        }
        if proof.model_manifest_digest != self.manifest_digest.into_bytes() {
            return Err(DoryV3TranscriptError::ModelManifestDigest);
        }
        let mut hasher = Hasher::new_derive_key(DORY_V3_ALGEBRAIC_BINDING_DOMAIN);
        hasher.update(&DORY_V3_ALGEBRAIC_BINDING_VERSION.to_le_bytes());
        hasher.update(&DORY_V3_POW_TYPE.to_le_bytes());
        hasher.update(&self.network_id);
        hasher.update(&proof.algorithm_version.to_le_bytes());
        hasher.update(&proof.proof_version.to_le_bytes());
        hasher.update(self.suite_digest.as_bytes());
        hasher.update(self.model_record_digest.as_bytes());
        hasher.update(self.manifest_digest.as_bytes());
        hasher.update(self.model_identity_digest.as_bytes());
        hasher.update(&block.previous_block);
        hasher.update(&block.transaction_root);
        hasher.update(&block.height.to_le_bytes());
        hasher.update(&block.timestamp.to_le_bytes());
        hasher.update(&block.target);
        hasher.update(&proof.nonce.to_le_bytes());
        hasher.update(&proof.challenge_digest);
        hasher.update(&proof.final_activation_digest);
        hasher.update(&proof.work_digest);
        Ok(*hasher.finalize().as_bytes())
    }
}

/// Expand one affine V3 mask using the frozen rejection sampler.
pub fn dory_v3_mask_coefficients(
    challenge_digest: &[u8; 32],
    layer: u32,
    rows: usize,
    columns: usize,
) -> Result<Vec<u8>, DoryV3TranscriptError> {
    if rows == 0 || columns == 0 || !rows.is_power_of_two() || !columns.is_power_of_two() {
        return Err(DoryV3TranscriptError::MaskDimensions);
    }
    let count = 1_usize
        .checked_add(rows.ilog2() as usize)
        .and_then(|count| count.checked_add(columns.ilog2() as usize))
        .ok_or(DoryV3TranscriptError::LengthOverflow)?;
    let mut hasher = Hasher::new_derive_key(DORY_V3_MASK_DOMAIN);
    hasher.update(challenge_digest);
    hasher.update(&layer.to_le_bytes());
    let mut reader = hasher.finalize_xof();
    let mut coefficients = Vec::with_capacity(count);
    let mut buffer = [0_u8; 64];
    while coefficients.len() < count {
        reader.fill(&mut buffer);
        coefficients.extend(
            buffer
                .iter()
                .copied()
                .filter(|byte| *byte <= 250)
                .take(count - coefficients.len()),
        );
    }
    Ok(coefficients)
}

#[derive(Debug, Error)]
pub enum DoryV3TranscriptError {
    #[error("the V3 transcript requires a nonzero network identity")]
    NetworkIdentity,
    #[error("the block belongs to another network")]
    WrongNetwork,
    #[error("the model record does not select the compiled V3 suite")]
    SuiteDigest,
    #[error("the proof model manifest does not match the authenticated V3 context")]
    ModelManifestDigest,
    #[error("the final activation length is {actual}; expected {expected}")]
    ActivationLength { expected: usize, actual: usize },
    #[error("the final activation is outside the canonical byte range")]
    Activation,
    #[error("the mask dimensions are not nonzero powers of two")]
    MaskDimensions,
    #[error("a transcript length does not fit its canonical encoding")]
    LengthOverflow,
    #[error("the model commitment record is invalid: {0}")]
    ModelRecord(#[from] DoryV3ModelCommitmentRecordError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forgematrix_v2::mask_coefficients as v2_mask_coefficients;

    fn context() -> DoryV3TranscriptContext {
        DoryV3TranscriptContext {
            network_id: [0x11; 32],
            suite_digest: *DORY_V3_PRODUCTION_SUITE_DIGEST,
            manifest_digest: Digest32::new([0x22; 32]),
            model_identity_digest: Digest32::new([0x33; 32]),
            model_record_digest: Digest32::new([0x44; 32]),
        }
    }

    fn block() -> BlockChallenge {
        BlockChallenge {
            network_id: [0x11; 32],
            previous_block: [0x55; 32],
            transaction_root: [0x66; 32],
            height: 0x0102_0304_0506_0708,
            timestamp: 0x1112_1314_1516_1718,
            target: [0x77; 32],
        }
    }

    fn proof() -> ForgeMatrixV3CandidateProof {
        ForgeMatrixV3CandidateProof {
            algorithm_version: DORY_V3_ALGORITHM_VERSION,
            proof_version: DORY_V3_PROOF_VERSION,
            nonce: 0x2122_2324_2526_2728,
            model_manifest_digest: [0x22; 32],
            challenge_digest: [0x88; 32],
            final_activation_digest: [0x99; 32],
            work_digest: [0xaa; 32],
            structured_proof: vec![0xbb],
        }
    }

    fn production_activation() -> Vec<u8> {
        const PATTERN: [u8; 4] = [0, 1, 125, 250];
        (0..BLS_DORY_BLAKE3_PRODUCTION_ACTIVATION_BYTES)
            .map(|index| PATTERN[index % PATTERN.len()])
            .collect()
    }

    #[test]
    fn context_constructor_requires_the_bank_authenticated_capability() {
        let constructor: fn(
            [u8; 32],
            &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
        ) -> Result<DoryV3TranscriptContext, DoryV3TranscriptError> =
            DoryV3TranscriptContext::from_bank_authenticated_record;
        let _ = constructor;
    }

    #[test]
    fn typed_challenge_preserves_context_and_raw_digest_compatibility() {
        let context = context();
        let block = block();
        let nonce = 0x2122_2324_2526_2728;
        let typed = context.challenge_context(&block, nonce).unwrap();
        assert_eq!(typed.transcript_context(), context);
        assert_eq!(
            typed.digest(),
            context.challenge_digest(&block, nonce).unwrap()
        );
        assert_eq!(
            hex::encode(typed.digest()),
            "ad91a6d599cdf73e0bd2ec56fb23ad66d0d97ab14fead9b09607d374e52e2535"
        );
        let activation = production_activation();
        let output = context.output_digest(typed.digest(), &activation).unwrap();
        assert_eq!(typed.output_digest(&activation).unwrap(), output);
        assert_eq!(
            typed.work_digest(output),
            context.work_digest(typed.digest(), output)
        );

        let mut wrong_network = block;
        wrong_network.network_id[0] ^= 1;
        assert!(matches!(
            context.challenge_context(&wrong_network, nonce),
            Err(DoryV3TranscriptError::WrongNetwork)
        ));
    }

    #[test]
    fn transcript_known_answers_are_stable_and_distinct_from_v2() {
        let context = context();
        let challenge = context
            .challenge_digest(&block(), 0x2122_2324_2526_2728)
            .unwrap();
        let output = context
            .output_digest(challenge, &production_activation())
            .unwrap();
        let work = context.work_digest(challenge, output);
        let binding = context.algebraic_binding(&block(), &proof()).unwrap();
        let v3_mask = dory_v3_mask_coefficients(&challenge, 7, 128, 4_096).unwrap();
        assert_eq!(
            hex::encode(challenge),
            "ad91a6d599cdf73e0bd2ec56fb23ad66d0d97ab14fead9b09607d374e52e2535"
        );
        assert_eq!(
            hex::encode(output),
            "00dd4a25c8c7712f892928969788f2a59a1cb39c7c67051a245af079f1a066c2"
        );
        assert_eq!(
            hex::encode(work),
            "2f86a43c0ce5db393da290196915c705a3a94f463f4faf17399745dffa918ef1"
        );
        assert_eq!(
            hex::encode(binding),
            "29e49cc6dad8162e77382a741b8395dc46b553b2fb9dd9a5101f96b21d0cf887"
        );

        assert_eq!(
            v3_mask,
            vec![
                59, 81, 60, 232, 27, 51, 148, 49, 140, 126, 73, 244, 239, 210, 59, 58, 238, 23, 34,
                133,
            ]
        );
        assert_ne!(v3_mask, v2_mask_coefficients(&challenge, 7, 128, 4_096));
    }

    #[test]
    fn challenge_commits_every_field_and_rejects_the_wrong_network() {
        let context = context();
        let base_block = block();
        let nonce = 31;
        let expected = context.challenge_digest(&base_block, nonce).unwrap();
        let mutations: [fn(&mut BlockChallenge); 5] = [
            |value| value.previous_block[0] ^= 1,
            |value| value.transaction_root[0] ^= 1,
            |value| value.height ^= 1,
            |value| value.timestamp ^= 1,
            |value| value.target[0] ^= 1,
        ];
        for mutate in mutations {
            let mut changed = base_block;
            mutate(&mut changed);
            assert_ne!(context.challenge_digest(&changed, nonce).unwrap(), expected);
        }
        assert_ne!(
            context.challenge_digest(&base_block, nonce + 1).unwrap(),
            expected
        );
        for changed_context in [
            DoryV3TranscriptContext {
                network_id: [0x12; 32],
                ..context
            },
            DoryV3TranscriptContext {
                suite_digest: Digest32::new([0x13; 32]),
                ..context
            },
            DoryV3TranscriptContext {
                manifest_digest: Digest32::new([0x14; 32]),
                ..context
            },
            DoryV3TranscriptContext {
                model_identity_digest: Digest32::new([0x15; 32]),
                ..context
            },
        ] {
            let mut changed_block = base_block;
            changed_block.network_id = changed_context.network_id;
            assert_ne!(
                changed_context
                    .challenge_digest(&changed_block, nonce)
                    .unwrap(),
                expected
            );
        }
        let mut wrong_network = base_block;
        wrong_network.network_id[0] ^= 1;
        assert!(matches!(
            context.challenge_digest(&wrong_network, nonce),
            Err(DoryV3TranscriptError::WrongNetwork)
        ));
    }

    #[test]
    fn output_work_and_binding_commit_every_declared_field() {
        let context = context();
        let challenge = [0x31; 32];
        let activation = production_activation();
        let output = context.output_digest(challenge, &activation).unwrap();
        assert_ne!(
            output,
            context.output_digest([0x32; 32], &activation).unwrap()
        );
        let mut changed_activation = activation.clone();
        changed_activation[0] ^= 1;
        assert_ne!(
            output,
            context
                .output_digest(challenge, &changed_activation)
                .unwrap()
        );
        assert!(matches!(
            context.output_digest(challenge, &[]),
            Err(DoryV3TranscriptError::ActivationLength { .. })
        ));
        let mut wrong_length = activation.clone();
        wrong_length.pop();
        assert!(matches!(
            context.output_digest(challenge, &wrong_length),
            Err(DoryV3TranscriptError::ActivationLength { .. })
        ));
        let mut invalid_activation = activation;
        invalid_activation[0] = 251;
        assert!(matches!(
            context.output_digest(challenge, &invalid_activation),
            Err(DoryV3TranscriptError::Activation)
        ));

        let work = context.work_digest(challenge, output);
        assert_ne!(work, context.work_digest([0x32; 32], output));
        assert_ne!(work, context.work_digest(challenge, [0x33; 32]));
        assert_ne!(
            work,
            DoryV3TranscriptContext {
                suite_digest: Digest32::new([0x34; 32]),
                ..context
            }
            .work_digest(challenge, output)
        );
        assert_ne!(
            work,
            DoryV3TranscriptContext {
                model_identity_digest: Digest32::new([0x35; 32]),
                ..context
            }
            .work_digest(challenge, output)
        );

        let base_block = block();
        let base_proof = proof();
        let binding = context.algebraic_binding(&base_block, &base_proof).unwrap();
        let mut wrong_manifest = base_proof.clone();
        wrong_manifest.model_manifest_digest[0] ^= 1;
        assert!(matches!(
            context.algebraic_binding(&base_block, &wrong_manifest),
            Err(DoryV3TranscriptError::ModelManifestDigest)
        ));
        type Mutation = fn(&mut BlockChallenge, &mut ForgeMatrixV3CandidateProof);
        let mutations: [Mutation; 11] = [
            |value, _| value.previous_block[0] ^= 1,
            |value, _| value.transaction_root[0] ^= 1,
            |value, _| value.height ^= 1,
            |value, _| value.timestamp ^= 1,
            |value, _| value.target[0] ^= 1,
            |_, value| value.algorithm_version ^= 1,
            |_, value| value.proof_version ^= 1,
            |_, value| value.nonce ^= 1,
            |_, value| value.challenge_digest[0] ^= 1,
            |_, value| value.final_activation_digest[0] ^= 1,
            |_, value| value.work_digest[0] ^= 1,
        ];
        for mutate in mutations {
            let mut changed_block = base_block;
            let mut changed_proof = base_proof.clone();
            mutate(&mut changed_block, &mut changed_proof);
            assert_ne!(
                context
                    .algebraic_binding(&changed_block, &changed_proof)
                    .unwrap(),
                binding
            );
        }
        for changed_context in [
            DoryV3TranscriptContext {
                network_id: [0x12; 32],
                ..context
            },
            DoryV3TranscriptContext {
                suite_digest: Digest32::new([0x13; 32]),
                ..context
            },
            DoryV3TranscriptContext {
                manifest_digest: Digest32::new([0x14; 32]),
                ..context
            },
            DoryV3TranscriptContext {
                model_identity_digest: Digest32::new([0x15; 32]),
                ..context
            },
            DoryV3TranscriptContext {
                model_record_digest: Digest32::new([0x16; 32]),
                ..context
            },
        ] {
            let mut changed_block = base_block;
            changed_block.network_id = changed_context.network_id;
            let mut changed_proof = base_proof.clone();
            changed_proof.model_manifest_digest = changed_context.manifest_digest.into_bytes();
            assert_ne!(
                changed_context
                    .algebraic_binding(&changed_block, &changed_proof)
                    .unwrap(),
                binding
            );
        }
    }

    #[test]
    fn mask_sampler_is_deterministic_bounded_and_shape_checked() {
        let challenge = [0x51; 32];
        let coefficients = dory_v3_mask_coefficients(&challenge, 9, 8, 16).unwrap();
        assert_eq!(coefficients.len(), 8);
        assert!(coefficients.iter().all(|value| *value <= 250));
        assert_eq!(
            coefficients,
            dory_v3_mask_coefficients(&challenge, 9, 8, 16).unwrap()
        );
        assert_ne!(
            coefficients,
            dory_v3_mask_coefficients(&challenge, 10, 8, 16).unwrap()
        );
        for (rows, columns) in [(0, 16), (3, 16), (8, 0), (8, 6)] {
            assert!(matches!(
                dory_v3_mask_coefficients(&challenge, 9, rows, columns),
                Err(DoryV3TranscriptError::MaskDimensions)
            ));
        }
    }
}
