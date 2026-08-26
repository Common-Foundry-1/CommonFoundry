use blake3::Hasher;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const CHALLENGE_DOMAIN: &str = "CMFD/FORGEMATRIX/CHALLENGE/V1";
const MODEL_DOMAIN: &str = "CMFD/FORGEMATRIX/MODEL/V1";
const ACTIVATION_DOMAIN: &str = "CMFD/FORGEMATRIX/ACTIVATION/V1";
const MASK_DOMAIN: &str = "CMFD/FORGEMATRIX/MASK/V1";
const OUTPUT_DOMAIN: &str = "CMFD/FORGEMATRIX/OUTPUT/V1";
const WORK_DOMAIN: &str = "CMFD/FORGEMATRIX/WORK/V1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForgeMatrixProfile {
    pub algorithm_version: u32,
    pub model_version: u32,
    pub dimension: u32,
    pub batch: u32,
    pub layers: u32,
    pub model_seed: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileMetrics {
    pub model_bytes: u128,
    pub activation_bytes: u128,
    pub core_device_bytes: u128,
    pub multiply_accumulates_per_nonce: u128,
}

pub const TEST_PROFILE: ForgeMatrixProfile = ForgeMatrixProfile {
    algorithm_version: 1,
    model_version: 1,
    dimension: 32,
    batch: 4,
    layers: 4,
    model_seed: [0x43; 32],
};

pub const CANDIDATE_16GB_PROFILE: ForgeMatrixProfile = ForgeMatrixProfile {
    algorithm_version: 1,
    model_version: 1,
    dimension: 4096,
    batch: 128,
    layers: 384,
    model_seed: [0; 32],
};

impl ForgeMatrixProfile {
    pub fn metrics(self) -> ProfileMetrics {
        let model_bytes =
            u128::from(self.layers) * u128::from(self.dimension) * u128::from(self.dimension);
        let activation_bytes = u128::from(self.batch) * u128::from(self.dimension);
        ProfileMetrics {
            model_bytes,
            activation_bytes,
            core_device_bytes: model_bytes + 3 * activation_bytes,
            multiply_accumulates_per_nonce: model_bytes * u128::from(self.batch),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockChallenge {
    pub network_id: [u8; 32],
    pub previous_block: [u8; 32],
    pub transaction_root: [u8; 32],
    pub height: u64,
    pub timestamp: u64,
    pub target: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForgeMatrixProof {
    pub algorithm_version: u32,
    pub model_version: u32,
    pub nonce: u64,
    pub model_root: [u8; 32],
    pub output_digest: [u8; 32],
    pub work_digest: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkStats {
    pub multiply_accumulates: u128,
    pub model_bytes_touched: u128,
    pub activation_values: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Evaluation {
    output_digest: [u8; 32],
    work_digest: [u8; 32],
    stats: WorkStats,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ForgeMatrixError {
    #[error("profile dimensions must be nonzero")]
    EmptyProfile,
    #[error("profile allocation exceeds this platform")]
    ProfileTooLarge,
    #[error("candidate production profile has no committed model seed")]
    UncommittedModel,
    #[error("algorithm version mismatch")]
    AlgorithmVersion,
    #[error("model version mismatch")]
    ModelVersion,
    #[error("model root mismatch")]
    ModelRoot,
    #[error("final activation digest mismatch")]
    OutputDigest,
    #[error("work digest mismatch")]
    WorkDigest,
    #[error("work digest does not meet target")]
    HighHash,
    #[error("nonce range exhausted")]
    NonceExhausted,
}

#[derive(Debug, Clone)]
pub struct ForgeMatrixVerifier {
    profile: ForgeMatrixProfile,
    model: Vec<Vec<i8>>,
    model_root: [u8; 32],
}

impl ForgeMatrixVerifier {
    pub fn new(profile: ForgeMatrixProfile) -> Result<Self, ForgeMatrixError> {
        if profile.dimension == 0 || profile.batch == 0 || profile.layers == 0 {
            return Err(ForgeMatrixError::EmptyProfile);
        }
        if profile.model_seed == [0; 32] {
            return Err(ForgeMatrixError::UncommittedModel);
        }

        let layer_len = usize::try_from(profile.dimension)
            .ok()
            .and_then(|n| n.checked_mul(n))
            .ok_or(ForgeMatrixError::ProfileTooLarge)?;
        let layer_count =
            usize::try_from(profile.layers).map_err(|_| ForgeMatrixError::ProfileTooLarge)?;
        let mut model = Vec::with_capacity(layer_count);
        let mut root_hasher = Hasher::new_derive_key(MODEL_DOMAIN);
        encode_profile(&profile, &mut root_hasher);

        for layer in 0..profile.layers {
            let bytes = derive_bytes(MODEL_DOMAIN, &profile.model_seed, layer, layer_len);
            let weights: Vec<i8> = bytes.into_iter().map(nonzero_i8).collect();
            root_hasher.update(&layer.to_le_bytes());
            root_hasher.update(as_u8_slice(&weights));
            model.push(weights);
        }

        let model_root = *root_hasher.finalize().as_bytes();
        Ok(Self {
            profile,
            model,
            model_root,
        })
    }

    pub fn profile(&self) -> ForgeMatrixProfile {
        self.profile
    }

    pub fn model_root(&self) -> [u8; 32] {
        self.model_root
    }

    pub fn prove(&self, block: &BlockChallenge, nonce: u64) -> ForgeMatrixProof {
        let evaluation = self.evaluate(block, nonce);
        ForgeMatrixProof {
            algorithm_version: self.profile.algorithm_version,
            model_version: self.profile.model_version,
            nonce,
            model_root: self.model_root,
            output_digest: evaluation.output_digest,
            work_digest: evaluation.work_digest,
        }
    }

    pub fn mine(
        &self,
        block: &BlockChallenge,
        start_nonce: u64,
        attempts: u64,
    ) -> Result<ForgeMatrixProof, ForgeMatrixError> {
        for offset in 0..attempts {
            let nonce = start_nonce.wrapping_add(offset);
            let proof = self.prove(block, nonce);
            if meets_target(&proof.work_digest, &block.target) {
                return Ok(proof);
            }
        }
        Err(ForgeMatrixError::NonceExhausted)
    }

    pub fn verify(
        &self,
        block: &BlockChallenge,
        proof: &ForgeMatrixProof,
    ) -> Result<WorkStats, ForgeMatrixError> {
        let stats = self.verify_relation(block, proof)?;
        if !meets_target(&proof.work_digest, &block.target) {
            return Err(ForgeMatrixError::HighHash);
        }
        Ok(stats)
    }

    /// Rejects every cheaply decidable envelope, binding, and target failure
    /// before the matrix relation is evaluated. Every check is also enforced
    /// by [`Self::verify`]; the consensus wrapper invokes both paths, so using
    /// this as an admission gate cannot create a second validity rule.
    pub(crate) fn preflight(
        &self,
        block: &BlockChallenge,
        proof: &ForgeMatrixProof,
    ) -> Result<(), ForgeMatrixError> {
        if proof.algorithm_version != self.profile.algorithm_version {
            return Err(ForgeMatrixError::AlgorithmVersion);
        }
        if proof.model_version != self.profile.model_version {
            return Err(ForgeMatrixError::ModelVersion);
        }
        if proof.model_root != self.model_root {
            return Err(ForgeMatrixError::ModelRoot);
        }

        let expected_work = self.claimed_work_digest(block, proof.nonce, proof.output_digest);
        if proof.work_digest != expected_work {
            return Err(ForgeMatrixError::WorkDigest);
        }
        if !meets_target(&proof.work_digest, &block.target) {
            return Err(ForgeMatrixError::HighHash);
        }
        Ok(())
    }

    pub(crate) fn claimed_work_digest(
        &self,
        block: &BlockChallenge,
        nonce: u64,
        output_digest: [u8; 32],
    ) -> [u8; 32] {
        let challenge = challenge_digest(&self.profile, self.model_root, block, nonce);
        let mut work_hasher = Hasher::new_derive_key(WORK_DOMAIN);
        work_hasher.update(&challenge);
        work_hasher.update(&self.model_root);
        work_hasher.update(&output_digest);
        *work_hasher.finalize().as_bytes()
    }

    /// Recomputes the complete committed ForgeMatrix relation without
    /// interpreting any proof target. Consensus callers must still use
    /// [`Self::verify`] when deciding whether a block is valid.
    pub(crate) fn verify_relation(
        &self,
        block: &BlockChallenge,
        proof: &ForgeMatrixProof,
    ) -> Result<WorkStats, ForgeMatrixError> {
        if proof.algorithm_version != self.profile.algorithm_version {
            return Err(ForgeMatrixError::AlgorithmVersion);
        }
        if proof.model_version != self.profile.model_version {
            return Err(ForgeMatrixError::ModelVersion);
        }
        if proof.model_root != self.model_root {
            return Err(ForgeMatrixError::ModelRoot);
        }

        let expected = self.evaluate(block, proof.nonce);
        if proof.output_digest != expected.output_digest {
            return Err(ForgeMatrixError::OutputDigest);
        }
        if proof.work_digest != expected.work_digest {
            return Err(ForgeMatrixError::WorkDigest);
        }
        Ok(expected.stats)
    }

    /// Builds a deterministic fixture for differential testing of an
    /// independent GPU implementation. The format is intentionally simple:
    /// magic, dimensions, initial activation, each layer's weights and masks,
    /// then the expected final activation.
    pub fn gpu_fixture(&self, block: &BlockChallenge, nonce: u64) -> Vec<u8> {
        let challenge = challenge_digest(&self.profile, self.model_root, block, nonce);
        let mut fixture = Vec::new();
        fixture.extend_from_slice(b"CMFDGPU1");
        fixture.extend_from_slice(&self.profile.dimension.to_le_bytes());
        fixture.extend_from_slice(&self.profile.batch.to_le_bytes());
        fixture.extend_from_slice(&self.profile.layers.to_le_bytes());
        let activation = self.compute_activation(&challenge, Some(&mut fixture));
        fixture.extend_from_slice(as_u8_slice(&activation));
        fixture
    }

    fn evaluate(&self, block: &BlockChallenge, nonce: u64) -> Evaluation {
        let challenge = challenge_digest(&self.profile, self.model_root, block, nonce);
        let input = self.compute_activation(&challenge, None);

        let mut output_hasher = Hasher::new_derive_key(OUTPUT_DOMAIN);
        output_hasher.update(&challenge);
        output_hasher.update(as_u8_slice(&input));
        let output_digest = *output_hasher.finalize().as_bytes();

        let mut work_hasher = Hasher::new_derive_key(WORK_DOMAIN);
        work_hasher.update(&challenge);
        work_hasher.update(&self.model_root);
        work_hasher.update(&output_digest);
        let work_digest = *work_hasher.finalize().as_bytes();

        let stats = WorkStats {
            multiply_accumulates: u128::from(self.profile.layers)
                * u128::from(self.profile.batch)
                * u128::from(self.profile.dimension)
                * u128::from(self.profile.dimension),
            model_bytes_touched: u128::from(self.profile.layers)
                * u128::from(self.profile.dimension)
                * u128::from(self.profile.dimension),
            activation_values: u128::from(self.profile.layers)
                * u128::from(self.profile.batch)
                * u128::from(self.profile.dimension),
        };
        Evaluation {
            output_digest,
            work_digest,
            stats,
        }
    }

    fn compute_activation(
        &self,
        challenge: &[u8; 32],
        mut fixture: Option<&mut Vec<u8>>,
    ) -> Vec<i8> {
        let rows = self.profile.batch as usize;
        let width = self.profile.dimension as usize;
        let activation_len = rows * width;
        let initial = derive_bytes(ACTIVATION_DOMAIN, challenge, 0, activation_len);
        let mut input: Vec<i8> = initial.into_iter().map(nonzero_i8).collect();
        let mut output = vec![0i8; activation_len];

        if let Some(bytes) = fixture.as_deref_mut() {
            bytes.extend_from_slice(as_u8_slice(&input));
        }

        for (layer_index, weights) in self.model.iter().enumerate() {
            let masks = derive_bytes(MASK_DOMAIN, challenge, layer_index as u32, activation_len);
            if let Some(bytes) = fixture.as_deref_mut() {
                bytes.extend_from_slice(as_u8_slice(weights));
                bytes.extend_from_slice(&masks);
            }
            for row in 0..rows {
                for col in 0..width {
                    let mut accumulator = 0i64;
                    for common in 0..width {
                        accumulator += i64::from(input[row * width + common])
                            * i64::from(weights[common * width + col]);
                    }
                    output[row * width + col] = quantize_nonzero(
                        accumulator,
                        masks[row * width + col],
                        layer_index as u32,
                        row as u32,
                        col as u32,
                    );
                }
            }
            std::mem::swap(&mut input, &mut output);
        }
        input
    }
}

fn challenge_digest(
    profile: &ForgeMatrixProfile,
    model_root: [u8; 32],
    block: &BlockChallenge,
    nonce: u64,
) -> [u8; 32] {
    let mut hasher = Hasher::new_derive_key(CHALLENGE_DOMAIN);
    hasher.update(&block.network_id);
    encode_profile(profile, &mut hasher);
    hasher.update(&model_root);
    hasher.update(&block.previous_block);
    hasher.update(&block.transaction_root);
    hasher.update(&block.height.to_le_bytes());
    hasher.update(&block.timestamp.to_le_bytes());
    hasher.update(&block.target);
    hasher.update(&nonce.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn encode_profile(profile: &ForgeMatrixProfile, hasher: &mut Hasher) {
    hasher.update(&profile.algorithm_version.to_le_bytes());
    hasher.update(&profile.model_version.to_le_bytes());
    hasher.update(&profile.dimension.to_le_bytes());
    hasher.update(&profile.batch.to_le_bytes());
    hasher.update(&profile.layers.to_le_bytes());
    hasher.update(&profile.model_seed);
}

fn derive_bytes(domain: &str, seed: &[u8; 32], index: u32, len: usize) -> Vec<u8> {
    let mut hasher = Hasher::new_derive_key(domain);
    hasher.update(seed);
    hasher.update(&index.to_le_bytes());
    let mut reader = hasher.finalize_xof();
    let mut bytes = vec![0u8; len];
    reader.fill(&mut bytes);
    bytes
}

fn nonzero_i8(byte: u8) -> i8 {
    let value = i16::from(byte % 254) - 127;
    if value == 0 { 1 } else { value as i8 }
}

fn quantize_nonzero(accumulator: i64, mask: u8, layer: u32, row: u32, col: u32) -> i8 {
    let coordinate_mix = i64::from(layer)
        .wrapping_mul(0x1f123bb5)
        .wrapping_add(i64::from(row).wrapping_mul(0x05491333))
        .wrapping_add(i64::from(col).wrapping_mul(0x0127a2f1));
    let value = accumulator
        .wrapping_add(i64::from(mask))
        .wrapping_add(coordinate_mix)
        .rem_euclid(254)
        - 127;
    if value == 0 { 1 } else { value as i8 }
}

fn as_u8_slice(values: &[i8]) -> &[u8] {
    // i8 and u8 have identical layout and alignment. This conversion preserves
    // the canonical two's-complement byte representation hashed by consensus.
    unsafe { std::slice::from_raw_parts(values.as_ptr().cast::<u8>(), values.len()) }
}

pub fn meets_target(digest: &[u8; 32], target: &[u8; 32]) -> bool {
    digest <= target
}

pub fn target_with_leading_zero_bits(bits: u16) -> [u8; 32] {
    let capped = bits.min(256);
    let mut target = [0xff; 32];
    let full_bytes = usize::from(capped / 8);
    let partial_bits = (capped % 8) as u8;
    for byte in target.iter_mut().take(full_bytes) {
        *byte = 0;
    }
    if full_bytes < 32 && partial_bits > 0 {
        target[full_bytes] = 0xff >> partial_bits;
    }
    target
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block() -> BlockChallenge {
        BlockChallenge {
            network_id: [0x33; 32],
            previous_block: [0x11; 32],
            transaction_root: [0x22; 32],
            height: 42,
            timestamp: 1_777_777_777,
            target: [0xff; 32],
        }
    }

    #[test]
    fn model_and_proof_are_deterministic() {
        let a = ForgeMatrixVerifier::new(TEST_PROFILE).unwrap();
        let b = ForgeMatrixVerifier::new(TEST_PROFILE).unwrap();
        assert_eq!(a.model_root(), b.model_root());
        assert_eq!(a.prove(&block(), 7), b.prove(&block(), 7));
    }

    #[test]
    fn network_id_is_bound_to_v1_work() {
        let verifier = ForgeMatrixVerifier::new(TEST_PROFILE).unwrap();
        let original = block();
        let proof = verifier.prove(&original, 7);
        let mut wrong_network = original;
        wrong_network.network_id[0] ^= 1;
        assert!(matches!(
            verifier.verify(&wrong_network, &proof),
            Err(ForgeMatrixError::OutputDigest)
        ));
    }

    #[test]
    fn canonical_vector_is_stable() {
        let verifier = ForgeMatrixVerifier::new(TEST_PROFILE).unwrap();
        let proof = verifier.prove(&block(), 7);
        assert_eq!(
            hex::encode(proof.model_root),
            "1698e75ee64c62b5af937d042569b25c7b821f25082c898d92031a6aa7d2ecb9"
        );
        assert_eq!(
            hex::encode(proof.output_digest),
            "b069abab2c640469fac2c59f52fd5f21f4131ffffa8c3cd442384112d5fd6e7e"
        );
        assert_eq!(
            hex::encode(proof.work_digest),
            "05bd64dc7b1e29f896844bc58120924fe7a47f4beeef6313763842855f6591a6"
        );
    }

    #[test]
    fn gpu_fixture_has_complete_expected_length() {
        let verifier = ForgeMatrixVerifier::new(TEST_PROFILE).unwrap();
        let fixture = verifier.gpu_fixture(&block(), 7);
        let activation = usize::try_from(TEST_PROFILE.batch * TEST_PROFILE.dimension).unwrap();
        let weights = usize::try_from(TEST_PROFILE.dimension * TEST_PROFILE.dimension).unwrap();
        let expected = 8
            + 12
            + activation
            + usize::try_from(TEST_PROFILE.layers).unwrap() * (weights + activation)
            + activation;
        assert_eq!(fixture.len(), expected);
        assert_eq!(&fixture[..8], b"CMFDGPU1");
    }

    #[test]
    fn verifier_recomputes_every_dense_operation() {
        let verifier = ForgeMatrixVerifier::new(TEST_PROFILE).unwrap();
        let proof = verifier.prove(&block(), 9);
        let stats = verifier.verify(&block(), &proof).unwrap();
        assert_eq!(stats.multiply_accumulates, 4 * 4 * 32 * 32);
        assert_eq!(stats.model_bytes_touched, 4 * 32 * 32);
        assert_eq!(stats.activation_values, 4 * 4 * 32);
        assert!(verifier.model.iter().flatten().all(|value| *value != 0));
    }

    #[test]
    fn target_builder_is_big_endian() {
        assert_eq!(target_with_leading_zero_bits(0), [0xff; 32]);
        let t9 = target_with_leading_zero_bits(9);
        assert_eq!(t9[0], 0);
        assert_eq!(t9[1], 0x7f);
        assert!(t9[2..].iter().all(|b| *b == 0xff));
        assert_eq!(target_with_leading_zero_bits(256), [0; 32]);
    }

    #[test]
    fn candidate_profile_leaves_headroom_on_a_16_gib_card() {
        let metrics = CANDIDATE_16GB_PROFILE.metrics();
        assert_eq!(metrics.model_bytes, 6 * 1024 * 1024 * 1024);
        assert_eq!(metrics.activation_bytes, 128 * 4096);
        assert_eq!(metrics.multiply_accumulates_per_nonce, 824_633_720_832);
        assert!(metrics.core_device_bytes < 7 * 1024 * 1024 * 1024);
        assert!(metrics.core_device_bytes < 16 * 1024 * 1024 * 1024);
    }
}
