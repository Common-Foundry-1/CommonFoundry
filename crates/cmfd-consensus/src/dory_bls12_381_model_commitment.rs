//! Offline record for pinning authenticated fixed-model BLS commitments.

use std::io::{Cursor, Read};

use dory_pcs::primitives::{DoryDeserialize, DorySerialize, arithmetic::Group};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    ModelBankError, ModelBankFieldStreamError, ModelBankManifest, ModelPcsIdentity,
    dory_bls12_381_layout::{
        BLS_DORY_FIXED_MODEL_IDENTITY_VERSION, BlsDoryFixedModelIdentity,
        BlsDoryFixedModelStreamError, BlsDorySharedLayoutError,
        derive_bls_dory_fixed_model_identity_from_verified_bank,
    },
    dory_bls12_381_prototype::{BlsDoryGt, DeterministicBlsDorySetup},
};

/// Version of the canonical fixed-model commitment record.
pub const BLS_DORY_MODEL_COMMITMENT_RECORD_VERSION: u16 = 1;
const RECORD_DIGEST_DOMAIN: &str = "CommonFoundry/ForgeMatrix/BlsDoryModelCommitmentRecord/v1";

/// Reviewable output of authenticating a model bank and deriving its fixed BLS commitments.
///
/// The manifest and `ModelPcsIdentity` remain separate trust inputs. This record
/// does not activate production consensus and must be independently reproduced
/// before its digest is pinned by a network configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlsDoryModelCommitmentRecord {
    pub record_version: u16,
    pub padded_variables: u32,
    pub manifest: ModelBankManifest,
    pub model_pcs_identity: ModelPcsIdentity,
    pub manifest_digest: String,
    pub model_pcs_identity_digest: String,
    pub setup_identity: String,
    pub fixed_model_protocol_version: u16,
    pub base_input_bls_commitment: String,
    pub weight_bank_bls_commitments: Vec<String>,
    pub fixed_model_identity_digest: String,
    pub record_digest: String,
}

impl BlsDoryModelCommitmentRecord {
    /// Validate every redundant field and reconstruct the pinned fixed-model identity.
    pub fn validate(
        &self,
        setup: &DeterministicBlsDorySetup,
    ) -> Result<(), BlsDoryModelCommitmentRecordError> {
        if self.record_version != BLS_DORY_MODEL_COMMITMENT_RECORD_VERSION {
            return Err(BlsDoryModelCommitmentRecordError::UnsupportedVersion);
        }
        if usize::try_from(self.padded_variables).ok() != Some(setup.max_log_n()) {
            return Err(BlsDoryModelCommitmentRecordError::InvalidGeometry);
        }
        setup
            .validate()
            .map_err(|_| BlsDoryModelCommitmentRecordError::InvalidSetup)?;
        self.manifest
            .verify_pcs_identity(&self.model_pcs_identity)
            .map_err(BlsDoryModelCommitmentRecordError::ModelIdentity)?;

        require_digest(
            "manifest",
            self.manifest
                .digest()
                .map_err(BlsDoryModelCommitmentRecordError::ModelIdentity)?,
            &self.manifest_digest,
        )?;
        let model_digest = self
            .model_pcs_identity
            .digest()
            .map_err(BlsDoryModelCommitmentRecordError::ModelIdentity)?;
        require_digest(
            "model PCS identity",
            model_digest,
            &self.model_pcs_identity_digest,
        )?;
        require_digest("setup", setup.identity(), &self.setup_identity)?;

        let fixed_identity = self.fixed_identity()?;
        fixed_identity
            .validate(
                &self.model_pcs_identity,
                self.model_pcs_identity.weight_bank_commitments.len(),
                setup,
            )
            .map_err(BlsDoryModelCommitmentRecordError::FixedIdentity)?;
        require_digest(
            "fixed-model identity",
            fixed_identity
                .digest()
                .map_err(BlsDoryModelCommitmentRecordError::FixedIdentity)?,
            &self.fixed_model_identity_digest,
        )?;
        require_digest("record", self.canonical_digest()?, &self.record_digest)?;
        Ok(())
    }

    /// Reconstruct the fixed BLS commitment identity after validating its
    /// canonical encodings and commitment count.
    pub fn fixed_identity(
        &self,
    ) -> Result<BlsDoryFixedModelIdentity, BlsDoryModelCommitmentRecordError> {
        if self.fixed_model_protocol_version != BLS_DORY_FIXED_MODEL_IDENTITY_VERSION {
            return Err(BlsDoryModelCommitmentRecordError::UnsupportedFixedIdentity);
        }
        if self.weight_bank_bls_commitments.len()
            != self.model_pcs_identity.weight_bank_commitments.len()
        {
            return Err(BlsDoryModelCommitmentRecordError::InvalidCommitmentCount);
        }
        let model_pcs_identity_digest =
            decode_hex_32("model PCS identity", &self.model_pcs_identity_digest)?;
        let setup_identity = decode_hex_32("setup", &self.setup_identity)?;
        let base_input_commitment =
            decode_commitment("base input", &self.base_input_bls_commitment)?;
        let weight_bank_commitments = self
            .weight_bank_bls_commitments
            .iter()
            .map(|encoded| decode_commitment("weight bank", encoded))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(BlsDoryFixedModelIdentity {
            protocol_version: self.fixed_model_protocol_version,
            model_pcs_identity_digest,
            setup_identity,
            base_input_commitment,
            weight_bank_commitments,
        })
    }

    /// Return the canonical digest that a network configuration must pin.
    pub fn canonical_digest(&self) -> Result<[u8; 32], BlsDoryModelCommitmentRecordError> {
        let manifest_digest = decode_hex_32("manifest", &self.manifest_digest)?;
        let model_digest = decode_hex_32("model PCS identity", &self.model_pcs_identity_digest)?;
        let setup_identity = decode_hex_32("setup", &self.setup_identity)?;
        let fixed_digest =
            decode_hex_32("fixed-model identity", &self.fixed_model_identity_digest)?;
        let base_commitment =
            decode_commitment_bytes("base input", &self.base_input_bls_commitment)?;
        let weight_commitments = self
            .weight_bank_bls_commitments
            .iter()
            .map(|encoded| decode_commitment_bytes("weight bank", encoded))
            .collect::<Result<Vec<_>, _>>()?;
        let bank_count = u32::try_from(weight_commitments.len())
            .map_err(|_| BlsDoryModelCommitmentRecordError::InvalidCommitmentCount)?;

        let mut hasher = blake3::Hasher::new_derive_key(RECORD_DIGEST_DOMAIN);
        hasher.update(&self.record_version.to_le_bytes());
        hasher.update(&self.padded_variables.to_le_bytes());
        hasher.update(&manifest_digest);
        hasher.update(&model_digest);
        hasher.update(&setup_identity);
        hasher.update(&self.fixed_model_protocol_version.to_le_bytes());
        hasher.update(&fixed_digest);
        hasher.update(&bank_count.to_le_bytes());
        absorb_bytes(&mut hasher, &base_commitment)?;
        for commitment in &weight_commitments {
            absorb_bytes(&mut hasher, commitment)?;
        }
        Ok(*hasher.finalize().as_bytes())
    }
}

/// Authenticate a complete model bank and produce the deterministic record to reproduce and pin.
pub fn derive_bls_dory_model_commitment_record<R: Read>(
    reader: R,
    expected_manifest: &ModelBankManifest,
    trusted_model: &ModelPcsIdentity,
    padded_variables: usize,
    setup: &DeterministicBlsDorySetup,
) -> Result<BlsDoryModelCommitmentRecord, BlsDoryModelCommitmentRecordError> {
    if padded_variables != setup.max_log_n() {
        return Err(BlsDoryModelCommitmentRecordError::InvalidGeometry);
    }
    let padded_variables = u32::try_from(padded_variables)
        .map_err(|_| BlsDoryModelCommitmentRecordError::InvalidGeometry)?;
    expected_manifest
        .verify_pcs_identity(trusted_model)
        .map_err(BlsDoryModelCommitmentRecordError::ModelIdentity)?;
    let fixed_identity = derive_bls_dory_fixed_model_identity_from_verified_bank(
        reader,
        expected_manifest,
        trusted_model,
        padded_variables as usize,
        setup,
    )?;
    let base_input_bls_commitment = encode_commitment(&fixed_identity.base_input_commitment)?;
    let weight_bank_bls_commitments = fixed_identity
        .weight_bank_commitments
        .iter()
        .map(encode_commitment)
        .collect::<Result<Vec<_>, _>>()?;
    let mut record = BlsDoryModelCommitmentRecord {
        record_version: BLS_DORY_MODEL_COMMITMENT_RECORD_VERSION,
        padded_variables,
        manifest: *expected_manifest,
        model_pcs_identity: trusted_model.clone(),
        manifest_digest: hex::encode(
            expected_manifest
                .digest()
                .map_err(BlsDoryModelCommitmentRecordError::ModelIdentity)?,
        ),
        model_pcs_identity_digest: hex::encode(
            trusted_model
                .digest()
                .map_err(BlsDoryModelCommitmentRecordError::ModelIdentity)?,
        ),
        setup_identity: hex::encode(setup.identity()),
        fixed_model_protocol_version: fixed_identity.protocol_version,
        base_input_bls_commitment,
        weight_bank_bls_commitments,
        fixed_model_identity_digest: hex::encode(
            fixed_identity
                .digest()
                .map_err(BlsDoryModelCommitmentRecordError::FixedIdentity)?,
        ),
        record_digest: String::new(),
    };
    record.record_digest = hex::encode(record.canonical_digest()?);
    record.validate(setup)?;
    Ok(record)
}

#[derive(Debug, Error)]
pub enum BlsDoryModelCommitmentRecordError {
    #[error("unsupported fixed-model commitment record version")]
    UnsupportedVersion,
    #[error("the fixed-model commitment record uses an unsupported identity version")]
    UnsupportedFixedIdentity,
    #[error(
        "the ceremony must use a setup whose maximum variable count equals the padded geometry"
    )]
    InvalidGeometry,
    #[error("the deterministic BLS setup is invalid")]
    InvalidSetup,
    #[error("the trusted model manifest and PCS identity are inconsistent: {0}")]
    ModelIdentity(#[source] ModelBankError),
    #[error("authenticated model-bank commitment derivation failed: {0}")]
    Derivation(#[from] ModelBankFieldStreamError<BlsDoryFixedModelStreamError>),
    #[error("fixed-model identity validation failed: {0}")]
    FixedIdentity(#[source] BlsDorySharedLayoutError),
    #[error("the {0} field is not canonical lowercase hexadecimal")]
    InvalidHex(&'static str),
    #[error("the {0} digest does not match the record contents")]
    DigestMismatch(&'static str),
    #[error("the record contains too many fixed-model commitments")]
    InvalidCommitmentCount,
    #[error("canonical fixed-model commitment serialization failed: {0}")]
    CommitmentSerialization(String),
}

fn require_digest(
    label: &'static str,
    expected: [u8; 32],
    encoded: &str,
) -> Result<(), BlsDoryModelCommitmentRecordError> {
    if decode_hex_32(label, encoded)? != expected {
        return Err(BlsDoryModelCommitmentRecordError::DigestMismatch(label));
    }
    Ok(())
}

fn decode_hex_32(
    label: &'static str,
    encoded: &str,
) -> Result<[u8; 32], BlsDoryModelCommitmentRecordError> {
    if encoded.len() != 64 {
        return Err(BlsDoryModelCommitmentRecordError::InvalidHex(label));
    }
    let bytes = decode_hex(label, encoded)?;
    bytes
        .try_into()
        .map_err(|_| BlsDoryModelCommitmentRecordError::InvalidHex(label))
}

fn decode_hex(
    label: &'static str,
    encoded: &str,
) -> Result<Vec<u8>, BlsDoryModelCommitmentRecordError> {
    let bytes =
        hex::decode(encoded).map_err(|_| BlsDoryModelCommitmentRecordError::InvalidHex(label))?;
    if hex::encode(&bytes) != encoded {
        return Err(BlsDoryModelCommitmentRecordError::InvalidHex(label));
    }
    Ok(bytes)
}

fn encode_commitment(commitment: &BlsDoryGt) -> Result<String, BlsDoryModelCommitmentRecordError> {
    let mut bytes = Vec::new();
    commitment
        .serialize_compressed(&mut bytes)
        .map_err(|error| {
            BlsDoryModelCommitmentRecordError::CommitmentSerialization(error.to_string())
        })?;
    Ok(hex::encode(bytes))
}

fn decode_commitment(
    label: &'static str,
    encoded: &str,
) -> Result<BlsDoryGt, BlsDoryModelCommitmentRecordError> {
    let bytes = decode_commitment_bytes(label, encoded)?;
    let mut cursor = Cursor::new(bytes.as_slice());
    let commitment = BlsDoryGt::deserialize_compressed(&mut cursor).map_err(|error| {
        BlsDoryModelCommitmentRecordError::CommitmentSerialization(error.to_string())
    })?;
    if cursor.position() != bytes.len() as u64 || encode_commitment(&commitment)? != encoded {
        return Err(BlsDoryModelCommitmentRecordError::InvalidHex(label));
    }
    Ok(commitment)
}

fn decode_commitment_bytes(
    label: &'static str,
    encoded: &str,
) -> Result<Vec<u8>, BlsDoryModelCommitmentRecordError> {
    let encoded_len = BlsDoryGt::identity()
        .compressed_size()
        .checked_mul(2)
        .ok_or(BlsDoryModelCommitmentRecordError::InvalidCommitmentCount)?;
    if encoded.len() != encoded_len {
        return Err(BlsDoryModelCommitmentRecordError::InvalidHex(label));
    }
    decode_hex(label, encoded)
}

fn absorb_bytes(
    hasher: &mut blake3::Hasher,
    bytes: &[u8],
) -> Result<(), BlsDoryModelCommitmentRecordError> {
    let len = u32::try_from(bytes.len())
        .map_err(|_| BlsDoryModelCommitmentRecordError::InvalidCommitmentCount)?;
    hasher.update(&len.to_le_bytes());
    hasher.update(bytes);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dory_bls12_381_prototype::deterministic_bls_dory_setup;
    use crate::{SmallModelBankFixture, build_small_model_bank};

    fn fixture() -> (Vec<u8>, ModelBankManifest, ModelPcsIdentity) {
        let base = [0, 125, 250, 126];
        let layers = [
            [1, 2, 3, 4],
            [5, 6, 7, 8],
            [9, 10, 11, 12],
            [13, 14, 15, 16],
        ];
        let layer_slices = layers
            .iter()
            .map(|layer| layer.as_slice())
            .collect::<Vec<_>>();
        let suite = [0x51; 32];
        let provisional = build_small_model_bank(SmallModelBankFixture {
            model_version: 2,
            dimension: 2,
            batch: 2,
            base_input: &base,
            layers: &layer_slices,
            pcs_parameter_digest: suite,
            pcs_commitment_root: [0x52; 32],
        })
        .unwrap();
        let identity = ModelPcsIdentity {
            model_version: 2,
            batch: 2,
            dimension: 2,
            layers_per_bank: 2,
            model_byte_root: provisional.manifest.raw_blake3_root,
            pcs_suite_parameter_digest: suite,
            base_input_commitment: [0x61; 32],
            weight_bank_commitments: vec![[0x71; 32], [0x72; 32]],
        };
        let built = build_small_model_bank(SmallModelBankFixture {
            model_version: 2,
            dimension: 2,
            batch: 2,
            base_input: &base,
            layers: &layer_slices,
            pcs_parameter_digest: suite,
            pcs_commitment_root: identity.commitment_root().unwrap(),
        })
        .unwrap();
        (built.bytes, built.manifest, identity)
    }

    #[test]
    fn authenticated_record_is_deterministic_and_self_consistent() {
        const VARIABLES: usize = 5;
        let setup = deterministic_bls_dory_setup(VARIABLES).unwrap();
        let (bytes, manifest, identity) = fixture();
        let first = derive_bls_dory_model_commitment_record(
            Cursor::new(&bytes),
            &manifest,
            &identity,
            VARIABLES,
            &setup,
        )
        .unwrap();
        let second = derive_bls_dory_model_commitment_record(
            Cursor::new(&bytes),
            &manifest,
            &identity,
            VARIABLES,
            &setup,
        )
        .unwrap();

        assert_eq!(first, second);
        let encoded = serde_json::to_vec_pretty(&first).unwrap();
        assert_eq!(
            first.record_digest,
            "bfe12aebd5e3cb83f62101c741a0678c210b0f94c7860aaa9ea8c077e1abaf32"
        );
        assert_eq!(
            first.fixed_model_identity_digest,
            "219f2f597f11799e78fa440190babf9a8073c5ea6a87bb627a37fa358b085b14"
        );
        assert_eq!(encoded.len(), 7_851);
        assert_eq!(
            blake3::hash(&encoded).to_hex().as_str(),
            "dd491e6f8f2f5d74ae7cd24f4844250d41f073be47b47244dde1c988cb080d0e"
        );
        assert_eq!(encoded, serde_json::to_vec_pretty(&second).unwrap());
        let decoded: BlsDoryModelCommitmentRecord = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, first);
        decoded.validate(&setup).unwrap();
        first.validate(&setup).unwrap();

        let parsed: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        for path in ["record", "manifest", "model_pcs_identity"] {
            let mut with_unknown = parsed.clone();
            let object = match path {
                "record" => with_unknown.as_object_mut().unwrap(),
                nested => with_unknown
                    .get_mut(nested)
                    .unwrap()
                    .as_object_mut()
                    .unwrap(),
            };
            object.insert("v2_only_field".into(), serde_json::Value::Bool(true));
            assert!(
                serde_json::from_value::<BlsDoryModelCommitmentRecord>(with_unknown).is_err(),
                "unknown {path} field must fail closed"
            );
        }

        let text = String::from_utf8(encoded.clone()).unwrap();
        let duplicate = text.replacen(
            "  \"record_version\": 1,",
            "  \"record_version\": 1,\n  \"record_version\": 1,",
            1,
        );
        assert!(serde_json::from_str::<BlsDoryModelCommitmentRecord>(&duplicate).is_err());

        let mut changed = first.clone();
        changed.base_input_bls_commitment.replace_range(0..2, "00");
        assert!(changed.validate(&setup).is_err());
    }

    #[test]
    fn corrupted_bank_never_publishes_a_record() {
        const VARIABLES: usize = 5;
        let setup = deterministic_bls_dory_setup(VARIABLES).unwrap();
        let (mut bytes, manifest, identity) = fixture();
        let payload = bytes.last_mut().unwrap();
        *payload ^= 1;

        assert!(matches!(
            derive_bls_dory_model_commitment_record(
                Cursor::new(bytes),
                &manifest,
                &identity,
                VARIABLES,
                &setup,
            ),
            Err(BlsDoryModelCommitmentRecordError::Derivation(_))
        ));
    }

    #[test]
    fn substituted_model_identity_is_rejected_before_derivation() {
        const VARIABLES: usize = 5;
        let setup = deterministic_bls_dory_setup(VARIABLES).unwrap();
        let (bytes, manifest, mut identity) = fixture();
        identity.base_input_commitment[0] ^= 1;

        assert!(matches!(
            derive_bls_dory_model_commitment_record(
                Cursor::new(bytes),
                &manifest,
                &identity,
                VARIABLES,
                &setup,
            ),
            Err(BlsDoryModelCommitmentRecordError::ModelIdentity(_))
        ));
    }
}
