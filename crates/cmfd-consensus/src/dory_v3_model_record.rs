//! Immutable, byte-authenticated model commitment record for Dory V3.
//!
//! The serializable record proves internal consistency only. The distinct
//! non-serializable capability is returned exclusively after one reader has
//! authenticated the complete model bank and rederived every ordered Dory
//! commitment from those exact bytes.

use std::io::Read;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _, ser::Error as _};
use thiserror::Error;

use crate::{
    ModelBankError, ModelBankFieldStreamError, ModelBankManifest,
    dory_bls12_381_layout::{
        BlsDoryFixedModelStreamError, derive_bls_dory_model_commitments_from_verified_layout,
    },
    dory_bls12_381_prototype::DeterministicBlsDorySetup,
    dory_v3_model::{
        DoryV3ModelIdentityError, DoryV3ModelIdentityV1,
        StructurallyValidatedProductionDoryV3ModelIdentity,
    },
    dory_v3_suite::{
        DORY_V3_MODEL_RECORD_CANONICAL_BYTES, DORY_V3_MODEL_RECORD_DOMAIN,
        DORY_V3_MODEL_RECORD_VERSION, Digest32,
    },
};

const CANONICAL_BYTES: usize = DORY_V3_MODEL_RECORD_CANONICAL_BYTES as usize;

/// Audit representation of a Dory V3 model commitment ceremony result.
///
/// All fields are private. Serialization and deserialization both enforce the
/// complete fixture-safe consistency check. Deserializing this type does not
/// recreate the same-reader bank-authentication capability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DoryV3ModelCommitmentRecordV2 {
    record_version: u16,
    suite_digest: Digest32,
    manifest: ModelBankManifest,
    manifest_digest: Digest32,
    model_identity: DoryV3ModelIdentityV1,
    model_identity_digest: Digest32,
    setup_identity: Digest32,
    padded_variables: u32,
    commitment_root: Digest32,
    record_digest: Digest32,
}

impl DoryV3ModelCommitmentRecordV2 {
    pub(crate) fn new(
        manifest: ModelBankManifest,
        model_identity: DoryV3ModelIdentityV1,
    ) -> Result<Self, DoryV3ModelCommitmentRecordError> {
        model_identity
            .verify_manifest(&manifest)
            .map_err(DoryV3ModelCommitmentRecordError::ModelIdentity)?;
        let mut record = Self {
            record_version: DORY_V3_MODEL_RECORD_VERSION,
            suite_digest: Digest32::new(model_identity.suite_parameter_digest()),
            manifest,
            manifest_digest: Digest32::new(
                manifest
                    .digest()
                    .map_err(DoryV3ModelCommitmentRecordError::InvalidManifest)?,
            ),
            model_identity_digest: Digest32::new(
                model_identity
                    .digest()
                    .map_err(DoryV3ModelCommitmentRecordError::ModelIdentity)?,
            ),
            setup_identity: Digest32::new(model_identity.setup_identity()),
            padded_variables: model_identity.padded_variables(),
            commitment_root: Digest32::new(
                model_identity
                    .commitment_root()
                    .map_err(DoryV3ModelCommitmentRecordError::ModelIdentity)?,
            ),
            model_identity,
            record_digest: Digest32::ZERO,
        };
        record.record_digest = record.canonical_digest();
        record.validate()?;
        Ok(record)
    }

    /// Validate every redundant field without claiming model-bank I/O.
    pub fn validate(&self) -> Result<(), DoryV3ModelCommitmentRecordError> {
        if self.record_version != DORY_V3_MODEL_RECORD_VERSION {
            return Err(DoryV3ModelCommitmentRecordError::UnsupportedVersion);
        }
        self.model_identity
            .validate()
            .map_err(DoryV3ModelCommitmentRecordError::ModelIdentity)?;
        self.model_identity
            .verify_manifest(&self.manifest)
            .map_err(DoryV3ModelCommitmentRecordError::ModelIdentity)?;
        let manifest_digest = self
            .manifest
            .digest()
            .map_err(DoryV3ModelCommitmentRecordError::InvalidManifest)?;
        if self.manifest_digest.into_bytes() != manifest_digest {
            return Err(DoryV3ModelCommitmentRecordError::ManifestDigestMismatch);
        }
        if self.suite_digest.into_bytes() != self.model_identity.suite_parameter_digest() {
            return Err(DoryV3ModelCommitmentRecordError::SuiteDigestMismatch);
        }
        let model_identity_digest = self
            .model_identity
            .digest()
            .map_err(DoryV3ModelCommitmentRecordError::ModelIdentity)?;
        if self.model_identity_digest.into_bytes() != model_identity_digest {
            return Err(DoryV3ModelCommitmentRecordError::ModelIdentityDigestMismatch);
        }
        if self.setup_identity.into_bytes() != self.model_identity.setup_identity() {
            return Err(DoryV3ModelCommitmentRecordError::SetupIdentityMismatch);
        }
        if self.padded_variables != self.model_identity.padded_variables() {
            return Err(DoryV3ModelCommitmentRecordError::PaddedVariablesMismatch);
        }
        let commitment_root = self
            .model_identity
            .commitment_root()
            .map_err(DoryV3ModelCommitmentRecordError::ModelIdentity)?;
        if self.commitment_root.into_bytes() != commitment_root {
            return Err(DoryV3ModelCommitmentRecordError::CommitmentRootMismatch);
        }
        if self.record_digest != self.canonical_digest() {
            return Err(DoryV3ModelCommitmentRecordError::RecordDigestMismatch);
        }
        Ok(())
    }

    /// Require the exact compiled production identity, manifest, geometry, and
    /// setup. This structural check performs no model-bank I/O and does not
    /// create a bank-authentication capability.
    pub fn validate_production(
        &self,
        setup: &DeterministicBlsDorySetup,
    ) -> Result<(), DoryV3ModelCommitmentRecordError> {
        self.validate()?;
        let validated = self
            .model_identity
            .validate_production_structure(&self.manifest, setup)
            .map_err(DoryV3ModelCommitmentRecordError::ModelIdentity)?;
        if validated.identity() != &self.model_identity
            || validated.manifest() != &self.manifest
            || validated.identity_digest() != self.model_identity_digest.into_bytes()
            || validated.manifest_digest() != self.manifest_digest.into_bytes()
            || validated.commitment_root() != self.commitment_root.into_bytes()
        {
            return Err(DoryV3ModelCommitmentRecordError::StructuralCapabilityMismatch);
        }
        Ok(())
    }

    /// Exact fixed-width transcript hashed by the Record V2 domain.
    #[must_use]
    pub fn canonical_bytes(&self) -> [u8; CANONICAL_BYTES] {
        let mut encoded = [0_u8; CANONICAL_BYTES];
        encoded[0..2].copy_from_slice(&self.record_version.to_le_bytes());
        encoded[2..34].copy_from_slice(self.suite_digest.as_bytes());
        encoded[34..66].copy_from_slice(self.manifest_digest.as_bytes());
        encoded[66..98].copy_from_slice(self.model_identity_digest.as_bytes());
        encoded[98..130].copy_from_slice(self.setup_identity.as_bytes());
        encoded[130..134].copy_from_slice(&self.padded_variables.to_le_bytes());
        encoded[134..166].copy_from_slice(self.commitment_root.as_bytes());
        encoded
    }

    /// Domain-separated digest of the exact 166-byte Record V2 transcript.
    #[must_use]
    pub fn canonical_digest(&self) -> Digest32 {
        let mut hasher = blake3::Hasher::new_derive_key(DORY_V3_MODEL_RECORD_DOMAIN);
        hasher.update(&self.canonical_bytes());
        Digest32::new(*hasher.finalize().as_bytes())
    }

    pub const fn record_version(&self) -> u16 {
        self.record_version
    }

    pub const fn suite_digest(&self) -> Digest32 {
        self.suite_digest
    }

    pub const fn manifest(&self) -> &ModelBankManifest {
        &self.manifest
    }

    pub const fn manifest_digest(&self) -> Digest32 {
        self.manifest_digest
    }

    pub const fn model_identity(&self) -> &DoryV3ModelIdentityV1 {
        &self.model_identity
    }

    pub const fn model_identity_digest(&self) -> Digest32 {
        self.model_identity_digest
    }

    pub const fn setup_identity(&self) -> Digest32 {
        self.setup_identity
    }

    pub const fn padded_variables(&self) -> u32 {
        self.padded_variables
    }

    pub const fn commitment_root(&self) -> Digest32 {
        self.commitment_root
    }

    pub const fn record_digest(&self) -> Digest32 {
        self.record_digest
    }
}

/// Encode the exact human-readable Record V2 artifact: pretty JSON followed
/// by exactly one line feed.
pub(crate) fn canonical_dory_v3_model_record_v2_json(
    record: &DoryV3ModelCommitmentRecordV2,
) -> Result<Vec<u8>, serde_json::Error> {
    let mut encoded = serde_json::to_vec_pretty(record)?;
    encoded.push(b'\n');
    Ok(encoded)
}

/// Non-serializable evidence that one exact reader authenticated the model
/// bank and reproduced every commitment in the enclosed immutable record.
#[must_use]
#[derive(Debug)]
pub struct BankAuthenticatedDoryV3ModelCommitmentRecordV2 {
    record: DoryV3ModelCommitmentRecordV2,
}

impl BankAuthenticatedDoryV3ModelCommitmentRecordV2 {
    pub const fn record(&self) -> &DoryV3ModelCommitmentRecordV2 {
        &self.record
    }

    pub fn into_record(self) -> DoryV3ModelCommitmentRecordV2 {
        self.record
    }
}

/// Authenticate one production bank reader, rederive all four ordered Dory
/// commitments, compare each role individually, and publish Record V2.
pub fn derive_bank_authenticated_dory_v3_model_commitment_record_v2<R: Read>(
    reader: R,
    validated: &StructurallyValidatedProductionDoryV3ModelIdentity,
    setup: &DeterministicBlsDorySetup,
) -> Result<BankAuthenticatedDoryV3ModelCommitmentRecordV2, DoryV3ModelCommitmentRecordError> {
    let reproduced = validated
        .identity()
        .validate_production_structure(validated.manifest(), setup)
        .map_err(DoryV3ModelCommitmentRecordError::ModelIdentity)?;
    if &reproduced != validated {
        return Err(DoryV3ModelCommitmentRecordError::StructuralCapabilityMismatch);
    }
    let authenticated = derive_bank_authenticated_record_v2(
        reader,
        validated.manifest(),
        validated.identity(),
        setup,
    )?;
    authenticated.record.validate_production(setup)?;
    Ok(authenticated)
}

/// Authenticate a bounded fixture with the same transactional reader path but
/// without claiming the compiled production geometry.
#[cfg(test)]
pub(crate) fn derive_bank_authenticated_dory_v3_model_commitment_record_v2_for_test<R: Read>(
    reader: R,
    manifest: &ModelBankManifest,
    identity: &DoryV3ModelIdentityV1,
    setup: &DeterministicBlsDorySetup,
) -> Result<BankAuthenticatedDoryV3ModelCommitmentRecordV2, DoryV3ModelCommitmentRecordError> {
    derive_bank_authenticated_record_v2(reader, manifest, identity, setup)
}

fn derive_bank_authenticated_record_v2<R: Read>(
    reader: R,
    manifest: &ModelBankManifest,
    identity: &DoryV3ModelIdentityV1,
    setup: &DeterministicBlsDorySetup,
) -> Result<BankAuthenticatedDoryV3ModelCommitmentRecordV2, DoryV3ModelCommitmentRecordError> {
    identity
        .validate()
        .map_err(DoryV3ModelCommitmentRecordError::ModelIdentity)?;
    identity
        .verify_manifest(manifest)
        .map_err(DoryV3ModelCommitmentRecordError::ModelIdentity)?;
    setup
        .validate()
        .map_err(|_| DoryV3ModelCommitmentRecordError::InvalidSetup)?;
    if identity.setup_identity() != setup.identity()
        || usize::try_from(identity.padded_variables()).ok() != Some(setup.max_log_n())
    {
        return Err(DoryV3ModelCommitmentRecordError::SetupIdentityMismatch);
    }

    let weight_bank_count = identity
        .weight_bank_count()
        .map_err(DoryV3ModelCommitmentRecordError::ModelIdentity)?;
    let derived = derive_bls_dory_model_commitments_from_verified_layout(
        reader,
        manifest,
        identity.batch(),
        identity.dimension(),
        identity.layers_per_bank(),
        weight_bank_count,
        usize::try_from(identity.padded_variables())
            .map_err(|_| DoryV3ModelCommitmentRecordError::PaddedVariablesMismatch)?,
        setup,
    )?;
    if derived.base_input != identity.base_input_commitment() {
        return Err(DoryV3ModelCommitmentRecordError::DerivedCommitmentMismatch { role: 0 });
    }
    let expected_weights = identity.weight_bank_commitments();
    if derived.weight_banks.len() != expected_weights.len() {
        return Err(
            DoryV3ModelCommitmentRecordError::InvalidDerivedCommitmentCount {
                expected: weight_bank_count,
                actual: derived.weight_banks.len(),
            },
        );
    }
    for (index, (actual, expected)) in derived
        .weight_banks
        .iter()
        .zip(expected_weights.iter())
        .enumerate()
    {
        if actual != expected {
            let role = u16::try_from(index + 1).map_err(|_| {
                DoryV3ModelCommitmentRecordError::InvalidDerivedCommitmentCount {
                    expected: weight_bank_count,
                    actual: derived.weight_banks.len(),
                }
            })?;
            return Err(DoryV3ModelCommitmentRecordError::DerivedCommitmentMismatch { role });
        }
    }

    Ok(BankAuthenticatedDoryV3ModelCommitmentRecordV2 {
        record: DoryV3ModelCommitmentRecordV2::new(*manifest, identity.clone())?,
    })
}

#[derive(Serialize)]
struct DoryV3ModelCommitmentRecordV2Ref<'a> {
    record_version: u16,
    suite_digest: Digest32,
    manifest: &'a ModelBankManifest,
    manifest_digest: Digest32,
    model_identity: &'a DoryV3ModelIdentityV1,
    model_identity_digest: Digest32,
    setup_identity: Digest32,
    padded_variables: u32,
    commitment_root: Digest32,
    record_digest: Digest32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DoryV3ModelCommitmentRecordV2Owned {
    record_version: u16,
    suite_digest: Digest32,
    manifest: ModelBankManifest,
    manifest_digest: Digest32,
    model_identity: DoryV3ModelIdentityV1,
    model_identity_digest: Digest32,
    setup_identity: Digest32,
    padded_variables: u32,
    commitment_root: Digest32,
    record_digest: Digest32,
}

impl Serialize for DoryV3ModelCommitmentRecordV2 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if !serializer.is_human_readable() {
            return Err(S::Error::custom(
                "Dory V3 model commitment records only support human-readable audit encoding",
            ));
        }
        self.validate().map_err(S::Error::custom)?;
        DoryV3ModelCommitmentRecordV2Ref {
            record_version: self.record_version,
            suite_digest: self.suite_digest,
            manifest: &self.manifest,
            manifest_digest: self.manifest_digest,
            model_identity: &self.model_identity,
            model_identity_digest: self.model_identity_digest,
            setup_identity: self.setup_identity,
            padded_variables: self.padded_variables,
            commitment_root: self.commitment_root,
            record_digest: self.record_digest,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DoryV3ModelCommitmentRecordV2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if !deserializer.is_human_readable() {
            return Err(D::Error::custom(
                "Dory V3 model commitment records only support human-readable audit encoding",
            ));
        }
        let decoded = DoryV3ModelCommitmentRecordV2Owned::deserialize(deserializer)?;
        let record = Self {
            record_version: decoded.record_version,
            suite_digest: decoded.suite_digest,
            manifest: decoded.manifest,
            manifest_digest: decoded.manifest_digest,
            model_identity: decoded.model_identity,
            model_identity_digest: decoded.model_identity_digest,
            setup_identity: decoded.setup_identity,
            padded_variables: decoded.padded_variables,
            commitment_root: decoded.commitment_root,
            record_digest: decoded.record_digest,
        };
        record.validate().map_err(D::Error::custom)?;
        Ok(record)
    }
}

/// Fail-closed errors for immutable Record V2 construction and validation.
#[derive(Debug, Error)]
pub enum DoryV3ModelCommitmentRecordError {
    #[error("unsupported Dory V3 model commitment record version")]
    UnsupportedVersion,
    #[error("invalid Dory V3 model identity: {0}")]
    ModelIdentity(#[source] DoryV3ModelIdentityError),
    #[error("invalid model-bank manifest: {0}")]
    InvalidManifest(#[source] ModelBankError),
    #[error("record suite digest does not match the model identity")]
    SuiteDigestMismatch,
    #[error("record manifest digest does not match the manifest")]
    ManifestDigestMismatch,
    #[error("record model identity digest does not match the model identity")]
    ModelIdentityDigestMismatch,
    #[error("record setup identity does not match the model identity")]
    SetupIdentityMismatch,
    #[error("record padded-variable count does not match the model identity")]
    PaddedVariablesMismatch,
    #[error("record commitment root does not match the model identity")]
    CommitmentRootMismatch,
    #[error("record digest does not match the canonical Record V2 transcript")]
    RecordDigestMismatch,
    #[error("the deterministic Dory setup is invalid")]
    InvalidSetup,
    #[error("the supplied structural production capability could not be reproduced")]
    StructuralCapabilityMismatch,
    #[error("derived fixed-model commitment count is {actual}; expected {expected}")]
    InvalidDerivedCommitmentCount { expected: u32, actual: usize },
    #[error("derived Dory commitment does not match fixed role {role}")]
    DerivedCommitmentMismatch { role: u16 },
    #[error("authenticated model-bank commitment derivation failed: {0}")]
    Derivation(#[from] ModelBankFieldStreamError<BlsDoryFixedModelStreamError>),
}

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        fs::File,
        io::{self, Cursor, Read},
        path::PathBuf,
        rc::Rc,
    };

    use dory_pcs::primitives::arithmetic::Field;
    use serde_json::{Value, json};

    use super::*;
    use crate::{
        ModelFieldChunk, SmallModelBankFixture, build_small_model_bank,
        dory_bls12_381_aggregate::commit_bls_dory_polynomial,
        dory_bls12_381_prototype::{BlsDoryFr, BlsDoryGt, deterministic_bls_dory_setup},
        dory_v3_model::CanonicalBlsDoryGtHex,
        dory_v3_model_stream::{
            BankAuthenticatedDoryV3ModelFieldStreamError, StagedDoryV3ModelFieldSink,
            VerifiedBankAuthenticatedDoryV3ModelReceipt,
            verify_dory_v3_model_bank_into_staged_field_sink_for_test,
        },
        dory_v3_suite::{
            DORY_V3_MODEL_IDENTITY_VERSION, DORY_V3_PADDED_VARIABLES,
            DORY_V3_PRODUCTION_SUITE_DIGEST,
        },
        dory_v3_transcript::{DoryV3TranscriptContext, DoryV3TranscriptError},
    };

    #[cfg(feature = "whir-prototype")]
    use crate::{
        BlockChallenge,
        dory_bls12_381_execution_artifact::BlsDoryExecutionAccumulatorArtifactError,
        dory_bls12_381_execution_provider::BlsDoryV3ExecutionAccumulatorArtifactContext,
        dory_v3_transcript::DoryV3ChallengeContext,
    };

    const VARIABLES: usize = 5;
    const MODEL_VERSION: u32 = 2;
    const BATCH: u32 = 2;
    const DIMENSION: u32 = 2;
    const LAYERS_PER_BANK: u32 = 2;
    const SUITE_DIGEST: [u8; 32] = [0x51; 32];
    const BASE: [u8; 4] = [125, 126, 124, 130];
    const LAYERS: [[u8; 4]; 6] = [
        [125, 127, 129, 131],
        [124, 122, 120, 118],
        [126, 128, 130, 132],
        [123, 121, 119, 117],
        [133, 135, 137, 139],
        [116, 114, 112, 110],
    ];

    struct Fixture {
        bytes: Vec<u8>,
        manifest: ModelBankManifest,
        identity: DoryV3ModelIdentityV1,
        setup: DeterministicBlsDorySetup,
    }

    fn commit_bytes(bytes: &[u8], setup: &DeterministicBlsDorySetup) -> BlsDoryGt {
        let coefficient_count = 1_usize << VARIABLES;
        let mut coefficients = bytes
            .iter()
            .map(|value| BlsDoryFr::from_i64(i64::from(*value) - 125))
            .collect::<Vec<_>>();
        coefficients.resize(coefficient_count, BlsDoryFr::from_i64(0));
        commit_bls_dory_polynomial(
            coefficients,
            VARIABLES / 2,
            VARIABLES - VARIABLES / 2,
            setup,
        )
        .unwrap()
        .commitment()
    }

    fn actual_commitments(setup: &DeterministicBlsDorySetup) -> (BlsDoryGt, Vec<BlsDoryGt>) {
        let base = commit_bytes(&BASE, setup);
        let weights = LAYERS
            .chunks_exact(LAYERS_PER_BANK as usize)
            .map(|bank| {
                let bytes = bank
                    .iter()
                    .flat_map(|layer| layer.iter().copied())
                    .collect::<Vec<_>>();
                commit_bytes(&bytes, setup)
            })
            .collect();
        (base, weights)
    }

    fn identity_from_commitments(
        manifest: &ModelBankManifest,
        setup: &DeterministicBlsDorySetup,
        base_input: BlsDoryGt,
        weight_banks: &[BlsDoryGt],
        layers_per_bank: u32,
        suite_digest: [u8; 32],
    ) -> DoryV3ModelIdentityV1 {
        let base_input = CanonicalBlsDoryGtHex::from_commitment(base_input)
            .unwrap()
            .to_hex()
            .unwrap();
        let weight_banks = weight_banks
            .iter()
            .copied()
            .map(|commitment| {
                CanonicalBlsDoryGtHex::from_commitment(commitment)
                    .unwrap()
                    .to_hex()
                    .unwrap()
            })
            .collect::<Vec<_>>();
        serde_json::from_value(json!({
            "identity_version": DORY_V3_MODEL_IDENTITY_VERSION,
            "model_version": MODEL_VERSION,
            "batch": BATCH,
            "dimension": DIMENSION,
            "layers_per_bank": layers_per_bank,
            "model_byte_root": manifest.raw_blake3_root,
            "layer_roots_aggregate": manifest.layer_roots_aggregate,
            "suite_parameter_digest": suite_digest,
            "setup_identity": setup.identity(),
            "padded_variables": VARIABLES,
            "base_input_commitment": base_input,
            "weight_bank_commitments": weight_banks,
        }))
        .unwrap()
    }

    fn fixture_with_commitments(
        setup: DeterministicBlsDorySetup,
        base_input: BlsDoryGt,
        weight_banks: Vec<BlsDoryGt>,
        layers_per_bank: u32,
        suite_digest: [u8; 32],
    ) -> Fixture {
        let layer_slices = LAYERS
            .iter()
            .map(|layer| layer.as_slice())
            .collect::<Vec<_>>();
        let provisional = build_small_model_bank(SmallModelBankFixture {
            model_version: MODEL_VERSION,
            dimension: DIMENSION,
            batch: BATCH,
            base_input: &BASE,
            layers: &layer_slices,
            pcs_parameter_digest: suite_digest,
            pcs_commitment_root: [0x52; 32],
        })
        .unwrap();
        let identity = identity_from_commitments(
            &provisional.manifest,
            &setup,
            base_input,
            &weight_banks,
            layers_per_bank,
            suite_digest,
        );
        let built = build_small_model_bank(SmallModelBankFixture {
            model_version: MODEL_VERSION,
            dimension: DIMENSION,
            batch: BATCH,
            base_input: &BASE,
            layers: &layer_slices,
            pcs_parameter_digest: suite_digest,
            pcs_commitment_root: identity.commitment_root().unwrap(),
        })
        .unwrap();
        identity.verify_manifest(&built.manifest).unwrap();
        Fixture {
            bytes: built.bytes,
            manifest: built.manifest,
            identity,
            setup,
        }
    }

    fn fixture() -> Fixture {
        let setup = deterministic_bls_dory_setup(VARIABLES).unwrap();
        let (base_input, weight_banks) = actual_commitments(&setup);
        fixture_with_commitments(
            setup,
            base_input,
            weight_banks,
            LAYERS_PER_BANK,
            SUITE_DIGEST,
        )
    }

    fn production_suite_fixture() -> Fixture {
        let setup = deterministic_bls_dory_setup(VARIABLES).unwrap();
        let (base_input, weight_banks) = actual_commitments(&setup);
        fixture_with_commitments(
            setup,
            base_input,
            weight_banks,
            LAYERS_PER_BANK,
            DORY_V3_PRODUCTION_SUITE_DIGEST.into_bytes(),
        )
    }

    fn derive_fixture(fixture: &Fixture) -> BankAuthenticatedDoryV3ModelCommitmentRecordV2 {
        derive_with_reader(fixture, Cursor::new(&fixture.bytes)).unwrap()
    }

    fn derive_with_reader<R: Read>(
        fixture: &Fixture,
        reader: R,
    ) -> Result<BankAuthenticatedDoryV3ModelCommitmentRecordV2, DoryV3ModelCommitmentRecordError>
    {
        derive_bank_authenticated_record_v2(
            reader,
            &fixture.manifest,
            &fixture.identity,
            &fixture.setup,
        )
    }

    #[derive(Default)]
    struct StreamState {
        reads: Cell<usize>,
        chunks: Cell<usize>,
        drops: Cell<usize>,
        published: Cell<bool>,
    }

    struct ReadProbe {
        inner: Cursor<Vec<u8>>,
        state: Rc<StreamState>,
    }

    impl Read for ReadProbe {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            self.state.reads.set(self.state.reads.get() + 1);
            self.inner.read(bytes)
        }
    }

    #[derive(Debug)]
    struct StreamSinkError;

    impl std::fmt::Display for StreamSinkError {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("stream sink failed")
        }
    }

    impl std::error::Error for StreamSinkError {}

    struct StreamSink {
        state: Rc<StreamState>,
    }

    impl StagedDoryV3ModelFieldSink for StreamSink {
        type Error = StreamSinkError;
        type Output = VerifiedBankAuthenticatedDoryV3ModelReceipt;

        fn write_chunk(&mut self, _chunk: ModelFieldChunk<'_>) -> Result<(), Self::Error> {
            self.state.chunks.set(self.state.chunks.get() + 1);
            Ok(())
        }

        fn finish_verified(
            self,
            receipt: VerifiedBankAuthenticatedDoryV3ModelReceipt,
        ) -> Result<Self::Output, Self::Error> {
            self.state.published.set(true);
            Ok(receipt)
        }
    }

    impl Drop for StreamSink {
        fn drop(&mut self) {
            self.state.drops.set(self.state.drops.get() + 1);
        }
    }

    fn stream_fixture(
        fixture: &Fixture,
        authenticated: &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
        setup: &DeterministicBlsDorySetup,
        state: Rc<StreamState>,
    ) -> Result<
        VerifiedBankAuthenticatedDoryV3ModelReceipt,
        BankAuthenticatedDoryV3ModelFieldStreamError<StreamSinkError>,
    > {
        verify_dory_v3_model_bank_into_staged_field_sink_for_test(
            ReadProbe {
                inner: Cursor::new(fixture.bytes.clone()),
                state: Rc::clone(&state),
            },
            authenticated,
            setup,
            StreamSink { state },
        )
    }

    #[test]
    fn record_v2_derives_from_one_authenticated_reader_and_matches_every_role() {
        let fixture = fixture();
        let authenticated = derive_fixture(&fixture);
        let record = authenticated.record();
        record.validate().unwrap();
        assert_eq!(record.model_identity(), &fixture.identity);
        assert_eq!(record.manifest(), &fixture.manifest);
        assert_eq!(record.record_version(), DORY_V3_MODEL_RECORD_VERSION);
        assert_eq!(
            record.setup_identity().into_bytes(),
            fixture.setup.identity()
        );
        assert_eq!(record.model_identity().weight_bank_count().unwrap(), 3);
    }

    #[test]
    fn authenticated_stream_rejects_mismatched_setup_before_reading_or_publishing() {
        let fixture = fixture();
        let authenticated = derive_fixture(&fixture);
        let wrong_setup = deterministic_bls_dory_setup(VARIABLES + 1).unwrap();
        let state = Rc::new(StreamState::default());

        let error =
            stream_fixture(&fixture, &authenticated, &wrong_setup, Rc::clone(&state)).unwrap_err();

        assert!(matches!(
            error,
            BankAuthenticatedDoryV3ModelFieldStreamError::Authority(
                DoryV3ModelCommitmentRecordError::SetupIdentityMismatch
            )
        ));
        assert_eq!(state.reads.get(), 0);
        assert_eq!(state.chunks.get(), 0);
        assert_eq!(state.drops.get(), 1);
        assert!(!state.published.get());
    }

    #[test]
    fn authenticated_stream_rejects_bank_from_a_different_manifest() {
        const RAW_ROOT_OFFSET: usize = 56;
        let mut fixture = fixture();
        let authenticated = derive_fixture(&fixture);
        fixture.bytes[RAW_ROOT_OFFSET] ^= 1;
        let state = Rc::new(StreamState::default());

        let error = stream_fixture(&fixture, &authenticated, &fixture.setup, Rc::clone(&state))
            .unwrap_err();

        assert!(matches!(
            error,
            BankAuthenticatedDoryV3ModelFieldStreamError::ModelBank(
                ModelBankError::ManifestMismatch
            )
        ));
        assert!(state.reads.get() > 0);
        assert_eq!(state.chunks.get(), 0);
        assert_eq!(state.drops.get(), 1);
        assert!(!state.published.get());
    }

    #[test]
    fn authenticated_stream_receipt_binds_the_exact_record_v2() {
        let fixture = fixture();
        let authenticated = derive_fixture(&fixture);
        let state = Rc::new(StreamState::default());
        let receipt =
            stream_fixture(&fixture, &authenticated, &fixture.setup, Rc::clone(&state)).unwrap();
        assert!(receipt.is_bound_to_bank_authenticated_record(&authenticated));
        assert!(state.published.get());

        let setup = deterministic_bls_dory_setup(VARIABLES).unwrap();
        let (base_input, weight_banks) = actual_commitments(&setup);
        let other =
            fixture_with_commitments(setup, base_input, weight_banks, LAYERS_PER_BANK, [0x52; 32]);
        let other_authenticated = derive_fixture(&other);
        assert!(!receipt.is_bound_to_bank_authenticated_record(&other_authenticated));
    }

    #[test]
    fn transcript_context_requires_and_copies_the_authenticated_record() {
        let fixture = fixture();
        let authenticated = derive_fixture(&fixture);
        assert!(matches!(
            DoryV3TranscriptContext::from_bank_authenticated_record([0; 32], &authenticated),
            Err(DoryV3TranscriptError::NetworkIdentity)
        ));
        assert!(matches!(
            DoryV3TranscriptContext::from_bank_authenticated_record([0x11; 32], &authenticated),
            Err(DoryV3TranscriptError::SuiteDigest)
        ));

        let production_suite_fixture = production_suite_fixture();
        let authenticated = derive_fixture(&production_suite_fixture);
        let record = authenticated.record();
        let context =
            DoryV3TranscriptContext::from_bank_authenticated_record([0x11; 32], &authenticated)
                .unwrap();
        assert_eq!(context.network_id(), [0x11; 32]);
        assert_eq!(context.suite_digest(), record.suite_digest());
        assert_eq!(context.manifest_digest(), record.manifest_digest());
        assert_eq!(
            context.model_identity_digest(),
            record.model_identity_digest()
        );
        assert_eq!(context.model_record_digest(), record.record_digest());
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    fn typed_challenge_artifact_context_is_exact_and_rejects_substitution() {
        let typed_constructor: fn(
            DoryV3ChallengeContext,
            &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
            &DeterministicBlsDorySetup,
        ) -> Result<
            BlsDoryV3ExecutionAccumulatorArtifactContext,
            BlsDoryExecutionAccumulatorArtifactError,
        > = BlsDoryV3ExecutionAccumulatorArtifactContext::for_test;
        let _ = typed_constructor;

        let fixture = production_suite_fixture();
        let authenticated = derive_fixture(&fixture);
        let transcript =
            DoryV3TranscriptContext::from_bank_authenticated_record([0x11; 32], &authenticated)
                .unwrap();
        let block = BlockChallenge {
            network_id: [0x11; 32],
            previous_block: [0x21; 32],
            transaction_root: [0x22; 32],
            height: 23,
            timestamp: 24,
            target: [0x25; 32],
        };
        let challenge = transcript.challenge_context(&block, 26).unwrap();

        let typed = BlsDoryV3ExecutionAccumulatorArtifactContext::for_test(
            challenge,
            &authenticated,
            &fixture.setup,
        )
        .unwrap();
        assert_eq!(typed.raw_for_test().network_identity(), block.network_id);
        assert_eq!(
            typed.raw_for_test().model_record_identity(),
            authenticated.record().record_digest().into_bytes()
        );
        assert_eq!(
            typed.raw_for_test().setup_identity(),
            fixture.setup.identity()
        );
        assert_eq!(
            typed.raw_for_test().challenge_identity(),
            challenge.digest()
        );

        let mut changed_manifest = *authenticated.record().manifest();
        changed_manifest.model_version += 1;
        let mut changed_identity =
            serde_json::to_value(authenticated.record().model_identity()).unwrap();
        changed_identity["model_version"] = Value::from(changed_manifest.model_version);
        let changed_identity = serde_json::from_value(changed_identity).unwrap();
        let changed_record =
            DoryV3ModelCommitmentRecordV2::new(changed_manifest, changed_identity).unwrap();
        let changed_authenticated = BankAuthenticatedDoryV3ModelCommitmentRecordV2 {
            record: changed_record,
        };
        assert!(matches!(
            BlsDoryV3ExecutionAccumulatorArtifactContext::for_test(
                challenge,
                &changed_authenticated,
                &fixture.setup,
            ),
            Err(BlsDoryExecutionAccumulatorArtifactError::WrongContext)
        ));

        let wrong_setup = deterministic_bls_dory_setup(VARIABLES + 1).unwrap();
        assert!(matches!(
            BlsDoryV3ExecutionAccumulatorArtifactContext::for_test(
                challenge,
                &authenticated,
                &wrong_setup,
            ),
            Err(BlsDoryExecutionAccumulatorArtifactError::WrongContext)
        ));
    }

    #[test]
    fn record_v2_reproduces_identically_from_two_independent_readers() {
        let fixture = fixture();
        let first = derive_fixture(&fixture).into_record();
        let second = derive_fixture(&fixture).into_record();
        assert_eq!(first, second);
        assert_eq!(
            serde_json::to_vec(&first).unwrap(),
            serde_json::to_vec(&second).unwrap()
        );
    }

    #[test]
    fn record_v2_canonical_transcript_is_exactly_166_bytes_and_has_a_kat() {
        let record = derive_fixture(&fixture()).into_record();
        let encoded = record.canonical_bytes();
        assert_eq!(encoded.len(), DORY_V3_MODEL_RECORD_CANONICAL_BYTES as usize);
        assert_eq!(&encoded[0..2], &DORY_V3_MODEL_RECORD_VERSION.to_le_bytes());
        assert_eq!(&encoded[2..34], record.suite_digest().as_bytes());
        assert_eq!(&encoded[34..66], record.manifest_digest().as_bytes());
        assert_eq!(&encoded[66..98], record.model_identity_digest().as_bytes());
        assert_eq!(&encoded[98..130], record.setup_identity().as_bytes());
        assert_eq!(&encoded[130..134], &record.padded_variables().to_le_bytes());
        assert_eq!(&encoded[134..166], record.commitment_root().as_bytes());
        assert_eq!(record.canonical_digest(), record.record_digest());
        assert_eq!(
            record.record_digest().to_hex(),
            "bbc72cbe4f1327cf365bef95a0076eeb2080cf3c32ce19914b266da92ed06126"
        );
    }

    #[test]
    fn record_v2_canonical_json_is_pretty_and_has_exactly_one_lf() {
        let record = derive_fixture(&fixture()).into_record();
        let encoded = canonical_dory_v3_model_record_v2_json(&record).unwrap();
        assert!(encoded.ends_with(b"\n"));
        assert!(!encoded.ends_with(b"\n\n"));
        assert_eq!(encoded, {
            let mut expected = serde_json::to_vec_pretty(&record).unwrap();
            expected.push(b'\n');
            expected
        });
        assert_eq!(
            serde_json::from_slice::<DoryV3ModelCommitmentRecordV2>(&encoded).unwrap(),
            record
        );
    }

    #[test]
    fn record_v2_rejects_each_top_level_field_mutation() {
        let record = derive_fixture(&fixture()).into_record();

        let mut changed = record.clone();
        changed.record_version = 1;
        assert!(matches!(
            changed.validate(),
            Err(DoryV3ModelCommitmentRecordError::UnsupportedVersion)
        ));

        let mut changed = record.clone();
        changed.suite_digest = Digest32::new([0x81; 32]);
        assert!(matches!(
            changed.validate(),
            Err(DoryV3ModelCommitmentRecordError::SuiteDigestMismatch)
        ));

        let mut changed = record.clone();
        changed.manifest_digest = Digest32::new([0x82; 32]);
        assert!(matches!(
            changed.validate(),
            Err(DoryV3ModelCommitmentRecordError::ManifestDigestMismatch)
        ));

        let mut changed = record.clone();
        changed.model_identity_digest = Digest32::new([0x83; 32]);
        assert!(matches!(
            changed.validate(),
            Err(DoryV3ModelCommitmentRecordError::ModelIdentityDigestMismatch)
        ));

        let mut changed = record.clone();
        changed.setup_identity = Digest32::new([0x84; 32]);
        assert!(matches!(
            changed.validate(),
            Err(DoryV3ModelCommitmentRecordError::SetupIdentityMismatch)
        ));

        let mut changed = record.clone();
        changed.padded_variables += 1;
        assert!(matches!(
            changed.validate(),
            Err(DoryV3ModelCommitmentRecordError::PaddedVariablesMismatch)
        ));

        let mut changed = record.clone();
        changed.commitment_root = Digest32::new([0x85; 32]);
        assert!(matches!(
            changed.validate(),
            Err(DoryV3ModelCommitmentRecordError::CommitmentRootMismatch)
        ));

        let mut changed = record;
        changed.record_digest = Digest32::new([0x86; 32]);
        assert!(matches!(
            changed.validate(),
            Err(DoryV3ModelCommitmentRecordError::RecordDigestMismatch)
        ));
    }

    #[test]
    fn record_v2_every_canonical_field_changes_the_digest_but_record_digest_is_excluded() {
        let record = derive_fixture(&fixture()).into_record();
        let expected = record.canonical_digest();
        let mut variants = Vec::new();

        let mut changed = record.clone();
        changed.record_version += 1;
        variants.push(changed);
        let mut changed = record.clone();
        changed.suite_digest = Digest32::new([0x91; 32]);
        variants.push(changed);
        let mut changed = record.clone();
        changed.manifest_digest = Digest32::new([0x92; 32]);
        variants.push(changed);
        let mut changed = record.clone();
        changed.model_identity_digest = Digest32::new([0x93; 32]);
        variants.push(changed);
        let mut changed = record.clone();
        changed.setup_identity = Digest32::new([0x94; 32]);
        variants.push(changed);
        let mut changed = record.clone();
        changed.padded_variables += 1;
        variants.push(changed);
        let mut changed = record.clone();
        changed.commitment_root = Digest32::new([0x95; 32]);
        variants.push(changed);

        assert!(
            variants
                .iter()
                .all(|changed| changed.canonical_digest() != expected)
        );
        let mut changed_record_digest = record;
        changed_record_digest.record_digest = Digest32::new([0x96; 32]);
        assert_eq!(changed_record_digest.canonical_digest(), expected);
        assert!(serde_json::to_vec(&changed_record_digest).is_err());
    }

    #[test]
    fn record_v2_rejects_wrong_or_reordered_individual_commitments() {
        let correct = fixture();
        let actual_base = correct.identity.base_input_commitment();
        let actual_weights = correct.identity.weight_bank_commitments();

        let swapped_base = fixture_with_commitments(
            correct.setup.clone(),
            actual_weights[0],
            vec![actual_base, actual_weights[1], actual_weights[2]],
            LAYERS_PER_BANK,
            SUITE_DIGEST,
        );
        assert!(matches!(
            derive_bank_authenticated_record_v2(
                Cursor::new(&swapped_base.bytes),
                &swapped_base.manifest,
                &swapped_base.identity,
                &swapped_base.setup,
            ),
            Err(DoryV3ModelCommitmentRecordError::DerivedCommitmentMismatch { role: 0 })
        ));

        let reordered_weights = fixture_with_commitments(
            correct.setup.clone(),
            actual_base,
            vec![actual_weights[1], actual_weights[0], actual_weights[2]],
            LAYERS_PER_BANK,
            SUITE_DIGEST,
        );
        assert!(matches!(
            derive_bank_authenticated_record_v2(
                Cursor::new(&reordered_weights.bytes),
                &reordered_weights.manifest,
                &reordered_weights.identity,
                &reordered_weights.setup,
            ),
            Err(DoryV3ModelCommitmentRecordError::DerivedCommitmentMismatch { role: 1 })
        ));

        let alternate_third =
            commit_bytes(&[140, 141, 142, 143, 144, 145, 146, 147], &correct.setup);
        let wrong_third = fixture_with_commitments(
            correct.setup,
            actual_base,
            vec![actual_weights[0], actual_weights[1], alternate_third],
            LAYERS_PER_BANK,
            SUITE_DIGEST,
        );
        assert!(matches!(
            derive_bank_authenticated_record_v2(
                Cursor::new(&wrong_third.bytes),
                &wrong_third.manifest,
                &wrong_third.identity,
                &wrong_third.setup,
            ),
            Err(DoryV3ModelCommitmentRecordError::DerivedCommitmentMismatch { role: 3 })
        ));
    }

    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("injected read failure"))
        }
    }

    #[test]
    fn record_v2_rejects_corruption_truncation_trailing_bytes_and_io_failure() {
        let fixture = fixture();

        let mut corrupt = fixture.bytes.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(derive_with_reader(&fixture, Cursor::new(corrupt)).is_err());
        assert!(
            derive_with_reader(
                &fixture,
                Cursor::new(&fixture.bytes[..fixture.bytes.len() - 1])
            )
            .is_err()
        );
        let mut trailing = fixture.bytes.clone();
        trailing.push(0);
        assert!(derive_with_reader(&fixture, Cursor::new(trailing)).is_err());
        assert!(derive_with_reader(&fixture, FailingReader).is_err());
    }

    struct CountingReader<'a> {
        inner: Cursor<&'a [u8]>,
        reads: Cell<usize>,
    }

    impl<'a> CountingReader<'a> {
        fn new(bytes: &'a [u8]) -> Self {
            Self {
                inner: Cursor::new(bytes),
                reads: Cell::new(0),
            }
        }
    }

    impl Read for CountingReader<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.reads.set(self.reads.get() + 1);
            self.inner.read(buffer)
        }
    }

    #[test]
    fn record_v2_rejects_setup_or_layout_mismatch_before_reading() {
        let fixture = fixture();
        let wrong_setup = deterministic_bls_dory_setup(VARIABLES - 1).unwrap();
        let mut setup_reader = CountingReader::new(&fixture.bytes);
        assert!(
            derive_bank_authenticated_record_v2(
                &mut setup_reader,
                &fixture.manifest,
                &fixture.identity,
                &wrong_setup,
            )
            .is_err()
        );
        assert_eq!(setup_reader.reads.get(), 0);

        let mut identity_json = serde_json::to_value(&fixture.identity).unwrap();
        identity_json["layers_per_bank"] = Value::from(1);
        let wrong_layout: DoryV3ModelIdentityV1 = serde_json::from_value(identity_json).unwrap();
        let mut layout_reader = CountingReader::new(&fixture.bytes);
        assert!(
            derive_bank_authenticated_record_v2(
                &mut layout_reader,
                &fixture.manifest,
                &wrong_layout,
                &fixture.setup,
            )
            .is_err()
        );
        assert_eq!(layout_reader.reads.get(), 0);
    }

    #[test]
    fn record_v2_json_rejects_unknown_duplicate_uppercase_and_nested_unknown_fields() {
        let record = derive_fixture(&fixture()).into_record();
        let encoded = serde_json::to_string_pretty(&record).unwrap();
        let decoded: DoryV3ModelCommitmentRecordV2 = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, record);

        let parsed: Value = serde_json::from_str(&encoded).unwrap();
        for path in ["record", "manifest", "model_identity"] {
            let mut changed = parsed.clone();
            let object = match path {
                "record" => changed.as_object_mut().unwrap(),
                nested => changed[nested].as_object_mut().unwrap(),
            };
            object.insert("unknown_v3_field".into(), Value::Bool(true));
            assert!(serde_json::from_value::<DoryV3ModelCommitmentRecordV2>(changed).is_err());
        }

        let duplicate = encoded.replacen(
            "  \"record_version\": 2,",
            "  \"record_version\": 2,\n  \"record_version\": 2,",
            1,
        );
        assert!(serde_json::from_str::<DoryV3ModelCommitmentRecordV2>(&duplicate).is_err());

        let mut uppercase = parsed.clone();
        let mut digest = uppercase["suite_digest"].as_str().unwrap().to_owned();
        digest.replace_range(0..1, "A");
        uppercase["suite_digest"] = Value::String(digest);
        assert!(serde_json::from_value::<DoryV3ModelCommitmentRecordV2>(uppercase).is_err());

        let mut noncanonical_gt = parsed;
        let encoded_gt = noncanonical_gt["model_identity"]["base_input_commitment"]
            .as_str()
            .unwrap()
            .to_owned();
        noncanonical_gt["model_identity"]["base_input_commitment"] =
            Value::String(encoded_gt.to_uppercase());
        assert!(serde_json::from_value::<DoryV3ModelCommitmentRecordV2>(noncanonical_gt).is_err());
    }

    #[test]
    fn record_v2_rejects_nested_commitment_reordering_and_v1_codec_confusion() {
        let record = derive_fixture(&fixture()).into_record();
        let mut encoded = serde_json::to_value(&record).unwrap();
        encoded["model_identity"]["weight_bank_commitments"]
            .as_array_mut()
            .unwrap()
            .swap(0, 1);
        assert!(serde_json::from_value::<DoryV3ModelCommitmentRecordV2>(encoded).is_err());

        assert!(
            serde_json::from_value::<
                crate::dory_bls12_381_model_commitment::BlsDoryModelCommitmentRecord,
            >(serde_json::to_value(record).unwrap())
            .is_err()
        );
    }

    #[test]
    fn record_v2_rejects_record_v1_downgrade() {
        let record = derive_fixture(&fixture()).into_record();
        let mut encoded = serde_json::to_value(record).unwrap();
        encoded["record_version"] = Value::from(1);
        assert!(serde_json::from_value::<DoryV3ModelCommitmentRecordV2>(encoded).is_err());
    }

    #[test]
    #[ignore = "release-only: requires finalized production bank, pinned record, and n=33 setup"]
    fn record_v2_production_n33_two_pass_reproduction() {
        let bank_path = PathBuf::from(
            std::env::var_os("CMFD_DORY_V3_MODEL_BANK_PATH")
                .expect("CMFD_DORY_V3_MODEL_BANK_PATH is required"),
        );
        let record_path = PathBuf::from(
            std::env::var_os("CMFD_DORY_V3_MODEL_RECORD_PATH")
                .expect("CMFD_DORY_V3_MODEL_RECORD_PATH is required"),
        );
        let pinned: DoryV3ModelCommitmentRecordV2 =
            serde_json::from_reader(File::open(record_path).unwrap()).unwrap();
        let setup = deterministic_bls_dory_setup(DORY_V3_PADDED_VARIABLES as usize).unwrap();
        let structural = pinned
            .model_identity()
            .validate_production_structure(pinned.manifest(), &setup)
            .unwrap();
        let first_authenticated = derive_bank_authenticated_dory_v3_model_commitment_record_v2(
            File::open(&bank_path).unwrap(),
            &structural,
            &setup,
        )
        .unwrap();
        let first = first_authenticated.record().clone();
        let second = derive_bank_authenticated_dory_v3_model_commitment_record_v2(
            File::open(bank_path).unwrap(),
            &structural,
            &setup,
        )
        .unwrap()
        .into_record();
        assert_eq!(first, second);
        assert_eq!(first, pinned);

        #[cfg(feature = "whir-prototype")]
        {
            let network_id = [0x31; 32];
            let transcript = DoryV3TranscriptContext::from_bank_authenticated_record(
                network_id,
                &first_authenticated,
            )
            .unwrap();
            let block = BlockChallenge {
                network_id,
                previous_block: [0x32; 32],
                transaction_root: [0x33; 32],
                height: 34,
                timestamp: 35,
                target: [0xff; 32],
            };
            let challenge = transcript.challenge_context(&block, 36).unwrap();
            let typed = BlsDoryV3ExecutionAccumulatorArtifactContext::from_challenge(
                challenge,
                &first_authenticated,
                &setup,
            )
            .unwrap();
            assert_eq!(typed.raw_for_test().network_identity(), network_id);
            assert_eq!(
                typed.raw_for_test().model_record_identity(),
                first.record_digest().into_bytes()
            );
            assert_eq!(typed.raw_for_test().setup_identity(), setup.identity());
            assert_eq!(
                typed.raw_for_test().challenge_identity(),
                challenge.digest()
            );
        }
    }
}
