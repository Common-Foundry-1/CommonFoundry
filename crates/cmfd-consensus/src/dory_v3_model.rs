//! Dory-native fixed-model identity for the non-consensus V3 proof candidate.
//!
//! This identity deliberately does not admit a conversion from the legacy
//! `ModelPcsIdentity`. It hash-commits caller-supplied model roots, the
//! deterministic BLS12-381 Dory setup identity, and the complete ordered set
//! of supplied Dory target-group commitments. Structural validation alone does
//! not authenticate model-bank bytes or prove that the commitments were
//! derived from them; the transactional Record V2 path must do both before
//! publication. The model-bank manifest retains its generic PCS fields, but a
//! V3 identity requires those fields to contain this module's suite digest and
//! Dory commitment root.

use std::{fmt, io::Cursor};

use blake3::Hasher;
use dory_pcs::primitives::{
    DoryDeserialize, DorySerialize, arithmetic::Group, serialization::Valid as DoryValid,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _, ser::Error as _};
use thiserror::Error;

use crate::{
    ModelBankError, ModelBankManifest,
    dory_bls12_381_prototype::{
        BlsDoryGt, DeterministicBlsDorySetup, MAX_BLS_DORY_SETUP_VARIABLES,
    },
    dory_v3_suite::{
        DORY_V3_BANKS, DORY_V3_BATCH, DORY_V3_DIMENSION, DORY_V3_GT_CANONICAL_BYTES,
        DORY_V3_LAYERS, DORY_V3_LAYERS_PER_BANK, DORY_V3_MODEL_COMMITMENT_ROOT_DOMAIN,
        DORY_V3_MODEL_IDENTITY_DOMAIN, DORY_V3_MODEL_IDENTITY_VERSION, DORY_V3_MODEL_VERSION,
        DORY_V3_PADDED_VARIABLES, DORY_V3_PRODUCTION_SUITE_MANIFEST,
        DoryV3ConsensusSuiteManifestV1, DoryV3SuiteError,
    },
};

const BASE_INPUT_ROLE: u16 = 0;
pub const DORY_V3_GT_CANONICAL_ENCODING: &str = "validated canonical compressed BLS12-381 pairing-target encoding; exact decode, subgroup check, full consumption, byte-identical re-encode";
pub const DORY_V3_FIXED_ROLE_ORDER: &str =
    "0=base_input,1=weight_bank_0,2=weight_bank_1,3=weight_bank_2";
pub const DORY_V3_COMMITMENT_ROOT_FIELDS: &str = "identity_version_u16le,suite_digest[32],setup_identity[32],padded_variables_u32le,role_count_u16le,then for each fixed role in order: role_tag_u16le,commitment_length_u32le=576,commitment[576]";
pub const DORY_V3_IDENTITY_FIELDS: &str = "identity_version_u16le,suite_digest[32],model_version_u32le,batch_u32le,dimension_u32le,layers_per_bank_u32le,bank_count_u32le,model_byte_root[32],layer_roots_aggregate[32],setup_identity[32],padded_variables_u32le,commitment_root[32]";
pub const DORY_V3_MODEL_BANK_HEADER_INTERPRETATION: &str = "pcs_parameter_digest[32] must equal the Dory V3 suite digest; pcs_commitment_root[32] must equal the ordered Dory V3 commitment root";

/// A validated BLS12-381 target-group element serialized as canonical lowercase
/// compressed hexadecimal in human-readable formats.
///
/// The wrapper owns the actual group element. Decoding checks the exact fixed
/// width, validates the group element, consumes the complete input, and then
/// requires byte-for-byte canonical re-encoding.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CanonicalBlsDoryGtHex(BlsDoryGt);

impl CanonicalBlsDoryGtHex {
    /// Validate and wrap one in-memory target-group element.
    pub fn from_commitment(commitment: BlsDoryGt) -> Result<Self, DoryV3ModelIdentityError> {
        validate_backend_commitment_width()?;
        DoryValid::check(&commitment).map_err(|error| {
            DoryV3ModelIdentityError::CommitmentSerialization(error.to_string())
        })?;
        if commitment == BlsDoryGt::identity() {
            return Err(DoryV3ModelIdentityError::TargetGroupIdentity);
        }
        let wrapped = Self(commitment);
        let encoded = wrapped.canonical_bytes()?;
        let decoded = decode_canonical_commitment(&encoded)?;
        if decoded != commitment {
            return Err(DoryV3ModelIdentityError::NonCanonicalCommitmentEncoding);
        }
        Ok(wrapped)
    }

    /// Parse exact lowercase canonical compressed hexadecimal.
    pub fn from_hex(encoded: &str) -> Result<Self, DoryV3ModelIdentityError> {
        validate_backend_commitment_width()?;
        let expected_hex_len = canonical_commitment_bytes()
            .checked_mul(2)
            .ok_or(DoryV3ModelIdentityError::SizeOverflow)?;
        if encoded.len() != expected_hex_len
            || !encoded
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        {
            return Err(DoryV3ModelIdentityError::NonCanonicalCommitmentEncoding);
        }
        let bytes = hex::decode(encoded)
            .map_err(|_| DoryV3ModelIdentityError::NonCanonicalCommitmentEncoding)?;
        let commitment = Self::from_commitment(decode_canonical_commitment(&bytes)?)?;
        if commitment.to_hex()? != encoded {
            return Err(DoryV3ModelIdentityError::NonCanonicalCommitmentEncoding);
        }
        Ok(commitment)
    }

    /// Return the underlying validated group element.
    #[must_use]
    pub const fn commitment(&self) -> BlsDoryGt {
        self.0
    }

    /// Return the exact canonical compressed bytes committed by V3 transcripts.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, DoryV3ModelIdentityError> {
        validate_backend_commitment_width()?;
        DoryValid::check(&self.0).map_err(|error| {
            DoryV3ModelIdentityError::CommitmentSerialization(error.to_string())
        })?;
        if self.0 == BlsDoryGt::identity() {
            return Err(DoryV3ModelIdentityError::TargetGroupIdentity);
        }
        let expected = canonical_commitment_bytes();
        let mut encoded = Vec::with_capacity(expected);
        self.0.serialize_compressed(&mut encoded).map_err(|error| {
            DoryV3ModelIdentityError::CommitmentSerialization(error.to_string())
        })?;
        if encoded.len() != expected || decode_canonical_commitment(&encoded)? != self.0 {
            return Err(DoryV3ModelIdentityError::NonCanonicalCommitmentEncoding);
        }
        Ok(encoded)
    }

    /// Return exact lowercase canonical compressed hexadecimal.
    pub fn to_hex(&self) -> Result<String, DoryV3ModelIdentityError> {
        Ok(hex::encode(self.canonical_bytes()?))
    }
}

impl fmt::Debug for CanonicalBlsDoryGtHex {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.to_hex() {
            Ok(encoded) => formatter
                .debug_tuple("CanonicalBlsDoryGtHex")
                .field(&encoded)
                .finish(),
            Err(_) => formatter
                .debug_tuple("CanonicalBlsDoryGtHex")
                .field(&"<invalid>")
                .finish(),
        }
    }
}

impl Serialize for CanonicalBlsDoryGtHex {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex().map_err(S::Error::custom)?)
    }
}

impl<'de> Deserialize<'de> for CanonicalBlsDoryGtHex {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        Self::from_hex(&encoded).map_err(D::Error::custom)
    }
}

/// Complete Dory-native identity of one canonical V3 model artifact.
///
/// Fields are private so invalid identities cannot be constructed or mutated
/// through the safe public API. Serialization and deserialization both run the
/// complete fixture-safe validation path. Production ceremony code must first
/// call [`Self::validate_production_structure`] and then authenticate the model
/// bank transactionally before publishing any record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DoryV3ModelIdentityV1 {
    identity_version: u16,
    model_version: u32,
    batch: u32,
    dimension: u32,
    layers_per_bank: u32,
    model_byte_root: [u8; 32],
    layer_roots_aggregate: [u8; 32],
    suite_parameter_digest: [u8; 32],
    setup_identity: [u8; 32],
    padded_variables: u32,
    base_input_commitment: CanonicalBlsDoryGtHex,
    weight_bank_commitments: Vec<CanonicalBlsDoryGtHex>,
}

/// Opaque evidence that one identity, manifest, deterministic setup, and the
/// exact compiled suite passed every structural production check together.
///
/// The capability is intentionally not serializable and has no public
/// constructor. It does not read or authenticate model-bank bytes, prove that
/// the four commitments were derived from those bytes, authorize consensus or
/// candidate acceptance, or permit record publication. It may only feed the
/// record-V2 transactional derivation that authenticates one reader through
/// exact EOF, rederives every commitment, and compares them individually.
#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StructurallyValidatedProductionDoryV3ModelIdentity {
    identity: DoryV3ModelIdentityV1,
    manifest: ModelBankManifest,
    identity_digest: [u8; 32],
    manifest_digest: [u8; 32],
    commitment_root: [u8; 32],
}

impl StructurallyValidatedProductionDoryV3ModelIdentity {
    pub const fn identity(&self) -> &DoryV3ModelIdentityV1 {
        &self.identity
    }

    pub const fn manifest(&self) -> &ModelBankManifest {
        &self.manifest
    }

    pub const fn identity_digest(&self) -> [u8; 32] {
        self.identity_digest
    }

    pub const fn manifest_digest(&self) -> [u8; 32] {
        self.manifest_digest
    }

    pub const fn commitment_root(&self) -> [u8; 32] {
        self.commitment_root
    }
}

impl DoryV3ModelIdentityV1 {
    /// Construct a structural identity for the exact compiled production suite
    /// from supplied model roots, Dory commitments, and one validated setup.
    ///
    /// This constructor validates shape, encodings, setup identity, and role
    /// order. It does not read a model bank or prove that the supplied roots and
    /// commitments were derived from the same bytes; Record V2 derivation must
    /// authenticate and rederive them transactionally.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        suite: &DoryV3ConsensusSuiteManifestV1,
        model_version: u32,
        batch: u32,
        dimension: u32,
        layers_per_bank: u32,
        model_byte_root: [u8; 32],
        layer_roots_aggregate: [u8; 32],
        padded_variables: u32,
        setup: &DeterministicBlsDorySetup,
        base_input_commitment: BlsDoryGt,
        weight_bank_commitments: Vec<BlsDoryGt>,
    ) -> Result<Self, DoryV3ModelIdentityError> {
        suite
            .validate()
            .map_err(DoryV3ModelIdentityError::InvalidSuite)?;
        setup
            .validate()
            .map_err(|_| DoryV3ModelIdentityError::InvalidSetup)?;
        if usize::try_from(padded_variables).ok() != Some(setup.max_log_n()) {
            return Err(DoryV3ModelIdentityError::SetupMismatch);
        }
        let setup_identity = setup.identity();
        let identity = Self {
            identity_version: DORY_V3_MODEL_IDENTITY_VERSION,
            model_version,
            batch,
            dimension,
            layers_per_bank,
            model_byte_root,
            layer_roots_aggregate,
            suite_parameter_digest: suite.digest().into_bytes(),
            setup_identity,
            padded_variables,
            base_input_commitment: CanonicalBlsDoryGtHex::from_commitment(base_input_commitment)?,
            weight_bank_commitments: weight_bank_commitments
                .into_iter()
                .map(CanonicalBlsDoryGtHex::from_commitment)
                .collect::<Result<Vec<_>, _>>()?,
        };
        identity.validate_with_suite(suite)?;
        identity.validate_with_setup(setup)?;
        Ok(identity)
    }

    #[must_use]
    pub const fn identity_version(&self) -> u16 {
        self.identity_version
    }

    #[must_use]
    pub const fn model_version(&self) -> u32 {
        self.model_version
    }

    #[must_use]
    pub const fn batch(&self) -> u32 {
        self.batch
    }

    #[must_use]
    pub const fn dimension(&self) -> u32 {
        self.dimension
    }

    #[must_use]
    pub const fn layers_per_bank(&self) -> u32 {
        self.layers_per_bank
    }

    #[must_use]
    pub const fn model_byte_root(&self) -> [u8; 32] {
        self.model_byte_root
    }

    #[must_use]
    pub const fn layer_roots_aggregate(&self) -> [u8; 32] {
        self.layer_roots_aggregate
    }

    #[must_use]
    pub const fn suite_parameter_digest(&self) -> [u8; 32] {
        self.suite_parameter_digest
    }

    #[must_use]
    pub const fn setup_identity(&self) -> [u8; 32] {
        self.setup_identity
    }

    #[must_use]
    pub const fn padded_variables(&self) -> u32 {
        self.padded_variables
    }

    #[must_use]
    pub const fn base_input_commitment(&self) -> BlsDoryGt {
        self.base_input_commitment.commitment()
    }

    #[must_use]
    pub fn weight_bank_commitments(&self) -> Vec<BlsDoryGt> {
        self.weight_bank_commitments
            .iter()
            .map(CanonicalBlsDoryGtHex::commitment)
            .collect()
    }

    #[must_use]
    pub fn encoded_base_input_commitment(&self) -> &CanonicalBlsDoryGtHex {
        &self.base_input_commitment
    }

    #[must_use]
    pub fn encoded_weight_bank_commitments(&self) -> &[CanonicalBlsDoryGtHex] {
        &self.weight_bank_commitments
    }

    /// Number of ordered weight-bank roles.
    pub fn weight_bank_count(&self) -> Result<u32, DoryV3ModelIdentityError> {
        u32::try_from(self.weight_bank_commitments.len())
            .map_err(|_| DoryV3ModelIdentityError::InvalidBankCount)
    }

    /// Total layer count implied by the canonical bank partition.
    pub fn total_layers(&self) -> Result<u32, DoryV3ModelIdentityError> {
        self.layers_per_bank
            .checked_mul(self.weight_bank_count()?)
            .ok_or(DoryV3ModelIdentityError::SizeOverflow)
    }

    /// Validate all fixture-safe identity invariants without trusting an
    /// external setup or manifest.
    pub fn validate(&self) -> Result<(), DoryV3ModelIdentityError> {
        if self.identity_version != DORY_V3_MODEL_IDENTITY_VERSION {
            return Err(DoryV3ModelIdentityError::UnsupportedVersion);
        }
        if self.model_version == 0 {
            return Err(DoryV3ModelIdentityError::InvalidModelVersion);
        }
        if self.batch == 0
            || self.dimension == 0
            || self.layers_per_bank == 0
            || !self.batch.is_power_of_two()
            || !self.dimension.is_power_of_two()
            || !self.layers_per_bank.is_power_of_two()
        {
            return Err(DoryV3ModelIdentityError::InvalidGeometry);
        }
        let bank_count = self.weight_bank_count()?;
        if bank_count == 0 || bank_count > DORY_V3_BANKS {
            return Err(DoryV3ModelIdentityError::InvalidBankCount);
        }
        self.total_layers()?;
        if self.model_byte_root == [0; 32] {
            return Err(DoryV3ModelIdentityError::UnspecifiedModelRoot);
        }
        if self.layer_roots_aggregate == [0; 32] {
            return Err(DoryV3ModelIdentityError::UnspecifiedLayerRootsAggregate);
        }
        if self.setup_identity == [0; 32] {
            return Err(DoryV3ModelIdentityError::UnspecifiedSetup);
        }
        let maximum_variables = u32::try_from(MAX_BLS_DORY_SETUP_VARIABLES)
            .map_err(|_| DoryV3ModelIdentityError::SizeOverflow)?;
        if self.padded_variables == 0 || self.padded_variables > maximum_variables {
            return Err(DoryV3ModelIdentityError::InvalidPaddedVariables);
        }
        let padded_elements = 1_u64
            .checked_shl(self.padded_variables)
            .ok_or(DoryV3ModelIdentityError::SizeOverflow)?;
        let dimension = u64::from(self.dimension);
        let base_elements = u64::from(self.batch)
            .checked_mul(dimension)
            .ok_or(DoryV3ModelIdentityError::SizeOverflow)?;
        let weight_elements = u64::from(self.layers_per_bank)
            .checked_mul(dimension)
            .and_then(|elements| elements.checked_mul(dimension))
            .ok_or(DoryV3ModelIdentityError::SizeOverflow)?;
        if !base_elements.is_power_of_two()
            || !weight_elements.is_power_of_two()
            || base_elements > padded_elements
            || weight_elements > padded_elements
        {
            return Err(DoryV3ModelIdentityError::InvalidGeometry);
        }
        if self.suite_parameter_digest == [0; 32] {
            return Err(DoryV3ModelIdentityError::UnspecifiedSuite);
        }

        let identity = BlsDoryGt::identity();
        if self.base_input_commitment.commitment() == identity {
            return Err(DoryV3ModelIdentityError::IdentityCommitment { role: 0 });
        }
        self.base_input_commitment.canonical_bytes()?;
        for (index, commitment) in self.weight_bank_commitments.iter().enumerate() {
            let role =
                u32::try_from(index + 1).map_err(|_| DoryV3ModelIdentityError::InvalidBankCount)?;
            if commitment.commitment() == identity {
                return Err(DoryV3ModelIdentityError::IdentityCommitment { role });
            }
            commitment.canonical_bytes()?;
            if commitment == &self.base_input_commitment {
                return Err(DoryV3ModelIdentityError::DuplicateCommitment {
                    first_role: 0,
                    second_role: role,
                });
            }
            if let Some(first) = self.weight_bank_commitments[..index]
                .iter()
                .position(|prior| prior == commitment)
            {
                return Err(DoryV3ModelIdentityError::DuplicateCommitment {
                    first_role: u32::try_from(first + 1)
                        .map_err(|_| DoryV3ModelIdentityError::InvalidBankCount)?,
                    second_role: role,
                });
            }
        }
        Ok(())
    }

    /// Validate that this identity names exactly the supplied V3 suite.
    ///
    /// This comparison intentionally does not require the production suite,
    /// so bounded fixtures can exercise the identity codec. Production callers
    /// must use [`Self::validate_production_structure`], which validates the
    /// compiled production suite itself but does not authenticate bank bytes.
    fn validate_with_suite(
        &self,
        suite: &DoryV3ConsensusSuiteManifestV1,
    ) -> Result<(), DoryV3ModelIdentityError> {
        self.validate()?;
        if self.suite_parameter_digest != suite.digest().into_bytes() {
            return Err(DoryV3ModelIdentityError::SuiteParameterDigestMismatch);
        }
        if suite.model_identity_version != self.identity_version
            || suite.model_version != self.model_version
            || suite.batch != self.batch
            || suite.dimension != self.dimension
            || suite.layers_per_bank != self.layers_per_bank
            || suite.banks != self.weight_bank_count()?
            || suite.layers != self.total_layers()?
            || suite.padded_variables != self.padded_variables
            || suite.setup_identity.into_bytes() != self.setup_identity
        {
            return Err(DoryV3ModelIdentityError::SuiteContextMismatch);
        }
        Ok(())
    }

    /// Validate the retained setup identity and exact padding geometry.
    fn validate_with_setup(
        &self,
        setup: &DeterministicBlsDorySetup,
    ) -> Result<(), DoryV3ModelIdentityError> {
        self.validate()?;
        setup
            .validate()
            .map_err(|_| DoryV3ModelIdentityError::InvalidSetup)?;
        if self.setup_identity != setup.identity()
            || usize::try_from(self.padded_variables).ok() != Some(setup.max_log_n())
        {
            return Err(DoryV3ModelIdentityError::SetupMismatch);
        }
        Ok(())
    }

    /// Validate the exact production V3 model shape without constructing the
    /// expensive n=33 deterministic setup.
    fn validate_production_shape(&self) -> Result<(), DoryV3ModelIdentityError> {
        self.validate()?;
        if self.model_version != DORY_V3_MODEL_VERSION
            || self.batch != DORY_V3_BATCH
            || self.dimension != DORY_V3_DIMENSION
            || self.layers_per_bank != DORY_V3_LAYERS_PER_BANK
            || self.weight_bank_count()? != DORY_V3_BANKS
            || self.total_layers()? != DORY_V3_LAYERS
            || self.padded_variables != DORY_V3_PADDED_VARIABLES
        {
            return Err(DoryV3ModelIdentityError::ProductionGeometry);
        }
        Ok(())
    }

    /// Validate only the structure of the production identity, setup, and
    /// model-bank manifest. This method performs no model-bank I/O.
    pub fn validate_production_structure(
        &self,
        manifest: &ModelBankManifest,
        setup: &DeterministicBlsDorySetup,
    ) -> Result<StructurallyValidatedProductionDoryV3ModelIdentity, DoryV3ModelIdentityError> {
        let suite = &*DORY_V3_PRODUCTION_SUITE_MANIFEST;
        let suite_digest = suite
            .validate()
            .map_err(DoryV3ModelIdentityError::InvalidSuite)?;
        self.validate_production_shape()?;
        self.validate_with_suite(suite)?;
        self.validate_with_setup(setup)?;
        if self.suite_parameter_digest != suite_digest.into_bytes()
            || self.setup_identity != suite.setup_identity.into_bytes()
        {
            return Err(DoryV3ModelIdentityError::ProductionSuiteMismatch);
        }
        self.verify_manifest(manifest)?;
        let identity_digest = self.digest()?;
        let manifest_digest = manifest
            .digest()
            .map_err(DoryV3ModelIdentityError::InvalidManifest)?;
        let commitment_root = self.commitment_root()?;
        Ok(StructurallyValidatedProductionDoryV3ModelIdentity {
            identity: self.clone(),
            manifest: *manifest,
            identity_digest,
            manifest_digest,
            commitment_root,
        })
    }

    /// Domain-separated root of the full canonical base commitment followed by
    /// every ordered canonical weight-bank commitment.
    pub fn commitment_root(&self) -> Result<[u8; 32], DoryV3ModelIdentityError> {
        self.validate()?;
        let role_count = self
            .weight_bank_count()?
            .checked_add(1)
            .and_then(|count| u16::try_from(count).ok())
            .ok_or(DoryV3ModelIdentityError::InvalidBankCount)?;
        let commitment_bytes = DORY_V3_GT_CANONICAL_BYTES;
        let mut hasher = Hasher::new_derive_key(DORY_V3_MODEL_COMMITMENT_ROOT_DOMAIN);
        hasher.update(&self.identity_version.to_le_bytes());
        hasher.update(&self.suite_parameter_digest);
        hasher.update(&self.setup_identity);
        hasher.update(&self.padded_variables.to_le_bytes());
        hasher.update(&role_count.to_le_bytes());
        hasher.update(&BASE_INPUT_ROLE.to_le_bytes());
        hasher.update(&commitment_bytes.to_le_bytes());
        hasher.update(&self.base_input_commitment.canonical_bytes()?);
        for (index, commitment) in self.weight_bank_commitments.iter().enumerate() {
            let role =
                u16::try_from(index + 1).map_err(|_| DoryV3ModelIdentityError::InvalidBankCount)?;
            hasher.update(&role.to_le_bytes());
            hasher.update(&commitment_bytes.to_le_bytes());
            hasher.update(&commitment.canonical_bytes()?);
        }
        let root = *hasher.finalize().as_bytes();
        if root == [0; 32] {
            return Err(DoryV3ModelIdentityError::UnspecifiedCommitmentRoot);
        }
        Ok(root)
    }

    /// Canonical digest of every model, setup, geometry, suite, and commitment
    /// field used by the Dory V3 candidate.
    pub fn digest(&self) -> Result<[u8; 32], DoryV3ModelIdentityError> {
        self.validate()?;
        let bank_count = self.weight_bank_count()?;
        let mut hasher = Hasher::new_derive_key(DORY_V3_MODEL_IDENTITY_DOMAIN);
        hasher.update(&self.identity_version.to_le_bytes());
        hasher.update(&self.suite_parameter_digest);
        hasher.update(&self.model_version.to_le_bytes());
        hasher.update(&self.batch.to_le_bytes());
        hasher.update(&self.dimension.to_le_bytes());
        hasher.update(&self.layers_per_bank.to_le_bytes());
        hasher.update(&bank_count.to_le_bytes());
        hasher.update(&self.model_byte_root);
        hasher.update(&self.layer_roots_aggregate);
        hasher.update(&self.setup_identity);
        hasher.update(&self.padded_variables.to_le_bytes());
        hasher.update(&self.commitment_root()?);
        Ok(*hasher.finalize().as_bytes())
    }

    /// Require the generic model-bank PCS fields to carry this exact Dory suite
    /// and commitment root, in addition to matching the model bytes and shape.
    pub(crate) fn verify_manifest(
        &self,
        manifest: &ModelBankManifest,
    ) -> Result<(), DoryV3ModelIdentityError> {
        self.validate()?;
        manifest
            .digest()
            .map_err(DoryV3ModelIdentityError::InvalidManifest)?;
        if manifest.model_version != self.model_version
            || manifest.batch != self.batch
            || manifest.dimension != self.dimension
            || manifest.layers != self.total_layers()?
        {
            return Err(DoryV3ModelIdentityError::ManifestGeometryMismatch);
        }
        if manifest.raw_blake3_root != self.model_byte_root {
            return Err(DoryV3ModelIdentityError::ManifestModelRootMismatch);
        }
        if manifest.layer_roots_aggregate != self.layer_roots_aggregate {
            return Err(DoryV3ModelIdentityError::ManifestLayerRootsMismatch);
        }
        if manifest.pcs_parameter_digest != self.suite_parameter_digest {
            return Err(DoryV3ModelIdentityError::ManifestSuiteMismatch);
        }
        if manifest.pcs_commitment_root != self.commitment_root()? {
            return Err(DoryV3ModelIdentityError::ManifestCommitmentRootMismatch);
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct DoryV3ModelIdentityV1Ref<'a> {
    identity_version: u16,
    model_version: u32,
    batch: u32,
    dimension: u32,
    layers_per_bank: u32,
    model_byte_root: [u8; 32],
    layer_roots_aggregate: [u8; 32],
    suite_parameter_digest: [u8; 32],
    setup_identity: [u8; 32],
    padded_variables: u32,
    base_input_commitment: &'a CanonicalBlsDoryGtHex,
    weight_bank_commitments: &'a [CanonicalBlsDoryGtHex],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DoryV3ModelIdentityV1Owned {
    identity_version: u16,
    model_version: u32,
    batch: u32,
    dimension: u32,
    layers_per_bank: u32,
    model_byte_root: [u8; 32],
    layer_roots_aggregate: [u8; 32],
    suite_parameter_digest: [u8; 32],
    setup_identity: [u8; 32],
    padded_variables: u32,
    base_input_commitment: CanonicalBlsDoryGtHex,
    weight_bank_commitments: Vec<CanonicalBlsDoryGtHex>,
}

impl Serialize for DoryV3ModelIdentityV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.validate().map_err(S::Error::custom)?;
        DoryV3ModelIdentityV1Ref {
            identity_version: self.identity_version,
            model_version: self.model_version,
            batch: self.batch,
            dimension: self.dimension,
            layers_per_bank: self.layers_per_bank,
            model_byte_root: self.model_byte_root,
            layer_roots_aggregate: self.layer_roots_aggregate,
            suite_parameter_digest: self.suite_parameter_digest,
            setup_identity: self.setup_identity,
            padded_variables: self.padded_variables,
            base_input_commitment: &self.base_input_commitment,
            weight_bank_commitments: &self.weight_bank_commitments,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DoryV3ModelIdentityV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let decoded = DoryV3ModelIdentityV1Owned::deserialize(deserializer)?;
        let identity = Self {
            identity_version: decoded.identity_version,
            model_version: decoded.model_version,
            batch: decoded.batch,
            dimension: decoded.dimension,
            layers_per_bank: decoded.layers_per_bank,
            model_byte_root: decoded.model_byte_root,
            layer_roots_aggregate: decoded.layer_roots_aggregate,
            suite_parameter_digest: decoded.suite_parameter_digest,
            setup_identity: decoded.setup_identity,
            padded_variables: decoded.padded_variables,
            base_input_commitment: decoded.base_input_commitment,
            weight_bank_commitments: decoded.weight_bank_commitments,
        };
        identity.validate().map_err(D::Error::custom)?;
        Ok(identity)
    }
}

/// Fail-closed Dory V3 fixed-model identity errors.
#[derive(Debug, Error)]
pub enum DoryV3ModelIdentityError {
    #[error("unsupported Dory V3 model identity version")]
    UnsupportedVersion,
    #[error("Dory V3 model version must be nonzero")]
    InvalidModelVersion,
    #[error("Dory V3 model geometry is invalid")]
    InvalidGeometry,
    #[error("Dory V3 model identity must contain between one and three weight banks")]
    InvalidBankCount,
    #[error("Dory V3 padded variable count is invalid")]
    InvalidPaddedVariables,
    #[error("Dory V3 model byte root is unspecified")]
    UnspecifiedModelRoot,
    #[error("Dory V3 layer-root aggregate is unspecified")]
    UnspecifiedLayerRootsAggregate,
    #[error("Dory V3 suite identity is unspecified")]
    UnspecifiedSuite,
    #[error("Dory V3 deterministic setup identity is unspecified")]
    UnspecifiedSetup,
    #[error("Dory V3 suite parameter digest does not match the supplied suite")]
    SuiteParameterDigestMismatch,
    #[error("Dory V3 suite geometry or setup does not match the model identity")]
    SuiteContextMismatch,
    #[error("Dory V3 deterministic setup is invalid")]
    InvalidSetup,
    #[error("Dory V3 identity does not match the supplied deterministic setup")]
    SetupMismatch,
    #[error("Dory V3 commitment for role {role} is the target-group identity")]
    IdentityCommitment { role: u32 },
    #[error("Dory V3 canonical commitment cannot encode the target-group identity")]
    TargetGroupIdentity,
    #[error("Dory V3 roles {first_role} and {second_role} reuse one commitment")]
    DuplicateCommitment { first_role: u32, second_role: u32 },
    #[error("Dory V3 commitment is not exact lowercase canonical compressed GT hexadecimal")]
    NonCanonicalCommitmentEncoding,
    #[error(
        "BLS12-381 target-group codec width is {actual} bytes; Dory V3 requires {expected} bytes"
    )]
    CommitmentEncodingWidth { expected: u32, actual: usize },
    #[error("Dory V3 commitment serialization failed: {0}")]
    CommitmentSerialization(String),
    #[error("Dory V3 identity size arithmetic overflowed")]
    SizeOverflow,
    #[error("Dory V3 commitment root is unspecified")]
    UnspecifiedCommitmentRoot,
    #[error("model-bank manifest is invalid: {0}")]
    InvalidManifest(#[source] ModelBankError),
    #[error("model-bank manifest geometry does not match the Dory V3 identity")]
    ManifestGeometryMismatch,
    #[error("model-bank manifest byte root does not match the Dory V3 identity")]
    ManifestModelRootMismatch,
    #[error("model-bank manifest suite does not match the Dory V3 identity")]
    ManifestSuiteMismatch,
    #[error("model-bank manifest commitment root does not match the Dory V3 identity")]
    ManifestCommitmentRootMismatch,
    #[error("Dory V3 identity does not have the exact production geometry")]
    ProductionGeometry,
    #[error("compiled Dory V3 production suite is invalid: {0}")]
    InvalidSuite(#[source] DoryV3SuiteError),
    #[error("Dory V3 identity does not match the compiled production suite")]
    ProductionSuiteMismatch,
    #[error("model-bank manifest layer-root aggregate does not match the Dory V3 identity")]
    ManifestLayerRootsMismatch,
}

fn canonical_commitment_bytes() -> usize {
    BlsDoryGt::identity().compressed_size()
}

fn validate_backend_commitment_width() -> Result<(), DoryV3ModelIdentityError> {
    let actual = canonical_commitment_bytes();
    if u32::try_from(actual).ok() != Some(DORY_V3_GT_CANONICAL_BYTES) {
        return Err(DoryV3ModelIdentityError::CommitmentEncodingWidth {
            expected: DORY_V3_GT_CANONICAL_BYTES,
            actual,
        });
    }
    Ok(())
}

fn decode_canonical_commitment(encoded: &[u8]) -> Result<BlsDoryGt, DoryV3ModelIdentityError> {
    if encoded.len() != canonical_commitment_bytes() {
        return Err(DoryV3ModelIdentityError::NonCanonicalCommitmentEncoding);
    }
    let mut reader = Cursor::new(encoded);
    let commitment = BlsDoryGt::deserialize_compressed(&mut reader)
        .map_err(|error| DoryV3ModelIdentityError::CommitmentSerialization(error.to_string()))?;
    if reader.position() != encoded.len() as u64 {
        return Err(DoryV3ModelIdentityError::NonCanonicalCommitmentEncoding);
    }
    DoryValid::check(&commitment)
        .map_err(|error| DoryV3ModelIdentityError::CommitmentSerialization(error.to_string()))?;
    let mut reencoded = Vec::with_capacity(encoded.len());
    commitment
        .serialize_compressed(&mut reencoded)
        .map_err(|error| DoryV3ModelIdentityError::CommitmentSerialization(error.to_string()))?;
    if reencoded != encoded {
        return Err(DoryV3ModelIdentityError::NonCanonicalCommitmentEncoding);
    }
    Ok(commitment)
}

#[cfg(test)]
mod tests {
    use super::*;

    use ark_bls12_381::{Bls12_381, Fq12};
    use ark_ec::pairing::PairingOutput;
    use dory_pcs::primitives::arithmetic::Field;
    use serde_json::json;

    use crate::{
        ModelPcsIdentity, SmallModelBankFixture, build_small_model_bank,
        dory_bls12_381_prototype::{BlsDoryFr, deterministic_bls_dory_setup},
        dory_v3_suite::{Digest32, production_dory_v3_suite_manifest},
    };

    fn commitment(setup: &DeterministicBlsDorySetup, scalar: i64, row: usize) -> BlsDoryGt {
        let committed_row = setup
            .commit_row_segment(0, &[BlsDoryFr::from_i64(scalar)])
            .unwrap();
        setup.pair_committed_row(row, &committed_row).unwrap()
    }

    fn legacy_identity(model_byte_root: [u8; 32]) -> ModelPcsIdentity {
        ModelPcsIdentity {
            model_version: 2,
            batch: 2,
            dimension: 2,
            layers_per_bank: 2,
            model_byte_root,
            pcs_suite_parameter_digest: [0x51; 32],
            base_input_commitment: [0x61; 32],
            weight_bank_commitments: vec![[0x62; 32], [0x63; 32]],
        }
    }

    fn fixture() -> (
        DeterministicBlsDorySetup,
        DoryV3ConsensusSuiteManifestV1,
        DoryV3ModelIdentityV1,
        ModelBankManifest,
    ) {
        let setup = deterministic_bls_dory_setup(3).unwrap();
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
        let provisional = build_small_model_bank(SmallModelBankFixture {
            model_version: 2,
            dimension: 2,
            batch: 2,
            base_input: &base,
            layers: &layer_slices,
            pcs_parameter_digest: [0x51; 32],
            pcs_commitment_root: [0x52; 32],
        })
        .unwrap();
        let mut suite = production_dory_v3_suite_manifest();
        suite.batch = 2;
        suite.dimension = 2;
        suite.layers = 4;
        suite.banks = 2;
        suite.layers_per_bank = 2;
        suite.padded_variables = 3;
        suite.setup_identity = Digest32::new(setup.identity());
        let identity = DoryV3ModelIdentityV1 {
            identity_version: DORY_V3_MODEL_IDENTITY_VERSION,
            model_version: 2,
            batch: 2,
            dimension: 2,
            layers_per_bank: 2,
            model_byte_root: provisional.manifest.raw_blake3_root,
            layer_roots_aggregate: provisional.manifest.layer_roots_aggregate,
            suite_parameter_digest: suite.digest().into_bytes(),
            setup_identity: setup.identity(),
            padded_variables: 3,
            base_input_commitment: CanonicalBlsDoryGtHex::from_commitment(commitment(&setup, 3, 0))
                .unwrap(),
            weight_bank_commitments: vec![
                CanonicalBlsDoryGtHex::from_commitment(commitment(&setup, 5, 1)).unwrap(),
                CanonicalBlsDoryGtHex::from_commitment(commitment(&setup, 7, 2)).unwrap(),
            ],
        };
        identity.validate_with_suite(&suite).unwrap();
        identity.validate_with_setup(&setup).unwrap();
        let bank = build_small_model_bank(SmallModelBankFixture {
            model_version: 2,
            dimension: 2,
            batch: 2,
            base_input: &base,
            layers: &layer_slices,
            pcs_parameter_digest: identity.suite_parameter_digest(),
            pcs_commitment_root: identity.commitment_root().unwrap(),
        })
        .unwrap();
        (setup, suite, identity, bank.manifest)
    }

    #[test]
    fn canonical_gt_hex_roundtrip_is_fixed_width_lowercase_and_validated() {
        let (setup, _, _, _) = fixture();
        let wrapped = CanonicalBlsDoryGtHex::from_commitment(commitment(&setup, 11, 0)).unwrap();
        let encoded = wrapped.to_hex().unwrap();
        assert_eq!(
            u32::try_from(canonical_commitment_bytes()).unwrap(),
            DORY_V3_GT_CANONICAL_BYTES
        );
        assert_eq!(encoded.len(), canonical_commitment_bytes() * 2);
        assert!(
            encoded
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
        assert_eq!(CanonicalBlsDoryGtHex::from_hex(&encoded).unwrap(), wrapped);
        assert!(CanonicalBlsDoryGtHex::from_hex(&encoded.to_uppercase()).is_err());
        assert!(CanonicalBlsDoryGtHex::from_hex(&encoded[..encoded.len() - 2]).is_err());
        assert!(CanonicalBlsDoryGtHex::from_hex(&format!("{encoded}00")).is_err());

        let outside_subgroup = BlsDoryGt(PairingOutput::<Bls12_381>(Fq12::from(2_u64)));
        assert!(CanonicalBlsDoryGtHex::from_commitment(outside_subgroup).is_err());
        let mut outside_encoding = Vec::new();
        outside_subgroup
            .serialize_compressed(&mut outside_encoding)
            .unwrap();
        assert!(CanonicalBlsDoryGtHex::from_hex(&hex::encode(outside_encoding)).is_err());
    }

    #[test]
    fn identity_transcripts_have_pinned_known_answers() {
        let (_, _, identity, _) = fixture();
        assert_eq!(
            DORY_V3_PRODUCTION_SUITE_MANIFEST.digest().to_hex(),
            "6c0950d4b5dcffef9f3296f9c0718a8d5124877719b3af76b2f68b3fcb64764a"
        );
        let commitment_encoding = identity
            .encoded_base_input_commitment()
            .canonical_bytes()
            .unwrap();
        assert_eq!(
            hex::encode(blake3::hash(&commitment_encoding).as_bytes()),
            "009e7834d89fb909d57172fb786ffb48aeabc13b0936bfd27f3d4767daee16da"
        );
        assert_eq!(
            hex::encode(identity.suite_parameter_digest()),
            "daecc7170c8b45b711e6127aba276ecde387685587bb5733ca3292cdee68681c"
        );
        assert_eq!(
            hex::encode(identity.commitment_root().unwrap()),
            "36a3b3261ecf38ad0b68f6ec09c880ced0c2da693379ab1aa22e7d006d99c6c3"
        );
        assert_eq!(
            hex::encode(identity.digest().unwrap()),
            "0a0387844c2dc0d9c4d70a7f1a4b618f3ac80f05f98e0badd090ce05f2171482"
        );
    }

    #[test]
    fn strict_serde_roundtrips_and_rejects_unknown_or_noncanonical_input() {
        let (_, _, identity, _) = fixture();
        let encoded = serde_json::to_vec_pretty(&identity).unwrap();
        let decoded: DoryV3ModelIdentityV1 = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, identity);
        assert_eq!(serde_json::to_vec_pretty(&decoded).unwrap(), encoded);

        let mut unknown: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("unknown".into(), json!(1));
        assert!(serde_json::from_value::<DoryV3ModelIdentityV1>(unknown).is_err());

        let base = identity.base_input_commitment.to_hex().unwrap();
        let uppercase =
            String::from_utf8(encoded.clone())
                .unwrap()
                .replacen(&base, &base.to_uppercase(), 1);
        assert!(serde_json::from_str::<DoryV3ModelIdentityV1>(&uppercase).is_err());

        let encoded_text = String::from_utf8(encoded.clone()).unwrap();
        let duplicate = encoded_text.replacen(
            "\"identity_version\": 1,",
            "\"identity_version\": 1,\n  \"identity_version\": 1,",
            1,
        );
        assert!(serde_json::from_str::<DoryV3ModelIdentityV1>(&duplicate).is_err());

        let mut invalid = identity.clone();
        invalid.suite_parameter_digest = [0; 32];
        assert!(serde_json::to_vec(&invalid).is_err());

        let legacy = legacy_identity(identity.model_byte_root());
        legacy.validate().unwrap();
        let legacy_json = serde_json::to_vec(&legacy).unwrap();
        assert!(serde_json::from_slice::<DoryV3ModelIdentityV1>(&legacy_json).is_err());
        assert!(serde_json::from_slice::<ModelPcsIdentity>(&encoded).is_err());
    }

    #[test]
    fn identity_and_duplicate_commitments_are_rejected() {
        let (_, _, identity, _) = fixture();

        assert!(matches!(
            CanonicalBlsDoryGtHex::from_commitment(BlsDoryGt::identity()),
            Err(DoryV3ModelIdentityError::TargetGroupIdentity)
        ));
        let mut encoded_identity = Vec::new();
        BlsDoryGt::identity()
            .serialize_compressed(&mut encoded_identity)
            .unwrap();
        assert!(matches!(
            CanonicalBlsDoryGtHex::from_hex(&hex::encode(encoded_identity)),
            Err(DoryV3ModelIdentityError::TargetGroupIdentity)
        ));
        let mut target_identity = identity.clone();
        target_identity.base_input_commitment = CanonicalBlsDoryGtHex(BlsDoryGt::identity());
        assert!(matches!(
            target_identity.validate(),
            Err(DoryV3ModelIdentityError::IdentityCommitment { role: 0 })
        ));
        let mut target_identity = identity.clone();
        target_identity.weight_bank_commitments[0] = CanonicalBlsDoryGtHex(BlsDoryGt::identity());
        assert!(matches!(
            target_identity.validate(),
            Err(DoryV3ModelIdentityError::IdentityCommitment { role: 1 })
        ));

        let mut duplicate_base = identity.clone();
        duplicate_base.weight_bank_commitments[0] = duplicate_base.base_input_commitment;
        assert!(matches!(
            duplicate_base.validate(),
            Err(DoryV3ModelIdentityError::DuplicateCommitment {
                first_role: 0,
                second_role: 1
            })
        ));

        let mut duplicate_weight = identity.clone();
        duplicate_weight.weight_bank_commitments[1] = duplicate_weight.weight_bank_commitments[0];
        assert!(matches!(
            duplicate_weight.validate(),
            Err(DoryV3ModelIdentityError::DuplicateCommitment {
                first_role: 1,
                second_role: 2
            })
        ));
        assert!(serde_json::to_vec(&duplicate_weight).is_err());
    }

    #[test]
    fn commitment_order_and_every_identity_field_are_bound() {
        let (setup, _, identity, _) = fixture();
        let root = identity.commitment_root().unwrap();
        let digest = identity.digest().unwrap();

        let mut reordered = identity.clone();
        reordered.weight_bank_commitments.swap(0, 1);
        reordered.validate().unwrap();
        assert_ne!(reordered.commitment_root().unwrap(), root);
        assert_ne!(reordered.digest().unwrap(), digest);

        let mut changed_base = identity.clone();
        changed_base.base_input_commitment =
            CanonicalBlsDoryGtHex::from_commitment(commitment(&setup, 13, 0)).unwrap();
        changed_base.validate().unwrap();
        assert_ne!(changed_base.commitment_root().unwrap(), root);
        assert_ne!(changed_base.digest().unwrap(), digest);

        let mut changed_weight = identity.clone();
        changed_weight.weight_bank_commitments[0] =
            CanonicalBlsDoryGtHex::from_commitment(commitment(&setup, 13, 1)).unwrap();
        changed_weight.validate().unwrap();
        assert_ne!(changed_weight.commitment_root().unwrap(), root);
        assert_ne!(changed_weight.digest().unwrap(), digest);

        let mut fewer_banks = identity.clone();
        fewer_banks.weight_bank_commitments.pop();
        fewer_banks.validate().unwrap();
        assert_ne!(fewer_banks.commitment_root().unwrap(), root);
        assert_ne!(fewer_banks.digest().unwrap(), digest);

        let mutations: [fn(&mut DoryV3ModelIdentityV1); 9] = [
            |value| value.model_version += 1,
            |value| value.batch *= 2,
            |value| value.dimension /= 2,
            |value| value.layers_per_bank /= 2,
            |value| value.model_byte_root[0] ^= 1,
            |value| value.layer_roots_aggregate[0] ^= 1,
            |value| value.suite_parameter_digest[0] ^= 1,
            |value| value.setup_identity[0] ^= 1,
            |value| value.padded_variables += 1,
        ];
        for mutate in mutations {
            let mut changed = identity.clone();
            mutate(&mut changed);
            changed.validate().unwrap();
            assert_ne!(changed.digest().unwrap(), digest);
        }
    }

    #[test]
    fn manifest_linkage_is_exact_and_dory_native() {
        let (_, _, identity, manifest) = fixture();
        identity.verify_manifest(&manifest).unwrap();

        let mut wrong = manifest;
        wrong.pcs_parameter_digest[0] ^= 1;
        assert!(matches!(
            identity.verify_manifest(&wrong),
            Err(DoryV3ModelIdentityError::ManifestSuiteMismatch)
        ));
        let mut wrong = manifest;
        wrong.pcs_commitment_root[0] ^= 1;
        assert!(matches!(
            identity.verify_manifest(&wrong),
            Err(DoryV3ModelIdentityError::ManifestCommitmentRootMismatch)
        ));
        let mut wrong = manifest;
        wrong.raw_blake3_root[0] ^= 1;
        assert!(matches!(
            identity.verify_manifest(&wrong),
            Err(DoryV3ModelIdentityError::ManifestModelRootMismatch)
        ));
        let mut wrong = manifest;
        wrong.layer_roots_aggregate[0] ^= 1;
        assert!(matches!(
            identity.verify_manifest(&wrong),
            Err(DoryV3ModelIdentityError::ManifestLayerRootsMismatch)
        ));
        let mut wrong = manifest;
        wrong.layers -= 1;
        assert!(identity.verify_manifest(&wrong).is_err());

        let legacy = legacy_identity(identity.model_byte_root());
        let mut legacy_manifest = manifest;
        legacy_manifest.pcs_parameter_digest = legacy.pcs_suite_parameter_digest;
        legacy_manifest.pcs_commitment_root = legacy.commitment_root().unwrap();
        assert!(matches!(
            identity.verify_manifest(&legacy_manifest),
            Err(DoryV3ModelIdentityError::ManifestSuiteMismatch)
        ));
    }

    #[test]
    fn fixture_validation_is_bounded_but_production_shape_is_exact() {
        let (setup, suite, identity, manifest) = fixture();
        identity.validate().unwrap();
        identity.validate_with_suite(&suite).unwrap();
        identity.validate_with_setup(&setup).unwrap();
        assert!(matches!(
            DoryV3ModelIdentityV1::new(
                &suite,
                identity.model_version(),
                identity.batch(),
                identity.dimension(),
                identity.layers_per_bank(),
                identity.model_byte_root(),
                identity.layer_roots_aggregate(),
                identity.padded_variables(),
                &setup,
                identity.base_input_commitment(),
                identity.weight_bank_commitments(),
            ),
            Err(DoryV3ModelIdentityError::InvalidSuite(_))
        ));
        let mut wrong_suite = suite;
        wrong_suite.batch *= 2;
        assert!(matches!(
            identity.validate_with_suite(&wrong_suite),
            Err(DoryV3ModelIdentityError::SuiteParameterDigestMismatch)
        ));
        assert!(matches!(
            identity.validate_production_shape(),
            Err(DoryV3ModelIdentityError::ProductionGeometry)
        ));

        let mut production = identity.clone();
        production.model_version = 2;
        production.batch = DORY_V3_BATCH;
        production.dimension = DORY_V3_DIMENSION;
        production.layers_per_bank = DORY_V3_LAYERS_PER_BANK;
        production.padded_variables = DORY_V3_PADDED_VARIABLES;
        production
            .weight_bank_commitments
            .push(CanonicalBlsDoryGtHex::from_commitment(commitment(&setup, 11, 3)).unwrap());
        production.suite_parameter_digest = DORY_V3_PRODUCTION_SUITE_MANIFEST.digest().into_bytes();
        production.validate_production_shape().unwrap();
        assert!(matches!(
            production.validate_production_structure(&manifest, &setup),
            Err(DoryV3ModelIdentityError::SuiteContextMismatch)
        ));

        for mutate in [
            |value: &mut DoryV3ModelIdentityV1| value.batch /= 2,
            |value: &mut DoryV3ModelIdentityV1| value.dimension /= 2,
            |value: &mut DoryV3ModelIdentityV1| value.layers_per_bank /= 2,
            |value: &mut DoryV3ModelIdentityV1| value.padded_variables -= 1,
        ] {
            let mut changed = production.clone();
            mutate(&mut changed);
            assert!(changed.validate_production_shape().is_err());
        }
    }

    #[test]
    fn setup_substitution_and_invalid_geometry_fail_closed() {
        let (_, _, identity, _) = fixture();
        let other_setup = deterministic_bls_dory_setup(4).unwrap();
        assert!(matches!(
            identity.validate_with_setup(&other_setup),
            Err(DoryV3ModelIdentityError::SetupMismatch)
        ));

        let mut invalid = identity.clone();
        invalid.batch = 3;
        assert!(matches!(
            invalid.validate(),
            Err(DoryV3ModelIdentityError::InvalidGeometry)
        ));
        let mut invalid = identity.clone();
        invalid.model_byte_root = [0; 32];
        assert!(matches!(
            invalid.validate(),
            Err(DoryV3ModelIdentityError::UnspecifiedModelRoot)
        ));
        let mut invalid = identity.clone();
        invalid.layer_roots_aggregate = [0; 32];
        assert!(matches!(
            invalid.validate(),
            Err(DoryV3ModelIdentityError::UnspecifiedLayerRootsAggregate)
        ));
        let mut invalid = identity;
        invalid.identity_version += 1;
        assert!(matches!(
            invalid.validate(),
            Err(DoryV3ModelIdentityError::UnsupportedVersion)
        ));
    }
}
