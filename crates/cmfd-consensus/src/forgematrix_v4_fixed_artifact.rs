//! Authenticated fixed-bank artifact record for the ProductionV4 prover.
//!
//! These artifacts are prover caches, not consensus proof bytes. Their roots
//! are nevertheless consensus-visible through each bank's fixed BaseFold
//! commitment, so every format and identity field is pinned before mining.

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _, ser::Error as _};
use slop_algebra::AbstractField;
use thiserror::Error;

use crate::{
    FORGEMATRIX_V4_BASEFOLD_LOG_BLOWUP, FORGEMATRIX_V4_BASEFOLD_ROW_VARIABLES,
    FORGEMATRIX_V4_BASEFOLD_ROWS, FORGEMATRIX_V4_FIELD_MODULUS, FORGEMATRIX_V4_FIXED_COLUMNS,
    ModelBankError, ModelBankManifest, PRODUCTION_V2_BANKS, PRODUCTION_V2_BATCH,
    PRODUCTION_V2_DIMENSION, PRODUCTION_V2_LAYERS,
    forgematrix_v4_basefold::{ForgeMatrixV4Digest, ForgeMatrixV4Field},
    forgematrix_v4_proof_system_digest,
};

pub const FORGEMATRIX_V4_FIXED_ARTIFACT_RECORD_VERSION: u16 = 1;
pub const FORGEMATRIX_V4_FIXED_ARTIFACT_FORMAT: &str = "cmfd-v4-fixed-basefold-v1/raw-montgomery-u32-le;codeword-column-major[column,row];tree-root-first-binary-heap;full-tree;digest8;separate-files";
pub const FORGEMATRIX_V4_FIXED_ARTIFACT_FORMAT_DOMAIN: &str =
    "CommonFoundry/ForgeMatrix/V4/FixedArtifactFormat/v1";
pub const FORGEMATRIX_V4_FIXED_ARTIFACT_RECORD_DOMAIN: &str =
    "CommonFoundry/ForgeMatrix/V4/FixedArtifactRecord/v1";

pub const FORGEMATRIX_V4_FIXED_CODEWORD_ROWS: u64 =
    (FORGEMATRIX_V4_BASEFOLD_ROWS as u64) << FORGEMATRIX_V4_BASEFOLD_LOG_BLOWUP;
pub const FORGEMATRIX_V4_FIXED_CODEWORD_BYTES: u64 = FORGEMATRIX_V4_FIXED_COLUMNS as u64
    * FORGEMATRIX_V4_FIXED_CODEWORD_ROWS
    * std::mem::size_of::<u32>() as u64;
pub const FORGEMATRIX_V4_FIXED_TREE_HEIGHT: u32 =
    FORGEMATRIX_V4_BASEFOLD_ROW_VARIABLES + FORGEMATRIX_V4_BASEFOLD_LOG_BLOWUP;
pub const FORGEMATRIX_V4_FIXED_TREE_NODES: u64 =
    (1_u64 << (FORGEMATRIX_V4_FIXED_TREE_HEIGHT + 1)) - 1;
pub const FORGEMATRIX_V4_FIXED_TREE_BYTES: u64 =
    FORGEMATRIX_V4_FIXED_TREE_NODES * 8 * std::mem::size_of::<u32>() as u64;

const RECORD_CANONICAL_BYTES: usize = 542;
const DIGEST_FIELDS: usize = 8;

#[must_use]
pub fn forgematrix_v4_fixed_artifact_format_digest() -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(FORGEMATRIX_V4_FIXED_ARTIFACT_FORMAT_DOMAIN);
    hasher.update(&1_u32.to_le_bytes());
    hasher.update(&(FORGEMATRIX_V4_FIXED_ARTIFACT_FORMAT.len() as u64).to_le_bytes());
    hasher.update(FORGEMATRIX_V4_FIXED_ARTIFACT_FORMAT.as_bytes());
    hasher.update(&FORGEMATRIX_V4_FIXED_CODEWORD_ROWS.to_le_bytes());
    hasher.update(&FORGEMATRIX_V4_FIXED_CODEWORD_BYTES.to_le_bytes());
    hasher.update(&FORGEMATRIX_V4_FIXED_TREE_HEIGHT.to_le_bytes());
    hasher.update(&FORGEMATRIX_V4_FIXED_TREE_NODES.to_le_bytes());
    hasher.update(&FORGEMATRIX_V4_FIXED_TREE_BYTES.to_le_bytes());
    *hasher.finalize().as_bytes()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForgeMatrixV4FixedBankArtifactV1 {
    bank: u32,
    commitment: [u32; DIGEST_FIELDS],
    merkle_root: [u32; DIGEST_FIELDS],
    codeword_bytes: u64,
    tree_bytes: u64,
    codeword_blake3: [u8; 32],
    tree_blake3: [u8; 32],
}

impl ForgeMatrixV4FixedBankArtifactV1 {
    pub fn new(
        bank: u32,
        commitment: [u32; DIGEST_FIELDS],
        merkle_root: [u32; DIGEST_FIELDS],
        codeword_blake3: [u8; 32],
        tree_blake3: [u8; 32],
    ) -> Result<Self, ForgeMatrixV4FixedArtifactRecordError> {
        let artifact = Self {
            bank,
            commitment,
            merkle_root,
            codeword_bytes: FORGEMATRIX_V4_FIXED_CODEWORD_BYTES,
            tree_bytes: FORGEMATRIX_V4_FIXED_TREE_BYTES,
            codeword_blake3,
            tree_blake3,
        };
        artifact.validate(bank)?;
        Ok(artifact)
    }

    fn validate(&self, expected_bank: u32) -> Result<(), ForgeMatrixV4FixedArtifactRecordError> {
        if self.bank != expected_bank || self.bank >= PRODUCTION_V2_BANKS {
            return Err(ForgeMatrixV4FixedArtifactRecordError::BankOrder);
        }
        validate_digest(&self.commitment)?;
        validate_digest(&self.merkle_root)?;
        if self.commitment.iter().all(|&value| value == 0)
            || self.merkle_root.iter().all(|&value| value == 0)
        {
            return Err(ForgeMatrixV4FixedArtifactRecordError::ZeroCommitment);
        }
        if self.codeword_bytes != FORGEMATRIX_V4_FIXED_CODEWORD_BYTES
            || self.tree_bytes != FORGEMATRIX_V4_FIXED_TREE_BYTES
        {
            return Err(ForgeMatrixV4FixedArtifactRecordError::ArtifactLength);
        }
        if self.codeword_blake3 == [0; 32] || self.tree_blake3 == [0; 32] {
            return Err(ForgeMatrixV4FixedArtifactRecordError::ZeroArtifactDigest);
        }
        Ok(())
    }

    pub const fn bank(&self) -> u32 {
        self.bank
    }

    pub const fn commitment_words(&self) -> [u32; DIGEST_FIELDS] {
        self.commitment
    }

    pub const fn merkle_root_words(&self) -> [u32; DIGEST_FIELDS] {
        self.merkle_root
    }

    pub const fn codeword_bytes(&self) -> u64 {
        self.codeword_bytes
    }

    pub const fn tree_bytes(&self) -> u64 {
        self.tree_bytes
    }

    pub const fn codeword_blake3(&self) -> [u8; 32] {
        self.codeword_blake3
    }

    pub const fn tree_blake3(&self) -> [u8; 32] {
        self.tree_blake3
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForgeMatrixV4FixedArtifactRecordV1 {
    record_version: u16,
    proof_system_digest: [u8; 32],
    manifest: ModelBankManifest,
    manifest_digest: [u8; 32],
    artifact_format_digest: [u8; 32],
    banks: [ForgeMatrixV4FixedBankArtifactV1; PRODUCTION_V2_BANKS as usize],
    record_digest: [u8; 32],
}

impl ForgeMatrixV4FixedArtifactRecordV1 {
    pub fn new(
        manifest: ModelBankManifest,
        banks: [ForgeMatrixV4FixedBankArtifactV1; PRODUCTION_V2_BANKS as usize],
    ) -> Result<Self, ForgeMatrixV4FixedArtifactRecordError> {
        let mut record = Self {
            record_version: FORGEMATRIX_V4_FIXED_ARTIFACT_RECORD_VERSION,
            proof_system_digest: forgematrix_v4_proof_system_digest(),
            manifest,
            manifest_digest: manifest
                .digest()
                .map_err(ForgeMatrixV4FixedArtifactRecordError::Manifest)?,
            artifact_format_digest: forgematrix_v4_fixed_artifact_format_digest(),
            banks,
            record_digest: [0; 32],
        };
        record.record_digest = record.canonical_digest();
        record.validate()?;
        Ok(record)
    }

    pub fn validate(&self) -> Result<(), ForgeMatrixV4FixedArtifactRecordError> {
        if self.record_version != FORGEMATRIX_V4_FIXED_ARTIFACT_RECORD_VERSION {
            return Err(ForgeMatrixV4FixedArtifactRecordError::Version);
        }
        validate_production_manifest(&self.manifest)?;
        if self.proof_system_digest != forgematrix_v4_proof_system_digest() {
            return Err(ForgeMatrixV4FixedArtifactRecordError::ProofSystemDigest);
        }
        if self.manifest_digest
            != self
                .manifest
                .digest()
                .map_err(ForgeMatrixV4FixedArtifactRecordError::Manifest)?
        {
            return Err(ForgeMatrixV4FixedArtifactRecordError::ManifestDigest);
        }
        if self.artifact_format_digest != forgematrix_v4_fixed_artifact_format_digest() {
            return Err(ForgeMatrixV4FixedArtifactRecordError::ArtifactFormatDigest);
        }
        for (bank, artifact) in self.banks.iter().enumerate() {
            artifact.validate(bank as u32)?;
        }
        for left in 0..self.banks.len() {
            for right in left + 1..self.banks.len() {
                if self.banks[left].commitment == self.banks[right].commitment
                    || self.banks[left].merkle_root == self.banks[right].merkle_root
                {
                    return Err(ForgeMatrixV4FixedArtifactRecordError::DuplicateCommitment);
                }
            }
        }
        if self.record_digest != self.canonical_digest() {
            return Err(ForgeMatrixV4FixedArtifactRecordError::RecordDigest);
        }
        Ok(())
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> [u8; RECORD_CANONICAL_BYTES] {
        let mut bytes = [0_u8; RECORD_CANONICAL_BYTES];
        let mut cursor = 0;
        write_bytes(&mut bytes, &mut cursor, &self.record_version.to_le_bytes());
        write_bytes(&mut bytes, &mut cursor, &self.proof_system_digest);
        write_bytes(&mut bytes, &mut cursor, &self.manifest_digest);
        write_bytes(&mut bytes, &mut cursor, &self.artifact_format_digest);
        for artifact in &self.banks {
            write_bytes(&mut bytes, &mut cursor, &artifact.bank.to_le_bytes());
            for word in artifact.commitment {
                write_bytes(&mut bytes, &mut cursor, &word.to_le_bytes());
            }
            for word in artifact.merkle_root {
                write_bytes(&mut bytes, &mut cursor, &word.to_le_bytes());
            }
            write_bytes(
                &mut bytes,
                &mut cursor,
                &artifact.codeword_bytes.to_le_bytes(),
            );
            write_bytes(&mut bytes, &mut cursor, &artifact.tree_bytes.to_le_bytes());
            write_bytes(&mut bytes, &mut cursor, &artifact.codeword_blake3);
            write_bytes(&mut bytes, &mut cursor, &artifact.tree_blake3);
        }
        debug_assert_eq!(cursor, RECORD_CANONICAL_BYTES);
        bytes
    }

    #[must_use]
    pub fn canonical_digest(&self) -> [u8; 32] {
        let mut hasher =
            blake3::Hasher::new_derive_key(FORGEMATRIX_V4_FIXED_ARTIFACT_RECORD_DOMAIN);
        hasher.update(&self.canonical_bytes());
        *hasher.finalize().as_bytes()
    }

    pub fn fixed_commitments(&self) -> [ForgeMatrixV4Digest; PRODUCTION_V2_BANKS as usize] {
        self.banks.map(|artifact| {
            artifact
                .commitment
                .map(ForgeMatrixV4Field::from_canonical_u32)
        })
    }

    pub const fn manifest(&self) -> &ModelBankManifest {
        &self.manifest
    }

    pub const fn manifest_digest(&self) -> [u8; 32] {
        self.manifest_digest
    }

    pub const fn banks(&self) -> &[ForgeMatrixV4FixedBankArtifactV1; PRODUCTION_V2_BANKS as usize] {
        &self.banks
    }

    pub const fn record_digest(&self) -> [u8; 32] {
        self.record_digest
    }
}

pub fn canonical_forgematrix_v4_fixed_artifact_record_json(
    record: &ForgeMatrixV4FixedArtifactRecordV1,
) -> Result<Vec<u8>, serde_json::Error> {
    let mut bytes = serde_json::to_vec_pretty(record)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn validate_digest(
    words: &[u32; DIGEST_FIELDS],
) -> Result<(), ForgeMatrixV4FixedArtifactRecordError> {
    if words
        .iter()
        .any(|&word| word >= FORGEMATRIX_V4_FIELD_MODULUS)
    {
        return Err(ForgeMatrixV4FixedArtifactRecordError::NonCanonicalField);
    }
    Ok(())
}

fn validate_production_manifest(
    manifest: &ModelBankManifest,
) -> Result<(), ForgeMatrixV4FixedArtifactRecordError> {
    manifest
        .digest()
        .map_err(ForgeMatrixV4FixedArtifactRecordError::Manifest)?;
    let dimension = u64::from(PRODUCTION_V2_DIMENSION);
    let expected_base = u64::from(PRODUCTION_V2_BATCH) * dimension;
    let expected_layer = dimension * dimension;
    let expected_payload = expected_base + u64::from(PRODUCTION_V2_LAYERS) * expected_layer;
    if manifest.model_version != 2
        || manifest.dimension != PRODUCTION_V2_DIMENSION
        || manifest.batch != PRODUCTION_V2_BATCH
        || manifest.layers != PRODUCTION_V2_LAYERS
        || manifest.base_input_bytes != expected_base
        || manifest.bytes_per_layer != expected_layer
        || manifest.payload_bytes != expected_payload
    {
        return Err(ForgeMatrixV4FixedArtifactRecordError::ManifestGeometry);
    }
    Ok(())
}

fn write_bytes<const N: usize>(output: &mut [u8; N], cursor: &mut usize, value: &[u8]) {
    output[*cursor..*cursor + value.len()].copy_from_slice(value);
    *cursor += value.len();
}

#[derive(Serialize)]
struct RecordRef<'a> {
    record_version: u16,
    proof_system_digest: [u8; 32],
    manifest: &'a ModelBankManifest,
    manifest_digest: [u8; 32],
    artifact_format_digest: [u8; 32],
    banks: &'a [ForgeMatrixV4FixedBankArtifactV1; PRODUCTION_V2_BANKS as usize],
    record_digest: [u8; 32],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordOwned {
    record_version: u16,
    proof_system_digest: [u8; 32],
    manifest: ModelBankManifest,
    manifest_digest: [u8; 32],
    artifact_format_digest: [u8; 32],
    banks: [ForgeMatrixV4FixedBankArtifactV1; PRODUCTION_V2_BANKS as usize],
    record_digest: [u8; 32],
}

impl Serialize for ForgeMatrixV4FixedArtifactRecordV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if !serializer.is_human_readable() {
            return Err(S::Error::custom(
                "V4 fixed artifact records require human-readable encoding",
            ));
        }
        self.validate().map_err(S::Error::custom)?;
        RecordRef {
            record_version: self.record_version,
            proof_system_digest: self.proof_system_digest,
            manifest: &self.manifest,
            manifest_digest: self.manifest_digest,
            artifact_format_digest: self.artifact_format_digest,
            banks: &self.banks,
            record_digest: self.record_digest,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ForgeMatrixV4FixedArtifactRecordV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if !deserializer.is_human_readable() {
            return Err(D::Error::custom(
                "V4 fixed artifact records require human-readable encoding",
            ));
        }
        let decoded = RecordOwned::deserialize(deserializer)?;
        let record = Self {
            record_version: decoded.record_version,
            proof_system_digest: decoded.proof_system_digest,
            manifest: decoded.manifest,
            manifest_digest: decoded.manifest_digest,
            artifact_format_digest: decoded.artifact_format_digest,
            banks: decoded.banks,
            record_digest: decoded.record_digest,
        };
        record.validate().map_err(D::Error::custom)?;
        Ok(record)
    }
}

#[derive(Debug, Error)]
pub enum ForgeMatrixV4FixedArtifactRecordError {
    #[error("unsupported V4 fixed artifact record version")]
    Version,
    #[error("invalid model-bank manifest: {0}")]
    Manifest(#[source] ModelBankError),
    #[error("the manifest does not describe the exact production geometry")]
    ManifestGeometry,
    #[error("the record proof-system digest is not the compiled V4 digest")]
    ProofSystemDigest,
    #[error("the record manifest digest is incorrect")]
    ManifestDigest,
    #[error("the fixed artifact format digest is incorrect")]
    ArtifactFormatDigest,
    #[error("fixed artifacts are missing or out of bank order")]
    BankOrder,
    #[error("a fixed commitment field is not canonical")]
    NonCanonicalField,
    #[error("a fixed commitment or Merkle root is zero")]
    ZeroCommitment,
    #[error("a fixed artifact has an incorrect byte length")]
    ArtifactLength,
    #[error("a fixed artifact content digest is zero")]
    ZeroArtifactDigest,
    #[error("fixed banks reuse a commitment or Merkle root")]
    DuplicateCommitment,
    #[error("the V4 fixed artifact record digest is incorrect")]
    RecordDigest,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> ModelBankManifest {
        ModelBankManifest {
            model_version: 2,
            dimension: PRODUCTION_V2_DIMENSION,
            batch: PRODUCTION_V2_BATCH,
            layers: PRODUCTION_V2_LAYERS,
            base_input_bytes: u64::from(PRODUCTION_V2_BATCH) * u64::from(PRODUCTION_V2_DIMENSION),
            bytes_per_layer: u64::from(PRODUCTION_V2_DIMENSION).pow(2),
            payload_bytes: u64::from(PRODUCTION_V2_BATCH) * u64::from(PRODUCTION_V2_DIMENSION)
                + u64::from(PRODUCTION_V2_LAYERS) * u64::from(PRODUCTION_V2_DIMENSION).pow(2),
            raw_blake3_root: [1; 32],
            layer_roots_aggregate: [2; 32],
            pcs_parameter_digest: [3; 32],
            pcs_commitment_root: [4; 32],
        }
    }

    fn bank(index: u32) -> ForgeMatrixV4FixedBankArtifactV1 {
        ForgeMatrixV4FixedBankArtifactV1::new(
            index,
            [index + 1; DIGEST_FIELDS],
            [index + 11; DIGEST_FIELDS],
            [index as u8 + 21; 32],
            [index as u8 + 31; 32],
        )
        .unwrap()
    }

    fn record() -> ForgeMatrixV4FixedArtifactRecordV1 {
        ForgeMatrixV4FixedArtifactRecordV1::new(manifest(), [bank(0), bank(1), bank(2)]).unwrap()
    }

    #[test]
    fn exact_artifact_geometry_is_pinned() {
        assert_eq!(FORGEMATRIX_V4_FIXED_CODEWORD_ROWS, 1 << 24);
        assert_eq!(FORGEMATRIX_V4_FIXED_CODEWORD_BYTES, 17_179_869_184);
        assert_eq!(FORGEMATRIX_V4_FIXED_TREE_HEIGHT, 24);
        assert_eq!(FORGEMATRIX_V4_FIXED_TREE_NODES, 33_554_431);
        assert_eq!(FORGEMATRIX_V4_FIXED_TREE_BYTES, 1_073_741_792);
        assert_ne!(forgematrix_v4_fixed_artifact_format_digest(), [0; 32]);
    }

    #[test]
    fn record_round_trip_is_canonical_and_recovers_commitments() {
        let record = record();
        assert_eq!(record.canonical_bytes().len(), RECORD_CANONICAL_BYTES);
        assert_eq!(record.canonical_digest(), record.record_digest());
        let json = canonical_forgematrix_v4_fixed_artifact_record_json(&record).unwrap();
        let decoded: ForgeMatrixV4FixedArtifactRecordV1 = serde_json::from_slice(&json).unwrap();
        assert_eq!(decoded, record);
        assert_eq!(
            decoded.fixed_commitments()[2],
            [ForgeMatrixV4Field::from_canonical_u32(3); DIGEST_FIELDS]
        );
    }

    #[test]
    fn malformed_record_fields_fail_closed() {
        let mut changed = record();
        changed.banks[0].codeword_bytes -= 4;
        assert!(matches!(
            changed.validate(),
            Err(ForgeMatrixV4FixedArtifactRecordError::ArtifactLength)
        ));

        let mut changed = record();
        changed.banks[1].commitment[0] = FORGEMATRIX_V4_FIELD_MODULUS;
        assert!(matches!(
            changed.validate(),
            Err(ForgeMatrixV4FixedArtifactRecordError::NonCanonicalField)
        ));

        let mut changed = record();
        changed.banks.swap(0, 1);
        assert!(matches!(
            changed.validate(),
            Err(ForgeMatrixV4FixedArtifactRecordError::BankOrder)
        ));

        let mut changed = record();
        changed.record_digest[0] ^= 1;
        assert!(matches!(
            changed.validate(),
            Err(ForgeMatrixV4FixedArtifactRecordError::RecordDigest)
        ));
    }
}
