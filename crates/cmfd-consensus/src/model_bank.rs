//! Canonical, seedless storage for ForgeMatrix v2 model bytes.
//!
//! A model bank is a fixed header followed by the base input in row-major
//! order and then each layer in ascending layer order, also row-major. The
//! production path in this module is read-only and streaming. Deliberately,
//! there is no seed or model-generation API: consensus must bind the actual
//! high-entropy bytes and the commitment produced by the selected PCS.

use std::io::{self, Read};

use blake3::Hasher;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::forgematrix_v2::PRODUCTION_V2_BANKS;

pub const MODEL_BANK_MAGIC: [u8; 8] = *b"CMFDBNK2";
pub const MODEL_BANK_FORMAT_VERSION: u32 = 2;
pub const MODEL_BANK_HEADER_BYTES: usize = 184;
pub const MAX_MODEL_BYTE: u8 = 250;

/// The writer is intentionally limited to test/research fixtures. Production
/// banks must be produced by a separately reviewed, reproducible ceremony.
pub const MAX_SMALL_FIXTURE_PAYLOAD_BYTES: u64 = 16 * 1024 * 1024;

/// Canonical encoding revision for the model PCS identity.
pub const MODEL_PCS_IDENTITY_VERSION: u32 = 1;
/// The production relation has exactly three ordered weight banks; research
/// identities may use a nonempty prefix of that layout.
pub const MAX_MODEL_PCS_WEIGHT_BANKS: usize = PRODUCTION_V2_BANKS as usize;
/// Model bytes are interpreted as signed integers centered at 125, then
/// embedded canonically in the Goldilocks field.
pub const MODEL_PCS_VALUE_ENCODING: &str =
    "u8 x in 0..=250 -> Goldilocks canonical signed integer (x - 125)";
/// Canonical base-input multilinear-extension axis order.
pub const MODEL_PCS_BASE_INPUT_AXIS_ORDER: &str =
    "[column,row] least-significant/fastest-changing first";
/// Canonical ordered weight-bank multilinear-extension axis order.
pub const MODEL_PCS_WEIGHT_BANK_AXIS_ORDER: &str =
    "[column,common,layer-within-bank] least-significant/fastest-changing first";

const LAYER_ROOTS_DOMAIN: &str = "CMFD/FORGEMATRIX/V2/LAYER-ROOTS";
const MANIFEST_DOMAIN: &str = "CMFD/FORGEMATRIX/V2/MANIFEST";
const MODEL_PCS_COMMITMENT_ROOT_DOMAIN: &str = "CMFD/FORGEMATRIX/V2/MODEL-PCS-COMMITMENTS/V1";
const MODEL_PCS_IDENTITY_DOMAIN: &str = "CMFD/FORGEMATRIX/V2/MODEL-PCS-IDENTITY/V1";
const VERIFY_CHUNK_BYTES: usize = 64 * 1024;

/// Canonical identity of the fixed model polynomials used by the structured
/// proof research path.
///
/// The base-input commitment is followed by one commitment per weight bank.
/// Bank order is consensus-significant. This descriptor is deliberately not
/// carried by the current 184-byte model-bank header and does not activate a
/// production proof format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelPcsIdentity {
    pub model_version: u32,
    pub batch: u32,
    pub dimension: u32,
    pub layers_per_bank: u32,
    pub model_byte_root: [u8; 32],
    pub pcs_suite_parameter_digest: [u8; 32],
    pub base_input_commitment: [u8; 32],
    pub weight_bank_commitments: Vec<[u8; 32]>,
}

impl ModelPcsIdentity {
    /// Validates the canonical structured-PCS shape and rejects placeholder
    /// roots or commitments.
    pub fn validate(&self) -> Result<(), ModelBankError> {
        if self.model_version == 0 {
            return Err(ModelBankError::InvalidModelVersion);
        }
        if self.batch == 0
            || self.dimension == 0
            || self.layers_per_bank == 0
            || !self.batch.is_power_of_two()
            || !self.dimension.is_power_of_two()
            || !self.layers_per_bank.is_power_of_two()
        {
            return Err(ModelBankError::NonCanonicalPcsShape);
        }

        if self.weight_bank_commitments.is_empty()
            || self.weight_bank_commitments.len() > MAX_MODEL_PCS_WEIGHT_BANKS
        {
            return Err(ModelBankError::InvalidPcsBankCount);
        }
        let bank_count = u32::try_from(self.weight_bank_commitments.len())
            .map_err(|_| ModelBankError::InvalidPcsBankCount)?;
        self.layers_per_bank
            .checked_mul(bank_count)
            .ok_or(ModelBankError::SizeOverflow)?;

        if self.model_byte_root == [0; 32]
            || self.pcs_suite_parameter_digest == [0; 32]
            || self.base_input_commitment == [0; 32]
            || self.weight_bank_commitments.contains(&[0; 32])
        {
            return Err(ModelBankError::UncommittedPcsIdentity);
        }
        for (weight_index, commitment) in self.weight_bank_commitments.iter().enumerate() {
            let second_role =
                u32::try_from(weight_index + 1).map_err(|_| ModelBankError::InvalidPcsBankCount)?;
            if *commitment == self.base_input_commitment {
                return Err(ModelBankError::DuplicatePcsRoleCommitment {
                    first_role: 0,
                    second_role,
                });
            }
            for (prior_weight_index, prior_commitment) in self.weight_bank_commitments
                [..weight_index]
                .iter()
                .enumerate()
            {
                if commitment == prior_commitment {
                    let first_role = u32::try_from(prior_weight_index + 1)
                        .map_err(|_| ModelBankError::InvalidPcsBankCount)?;
                    return Err(ModelBankError::DuplicatePcsRoleCommitment {
                        first_role,
                        second_role,
                    });
                }
            }
        }
        Ok(())
    }

    /// Domain-separated root of the ordered base-input and weight-bank PCS
    /// commitments.
    pub fn commitment_root(&self) -> Result<[u8; 32], ModelBankError> {
        self.validate()?;
        let bank_count = u32::try_from(self.weight_bank_commitments.len())
            .map_err(|_| ModelBankError::InvalidPcsBankCount)?;
        let mut hasher = Hasher::new_derive_key(MODEL_PCS_COMMITMENT_ROOT_DOMAIN);
        hasher.update(&MODEL_PCS_IDENTITY_VERSION.to_le_bytes());
        hasher.update(&(bank_count + 1).to_le_bytes());
        hasher.update(&0_u32.to_le_bytes());
        hasher.update(&self.base_input_commitment);
        for (bank_index, commitment) in self.weight_bank_commitments.iter().enumerate() {
            let commitment_index =
                u32::try_from(bank_index + 1).map_err(|_| ModelBankError::InvalidPcsBankCount)?;
            hasher.update(&commitment_index.to_le_bytes());
            hasher.update(commitment);
        }
        Ok(*hasher.finalize().as_bytes())
    }

    /// Domain-separated digest that freezes shape, model bytes, PCS suite,
    /// commitments, value encoding, and multilinear-extension axis order.
    pub fn digest(&self) -> Result<[u8; 32], ModelBankError> {
        self.validate()?;
        let bank_count = u32::try_from(self.weight_bank_commitments.len())
            .map_err(|_| ModelBankError::InvalidPcsBankCount)?;
        let mut hasher = Hasher::new_derive_key(MODEL_PCS_IDENTITY_DOMAIN);
        hasher.update(&MODEL_PCS_IDENTITY_VERSION.to_le_bytes());
        update_identity_label(&mut hasher, MODEL_PCS_VALUE_ENCODING);
        update_identity_label(&mut hasher, MODEL_PCS_BASE_INPUT_AXIS_ORDER);
        update_identity_label(&mut hasher, MODEL_PCS_WEIGHT_BANK_AXIS_ORDER);
        hasher.update(&self.model_version.to_le_bytes());
        hasher.update(&self.batch.to_le_bytes());
        hasher.update(&self.dimension.to_le_bytes());
        hasher.update(&self.layers_per_bank.to_le_bytes());
        hasher.update(&bank_count.to_le_bytes());
        hasher.update(&self.model_byte_root);
        hasher.update(&self.pcs_suite_parameter_digest);
        hasher.update(&self.commitment_root()?);
        Ok(*hasher.finalize().as_bytes())
    }
}

/// Trusted descriptor for one immutable model bank.
///
/// `raw_blake3_root` is plain BLAKE3 over the canonical payload bytes. Each
/// layer is also hashed with plain BLAKE3; `layer_roots_aggregate` is a
/// domain-separated hash of the layer count and the indexed layer roots.
/// The PCS fields are outputs of the external commitment ceremony. They
/// cannot be reconstructed by this byte-integrity verifier, so callers must
/// supply the trusted manifest instead of trusting the copy inside a bank.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelBankManifest {
    pub model_version: u32,
    pub dimension: u32,
    pub batch: u32,
    pub layers: u32,
    pub base_input_bytes: u64,
    pub bytes_per_layer: u64,
    pub payload_bytes: u64,
    pub raw_blake3_root: [u8; 32],
    pub layer_roots_aggregate: [u8; 32],
    pub pcs_parameter_digest: [u8; 32],
    pub pcs_commitment_root: [u8; 32],
}

impl ModelBankManifest {
    /// Domain-separated digest of every canonical header field.
    pub fn digest(&self) -> Result<[u8; 32], ModelBankError> {
        self.validate_shape()?;
        let mut hasher = Hasher::new_derive_key(MANIFEST_DOMAIN);
        hasher.update(&encode_header(self));
        Ok(*hasher.finalize().as_bytes())
    }

    /// Verifies that this byte manifest and a separately supplied structured
    /// PCS identity describe the same model and commitment ceremony.
    pub fn verify_pcs_identity(&self, identity: &ModelPcsIdentity) -> Result<(), ModelBankError> {
        self.validate_shape()?;
        identity.validate()?;
        let bank_count = u32::try_from(identity.weight_bank_commitments.len())
            .map_err(|_| ModelBankError::InvalidPcsBankCount)?;
        let total_layers = identity
            .layers_per_bank
            .checked_mul(bank_count)
            .ok_or(ModelBankError::SizeOverflow)?;

        if self.model_version != identity.model_version
            || self.batch != identity.batch
            || self.dimension != identity.dimension
            || self.layers != total_layers
        {
            return Err(ModelBankError::PcsIdentityShapeMismatch);
        }
        if self.raw_blake3_root != identity.model_byte_root {
            return Err(ModelBankError::PcsIdentityModelRootMismatch);
        }
        if self.pcs_parameter_digest != identity.pcs_suite_parameter_digest {
            return Err(ModelBankError::PcsParameterDigestMismatch);
        }
        if self.pcs_commitment_root != identity.commitment_root()? {
            return Err(ModelBankError::PcsCommitmentRootMismatch);
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), ModelBankError> {
        if self.model_version == 0 {
            return Err(ModelBankError::InvalidModelVersion);
        }
        if self.dimension == 0 || self.batch == 0 || self.layers == 0 {
            return Err(ModelBankError::InvalidDimensions);
        }

        let dimension = u64::from(self.dimension);
        let expected_base = u64::from(self.batch)
            .checked_mul(dimension)
            .ok_or(ModelBankError::SizeOverflow)?;
        let expected_layer = dimension
            .checked_mul(dimension)
            .ok_or(ModelBankError::SizeOverflow)?;
        let expected_payload = u64::from(self.layers)
            .checked_mul(expected_layer)
            .and_then(|layers| layers.checked_add(expected_base))
            .ok_or(ModelBankError::SizeOverflow)?;

        if self.base_input_bytes != expected_base
            || self.bytes_per_layer != expected_layer
            || self.payload_bytes != expected_payload
        {
            return Err(ModelBankError::NonCanonicalLengths);
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum ModelBankError {
    #[error("invalid model-bank magic")]
    InvalidMagic,
    #[error("unsupported model-bank format version")]
    UnsupportedFormatVersion,
    #[error("non-canonical model-bank header length")]
    InvalidHeaderLength,
    #[error("model version must be nonzero")]
    InvalidModelVersion,
    #[error("model-bank dimensions must be nonzero")]
    InvalidDimensions,
    #[error("structured PCS identity shape must be nonzero and power-of-two")]
    NonCanonicalPcsShape,
    #[error("structured PCS identity must contain between one and three weight banks")]
    InvalidPcsBankCount,
    #[error("structured PCS identity contains an unspecified root or commitment")]
    UncommittedPcsIdentity,
    #[error(
        "structured PCS identity reuses a commitment across fixed roles {first_role} and {second_role}"
    )]
    DuplicatePcsRoleCommitment { first_role: u32, second_role: u32 },
    #[error("model-bank size arithmetic overflowed")]
    SizeOverflow,
    #[error("header lengths do not match the declared dimensions")]
    NonCanonicalLengths,
    #[error("model-bank header does not match the trusted manifest")]
    ManifestMismatch,
    #[error("PCS parameter digest does not match the trusted manifest")]
    PcsParameterDigestMismatch,
    #[error("PCS commitment root does not match the trusted manifest")]
    PcsCommitmentRootMismatch,
    #[error("model-bank shape does not match the structured PCS identity")]
    PcsIdentityShapeMismatch,
    #[error("model-bank byte root does not match the structured PCS identity")]
    PcsIdentityModelRootMismatch,
    #[error("model bank ended before its canonical payload length")]
    Truncated,
    #[error("model bank contains bytes after its canonical payload")]
    TrailingBytes,
    #[error("payload byte {offset} has forbidden value {value}; maximum is 250")]
    OutOfRange { offset: u64, value: u8 },
    #[error("raw payload BLAKE3 root mismatch")]
    RawRootMismatch,
    #[error("per-layer root aggregate mismatch")]
    LayerRootsAggregateMismatch,
    #[error("small fixture exceeds the 16 MiB writer limit")]
    FixtureTooLarge,
    #[error("base input length does not match batch * dimension")]
    BaseInputLength,
    #[error("layer count or layer length does not match the declared dimensions")]
    LayerShape,
    #[error("I/O error while reading model bank: {0}")]
    Io(#[from] io::Error),
}

/// Explicit bytes for a small test/research model bank.
///
/// `base_input` is `batch * dimension` row-major bytes. Every entry in
/// `layers` is one `dimension * dimension` row-major matrix. Values in both
/// sections must be in `0..=250`.
pub struct SmallModelBankFixture<'a> {
    pub model_version: u32,
    pub dimension: u32,
    pub batch: u32,
    pub base_input: &'a [u8],
    pub layers: &'a [&'a [u8]],
    pub pcs_parameter_digest: [u8; 32],
    pub pcs_commitment_root: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltModelBankFixture {
    pub bytes: Vec<u8>,
    pub manifest: ModelBankManifest,
}

/// Builds only bounded fixtures. This function cannot create a production
/// multi-gigabyte bank by construction.
pub fn build_small_model_bank(
    fixture: SmallModelBankFixture<'_>,
) -> Result<BuiltModelBankFixture, ModelBankError> {
    if fixture.model_version == 0 {
        return Err(ModelBankError::InvalidModelVersion);
    }
    if fixture.dimension == 0 || fixture.batch == 0 || fixture.layers.is_empty() {
        return Err(ModelBankError::InvalidDimensions);
    }

    let dimension = u64::from(fixture.dimension);
    let base_input_bytes = u64::from(fixture.batch)
        .checked_mul(dimension)
        .ok_or(ModelBankError::SizeOverflow)?;
    let bytes_per_layer = dimension
        .checked_mul(dimension)
        .ok_or(ModelBankError::SizeOverflow)?;
    let layers = u32::try_from(fixture.layers.len()).map_err(|_| ModelBankError::SizeOverflow)?;
    let payload_bytes = u64::from(layers)
        .checked_mul(bytes_per_layer)
        .and_then(|layer_bytes| layer_bytes.checked_add(base_input_bytes))
        .ok_or(ModelBankError::SizeOverflow)?;

    if payload_bytes > MAX_SMALL_FIXTURE_PAYLOAD_BYTES {
        return Err(ModelBankError::FixtureTooLarge);
    }
    if u64::try_from(fixture.base_input.len()).ok() != Some(base_input_bytes) {
        return Err(ModelBankError::BaseInputLength);
    }
    if fixture
        .layers
        .iter()
        .any(|layer| u64::try_from(layer.len()).ok() != Some(bytes_per_layer))
    {
        return Err(ModelBankError::LayerShape);
    }

    validate_values(fixture.base_input, 0)?;
    let mut offset = base_input_bytes;
    for layer in fixture.layers {
        validate_values(layer, offset)?;
        offset = offset
            .checked_add(bytes_per_layer)
            .ok_or(ModelBankError::SizeOverflow)?;
    }

    let mut raw_hasher = Hasher::new();
    raw_hasher.update(fixture.base_input);
    let mut layer_aggregate = start_layer_aggregate(layers);
    for (index, layer) in fixture.layers.iter().enumerate() {
        raw_hasher.update(layer);
        add_layer_root(&mut layer_aggregate, index as u32, blake3::hash(layer));
    }

    let manifest = ModelBankManifest {
        model_version: fixture.model_version,
        dimension: fixture.dimension,
        batch: fixture.batch,
        layers,
        base_input_bytes,
        bytes_per_layer,
        payload_bytes,
        raw_blake3_root: *raw_hasher.finalize().as_bytes(),
        layer_roots_aggregate: *layer_aggregate.finalize().as_bytes(),
        pcs_parameter_digest: fixture.pcs_parameter_digest,
        pcs_commitment_root: fixture.pcs_commitment_root,
    };

    let capacity = MODEL_BANK_HEADER_BYTES
        .checked_add(usize::try_from(payload_bytes).map_err(|_| ModelBankError::SizeOverflow)?)
        .ok_or(ModelBankError::SizeOverflow)?;
    let mut bytes = Vec::with_capacity(capacity);
    bytes.extend_from_slice(&encode_header(&manifest));
    bytes.extend_from_slice(fixture.base_input);
    for layer in fixture.layers {
        bytes.extend_from_slice(layer);
    }

    Ok(BuiltModelBankFixture { bytes, manifest })
}

/// Verifies a bank against a trusted, consensus-selected manifest while using
/// at most a fixed 64 KiB payload buffer.
pub fn verify_model_bank<R: Read>(
    mut reader: R,
    expected: &ModelBankManifest,
) -> Result<(), ModelBankError> {
    expected.validate_shape()?;
    let actual = read_header(&mut reader)?;
    compare_manifests(expected, &actual)?;

    let mut raw_hasher = Hasher::new();
    let mut payload_offset = 0_u64;
    stream_section(
        &mut reader,
        actual.base_input_bytes,
        &mut payload_offset,
        &mut raw_hasher,
        None,
    )?;

    let mut layer_aggregate = start_layer_aggregate(actual.layers);
    for layer_index in 0..actual.layers {
        let mut layer_hasher = Hasher::new();
        stream_section(
            &mut reader,
            actual.bytes_per_layer,
            &mut payload_offset,
            &mut raw_hasher,
            Some(&mut layer_hasher),
        )?;
        add_layer_root(&mut layer_aggregate, layer_index, layer_hasher.finalize());
    }

    if payload_offset != actual.payload_bytes {
        return Err(ModelBankError::NonCanonicalLengths);
    }
    if *raw_hasher.finalize().as_bytes() != actual.raw_blake3_root {
        return Err(ModelBankError::RawRootMismatch);
    }
    if *layer_aggregate.finalize().as_bytes() != actual.layer_roots_aggregate {
        return Err(ModelBankError::LayerRootsAggregateMismatch);
    }

    let mut trailing = [0_u8; 1];
    match reader.read(&mut trailing) {
        Ok(0) => Ok(()),
        Ok(_) => Err(ModelBankError::TrailingBytes),
        Err(error) => Err(ModelBankError::Io(error)),
    }
}

fn compare_manifests(
    expected: &ModelBankManifest,
    actual: &ModelBankManifest,
) -> Result<(), ModelBankError> {
    if actual.pcs_parameter_digest != expected.pcs_parameter_digest {
        return Err(ModelBankError::PcsParameterDigestMismatch);
    }
    if actual.pcs_commitment_root != expected.pcs_commitment_root {
        return Err(ModelBankError::PcsCommitmentRootMismatch);
    }
    if actual != expected {
        return Err(ModelBankError::ManifestMismatch);
    }
    Ok(())
}

fn stream_section<R: Read>(
    reader: &mut R,
    bytes: u64,
    payload_offset: &mut u64,
    raw_hasher: &mut Hasher,
    mut section_hasher: Option<&mut Hasher>,
) -> Result<(), ModelBankError> {
    let mut remaining = bytes;
    let mut buffer = [0_u8; VERIFY_CHUNK_BYTES];
    while remaining != 0 {
        let take = usize::try_from(remaining.min(VERIFY_CHUNK_BYTES as u64))
            .map_err(|_| ModelBankError::SizeOverflow)?;
        read_exact(reader, &mut buffer[..take])?;
        validate_values(&buffer[..take], *payload_offset)?;
        raw_hasher.update(&buffer[..take]);
        if let Some(hasher) = section_hasher.as_deref_mut() {
            hasher.update(&buffer[..take]);
        }
        *payload_offset = payload_offset
            .checked_add(take as u64)
            .ok_or(ModelBankError::SizeOverflow)?;
        remaining -= take as u64;
    }
    Ok(())
}

fn validate_values(bytes: &[u8], start_offset: u64) -> Result<(), ModelBankError> {
    for (index, value) in bytes.iter().copied().enumerate() {
        if value > MAX_MODEL_BYTE {
            return Err(ModelBankError::OutOfRange {
                offset: start_offset + index as u64,
                value,
            });
        }
    }
    Ok(())
}

fn start_layer_aggregate(layers: u32) -> Hasher {
    let mut hasher = Hasher::new_derive_key(LAYER_ROOTS_DOMAIN);
    hasher.update(&layers.to_le_bytes());
    hasher
}

fn add_layer_root(aggregate: &mut Hasher, index: u32, root: blake3::Hash) {
    aggregate.update(&index.to_le_bytes());
    aggregate.update(root.as_bytes());
}

fn update_identity_label(hasher: &mut Hasher, label: &str) {
    let length = u32::try_from(label.len()).expect("fixed identity labels fit in u32");
    hasher.update(&length.to_le_bytes());
    hasher.update(label.as_bytes());
}

fn encode_header(manifest: &ModelBankManifest) -> [u8; MODEL_BANK_HEADER_BYTES] {
    let mut header = [0_u8; MODEL_BANK_HEADER_BYTES];
    let mut offset = 0;
    put(&mut header, &mut offset, &MODEL_BANK_MAGIC);
    put(
        &mut header,
        &mut offset,
        &MODEL_BANK_FORMAT_VERSION.to_le_bytes(),
    );
    put(
        &mut header,
        &mut offset,
        &(MODEL_BANK_HEADER_BYTES as u32).to_le_bytes(),
    );
    put(
        &mut header,
        &mut offset,
        &manifest.model_version.to_le_bytes(),
    );
    put(&mut header, &mut offset, &manifest.dimension.to_le_bytes());
    put(&mut header, &mut offset, &manifest.batch.to_le_bytes());
    put(&mut header, &mut offset, &manifest.layers.to_le_bytes());
    put(
        &mut header,
        &mut offset,
        &manifest.base_input_bytes.to_le_bytes(),
    );
    put(
        &mut header,
        &mut offset,
        &manifest.bytes_per_layer.to_le_bytes(),
    );
    put(
        &mut header,
        &mut offset,
        &manifest.payload_bytes.to_le_bytes(),
    );
    put(&mut header, &mut offset, &manifest.raw_blake3_root);
    put(&mut header, &mut offset, &manifest.layer_roots_aggregate);
    put(&mut header, &mut offset, &manifest.pcs_parameter_digest);
    put(&mut header, &mut offset, &manifest.pcs_commitment_root);
    debug_assert_eq!(offset, MODEL_BANK_HEADER_BYTES);
    header
}

fn put<const N: usize>(target: &mut [u8], offset: &mut usize, bytes: &[u8; N]) {
    target[*offset..*offset + N].copy_from_slice(bytes);
    *offset += N;
}

fn read_header<R: Read>(reader: &mut R) -> Result<ModelBankManifest, ModelBankError> {
    let mut header = [0_u8; MODEL_BANK_HEADER_BYTES];
    read_exact(reader, &mut header)?;
    let mut offset = 0;

    if take::<8>(&header, &mut offset) != MODEL_BANK_MAGIC {
        return Err(ModelBankError::InvalidMagic);
    }
    if u32::from_le_bytes(take::<4>(&header, &mut offset)) != MODEL_BANK_FORMAT_VERSION {
        return Err(ModelBankError::UnsupportedFormatVersion);
    }
    if u32::from_le_bytes(take::<4>(&header, &mut offset)) != MODEL_BANK_HEADER_BYTES as u32 {
        return Err(ModelBankError::InvalidHeaderLength);
    }

    let manifest = ModelBankManifest {
        model_version: u32::from_le_bytes(take::<4>(&header, &mut offset)),
        dimension: u32::from_le_bytes(take::<4>(&header, &mut offset)),
        batch: u32::from_le_bytes(take::<4>(&header, &mut offset)),
        layers: u32::from_le_bytes(take::<4>(&header, &mut offset)),
        base_input_bytes: u64::from_le_bytes(take::<8>(&header, &mut offset)),
        bytes_per_layer: u64::from_le_bytes(take::<8>(&header, &mut offset)),
        payload_bytes: u64::from_le_bytes(take::<8>(&header, &mut offset)),
        raw_blake3_root: take::<32>(&header, &mut offset),
        layer_roots_aggregate: take::<32>(&header, &mut offset),
        pcs_parameter_digest: take::<32>(&header, &mut offset),
        pcs_commitment_root: take::<32>(&header, &mut offset),
    };
    debug_assert_eq!(offset, MODEL_BANK_HEADER_BYTES);
    manifest.validate_shape()?;
    Ok(manifest)
}

fn take<const N: usize>(source: &[u8], offset: &mut usize) -> [u8; N] {
    let mut bytes = [0_u8; N];
    bytes.copy_from_slice(&source[*offset..*offset + N]);
    *offset += N;
    bytes
}

fn read_exact<R: Read>(reader: &mut R, bytes: &mut [u8]) -> Result<(), ModelBankError> {
    match reader.read_exact(bytes) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
            Err(ModelBankError::Truncated)
        }
        Err(error) => Err(ModelBankError::Io(error)),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::forgematrix_v2::{
        PRODUCTION_V2_BATCH, PRODUCTION_V2_DIMENSION, PRODUCTION_V2_LAYERS,
        PRODUCTION_V2_LAYERS_PER_BANK,
    };

    const MODEL_VERSION_OFFSET: usize = 16;
    const BASE_LENGTH_OFFSET: usize = 32;
    const PCS_PARAMETER_OFFSET: usize = 120;
    const PCS_COMMITMENT_OFFSET: usize = 152;

    fn fixture() -> BuiltModelBankFixture {
        let base = [0, 1, 2, 3, 4, 5];
        let layer_0 = [6, 7, 8, 9, 10, 11, 12, 13, 14];
        let layer_1 = [15, 16, 17, 18, 19, 20, 21, 22, 23];
        build_small_model_bank(SmallModelBankFixture {
            model_version: 2,
            dimension: 3,
            batch: 2,
            base_input: &base,
            layers: &[&layer_0, &layer_1],
            pcs_parameter_digest: [0x51; 32],
            pcs_commitment_root: [0xa7; 32],
        })
        .unwrap()
    }

    fn pcs_fixture() -> BuiltModelBankFixture {
        let base = [0, 1, 2, 3];
        let layer_0 = [4, 5, 6, 7];
        let layer_1 = [8, 9, 10, 11];
        build_small_model_bank(SmallModelBankFixture {
            model_version: 2,
            dimension: 2,
            batch: 2,
            base_input: &base,
            layers: &[&layer_0, &layer_1],
            pcs_parameter_digest: [0x51; 32],
            pcs_commitment_root: [0xa7; 32],
        })
        .unwrap()
    }

    fn production_pcs_identity() -> ModelPcsIdentity {
        ModelPcsIdentity {
            model_version: 2,
            batch: PRODUCTION_V2_BATCH,
            dimension: PRODUCTION_V2_DIMENSION,
            layers_per_bank: PRODUCTION_V2_LAYERS_PER_BANK,
            model_byte_root: [0x11; 32],
            pcs_suite_parameter_digest: [0x22; 32],
            base_input_commitment: [0x33; 32],
            weight_bank_commitments: vec![[0x44; 32], [0x55; 32], [0x66; 32]],
        }
    }

    #[test]
    fn production_pcs_identity_has_stable_known_answers() {
        let identity = production_pcs_identity();
        identity.validate().unwrap();
        assert_eq!(
            u32::try_from(identity.weight_bank_commitments.len()).unwrap(),
            PRODUCTION_V2_BANKS
        );
        assert_eq!(
            identity.layers_per_bank * PRODUCTION_V2_BANKS,
            PRODUCTION_V2_LAYERS
        );
        assert_eq!(
            (
                identity.commitment_root().unwrap(),
                identity.digest().unwrap()
            ),
            (
                [
                    0xb6, 0x64, 0x9b, 0xc5, 0xc0, 0x2a, 0x18, 0x21, 0x17, 0x7a, 0xb4, 0x0c, 0x6a,
                    0x41, 0xcd, 0x5d, 0xf6, 0x82, 0x2f, 0x25, 0x48, 0x62, 0x2e, 0x3a, 0x25, 0x1f,
                    0x20, 0x29, 0x56, 0x42, 0x6e, 0x2b,
                ],
                [
                    0x91, 0x55, 0x75, 0xa5, 0x0d, 0x05, 0x11, 0x60, 0x91, 0x72, 0xf9, 0x63, 0x2a,
                    0x2d, 0xa7, 0x60, 0x78, 0x96, 0xbd, 0xc2, 0x54, 0xab, 0xc6, 0x58, 0xeb, 0x93,
                    0x1a, 0x05, 0xad, 0xfc, 0x48, 0x33,
                ],
            )
        );
    }

    #[test]
    fn pcs_identity_digest_binds_every_field_and_bank_order() {
        let identity = production_pcs_identity();
        let expected_digest = identity.digest().unwrap();
        let expected_root = identity.commitment_root().unwrap();

        let mut mutations = Vec::new();
        let mut mutated = identity.clone();
        mutated.model_version += 1;
        mutations.push(mutated);
        let mut mutated = identity.clone();
        mutated.batch *= 2;
        mutations.push(mutated);
        let mut mutated = identity.clone();
        mutated.dimension *= 2;
        mutations.push(mutated);
        let mut mutated = identity.clone();
        mutated.layers_per_bank *= 2;
        mutations.push(mutated);
        let mut mutated = identity.clone();
        mutated.model_byte_root[0] ^= 1;
        mutations.push(mutated);
        let mut mutated = identity.clone();
        mutated.pcs_suite_parameter_digest[0] ^= 1;
        mutations.push(mutated);
        let mut mutated = identity.clone();
        mutated.base_input_commitment[0] ^= 1;
        mutations.push(mutated);
        for bank_index in 0..identity.weight_bank_commitments.len() {
            let mut mutated = identity.clone();
            mutated.weight_bank_commitments[bank_index][0] ^= 1;
            mutations.push(mutated);
        }

        for mutated in mutations {
            assert_ne!(mutated.digest().unwrap(), expected_digest);
        }

        let mut reordered = identity;
        reordered.weight_bank_commitments.swap(0, 1);
        assert_ne!(reordered.commitment_root().unwrap(), expected_root);
        assert_ne!(reordered.digest().unwrap(), expected_digest);
    }

    #[test]
    fn pcs_identity_validation_rejects_noncanonical_or_uncommitted_inputs() {
        let identity = production_pcs_identity();

        let mut invalid = identity.clone();
        invalid.batch = 3;
        assert!(matches!(
            invalid.validate(),
            Err(ModelBankError::NonCanonicalPcsShape)
        ));

        let mut invalid = identity.clone();
        invalid.weight_bank_commitments.clear();
        assert!(matches!(
            invalid.validate(),
            Err(ModelBankError::InvalidPcsBankCount)
        ));

        let mut invalid = identity.clone();
        invalid.weight_bank_commitments.push([0x77; 32]);
        assert!(matches!(
            invalid.validate(),
            Err(ModelBankError::InvalidPcsBankCount)
        ));

        let mut invalid = identity.clone();
        invalid.layers_per_bank = 1 << 31;
        assert!(matches!(
            invalid.validate(),
            Err(ModelBankError::SizeOverflow)
        ));

        let mut invalid = identity.clone();
        invalid.model_byte_root = [0; 32];
        assert!(matches!(
            invalid.validate(),
            Err(ModelBankError::UncommittedPcsIdentity)
        ));

        let mut invalid = identity;
        invalid.weight_bank_commitments[2] = [0; 32];
        assert!(matches!(
            invalid.validate(),
            Err(ModelBankError::UncommittedPcsIdentity)
        ));
    }

    #[test]
    fn pcs_identity_validation_rejects_duplicate_fixed_role_commitments() {
        let identity = production_pcs_identity();

        let mut base_vs_weight = identity.clone();
        base_vs_weight.weight_bank_commitments[1] = base_vs_weight.base_input_commitment;
        assert!(matches!(
            base_vs_weight.validate(),
            Err(ModelBankError::DuplicatePcsRoleCommitment {
                first_role: 0,
                second_role: 2,
            })
        ));

        let mut weight_vs_weight = identity;
        weight_vs_weight.weight_bank_commitments[2] = weight_vs_weight.weight_bank_commitments[0];
        assert!(matches!(
            weight_vs_weight.validate(),
            Err(ModelBankError::DuplicatePcsRoleCommitment {
                first_role: 1,
                second_role: 3,
            })
        ));
    }

    #[test]
    fn manifest_requires_the_exact_pcs_identity() {
        let built = pcs_fixture();
        let identity = ModelPcsIdentity {
            model_version: built.manifest.model_version,
            batch: built.manifest.batch,
            dimension: built.manifest.dimension,
            layers_per_bank: 1,
            model_byte_root: built.manifest.raw_blake3_root,
            pcs_suite_parameter_digest: built.manifest.pcs_parameter_digest,
            base_input_commitment: [0x61; 32],
            weight_bank_commitments: vec![[0x71; 32], [0x72; 32]],
        };
        let mut manifest = built.manifest;
        manifest.pcs_commitment_root = identity.commitment_root().unwrap();
        manifest.verify_pcs_identity(&identity).unwrap();

        let mut wrong_shape = identity.clone();
        wrong_shape.batch *= 2;
        assert!(matches!(
            manifest.verify_pcs_identity(&wrong_shape),
            Err(ModelBankError::PcsIdentityShapeMismatch)
        ));

        let mut wrong_model = identity.clone();
        wrong_model.model_byte_root[0] ^= 1;
        assert!(matches!(
            manifest.verify_pcs_identity(&wrong_model),
            Err(ModelBankError::PcsIdentityModelRootMismatch)
        ));

        let mut wrong_parameters = identity.clone();
        wrong_parameters.pcs_suite_parameter_digest[0] ^= 1;
        assert!(matches!(
            manifest.verify_pcs_identity(&wrong_parameters),
            Err(ModelBankError::PcsParameterDigestMismatch)
        ));

        let mut reordered = identity;
        reordered.weight_bank_commitments.swap(0, 1);
        assert!(matches!(
            manifest.verify_pcs_identity(&reordered),
            Err(ModelBankError::PcsCommitmentRootMismatch)
        ));
    }

    #[test]
    fn canonical_fixture_streams_and_binds_every_manifest_field() {
        let built = fixture();
        verify_model_bank(Cursor::new(&built.bytes), &built.manifest).unwrap();

        assert_eq!(built.bytes.len(), MODEL_BANK_HEADER_BYTES + 24);
        assert_eq!(
            &built.bytes[MODEL_BANK_HEADER_BYTES..][..6],
            &[0, 1, 2, 3, 4, 5]
        );
        assert_eq!(
            &built.bytes[MODEL_BANK_HEADER_BYTES + 6..],
            &(6_u8..=23).collect::<Vec<_>>()
        );
        assert_ne!(built.manifest.digest().unwrap(), [0; 32]);
    }

    #[test]
    fn bad_magic_and_format_version_are_rejected() {
        let built = fixture();
        let mut bad_magic = built.bytes.clone();
        bad_magic[0] ^= 1;
        assert!(matches!(
            verify_model_bank(Cursor::new(bad_magic), &built.manifest),
            Err(ModelBankError::InvalidMagic)
        ));

        let mut bad_version = built.bytes.clone();
        bad_version[8..12].copy_from_slice(&3_u32.to_le_bytes());
        assert!(matches!(
            verify_model_bank(Cursor::new(bad_version), &built.manifest),
            Err(ModelBankError::UnsupportedFormatVersion)
        ));
    }

    #[test]
    fn header_and_payload_lengths_are_exact() {
        let built = fixture();
        let mut bad_header_length = built.bytes.clone();
        bad_header_length[12..16].copy_from_slice(&183_u32.to_le_bytes());
        assert!(matches!(
            verify_model_bank(Cursor::new(bad_header_length), &built.manifest),
            Err(ModelBankError::InvalidHeaderLength)
        ));

        let mut bad_payload_length = built.bytes.clone();
        bad_payload_length[BASE_LENGTH_OFFSET..BASE_LENGTH_OFFSET + 8]
            .copy_from_slice(&5_u64.to_le_bytes());
        assert!(matches!(
            verify_model_bank(Cursor::new(bad_payload_length), &built.manifest),
            Err(ModelBankError::NonCanonicalLengths)
        ));

        let truncated = &built.bytes[..built.bytes.len() - 1];
        assert!(matches!(
            verify_model_bank(Cursor::new(truncated), &built.manifest),
            Err(ModelBankError::Truncated)
        ));

        let mut trailing = built.bytes.clone();
        trailing.push(0);
        assert!(matches!(
            verify_model_bank(Cursor::new(trailing), &built.manifest),
            Err(ModelBankError::TrailingBytes)
        ));
    }

    #[test]
    fn every_payload_byte_is_integrity_bound() {
        let built = fixture();
        for payload_index in 0..built.manifest.payload_bytes as usize {
            let mut mutated = built.bytes.clone();
            mutated[MODEL_BANK_HEADER_BYTES + payload_index] ^= 1;
            assert!(matches!(
                verify_model_bank(Cursor::new(mutated), &built.manifest),
                Err(ModelBankError::RawRootMismatch)
            ));
        }
    }

    #[test]
    fn forbidden_values_are_rejected_before_hash_comparison() {
        let built = fixture();
        let mut mutated = built.bytes.clone();
        mutated[MODEL_BANK_HEADER_BYTES + 7] = 251;
        assert!(matches!(
            verify_model_bank(Cursor::new(mutated), &built.manifest),
            Err(ModelBankError::OutOfRange {
                offset: 7,
                value: 251
            })
        ));

        let base = [251];
        let layer = [0];
        assert!(matches!(
            build_small_model_bank(SmallModelBankFixture {
                model_version: 1,
                dimension: 1,
                batch: 1,
                base_input: &base,
                layers: &[&layer],
                pcs_parameter_digest: [1; 32],
                pcs_commitment_root: [2; 32],
            }),
            Err(ModelBankError::OutOfRange {
                offset: 0,
                value: 251
            })
        ));
    }

    #[test]
    fn trusted_pcs_identities_cannot_be_substituted() {
        let built = fixture();

        let mut bad_parameters = built.bytes.clone();
        bad_parameters[PCS_PARAMETER_OFFSET] ^= 1;
        assert!(matches!(
            verify_model_bank(Cursor::new(bad_parameters), &built.manifest),
            Err(ModelBankError::PcsParameterDigestMismatch)
        ));

        let mut bad_commitment = built.bytes.clone();
        bad_commitment[PCS_COMMITMENT_OFFSET] ^= 1;
        assert!(matches!(
            verify_model_bank(Cursor::new(bad_commitment), &built.manifest),
            Err(ModelBankError::PcsCommitmentRootMismatch)
        ));
    }

    #[test]
    fn descriptor_fields_and_roots_cannot_be_substituted() {
        let built = fixture();

        let mut bad_model_version = built.bytes.clone();
        bad_model_version[MODEL_VERSION_OFFSET..MODEL_VERSION_OFFSET + 4]
            .copy_from_slice(&3_u32.to_le_bytes());
        assert!(matches!(
            verify_model_bank(Cursor::new(bad_model_version), &built.manifest),
            Err(ModelBankError::ManifestMismatch)
        ));

        let mut bad_raw_root = built.bytes.clone();
        bad_raw_root[56] ^= 1;
        assert!(matches!(
            verify_model_bank(Cursor::new(bad_raw_root), &built.manifest),
            Err(ModelBankError::ManifestMismatch)
        ));

        let mut bad_layer_aggregate = built.bytes.clone();
        bad_layer_aggregate[88] ^= 1;
        assert!(matches!(
            verify_model_bank(Cursor::new(bad_layer_aggregate), &built.manifest),
            Err(ModelBankError::ManifestMismatch)
        ));

        let mut consistently_bad = built.bytes.clone();
        consistently_bad[88] ^= 1;
        let mut bad_expected = built.manifest;
        bad_expected.layer_roots_aggregate[0] ^= 1;
        assert!(matches!(
            verify_model_bank(Cursor::new(consistently_bad), &bad_expected),
            Err(ModelBankError::LayerRootsAggregateMismatch)
        ));
    }

    #[test]
    fn builder_rejects_wrong_shapes_and_has_a_hard_size_ceiling() {
        let base = [0; 3];
        let layer = [0; 4];
        assert!(matches!(
            build_small_model_bank(SmallModelBankFixture {
                model_version: 1,
                dimension: 2,
                batch: 2,
                base_input: &base,
                layers: &[&layer],
                pcs_parameter_digest: [1; 32],
                pcs_commitment_root: [2; 32],
            }),
            Err(ModelBankError::BaseInputLength)
        ));

        let manifest = ModelBankManifest {
            model_version: 1,
            dimension: 4096,
            batch: 128,
            layers: 384,
            base_input_bytes: 128 * 4096,
            bytes_per_layer: 4096 * 4096,
            payload_bytes: 128 * 4096 + 384 * 4096 * 4096,
            raw_blake3_root: [1; 32],
            layer_roots_aggregate: [2; 32],
            pcs_parameter_digest: [3; 32],
            pcs_commitment_root: [4; 32],
        };
        assert!(manifest.payload_bytes > MAX_SMALL_FIXTURE_PAYLOAD_BYTES);
        assert!(manifest.validate_shape().is_ok());

        let tiny = [0];
        assert!(matches!(
            build_small_model_bank(SmallModelBankFixture {
                model_version: 1,
                dimension: 4097,
                batch: 1,
                base_input: &tiny,
                layers: &[&tiny],
                pcs_parameter_digest: [1; 32],
                pcs_commitment_root: [2; 32],
            }),
            Err(ModelBankError::FixtureTooLarge)
        ));
    }
}
