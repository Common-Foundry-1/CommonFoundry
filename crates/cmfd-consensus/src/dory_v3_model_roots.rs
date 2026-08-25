//! Canonical production roots for the Dory V3 model-generation ceremony.
//!
//! The roots file is deliberately small, fixed-width, and non-extensible. Its
//! contents are derived by streaming the complete raw model payload; callers
//! cannot supply precomputed roots to the generator. Decoding is fail-closed:
//! the production geometry, every ordered layer index, the expected ceremony
//! identifier, the layer-root aggregate, and exact EOF must all agree.

use std::{
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

use blake3::Hasher;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    dory_v3_model_ceremony_fs::{
        AuthenticatedInput, CeremonyFsError, ParentSyncOutcome, PendingOutput,
        TrustedCeremonyParent,
    },
    dory_v3_suite::{DORY_V3_BATCH, DORY_V3_DIMENSION, DORY_V3_LAYERS, Digest32},
    model_bank::{MAX_MODEL_BYTE, add_layer_root, start_layer_aggregate},
};

pub const PRODUCTION_DORY_V3_MODEL_ROOTS_MAGIC: [u8; 8] = *b"CMFDMR01";
pub const PRODUCTION_DORY_V3_MODEL_ROOTS_VERSION: u16 = 1;
pub const PRODUCTION_DORY_V3_MODEL_ROOTS_BYTES: usize = 14_006;
pub const PRODUCTION_DORY_V3_BASE_INPUT_BYTES: u64 =
    DORY_V3_BATCH as u64 * DORY_V3_DIMENSION as u64;
pub const PRODUCTION_DORY_V3_LAYER_BYTES: u64 = DORY_V3_DIMENSION as u64 * DORY_V3_DIMENSION as u64;
pub const PRODUCTION_DORY_V3_PAYLOAD_BYTES: u64 =
    PRODUCTION_DORY_V3_BASE_INPUT_BYTES + DORY_V3_LAYERS as u64 * PRODUCTION_DORY_V3_LAYER_BYTES;

const STREAM_BUFFER_BYTES: usize = 64 * 1024;
const FIXED_PREFIX_BYTES: usize = 8 + 2 + 32 + 8 + 32 + 32 + 32 + 4;
const LAYER_RECORD_BYTES: usize = 4 + 32;
const FIXED_SUFFIX_BYTES: usize = 32;

const _: [(); PRODUCTION_DORY_V3_MODEL_ROOTS_BYTES] =
    [(); FIXED_PREFIX_BYTES + DORY_V3_LAYERS as usize * LAYER_RECORD_BYTES + FIXED_SUFFIX_BYTES];

/// Syntax-validated claims decoded from one exact `CMFDMR01` artifact.
///
/// This type is deliberately not payload authority. It proves only that the
/// bytes use the frozen codec and that their claimed layer aggregate is
/// internally consistent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionDoryV3ModelRootsClaims {
    ceremony_id: Digest32,
    raw_blake3: Digest32,
    raw_sha256: Digest32,
    base_input_blake3_root: Digest32,
    layer_roots: [Digest32; DORY_V3_LAYERS as usize],
    layer_roots_aggregate: Digest32,
}

/// Opaque roots authority minted only after two identical complete payload
/// scans agree with each other and, when supplied, with decoded claims.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionDoryV3ModelRoots {
    claims: ProductionDoryV3ModelRootsClaims,
}

/// Durability reached by a successful create-new roots-file publication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProductionDoryV3ModelRootsDurability {
    FileAndParentDirectorySynced,
    FileSyncedParentDirectorySyncAccessDeniedOnWindows,
    FileSyncedParentDirectorySyncUnsupportedOnWindows,
    FileSyncedParentDirectorySyncUnsupportedOnPlatform,
}

/// Result of generating, synchronizing, reopening, and validating a roots file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionDoryV3ModelRootsFileReport {
    roots: ProductionDoryV3ModelRoots,
    durability: ProductionDoryV3ModelRootsDurability,
}

impl ProductionDoryV3ModelRootsFileReport {
    pub const fn roots(&self) -> &ProductionDoryV3ModelRoots {
        &self.roots
    }

    pub const fn durability(&self) -> ProductionDoryV3ModelRootsDurability {
        self.durability
    }

    pub fn into_roots(self) -> ProductionDoryV3ModelRoots {
        self.roots
    }
}

impl ProductionDoryV3ModelRootsClaims {
    pub const fn ceremony_id(&self) -> Digest32 {
        self.ceremony_id
    }

    pub const fn payload_bytes(&self) -> u64 {
        PRODUCTION_DORY_V3_PAYLOAD_BYTES
    }

    pub const fn raw_blake3(&self) -> Digest32 {
        self.raw_blake3
    }

    pub const fn raw_sha256(&self) -> Digest32 {
        self.raw_sha256
    }

    pub const fn base_input_blake3_root(&self) -> Digest32 {
        self.base_input_blake3_root
    }

    pub const fn layer_roots(&self) -> &[Digest32] {
        &self.layer_roots
    }

    pub const fn layer_roots_aggregate(&self) -> Digest32 {
        self.layer_roots_aggregate
    }

    /// Encode the exact 14,006-byte `CMFDMR01` production artifact.
    pub fn canonical_bytes(&self) -> [u8; PRODUCTION_DORY_V3_MODEL_ROOTS_BYTES] {
        let mut output = [0_u8; PRODUCTION_DORY_V3_MODEL_ROOTS_BYTES];
        let mut offset = 0_usize;
        put(
            &mut output,
            &mut offset,
            &PRODUCTION_DORY_V3_MODEL_ROOTS_MAGIC,
        );
        put(
            &mut output,
            &mut offset,
            &PRODUCTION_DORY_V3_MODEL_ROOTS_VERSION.to_le_bytes(),
        );
        put(&mut output, &mut offset, self.ceremony_id.as_bytes());
        put(
            &mut output,
            &mut offset,
            &PRODUCTION_DORY_V3_PAYLOAD_BYTES.to_le_bytes(),
        );
        put(&mut output, &mut offset, self.raw_blake3.as_bytes());
        put(&mut output, &mut offset, self.raw_sha256.as_bytes());
        put(
            &mut output,
            &mut offset,
            self.base_input_blake3_root.as_bytes(),
        );
        put(&mut output, &mut offset, &DORY_V3_LAYERS.to_le_bytes());
        for (index, root) in self.layer_roots.iter().enumerate() {
            put(&mut output, &mut offset, &(index as u32).to_le_bytes());
            put(&mut output, &mut offset, root.as_bytes());
        }
        put(
            &mut output,
            &mut offset,
            self.layer_roots_aggregate.as_bytes(),
        );
        debug_assert_eq!(offset, PRODUCTION_DORY_V3_MODEL_ROOTS_BYTES);
        output
    }

    /// Parse and syntax-validate one exact production roots artifact.
    ///
    /// A slice makes exact EOF unambiguous: shorter and longer encodings are
    /// both rejected before any field is trusted.
    pub fn parse_and_validate(
        bytes: &[u8],
        expected_ceremony_id: Digest32,
    ) -> Result<Self, ProductionDoryV3ModelRootsError> {
        if bytes.len() != PRODUCTION_DORY_V3_MODEL_ROOTS_BYTES {
            return Err(ProductionDoryV3ModelRootsError::EncodedLength {
                expected: PRODUCTION_DORY_V3_MODEL_ROOTS_BYTES,
                actual: bytes.len(),
            });
        }

        let mut offset = 0_usize;
        if take::<8>(bytes, &mut offset) != PRODUCTION_DORY_V3_MODEL_ROOTS_MAGIC {
            return Err(ProductionDoryV3ModelRootsError::Magic);
        }
        let version = u16::from_le_bytes(take::<2>(bytes, &mut offset));
        if version != PRODUCTION_DORY_V3_MODEL_ROOTS_VERSION {
            return Err(ProductionDoryV3ModelRootsError::Version { actual: version });
        }
        let ceremony_id = Digest32::new(take::<32>(bytes, &mut offset));
        if ceremony_id != expected_ceremony_id {
            return Err(ProductionDoryV3ModelRootsError::CeremonyId);
        }
        let payload_bytes = u64::from_le_bytes(take::<8>(bytes, &mut offset));
        if payload_bytes != PRODUCTION_DORY_V3_PAYLOAD_BYTES {
            return Err(ProductionDoryV3ModelRootsError::PayloadBytes {
                actual: payload_bytes,
            });
        }
        let raw_blake3 = Digest32::new(take::<32>(bytes, &mut offset));
        let raw_sha256 = Digest32::new(take::<32>(bytes, &mut offset));
        let base_input_blake3_root = Digest32::new(take::<32>(bytes, &mut offset));
        let layer_count = u32::from_le_bytes(take::<4>(bytes, &mut offset));
        if layer_count != DORY_V3_LAYERS {
            return Err(ProductionDoryV3ModelRootsError::LayerCount {
                actual: layer_count,
            });
        }

        let mut layer_roots = [Digest32::ZERO; DORY_V3_LAYERS as usize];
        for (position, root) in layer_roots.iter_mut().enumerate() {
            let actual = u32::from_le_bytes(take::<4>(bytes, &mut offset));
            let expected = position as u32;
            if actual != expected {
                return Err(ProductionDoryV3ModelRootsError::LayerIndex {
                    position: expected,
                    actual,
                });
            }
            *root = Digest32::new(take::<32>(bytes, &mut offset));
        }
        let layer_roots_aggregate = Digest32::new(take::<32>(bytes, &mut offset));
        debug_assert_eq!(offset, bytes.len());

        let expected_aggregate = aggregate_layer_roots(&layer_roots);
        if layer_roots_aggregate != expected_aggregate {
            return Err(ProductionDoryV3ModelRootsError::LayerRootsAggregate);
        }

        Ok(Self {
            ceremony_id,
            raw_blake3,
            raw_sha256,
            base_input_blake3_root,
            layer_roots,
            layer_roots_aggregate,
        })
    }
}

impl ProductionDoryV3ModelRoots {
    pub const fn ceremony_id(&self) -> Digest32 {
        self.claims.ceremony_id()
    }

    pub const fn payload_bytes(&self) -> u64 {
        self.claims.payload_bytes()
    }

    pub const fn raw_blake3(&self) -> Digest32 {
        self.claims.raw_blake3()
    }

    pub const fn raw_sha256(&self) -> Digest32 {
        self.claims.raw_sha256()
    }

    pub const fn base_input_blake3_root(&self) -> Digest32 {
        self.claims.base_input_blake3_root()
    }

    pub const fn layer_roots(&self) -> &[Digest32] {
        self.claims.layer_roots()
    }

    pub const fn layer_roots_aggregate(&self) -> Digest32 {
        self.claims.layer_roots_aggregate()
    }

    pub fn canonical_bytes(&self) -> [u8; PRODUCTION_DORY_V3_MODEL_ROOTS_BYTES] {
        self.claims.canonical_bytes()
    }
}

#[derive(Debug, Error)]
pub enum ProductionDoryV3ModelRootsError {
    #[error("roots encoding length mismatch: expected {expected} bytes, found {actual}")]
    EncodedLength { expected: usize, actual: usize },
    #[error("invalid CMFDMR01 magic")]
    Magic,
    #[error("unsupported CMFDMR01 version {actual}")]
    Version { actual: u16 },
    #[error("roots ceremony identifier does not match the expected ceremony")]
    CeremonyId,
    #[error("roots payload length is not the frozen production length: found {actual} bytes")]
    PayloadBytes { actual: u64 },
    #[error("roots layer count is not the frozen production count: found {actual}")]
    LayerCount { actual: u32 },
    #[error("roots layer index mismatch at position {position}: found {actual}")]
    LayerIndex { position: u32, actual: u32 },
    #[error("roots layer aggregate does not authenticate the ordered layer roots")]
    LayerRootsAggregate,
    #[error("payload ended early: expected {expected} bytes, read {actual}")]
    PayloadEarlyEof { expected: u64, actual: u64 },
    #[error("payload contains bytes after its frozen production length")]
    PayloadTrailingBytes,
    #[error("payload byte {offset} has forbidden value {value}; maximum is 250")]
    PayloadByte { offset: u64, value: u8 },
    #[error("failed while streaming the raw payload: {0}")]
    PayloadRead(#[source] std::io::Error),
    #[error("payload path is not a regular, non-link file: {0}")]
    PayloadNotRegular(PathBuf),
    #[error("payload path is a reparse point and is rejected: {0}")]
    PayloadReparsePoint(PathBuf),
    #[error("payload has an unexpected hard-link count of {links}: {path}")]
    PayloadHardLinks { path: PathBuf, links: u64 },
    #[error("payload path was replaced or no longer names the retained file: {0}")]
    PayloadIdentity(PathBuf),
    #[error("payload length mismatch: expected {expected} bytes, found {actual}")]
    PayloadFileLength { expected: u64, actual: u64 },
    #[error("failed to open or inspect payload {path}: {source}")]
    OpenPayload {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("the roots artifact does not match roots independently derived from the payload")]
    PayloadRootsMismatch,
    #[error("the payload produced different roots across two complete scans")]
    PayloadChangedBetweenScans,
    #[error("the roots artifact changed during independent payload validation")]
    RootsChangedDuringValidation,
    #[error("refusing to overwrite existing roots output: {0}")]
    OutputExists(PathBuf),
    #[error("roots output parent is not a real, non-reparse directory: {0}")]
    UnsafeOutputParent(PathBuf),
    #[error("failed to create roots output {path}: {source}")]
    CreateOutput {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to make the roots output private at {path}: {source}")]
    SetOutputPermissions {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to write or synchronize roots output {path}: {source}")]
    WriteOutput {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to reopen or inspect roots output {path}: {source}")]
    ReopenOutput {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("roots output path is not a regular, non-link file: {0}")]
    OutputNotRegular(PathBuf),
    #[error("roots output path is a reparse point and is rejected: {0}")]
    OutputReparsePoint(PathBuf),
    #[error("roots output has an unexpected hard-link count of {links}: {path}")]
    OutputHardLinks { path: PathBuf, links: u64 },
    #[error("roots output path is not the retained create-new file: {0}")]
    OutputIdentity(PathBuf),
    #[error("reopened roots output differs from the generated artifact")]
    ReopenedOutputMismatch,
    #[error("failed to synchronize roots output parent {path}: {source}")]
    SyncParent {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to remove unconfirmed roots output {path}: {source}")]
    Cleanup {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "unconfirmed roots output remains quarantined at {path}; original failure: {original}; cleanup failure: {cleanup}"
    )]
    QuarantinedOutput {
        path: PathBuf,
        original: String,
        cleanup: String,
    },
}

/// Derive all production roots by streaming the complete raw payload.
///
/// Memory use is bounded by one 64 KiB byte buffer plus the 384 roots. The
/// reader must contain exactly the frozen 6,442,975,232-byte payload and EOF,
/// with every byte in `0..=250`.
pub fn derive_production_dory_v3_model_roots<R: Read + Seek>(
    payload: &mut R,
    ceremony_id: Digest32,
) -> Result<ProductionDoryV3ModelRoots, ProductionDoryV3ModelRootsError> {
    let derived = derive_payload_roots_twice(payload, ProductionPayloadGeometry::PRODUCTION)?;
    let layer_roots: [Digest32; DORY_V3_LAYERS as usize] = derived
        .layer_roots
        .try_into()
        .expect("the frozen production geometry always emits exactly 384 layer roots");
    Ok(ProductionDoryV3ModelRoots {
        claims: ProductionDoryV3ModelRootsClaims {
            ceremony_id,
            raw_blake3: derived.raw_blake3,
            raw_sha256: derived.raw_sha256,
            base_input_blake3_root: derived.base_input_blake3_root,
            layer_roots,
            layer_roots_aggregate: derived.layer_roots_aggregate,
        },
    })
}

/// Parse one exact roots artifact and independently rescan the complete raw
/// payload, accepting only byte-for-byte agreement with every derived field.
pub fn validate_production_dory_v3_model_roots_against_payload<R: Read + Seek>(
    roots_bytes: &[u8],
    payload: &mut R,
    expected_ceremony_id: Digest32,
) -> Result<ProductionDoryV3ModelRoots, ProductionDoryV3ModelRootsError> {
    let claimed =
        ProductionDoryV3ModelRootsClaims::parse_and_validate(roots_bytes, expected_ceremony_id)?;
    let derived = derive_payload_roots_twice(payload, ProductionPayloadGeometry::PRODUCTION)?;
    if derived != DerivedPayloadRoots::from(&claimed) {
        return Err(ProductionDoryV3ModelRootsError::PayloadRootsMismatch);
    }
    Ok(ProductionDoryV3ModelRoots { claims: claimed })
}

/// Validate an exact roots file against a payload file while retaining and
/// rechecking both path identities across the complete payload scan.
pub fn validate_production_dory_v3_model_roots_files<P: AsRef<Path>, Q: AsRef<Path>>(
    roots_path: P,
    payload_path: Q,
    expected_ceremony_id: Digest32,
) -> Result<ProductionDoryV3ModelRoots, ProductionDoryV3ModelRootsError> {
    let roots_path = roots_path.as_ref();
    let payload_path = payload_path.as_ref();
    let roots_parent =
        TrustedCeremonyParent::for_artifact(roots_path).map_err(map_roots_input_fs)?;
    let payload_parent_holder = if payload_path.parent() == roots_path.parent() {
        None
    } else {
        Some(TrustedCeremonyParent::for_artifact(payload_path).map_err(map_payload_fs)?)
    };
    let payload_parent = payload_parent_holder.as_ref().unwrap_or(&roots_parent);
    let mut roots_input = AuthenticatedInput::open(
        &roots_parent,
        roots_path,
        Some(PRODUCTION_DORY_V3_MODEL_ROOTS_BYTES as u64),
    )
    .map_err(map_roots_input_fs)?;
    let roots_read = roots_input
        .read_bounded(PRODUCTION_DORY_V3_MODEL_ROOTS_BYTES)
        .map_err(map_roots_input_fs);
    let roots_recheck = roots_input
        .recheck(
            &roots_parent,
            Some(PRODUCTION_DORY_V3_MODEL_ROOTS_BYTES as u64),
        )
        .map_err(map_roots_input_fs);
    roots_recheck?;
    let roots_bytes = roots_read?;

    let mut payload = AuthenticatedInput::open(
        payload_parent,
        payload_path,
        Some(PRODUCTION_DORY_V3_PAYLOAD_BYTES),
    )
    .map_err(map_payload_fs)?;
    let validation = validate_production_dory_v3_model_roots_against_payload(
        &roots_bytes,
        payload.file_mut(),
        expected_ceremony_id,
    );
    let payload_recheck = payload
        .recheck(payload_parent, Some(PRODUCTION_DORY_V3_PAYLOAD_BYTES))
        .map_err(map_payload_fs);
    let roots_recheck = roots_input
        .recheck(
            &roots_parent,
            Some(PRODUCTION_DORY_V3_MODEL_ROOTS_BYTES as u64),
        )
        .map_err(map_roots_input_fs);
    payload_recheck?;
    roots_recheck?;
    let validated = validation?;
    let final_read = roots_input
        .read_bounded(PRODUCTION_DORY_V3_MODEL_ROOTS_BYTES)
        .map_err(map_roots_input_fs);
    let final_recheck = roots_input
        .recheck(
            &roots_parent,
            Some(PRODUCTION_DORY_V3_MODEL_ROOTS_BYTES as u64),
        )
        .map_err(map_roots_input_fs);
    final_recheck?;
    let final_roots_bytes = final_read?;
    if final_roots_bytes != roots_bytes {
        return Err(ProductionDoryV3ModelRootsError::RootsChangedDuringValidation);
    }
    Ok(validated)
}

/// Stream one production payload into a create-new roots file, synchronize it,
/// reopen it, and validate the exact persisted bytes before returning success.
pub fn generate_production_dory_v3_model_roots_file<P: AsRef<Path>, Q: AsRef<Path>>(
    payload_path: P,
    roots_output_path: Q,
    ceremony_id: Digest32,
) -> Result<ProductionDoryV3ModelRootsFileReport, ProductionDoryV3ModelRootsError> {
    let payload_path = payload_path.as_ref();
    let output_path = roots_output_path.as_ref();
    let payload_parent =
        TrustedCeremonyParent::for_artifact(payload_path).map_err(map_payload_fs)?;
    let output_parent_holder = if output_path.parent() == payload_path.parent() {
        None
    } else {
        Some(TrustedCeremonyParent::for_artifact(output_path).map_err(map_output_fs)?)
    };
    let output_parent = output_parent_holder.as_ref().unwrap_or(&payload_parent);
    output_parent
        .preflight_output(output_path)
        .map_err(map_output_fs)?;
    let mut payload = AuthenticatedInput::open(
        &payload_parent,
        payload_path,
        Some(PRODUCTION_DORY_V3_PAYLOAD_BYTES),
    )
    .map_err(map_payload_fs)?;
    let derivation = derive_production_dory_v3_model_roots(payload.file_mut(), ceremony_id);
    let payload_recheck = payload
        .recheck(&payload_parent, Some(PRODUCTION_DORY_V3_PAYLOAD_BYTES))
        .map_err(map_payload_fs);
    let output_recheck = output_parent.recheck().map_err(map_output_fs);
    payload_recheck?;
    output_recheck?;
    let roots = derivation?;
    let (roots, durability) =
        persist_create_new_and_reopen(output_parent, output_path, &roots, || {
            payload
                .recheck(&payload_parent, Some(PRODUCTION_DORY_V3_PAYLOAD_BYTES))
                .map_err(map_payload_fs)
        })?;
    Ok(ProductionDoryV3ModelRootsFileReport { roots, durability })
}

#[derive(Clone, Copy)]
struct ProductionPayloadGeometry {
    base_input_bytes: u64,
    layer_bytes: u64,
    layers: u32,
}

impl ProductionPayloadGeometry {
    const PRODUCTION: Self = Self {
        base_input_bytes: PRODUCTION_DORY_V3_BASE_INPUT_BYTES,
        layer_bytes: PRODUCTION_DORY_V3_LAYER_BYTES,
        layers: DORY_V3_LAYERS,
    };

    fn payload_bytes(self) -> u64 {
        self.base_input_bytes + u64::from(self.layers) * self.layer_bytes
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DerivedPayloadRoots {
    raw_blake3: Digest32,
    raw_sha256: Digest32,
    base_input_blake3_root: Digest32,
    layer_roots: Vec<Digest32>,
    layer_roots_aggregate: Digest32,
}

impl From<&ProductionDoryV3ModelRoots> for DerivedPayloadRoots {
    fn from(roots: &ProductionDoryV3ModelRoots) -> Self {
        Self::from(&roots.claims)
    }
}

impl From<&ProductionDoryV3ModelRootsClaims> for DerivedPayloadRoots {
    fn from(roots: &ProductionDoryV3ModelRootsClaims) -> Self {
        Self {
            raw_blake3: roots.raw_blake3(),
            raw_sha256: roots.raw_sha256(),
            base_input_blake3_root: roots.base_input_blake3_root(),
            layer_roots: roots.layer_roots().to_vec(),
            layer_roots_aggregate: roots.layer_roots_aggregate(),
        }
    }
}

#[cfg(test)]
fn validate_payload_roots<R: Read>(
    payload: R,
    geometry: ProductionPayloadGeometry,
    expected: &DerivedPayloadRoots,
) -> Result<(), ProductionDoryV3ModelRootsError> {
    let actual = derive_payload_roots(payload, geometry)?;
    if &actual != expected {
        return Err(ProductionDoryV3ModelRootsError::PayloadRootsMismatch);
    }
    Ok(())
}

fn derive_payload_roots_twice<R: Read + Seek>(
    payload: &mut R,
    geometry: ProductionPayloadGeometry,
) -> Result<DerivedPayloadRoots, ProductionDoryV3ModelRootsError> {
    payload
        .seek(SeekFrom::Start(0))
        .map_err(ProductionDoryV3ModelRootsError::PayloadRead)?;
    let first = derive_payload_roots(&mut *payload, geometry)?;
    payload
        .seek(SeekFrom::Start(0))
        .map_err(ProductionDoryV3ModelRootsError::PayloadRead)?;
    let second = derive_payload_roots(&mut *payload, geometry)?;
    if first != second {
        return Err(ProductionDoryV3ModelRootsError::PayloadChangedBetweenScans);
    }
    Ok(first)
}

fn derive_payload_roots<R: Read>(
    mut payload: R,
    geometry: ProductionPayloadGeometry,
) -> Result<DerivedPayloadRoots, ProductionDoryV3ModelRootsError> {
    let expected_bytes = geometry.payload_bytes();
    let mut payload_offset = 0_u64;
    let mut buffer = [0_u8; STREAM_BUFFER_BYTES];
    let mut raw_blake3 = Hasher::new();
    let mut raw_sha256 = Sha256::new();

    let base_input_blake3_root = stream_section(
        &mut payload,
        geometry.base_input_bytes,
        expected_bytes,
        &mut payload_offset,
        &mut buffer,
        &mut raw_blake3,
        &mut raw_sha256,
    )?;

    let mut layer_roots = Vec::with_capacity(geometry.layers as usize);
    let mut layer_aggregate = start_layer_aggregate(geometry.layers);
    for layer_index in 0..geometry.layers {
        let root = stream_section(
            &mut payload,
            geometry.layer_bytes,
            expected_bytes,
            &mut payload_offset,
            &mut buffer,
            &mut raw_blake3,
            &mut raw_sha256,
        )?;
        add_layer_root(
            &mut layer_aggregate,
            layer_index,
            blake3::Hash::from_bytes(root.into_bytes()),
        );
        layer_roots.push(root);
    }
    debug_assert_eq!(payload_offset, expected_bytes);

    let mut trailing = [0_u8; 1];
    loop {
        match payload.read(&mut trailing) {
            Ok(0) => break,
            Ok(_) => return Err(ProductionDoryV3ModelRootsError::PayloadTrailingBytes),
            Err(source) if source.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(source) => return Err(ProductionDoryV3ModelRootsError::PayloadRead(source)),
        }
    }

    Ok(DerivedPayloadRoots {
        raw_blake3: Digest32::new(*raw_blake3.finalize().as_bytes()),
        raw_sha256: Digest32::new(raw_sha256.finalize().into()),
        base_input_blake3_root,
        layer_roots,
        layer_roots_aggregate: Digest32::new(*layer_aggregate.finalize().as_bytes()),
    })
}

#[allow(clippy::too_many_arguments)]
fn stream_section<R: Read>(
    payload: &mut R,
    section_bytes: u64,
    expected_payload_bytes: u64,
    payload_offset: &mut u64,
    buffer: &mut [u8; STREAM_BUFFER_BYTES],
    raw_blake3: &mut Hasher,
    raw_sha256: &mut Sha256,
) -> Result<Digest32, ProductionDoryV3ModelRootsError> {
    let mut section_remaining = section_bytes;
    let mut section_blake3 = Hasher::new();
    while section_remaining != 0 {
        let take = usize::try_from(section_remaining.min(STREAM_BUFFER_BYTES as u64))
            .expect("the bounded stream buffer length fits usize");
        let read = loop {
            match payload.read(&mut buffer[..take]) {
                Ok(0) => {
                    return Err(ProductionDoryV3ModelRootsError::PayloadEarlyEof {
                        expected: expected_payload_bytes,
                        actual: *payload_offset,
                    });
                }
                Ok(read) => break read,
                Err(source) if source.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(source) => {
                    return Err(ProductionDoryV3ModelRootsError::PayloadRead(source));
                }
            }
        };

        for (index, value) in buffer[..read].iter().copied().enumerate() {
            if value > MAX_MODEL_BYTE {
                return Err(ProductionDoryV3ModelRootsError::PayloadByte {
                    offset: *payload_offset + index as u64,
                    value,
                });
            }
        }
        raw_blake3.update(&buffer[..read]);
        raw_sha256.update(&buffer[..read]);
        section_blake3.update(&buffer[..read]);
        *payload_offset += read as u64;
        section_remaining -= read as u64;
    }
    Ok(Digest32::new(*section_blake3.finalize().as_bytes()))
}

fn aggregate_layer_roots(layer_roots: &[Digest32]) -> Digest32 {
    let layer_count =
        u32::try_from(layer_roots.len()).expect("the fixed production layer count fits in u32");
    let mut aggregate = start_layer_aggregate(layer_count);
    for (index, root) in layer_roots.iter().copied().enumerate() {
        add_layer_root(
            &mut aggregate,
            index as u32,
            blake3::Hash::from_bytes(root.into_bytes()),
        );
    }
    Digest32::new(*aggregate.finalize().as_bytes())
}

fn persist_create_new_and_reopen<F>(
    parent: &TrustedCeremonyParent,
    output_path: &Path,
    roots: &ProductionDoryV3ModelRoots,
    before_confirm: F,
) -> Result<
    (
        ProductionDoryV3ModelRoots,
        ProductionDoryV3ModelRootsDurability,
    ),
    ProductionDoryV3ModelRootsError,
>
where
    F: FnOnce() -> Result<(), ProductionDoryV3ModelRootsError>,
{
    let mut pending = PendingOutput::create(parent, output_path).map_err(map_output_fs)?;
    let completion = (|| {
        let encoded = roots.canonical_bytes();
        pending.write_all(&encoded).map_err(map_output_fs)?;
        pending.sync_file().map_err(map_output_fs)?;
        let persisted = pending
            .reopen_exact(parent, &encoded)
            .map_err(map_output_fs)?;
        let reopened_claims =
            ProductionDoryV3ModelRootsClaims::parse_and_validate(&persisted, roots.ceremony_id())?;
        if reopened_claims != roots.claims {
            return Err(ProductionDoryV3ModelRootsError::ReopenedOutputMismatch);
        }
        let durability = map_roots_durability(pending.sync_parent(parent).map_err(map_output_fs)?);
        before_confirm()?;
        Ok((roots.clone(), durability))
    })();
    match completion {
        Ok(value) => match pending.confirm(parent) {
            Ok(()) => Ok(value),
            Err(error) => Err(cleanup_domain_output_error(
                &mut pending,
                parent,
                map_output_fs(error),
            )),
        },
        Err(error) => Err(cleanup_domain_output_error(&mut pending, parent, error)),
    }
}

fn map_roots_durability(durability: ParentSyncOutcome) -> ProductionDoryV3ModelRootsDurability {
    match durability {
        ParentSyncOutcome::Synced => {
            ProductionDoryV3ModelRootsDurability::FileAndParentDirectorySynced
        }
        #[cfg(windows)]
        ParentSyncOutcome::WindowsAccessDenied => {
            ProductionDoryV3ModelRootsDurability::FileSyncedParentDirectorySyncAccessDeniedOnWindows
        }
        #[cfg(windows)]
        ParentSyncOutcome::WindowsUnsupported => {
            ProductionDoryV3ModelRootsDurability::FileSyncedParentDirectorySyncUnsupportedOnWindows
        }
        #[cfg(not(any(unix, windows)))]
        ParentSyncOutcome::PlatformUnsupported => {
            ProductionDoryV3ModelRootsDurability::FileSyncedParentDirectorySyncUnsupportedOnPlatform
        }
    }
}

fn map_payload_fs(error: CeremonyFsError) -> ProductionDoryV3ModelRootsError {
    match error {
        CeremonyFsError::InputNotRegular(path) => {
            ProductionDoryV3ModelRootsError::PayloadNotRegular(path)
        }
        CeremonyFsError::InputReparsePoint(path) => {
            ProductionDoryV3ModelRootsError::PayloadReparsePoint(path)
        }
        CeremonyFsError::InputHardLinks { path, links } => {
            ProductionDoryV3ModelRootsError::PayloadHardLinks { path, links }
        }
        CeremonyFsError::InputLength { expected, actual } => {
            ProductionDoryV3ModelRootsError::PayloadFileLength { expected, actual }
        }
        CeremonyFsError::ParentIdentity(path) | CeremonyFsError::InputIdentity(path) => {
            ProductionDoryV3ModelRootsError::PayloadIdentity(path)
        }
        CeremonyFsError::OpenInput { path, source }
        | CeremonyFsError::InspectParent { path, source } => {
            ProductionDoryV3ModelRootsError::OpenPayload { path, source }
        }
        other => {
            let path = ceremony_fs_error_path(&other);
            ProductionDoryV3ModelRootsError::OpenPayload {
                path,
                source: std::io::Error::other(other.to_string()),
            }
        }
    }
}

fn map_roots_input_fs(error: CeremonyFsError) -> ProductionDoryV3ModelRootsError {
    match error {
        CeremonyFsError::InputNotRegular(path) => {
            ProductionDoryV3ModelRootsError::OutputNotRegular(path)
        }
        CeremonyFsError::InputReparsePoint(path) => {
            ProductionDoryV3ModelRootsError::OutputReparsePoint(path)
        }
        CeremonyFsError::InputHardLinks { path, links } => {
            ProductionDoryV3ModelRootsError::OutputHardLinks { path, links }
        }
        CeremonyFsError::InputLength { expected, actual } => {
            ProductionDoryV3ModelRootsError::EncodedLength {
                expected: usize::try_from(expected).unwrap_or(usize::MAX),
                actual: usize::try_from(actual).unwrap_or(usize::MAX),
            }
        }
        CeremonyFsError::ParentIdentity(path) | CeremonyFsError::InputIdentity(path) => {
            ProductionDoryV3ModelRootsError::OutputIdentity(path)
        }
        CeremonyFsError::OpenInput { path, source }
        | CeremonyFsError::InspectParent { path, source } => {
            ProductionDoryV3ModelRootsError::ReopenOutput { path, source }
        }
        other => {
            let path = ceremony_fs_error_path(&other);
            ProductionDoryV3ModelRootsError::ReopenOutput {
                path,
                source: std::io::Error::other(other.to_string()),
            }
        }
    }
}

fn map_output_fs(error: CeremonyFsError) -> ProductionDoryV3ModelRootsError {
    match error {
        CeremonyFsError::InvalidArtifactPath(path) | CeremonyFsError::UnsafeParent(path) => {
            ProductionDoryV3ModelRootsError::UnsafeOutputParent(path)
        }
        CeremonyFsError::InspectParent { path, source }
        | CeremonyFsError::CreateOutput { path, source } => {
            ProductionDoryV3ModelRootsError::CreateOutput { path, source }
        }
        CeremonyFsError::ParentIdentity(path) | CeremonyFsError::OutputIdentity(path) => {
            ProductionDoryV3ModelRootsError::OutputIdentity(path)
        }
        CeremonyFsError::OutputExists(path) => ProductionDoryV3ModelRootsError::OutputExists(path),
        CeremonyFsError::SetOutputPermissions { path, source } => {
            ProductionDoryV3ModelRootsError::SetOutputPermissions { path, source }
        }
        CeremonyFsError::WriteOutput { path, source } => {
            ProductionDoryV3ModelRootsError::WriteOutput { path, source }
        }
        CeremonyFsError::ReopenOutput { path, source } => {
            ProductionDoryV3ModelRootsError::ReopenOutput { path, source }
        }
        CeremonyFsError::OutputNotRegular(path) => {
            ProductionDoryV3ModelRootsError::OutputNotRegular(path)
        }
        CeremonyFsError::OutputReparsePoint(path) => {
            ProductionDoryV3ModelRootsError::OutputReparsePoint(path)
        }
        CeremonyFsError::OutputHardLinks { path, links } => {
            ProductionDoryV3ModelRootsError::OutputHardLinks { path, links }
        }
        CeremonyFsError::ReopenedOutputMismatch => {
            ProductionDoryV3ModelRootsError::ReopenedOutputMismatch
        }
        CeremonyFsError::SyncParent { path, source } => {
            ProductionDoryV3ModelRootsError::SyncParent { path, source }
        }
        CeremonyFsError::CleanupOutput { path, source } => {
            ProductionDoryV3ModelRootsError::Cleanup { path, source }
        }
        CeremonyFsError::QuarantinedOutput {
            path,
            original,
            cleanup,
        } => ProductionDoryV3ModelRootsError::QuarantinedOutput {
            path,
            original,
            cleanup,
        },
        other => {
            let path = ceremony_fs_error_path(&other);
            ProductionDoryV3ModelRootsError::CreateOutput {
                path,
                source: std::io::Error::other(other.to_string()),
            }
        }
    }
}

fn ceremony_fs_error_path(error: &CeremonyFsError) -> PathBuf {
    match error {
        CeremonyFsError::InvalidArtifactPath(path)
        | CeremonyFsError::UnsafeParent(path)
        | CeremonyFsError::ParentIdentity(path)
        | CeremonyFsError::InputNotRegular(path)
        | CeremonyFsError::InputReparsePoint(path)
        | CeremonyFsError::InputIdentity(path)
        | CeremonyFsError::OutputExists(path)
        | CeremonyFsError::OutputNotRegular(path)
        | CeremonyFsError::OutputReparsePoint(path)
        | CeremonyFsError::OutputIdentity(path) => path.clone(),
        CeremonyFsError::InspectParent { path, .. }
        | CeremonyFsError::OpenInput { path, .. }
        | CeremonyFsError::InputHardLinks { path, .. }
        | CeremonyFsError::CreateOutput { path, .. }
        | CeremonyFsError::SetOutputPermissions { path, .. }
        | CeremonyFsError::WriteOutput { path, .. }
        | CeremonyFsError::ReopenOutput { path, .. }
        | CeremonyFsError::OutputHardLinks { path, .. }
        | CeremonyFsError::SyncParent { path, .. }
        | CeremonyFsError::CleanupOutput { path, .. }
        | CeremonyFsError::QuarantinedOutput { path, .. } => path.clone(),
        CeremonyFsError::InputLength { .. } | CeremonyFsError::ReopenedOutputMismatch => {
            PathBuf::from("<ceremony-artifact>")
        }
    }
}

fn cleanup_domain_output_error(
    pending: &mut PendingOutput,
    parent: &TrustedCeremonyParent,
    original: ProductionDoryV3ModelRootsError,
) -> ProductionDoryV3ModelRootsError {
    match pending.remove_explicit(parent) {
        Ok(()) => original,
        Err(cleanup) if pending.was_removed() => map_output_fs(cleanup),
        Err(cleanup) => ProductionDoryV3ModelRootsError::QuarantinedOutput {
            path: ceremony_fs_error_path(&cleanup),
            original: original.to_string(),
            cleanup: cleanup.to_string(),
        },
    }
}

fn put<const N: usize>(output: &mut [u8; N], offset: &mut usize, value: &[u8]) {
    let end = *offset + value.len();
    output[*offset..end].copy_from_slice(value);
    *offset = end;
}

fn take<const N: usize>(input: &[u8], offset: &mut usize) -> [u8; N] {
    let end = *offset + N;
    let value = input[*offset..end]
        .try_into()
        .expect("the exact fixed-width roots encoding was length-checked");
    *offset = end;
    value
}

#[cfg(test)]
mod tests {
    #[cfg(windows)]
    use std::fs::OpenOptions;
    use std::{
        fs,
        io::Cursor,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;

    static TEMP_NONCE: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn frozen_geometry_and_encoding_size_are_exact() {
        assert_eq!(PRODUCTION_DORY_V3_BASE_INPUT_BYTES, 524_288);
        assert_eq!(PRODUCTION_DORY_V3_LAYER_BYTES, 16_777_216);
        assert_eq!(PRODUCTION_DORY_V3_PAYLOAD_BYTES, 6_442_975_232);
        assert_eq!(PRODUCTION_DORY_V3_MODEL_ROOTS_BYTES, 14_006);
        assert_eq!(
            PRODUCTION_DORY_V3_MODEL_ROOTS_BYTES,
            FIXED_PREFIX_BYTES + DORY_V3_LAYERS as usize * LAYER_RECORD_BYTES + FIXED_SUFFIX_BYTES
        );
    }

    #[test]
    fn canonical_codec_round_trips_every_field() {
        let roots = fixture_roots();
        let bytes = roots.canonical_bytes();
        assert_eq!(&bytes[..8], b"CMFDMR01");
        assert_eq!(u16::from_le_bytes(bytes[8..10].try_into().unwrap()), 1);
        assert_eq!(
            u64::from_le_bytes(bytes[42..50].try_into().unwrap()),
            PRODUCTION_DORY_V3_PAYLOAD_BYTES
        );
        assert_eq!(
            u32::from_le_bytes(bytes[146..150].try_into().unwrap()),
            DORY_V3_LAYERS
        );
        assert_eq!(bytes.len(), 14_006);

        let decoded =
            ProductionDoryV3ModelRootsClaims::parse_and_validate(&bytes, roots.ceremony_id())
                .unwrap();
        assert_eq!(decoded, roots.claims);
        assert_eq!(decoded.payload_bytes(), 6_442_975_232);
        assert_eq!(decoded.layer_roots().len(), 384);
        assert_eq!(decoded.canonical_bytes(), bytes);
    }

    #[test]
    fn syntax_claims_cannot_mint_payload_verified_authority() {
        use std::any::TypeId;

        let verified = fixture_roots();
        let forged_claims = ProductionDoryV3ModelRootsClaims::parse_and_validate(
            &verified.canonical_bytes(),
            verified.ceremony_id(),
        )
        .unwrap();
        assert_eq!(forged_claims.canonical_bytes(), verified.canonical_bytes());
        assert_ne!(
            TypeId::of::<ProductionDoryV3ModelRootsClaims>(),
            TypeId::of::<ProductionDoryV3ModelRoots>()
        );

        fn accepts_only_payload_verified(_: &ProductionDoryV3ModelRoots) {}
        accepts_only_payload_verified(&verified);
        // There is intentionally no public conversion from `forged_claims`
        // to the opaque type accepted above.
    }

    #[test]
    fn decoder_rejects_short_and_trailing_encodings() {
        let roots = fixture_roots();
        let bytes = roots.canonical_bytes();
        assert!(matches!(
            ProductionDoryV3ModelRootsClaims::parse_and_validate(
                &bytes[..bytes.len() - 1],
                roots.ceremony_id()
            ),
            Err(ProductionDoryV3ModelRootsError::EncodedLength { actual: 14_005, .. })
        ));
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert!(matches!(
            ProductionDoryV3ModelRootsClaims::parse_and_validate(&trailing, roots.ceremony_id()),
            Err(ProductionDoryV3ModelRootsError::EncodedLength { actual: 14_007, .. })
        ));
    }

    #[test]
    fn decoder_rejects_wrong_magic_version_and_ceremony() {
        let roots = fixture_roots();
        let mut bytes = roots.canonical_bytes();
        bytes[0] ^= 1;
        assert!(matches!(
            ProductionDoryV3ModelRootsClaims::parse_and_validate(&bytes, roots.ceremony_id()),
            Err(ProductionDoryV3ModelRootsError::Magic)
        ));

        let mut bytes = roots.canonical_bytes();
        bytes[8..10].copy_from_slice(&2_u16.to_le_bytes());
        assert!(matches!(
            ProductionDoryV3ModelRootsClaims::parse_and_validate(&bytes, roots.ceremony_id()),
            Err(ProductionDoryV3ModelRootsError::Version { actual: 2 })
        ));

        assert!(matches!(
            ProductionDoryV3ModelRootsClaims::parse_and_validate(
                &roots.canonical_bytes(),
                digest(b"other")
            ),
            Err(ProductionDoryV3ModelRootsError::CeremonyId)
        ));
    }

    #[test]
    fn decoder_rejects_nonproduction_geometry_and_layer_order() {
        let roots = fixture_roots();
        let mut bytes = roots.canonical_bytes();
        bytes[42..50].copy_from_slice(&(PRODUCTION_DORY_V3_PAYLOAD_BYTES - 1).to_le_bytes());
        assert!(matches!(
            ProductionDoryV3ModelRootsClaims::parse_and_validate(&bytes, roots.ceremony_id()),
            Err(ProductionDoryV3ModelRootsError::PayloadBytes { .. })
        ));

        let mut bytes = roots.canonical_bytes();
        bytes[146..150].copy_from_slice(&(DORY_V3_LAYERS - 1).to_le_bytes());
        assert!(matches!(
            ProductionDoryV3ModelRootsClaims::parse_and_validate(&bytes, roots.ceremony_id()),
            Err(ProductionDoryV3ModelRootsError::LayerCount { actual: 383 })
        ));

        let mut bytes = roots.canonical_bytes();
        let layer_17_index_offset = FIXED_PREFIX_BYTES + 17 * LAYER_RECORD_BYTES;
        bytes[layer_17_index_offset..layer_17_index_offset + 4]
            .copy_from_slice(&18_u32.to_le_bytes());
        assert!(matches!(
            ProductionDoryV3ModelRootsClaims::parse_and_validate(&bytes, roots.ceremony_id()),
            Err(ProductionDoryV3ModelRootsError::LayerIndex {
                position: 17,
                actual: 18
            })
        ));
    }

    #[test]
    fn decoder_recomputes_the_ordered_layer_aggregate() {
        let roots = fixture_roots();
        let mut changed_root = roots.canonical_bytes();
        changed_root[FIXED_PREFIX_BYTES + 4] ^= 1;
        assert!(matches!(
            ProductionDoryV3ModelRootsClaims::parse_and_validate(
                &changed_root,
                roots.ceremony_id()
            ),
            Err(ProductionDoryV3ModelRootsError::LayerRootsAggregate)
        ));

        let mut changed_aggregate = roots.canonical_bytes();
        *changed_aggregate.last_mut().unwrap() ^= 1;
        assert!(matches!(
            ProductionDoryV3ModelRootsClaims::parse_and_validate(
                &changed_aggregate,
                roots.ceremony_id()
            ),
            Err(ProductionDoryV3ModelRootsError::LayerRootsAggregate)
        ));
    }

    #[test]
    fn bounded_stream_derives_plain_section_and_raw_hashes() {
        let geometry = ProductionPayloadGeometry {
            base_input_bytes: 3,
            layer_bytes: 4,
            layers: 2,
        };
        let payload = [0_u8, 1, 250, 2, 3, 4, 5, 6, 7, 8, 9];
        let derived = derive_payload_roots(Cursor::new(payload), geometry).unwrap();
        assert_eq!(derived.raw_blake3, digest(&payload));
        let mut sha256 = Sha256::new();
        sha256.update(payload);
        assert_eq!(derived.raw_sha256, Digest32::new(sha256.finalize().into()));
        assert_eq!(derived.base_input_blake3_root, digest(&payload[..3]));
        assert_eq!(
            derived.layer_roots,
            vec![digest(&payload[3..7]), digest(&payload[7..11])]
        );
        assert_eq!(
            derived.layer_roots_aggregate,
            aggregate_layer_roots(&derived.layer_roots)
        );
    }

    #[test]
    fn bounded_independent_validator_requires_every_derived_field() {
        let geometry = ProductionPayloadGeometry {
            base_input_bytes: 3,
            layer_bytes: 4,
            layers: 2,
        };
        let payload = [0_u8, 1, 250, 2, 3, 4, 5, 6, 7, 8, 9];
        let expected = derive_payload_roots(Cursor::new(payload), geometry).unwrap();
        validate_payload_roots(Cursor::new(payload), geometry, &expected).unwrap();

        let mut wrong_raw = expected.clone();
        wrong_raw.raw_sha256 = digest(b"wrong");
        assert!(matches!(
            validate_payload_roots(Cursor::new(payload), geometry, &wrong_raw),
            Err(ProductionDoryV3ModelRootsError::PayloadRootsMismatch)
        ));

        let mut mutated_payload = payload;
        mutated_payload[5] ^= 1;
        assert!(matches!(
            validate_payload_roots(Cursor::new(mutated_payload), geometry, &expected),
            Err(ProductionDoryV3ModelRootsError::PayloadRootsMismatch)
        ));
    }

    #[test]
    fn double_scan_rejects_a_reader_that_mutates_between_scans() {
        let geometry = ProductionPayloadGeometry {
            base_input_bytes: 3,
            layer_bytes: 4,
            layers: 2,
        };
        let first = vec![0_u8, 1, 250, 2, 3, 4, 5, 6, 7, 8, 9];
        let mut second = first.clone();
        second[5] ^= 1;
        let mut reader = MutatingSeekReader::new(first, second);
        assert!(matches!(
            derive_payload_roots_twice(&mut reader, geometry),
            Err(ProductionDoryV3ModelRootsError::PayloadChangedBetweenScans)
        ));
    }

    #[test]
    fn bounded_stream_handles_short_reads_and_chunk_boundaries() {
        let geometry = ProductionPayloadGeometry {
            base_input_bytes: STREAM_BUFFER_BYTES as u64 + 1,
            layer_bytes: 2,
            layers: 1,
        };
        let mut payload = vec![7_u8; STREAM_BUFFER_BYTES + 3];
        let derived = derive_payload_roots(OneByteReader::new(payload.clone()), geometry).unwrap();
        assert_eq!(derived.raw_blake3, digest(&payload));
        assert_eq!(
            derived.base_input_blake3_root,
            digest(&payload[..STREAM_BUFFER_BYTES + 1])
        );
        assert_eq!(
            derived.layer_roots,
            vec![digest(&payload[STREAM_BUFFER_BYTES + 1..])]
        );

        payload[STREAM_BUFFER_BYTES] = 251;
        assert!(matches!(
            derive_payload_roots(Cursor::new(payload), geometry),
            Err(ProductionDoryV3ModelRootsError::PayloadByte {
                offset,
                value: 251
            }) if offset == STREAM_BUFFER_BYTES as u64
        ));
    }

    #[test]
    fn bounded_stream_rejects_early_eof_trailing_bytes_and_forbidden_values() {
        let geometry = ProductionPayloadGeometry {
            base_input_bytes: 2,
            layer_bytes: 2,
            layers: 1,
        };
        assert!(matches!(
            derive_payload_roots(Cursor::new([1_u8, 2, 3]), geometry),
            Err(ProductionDoryV3ModelRootsError::PayloadEarlyEof {
                expected: 4,
                actual: 3
            })
        ));
        assert!(matches!(
            derive_payload_roots(Cursor::new([1_u8, 2, 3, 4, 5]), geometry),
            Err(ProductionDoryV3ModelRootsError::PayloadTrailingBytes)
        ));
        assert!(matches!(
            derive_payload_roots(Cursor::new([1_u8, 251, 3, 4]), geometry),
            Err(ProductionDoryV3ModelRootsError::PayloadByte {
                offset: 1,
                value: 251
            })
        ));
    }

    #[test]
    fn create_new_writer_syncs_reopens_and_refuses_overwrite() {
        let directory = TestDirectory::new();
        let output = directory.path.join("roots.cmfd");
        let roots = fixture_roots();
        let parent = TrustedCeremonyParent::for_artifact(&output).unwrap();
        let (reopened, durability) =
            persist_create_new_and_reopen(&parent, &output, &roots, || Ok(())).unwrap();
        assert_eq!(reopened, roots);
        assert!(matches!(
            durability,
            ProductionDoryV3ModelRootsDurability::FileAndParentDirectorySynced
                | ProductionDoryV3ModelRootsDurability::FileSyncedParentDirectorySyncAccessDeniedOnWindows
                | ProductionDoryV3ModelRootsDurability::FileSyncedParentDirectorySyncUnsupportedOnWindows
        ));
        assert_eq!(fs::read(&output).unwrap(), roots.canonical_bytes());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(&output).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        let before = fs::read(&output).unwrap();
        assert!(matches!(
            persist_create_new_and_reopen(&parent, &output, &roots, || Ok(())),
            Err(ProductionDoryV3ModelRootsError::OutputExists(path)) if path == output
        ));
        assert_eq!(fs::read(&output).unwrap(), before);
    }

    #[test]
    fn post_create_failure_removes_only_the_retained_output() {
        let directory = TestDirectory::new();
        let output = directory.path.join("partial.cmfd");
        let parent = TrustedCeremonyParent::for_artifact(&output).unwrap();
        let mut pending = PendingOutput::create(&parent, &output).unwrap();
        pending.write_all(b"partial").unwrap();
        let error = cleanup_domain_output_error(
            &mut pending,
            &parent,
            ProductionDoryV3ModelRootsError::ReopenedOutputMismatch,
        );
        assert!(matches!(
            error,
            ProductionDoryV3ModelRootsError::ReopenedOutputMismatch
        ));
        assert!(!output.exists());
    }

    #[test]
    fn final_payload_recheck_failure_happens_before_output_confirmation() {
        let directory = TestDirectory::new();
        let output = directory.path.join("partial.cmfd");
        let parent = TrustedCeremonyParent::for_artifact(&output).unwrap();
        let roots = fixture_roots();

        let error = persist_create_new_and_reopen(&parent, &output, &roots, || {
            Err(ProductionDoryV3ModelRootsError::PayloadChangedBetweenScans)
        })
        .unwrap_err();

        assert!(matches!(
            error,
            ProductionDoryV3ModelRootsError::PayloadChangedBetweenScans
        ));
        assert!(!output.exists());
    }

    #[test]
    fn cleanup_preserves_a_replacement_path_on_identity_mismatch() {
        let directory = TestDirectory::new();
        let output = directory.path.join("partial.cmfd");
        let displaced = directory.path.join("displaced.cmfd");
        let parent = TrustedCeremonyParent::for_artifact(&output).unwrap();
        let mut pending = PendingOutput::create(&parent, &output).unwrap();
        pending.write_all(b"original").unwrap();
        pending.close_writer();
        fs::rename(&output, &displaced).unwrap();
        fs::write(&output, b"replacement").unwrap();

        let error = cleanup_domain_output_error(
            &mut pending,
            &parent,
            ProductionDoryV3ModelRootsError::ReopenedOutputMismatch,
        );
        assert!(matches!(
            error,
            ProductionDoryV3ModelRootsError::QuarantinedOutput {
                original,
                cleanup,
                ..
            } if original.contains("reopened roots output differs")
                && cleanup.contains("no longer names the create-new file")
        ));
        assert_eq!(fs::read(&output).unwrap(), b"replacement");
        assert_eq!(fs::read(&displaced).unwrap(), b"original");
    }

    #[test]
    fn payload_hard_links_are_rejected_before_a_long_scan() {
        let directory = TestDirectory::new();
        let payload = directory.path.join("payload.bin");
        let alias = directory.path.join("payload-alias.bin");
        fs::write(&payload, [0_u8; 4]).unwrap();
        fs::hard_link(&payload, &alias).unwrap();
        let parent = TrustedCeremonyParent::for_artifact(&payload).unwrap();
        assert!(matches!(
            AuthenticatedInput::open(&parent, &payload, None).map_err(map_payload_fs),
            Err(ProductionDoryV3ModelRootsError::PayloadHardLinks { links: 2, .. })
        ));
    }

    #[cfg(windows)]
    #[test]
    fn authenticated_read_handle_denies_concurrent_write_and_delete() {
        let directory = TestDirectory::new();
        let path = directory.path.join("authenticated.bin");
        fs::write(&path, b"payload").unwrap();
        let parent = TrustedCeremonyParent::for_artifact(&path).unwrap();
        let held = AuthenticatedInput::open(&parent, &path, Some(7)).unwrap();

        assert!(OpenOptions::new().write(true).open(&path).is_err());
        assert!(fs::remove_file(&path).is_err());

        drop(held);
        fs::remove_file(path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn payload_symlinks_are_rejected_before_a_long_scan() {
        use std::os::unix::fs::symlink;

        let directory = TestDirectory::new();
        let payload = directory.path.join("payload.bin");
        let alias = directory.path.join("payload-link.bin");
        fs::write(&payload, [0_u8; 4]).unwrap();
        symlink(&payload, &alias).unwrap();
        let parent = TrustedCeremonyParent::for_artifact(&alias).unwrap();
        assert!(matches!(
            AuthenticatedInput::open(&parent, &alias, None).map_err(map_payload_fs),
            Err(ProductionDoryV3ModelRootsError::PayloadReparsePoint(path)) if path == alias
        ));
    }

    #[test]
    fn path_runner_rejects_wrong_payload_length_before_creating_output() {
        let directory = TestDirectory::new();
        let payload = directory.path.join("payload.bin");
        let output = directory.path.join("roots.cmfd");
        fs::write(&payload, [0_u8; 4]).unwrap();
        assert!(matches!(
            generate_production_dory_v3_model_roots_file(&payload, &output, digest(b"ceremony")),
            Err(ProductionDoryV3ModelRootsError::PayloadFileLength {
                expected: PRODUCTION_DORY_V3_PAYLOAD_BYTES,
                actual: 4
            })
        ));
        assert!(!output.exists());
    }

    fn fixture_roots() -> ProductionDoryV3ModelRoots {
        let layer_roots = std::array::from_fn(|index| digest(&(index as u32).to_le_bytes()));
        ProductionDoryV3ModelRoots {
            claims: ProductionDoryV3ModelRootsClaims {
                ceremony_id: digest(b"ceremony"),
                raw_blake3: digest(b"raw-blake3"),
                raw_sha256: digest(b"raw-sha256-placeholder"),
                base_input_blake3_root: digest(b"base"),
                layer_roots_aggregate: aggregate_layer_roots(&layer_roots),
                layer_roots,
            },
        }
    }

    fn digest(bytes: &[u8]) -> Digest32 {
        Digest32::new(*blake3::hash(bytes).as_bytes())
    }

    struct MutatingSeekReader {
        first: Vec<u8>,
        second: Vec<u8>,
        offset: usize,
        scan: u8,
    }

    impl MutatingSeekReader {
        fn new(first: Vec<u8>, second: Vec<u8>) -> Self {
            assert_eq!(first.len(), second.len());
            Self {
                first,
                second,
                offset: 0,
                scan: 0,
            }
        }
    }

    impl Read for MutatingSeekReader {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            let input = if self.scan <= 1 {
                &self.first
            } else {
                &self.second
            };
            if self.offset == input.len() || output.is_empty() {
                return Ok(0);
            }
            let take = output.len().min(input.len() - self.offset);
            output[..take].copy_from_slice(&input[self.offset..self.offset + take]);
            self.offset += take;
            Ok(take)
        }
    }

    impl Seek for MutatingSeekReader {
        fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
            if position != SeekFrom::Start(0) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "test reader supports only rewind",
                ));
            }
            self.offset = 0;
            self.scan = self.scan.saturating_add(1);
            Ok(0)
        }
    }

    struct OneByteReader {
        bytes: Vec<u8>,
        offset: usize,
    }

    impl OneByteReader {
        fn new(bytes: Vec<u8>) -> Self {
            Self { bytes, offset: 0 }
        }
    }

    impl Read for OneByteReader {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            if self.offset == self.bytes.len() || output.is_empty() {
                return Ok(0);
            }
            output[0] = self.bytes[self.offset];
            self.offset += 1;
            Ok(1)
        }
    }

    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
        fn new() -> Self {
            for _ in 0..128 {
                let nonce = TEMP_NONCE.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "cmfd-model-roots-test-{}-{nonce}",
                    std::process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => {
                        crate::dory_v3_model_ceremony_fs::prepare_test_parent(&path).unwrap();
                        return Self { path };
                    }
                    Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(source) => panic!("failed to create test directory: {source}"),
                }
            }
            panic!("failed to allocate a unique test directory");
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.path).unwrap();
        }
    }
}
