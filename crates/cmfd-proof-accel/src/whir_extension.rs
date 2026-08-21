//! Authenticated external-memory encoding for a WHIR extension codeword.
//!
//! A residual row stores one cubic-extension evaluation in its first three
//! canonical Goldilocks limbs. With the protocol's fixed folding factor of two,
//! four consecutive residual evaluations form one row of four cubic-extension
//! coefficients. This module scatters those twelve base-field limbs into
//! bit-reversed rows, zero pads to the configured inverse-rate domain, performs
//! an exact bounded file-backed radix-2 DFT, and publishes only a fully
//! authenticated natural-row artifact.
//!
//! The artifact is prover-local scratch. Its identity is never absorbed into
//! Fiat-Shamir, and this module neither changes consensus nor raises an
//! activation cap.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use blake3::Hasher;
use same_file::Handle;
use thiserror::Error;

use crate::blake3_merkle_store::{
    BLAKE3_LEAF_BATCH_ROWS, Blake3DigestSource, Blake3MerkleDigest, Blake3MerkleStoreError,
};
use crate::external_radix2::{ExternalRadix2Error, dft_goldilocks_rows_in_place};
use crate::merkle_store::{GOLDILOCKS_MODULUS, MerkleRowSource, MerkleStoreError};
use crate::whir_residual::{
    AuthenticatedWhirResidualArtifact, WhirResidualArtifactError, WhirResidualArtifactIdentity,
};

const MAGIC: &[u8; 8] = b"CMFDWEX1";
const VERSION: u32 = 1;
const NATURAL_ROW_LAYOUT: u8 = 1;
const CANONICAL_U64_LE_ENCODING: u8 = 1;
const PREFIX_BYTES: usize = 256;
const DIGEST_BYTES: usize = 32;
const HEADER_BYTES: usize = PREFIX_BYTES + DIGEST_BYTES;
const AUTH_CHUNK_ROWS: usize = 8 * 1024;
const GLOBAL_DOMAIN: &str = "Common Foundry WHIR extension codeword artifact v1";
const AUTH_DOMAIN: &str = "Common Foundry WHIR extension codeword chunk v1";
const CREATE_ATTEMPTS: usize = 256;

/// Fixed number of residual variables folded into each extension row.
pub const WHIR_EXTENSION_FOLDING: usize = 2;
/// Number of cubic-extension elements in one protocol row.
pub const WHIR_EXTENSION_WIDTH: usize = 1 << WHIR_EXTENSION_FOLDING;
/// Canonical Goldilocks limbs in one cubic-extension element.
pub const WHIR_EXTENSION_LIMBS_PER_ELEMENT: usize = 3;
/// Canonical Goldilocks limbs in one on-disk row.
pub const WHIR_EXTENSION_LIMBS_PER_ROW: usize =
    WHIR_EXTENSION_WIDTH * WHIR_EXTENSION_LIMBS_PER_ELEMENT;
/// Smallest residual table supported by fixed folding two.
pub const WHIR_EXTENSION_MIN_VARIABLES: usize = WHIR_EXTENSION_FOLDING;
/// Production residual variable cap; this checkpoint does not raise it.
pub const WHIR_EXTENSION_MAX_VARIABLES: usize = 29;
/// Largest output domain admitted by the authenticated artifact.
pub const WHIR_EXTENSION_MAX_HEIGHT: usize = 1 << 29;
/// Execution cap for the exact but I/O-heavy reference DFT engine.
///
/// Checked geometry remains available through [`WHIR_EXTENSION_MAX_HEIGHT`]. A
/// blocked/GPU engine must match the exact artifact bytes before this reference
/// cap can be replaced or raised.
pub const WHIR_EXTENSION_REFERENCE_MAX_HEIGHT: usize = 1 << 20;
/// Maximum residual rows authenticated in one encoder read.
pub const WHIR_EXTENSION_MAX_SOURCE_READ_ROWS: usize = AUTH_CHUNK_ROWS;
/// Maximum field values retained in either external-DFT half-buffer.
pub const WHIR_EXTENSION_MAX_DFT_BUFFER_LIMBS: usize = WHIR_EXTENSION_LIMBS_PER_ROW * 512;
/// Maximum natural rows returned by one authenticated random read.
pub const WHIR_EXTENSION_MAX_READ_ROWS: usize = 256;

static NEXT_ARTIFACT: AtomicU64 = AtomicU64::new(0);

/// Checked extension-codeword geometry. Computing it does not allocate rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WhirExtensionGeometry {
    pub residual_rows: u64,
    pub coefficient_rows: u64,
    pub height: u64,
    pub data_bytes: u64,
    pub authentication_chunks: u64,
    pub artifact_bytes: u64,
}

/// Caller-retained identity required to reopen one exact extension codeword.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WhirExtensionCodewordIdentity {
    pub codeword_id: [u8; 32],
    pub residual: WhirResidualArtifactIdentity,
    pub folding: u8,
    pub log_inv_rate: u8,
    pub height: u64,
    pub width: u32,
    pub artifact_digest: [u8; 32],
}

impl WhirExtensionCodewordIdentity {
    /// Bind every caller-trusted identity field and every derived artifact
    /// geometry field into one domain-separated digest.
    ///
    /// This digest identifies the exact authenticated codeword consumed by an
    /// external commitment store. It remains prover-local metadata and is not
    /// absorbed into the Fiat--Shamir transcript.
    pub fn binding_digest(&self) -> Result<[u8; 32], WhirExtensionEncodingError> {
        if self.codeword_id == [0; 32]
            || self.folding != WHIR_EXTENSION_FOLDING as u8
            || self.width != WHIR_EXTENSION_WIDTH as u32
        {
            return Err(WhirExtensionEncodingError::IdentityMismatch);
        }
        let geometry = whir_extension_geometry(&self.residual, self.log_inv_rate)?;
        if self.height != geometry.height {
            return Err(WhirExtensionEncodingError::IdentityMismatch);
        }

        let mut hasher =
            Hasher::new_derive_key("Common Foundry WHIR extension codeword identity binding v1");
        hasher.update(&self.codeword_id);
        hasher.update(&self.residual.spec.source_digest);
        hasher.update(&self.residual.spec.context_digest);
        hasher.update(&self.residual.spec.num_variables.to_le_bytes());
        hasher.update(&self.residual.spec.generation.to_le_bytes());
        hasher.update(&self.residual.row_count.to_le_bytes());
        hasher.update(&self.residual.artifact_digest);
        hasher.update(&[self.folding]);
        hasher.update(&[self.log_inv_rate]);
        hasher.update(&self.height.to_le_bytes());
        hasher.update(&self.width.to_le_bytes());
        hasher.update(&self.artifact_digest);
        hasher.update(&geometry.residual_rows.to_le_bytes());
        hasher.update(&geometry.coefficient_rows.to_le_bytes());
        hasher.update(&geometry.height.to_le_bytes());
        hasher.update(&geometry.data_bytes.to_le_bytes());
        hasher.update(&geometry.authentication_chunks.to_le_bytes());
        hasher.update(&geometry.artifact_bytes.to_le_bytes());
        hasher.update(&(WHIR_EXTENSION_LIMBS_PER_ELEMENT as u32).to_le_bytes());
        hasher.update(&(WHIR_EXTENSION_LIMBS_PER_ROW as u32).to_le_bytes());
        hasher.update(&(AUTH_CHUNK_ROWS as u64).to_le_bytes());
        hasher.update(&[NATURAL_ROW_LAYOUT, CANONICAL_U64_LE_ENCODING]);
        Ok(*hasher.finalize().as_bytes())
    }
}

#[derive(Debug, Error)]
pub enum WhirExtensionEncodingError {
    #[error("invalid WHIR extension encoding: {0}")]
    Invalid(&'static str),
    #[error("WHIR extension encoding research limit exceeded: {0}")]
    ResearchLimit(&'static str),
    #[error("WHIR extension residual source failed: {0}")]
    Residual(#[from] WhirResidualArtifactError),
    #[error("WHIR extension scratch directory must be absolute and already exist: {0}")]
    InvalidScratchDirectory(PathBuf),
    #[error(
        "WHIR extension scratch directory has insufficient free space: need {required} bytes, have {available} bytes"
    )]
    InsufficientSpace { required: u64, available: u64 },
    #[error("could not allocate a unique WHIR extension artifact in {0}")]
    NameExhausted(PathBuf),
    #[error("WHIR extension artifact publication target already exists: {0}")]
    PublicationConflict(PathBuf),
    #[error("WHIR extension artifact I/O failed while {operation} {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("WHIR extension artifact checksum does not match")]
    ChecksumMismatch,
    #[error("WHIR extension artifact identity does not match")]
    IdentityMismatch,
    #[error("WHIR extension cleanup path no longer names the owned file: {0}")]
    CleanupTargetChanged(PathBuf),
    #[error("WHIR extension artifact file lock is poisoned")]
    LockPoisoned,
}

impl From<ExternalRadix2Error> for WhirExtensionEncodingError {
    fn from(error: ExternalRadix2Error) -> Self {
        match error {
            ExternalRadix2Error::Invalid(message) => Self::Invalid(message),
            ExternalRadix2Error::BufferAllocation => Self::ResearchLimit("DFT buffer"),
            ExternalRadix2Error::Io {
                operation,
                path,
                source,
            } => Self::Io {
                operation,
                path,
                source,
            },
        }
    }
}

/// Validate extension geometry without allocating proportional to its height.
pub fn whir_extension_geometry(
    residual: &WhirResidualArtifactIdentity,
    log_inv_rate: u8,
) -> Result<WhirExtensionGeometry, WhirExtensionEncodingError> {
    let variables = usize::try_from(residual.spec.num_variables)
        .map_err(|_| WhirExtensionEncodingError::ResearchLimit("variable count"))?;
    if variables < WHIR_EXTENSION_MIN_VARIABLES {
        return Err(WhirExtensionEncodingError::Invalid(
            "residual has fewer variables than folding",
        ));
    }
    if variables > WHIR_EXTENSION_MAX_VARIABLES {
        return Err(WhirExtensionEncodingError::ResearchLimit(
            "residual variable count exceeds 29",
        ));
    }
    let residual_rows = 1_u64.checked_shl(residual.spec.num_variables).ok_or(
        WhirExtensionEncodingError::ResearchLimit("residual row count"),
    )?;
    if residual.row_count != residual_rows {
        return Err(WhirExtensionEncodingError::Invalid(
            "residual identity row count is inconsistent",
        ));
    }
    let coefficient_rows = residual_rows >> WHIR_EXTENSION_FOLDING;
    let log_height = variables
        .checked_sub(WHIR_EXTENSION_FOLDING)
        .and_then(|value| value.checked_add(log_inv_rate as usize))
        .ok_or(WhirExtensionEncodingError::ResearchLimit(
            "extension height exponent",
        ))?;
    if log_height >= usize::BITS as usize {
        return Err(WhirExtensionEncodingError::ResearchLimit(
            "extension height exponent",
        ));
    }
    let height =
        1_usize
            .checked_shl(log_height as u32)
            .ok_or(WhirExtensionEncodingError::ResearchLimit(
                "extension height",
            ))?;
    if height < 2 {
        return Err(WhirExtensionEncodingError::Invalid(
            "extension DFT height must be at least two",
        ));
    }
    if height > WHIR_EXTENSION_MAX_HEIGHT {
        return Err(WhirExtensionEncodingError::ResearchLimit(
            "extension height exceeds 2^29",
        ));
    }
    let height_u64 = u64::try_from(height)
        .map_err(|_| WhirExtensionEncodingError::ResearchLimit("extension height"))?;
    if height_u64 < coefficient_rows {
        return Err(WhirExtensionEncodingError::Invalid(
            "extension domain is smaller than its coefficient rows",
        ));
    }
    let row_bytes = (WHIR_EXTENSION_LIMBS_PER_ROW as u64)
        .checked_mul(size_of::<u64>() as u64)
        .ok_or(WhirExtensionEncodingError::ResearchLimit(
            "extension row byte width",
        ))?;
    let data_bytes =
        height_u64
            .checked_mul(row_bytes)
            .ok_or(WhirExtensionEncodingError::ResearchLimit(
                "extension data byte length",
            ))?;
    let authentication_chunks = height_u64.div_ceil(AUTH_CHUNK_ROWS as u64);
    let authentication_bytes = authentication_chunks
        .checked_mul(DIGEST_BYTES as u64)
        .ok_or(WhirExtensionEncodingError::ResearchLimit(
            "extension authentication byte length",
        ))?;
    let artifact_bytes = (HEADER_BYTES as u64)
        .checked_add(data_bytes)
        .and_then(|bytes| bytes.checked_add(authentication_bytes))
        .ok_or(WhirExtensionEncodingError::ResearchLimit(
            "extension artifact byte length",
        ))?;
    Ok(WhirExtensionGeometry {
        residual_rows,
        coefficient_rows,
        height: height_u64,
        data_bytes,
        authentication_chunks,
        artifact_bytes,
    })
}

/// Fully authenticated, natural-row WHIR extension codeword.
pub struct AuthenticatedWhirExtensionCodeword {
    file: Option<Mutex<File>>,
    path: PathBuf,
    prefix: [u8; PREFIX_BYTES],
    identity: WhirExtensionCodewordIdentity,
    geometry: WhirExtensionGeometry,
    authentication_digests: Vec<[u8; DIGEST_BYTES]>,
    cleanup_path: Option<PathBuf>,
}

impl std::fmt::Debug for AuthenticatedWhirExtensionCodeword {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthenticatedWhirExtensionCodeword")
            .field("path", &self.path)
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl AuthenticatedWhirExtensionCodeword {
    /// Open and fully authenticate an artifact against caller-retained identity.
    pub fn open(
        path: impl AsRef<Path>,
        expected: &WhirExtensionCodewordIdentity,
    ) -> Result<Self, WhirExtensionEncodingError> {
        let path = path.as_ref().to_path_buf();
        let mut file = OpenOptions::new()
            .read(true)
            .open(&path)
            .map_err(|source| io_error("opening", &path, source))?;
        let mut prefix = [0_u8; PREFIX_BYTES];
        file.read_exact(&mut prefix)
            .map_err(|source| io_error("reading header from", &path, source))?;
        let mut stored_digest = [0_u8; DIGEST_BYTES];
        file.read_exact(&mut stored_digest)
            .map_err(|source| io_error("reading digest from", &path, source))?;
        let decoded = decode_prefix(&prefix)?;
        let identity = WhirExtensionCodewordIdentity {
            codeword_id: decoded.codeword_id,
            residual: decoded.residual,
            folding: WHIR_EXTENSION_FOLDING as u8,
            log_inv_rate: decoded.log_inv_rate,
            height: decoded.geometry.height,
            width: WHIR_EXTENSION_WIDTH as u32,
            artifact_digest: stored_digest,
        };
        if &identity != expected {
            return Err(WhirExtensionEncodingError::IdentityMismatch);
        }
        let actual_bytes = file
            .metadata()
            .map_err(|source| io_error("reading metadata for", &path, source))?
            .len();
        if actual_bytes != decoded.geometry.artifact_bytes {
            return Err(WhirExtensionEncodingError::ChecksumMismatch);
        }
        let authentication_digests =
            read_authentication_table(&mut file, &path, &decoded.geometry)?;
        authenticate_complete(
            &mut file,
            &path,
            &prefix,
            &decoded.geometry,
            &authentication_digests,
            stored_digest,
        )?;
        Ok(Self {
            file: Some(Mutex::new(file)),
            path,
            prefix,
            identity,
            geometry: decoded.geometry,
            authentication_digests,
            cleanup_path: None,
        })
    }

    pub const fn identity(&self) -> &WhirExtensionCodewordIdentity {
        &self.identity
    }

    pub const fn geometry(&self) -> WhirExtensionGeometry {
        self.geometry
    }

    #[cfg(test)]
    fn path(&self) -> &Path {
        &self.path
    }

    /// Close and remove an owned artifact, surfacing normal cleanup failure.
    ///
    /// Borrowed artifacts opened through [`Self::open`] are only closed. The
    /// scratch namespace contract forbids renaming or replacing generated paths
    /// while a capability is live; cleanup nevertheless verifies file identity
    /// immediately before unlinking as defense in depth.
    pub fn remove(mut self) -> Result<(), WhirExtensionEncodingError> {
        let Some(path) = self.cleanup_path.take() else {
            self.file.take();
            return Ok(());
        };
        let mutex = self.file.take().expect("live artifact owns its file");
        let file = mutex
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Err(error) = remove_owned_file(&path, &file) {
            self.file = Some(Mutex::new(file));
            self.cleanup_path = Some(path);
            return Err(error);
        }
        Ok(())
    }

    /// Authenticate and decode a bounded contiguous range of natural rows.
    ///
    /// The flattened result contains twelve canonical Goldilocks limbs per row:
    /// four consecutive cubic-extension elements in coefficient-limb order.
    pub fn read_canonical_rows(
        &self,
        row_start: usize,
        row_count: usize,
    ) -> Result<Vec<u64>, WhirExtensionEncodingError> {
        if row_count == 0 || row_count > WHIR_EXTENSION_MAX_READ_ROWS {
            return Err(WhirExtensionEncodingError::Invalid(
                "row read is empty or exceeds the bounded request",
            ));
        }
        let height = usize::try_from(self.geometry.height)
            .map_err(|_| WhirExtensionEncodingError::ResearchLimit("extension height"))?;
        let row_end = row_start
            .checked_add(row_count)
            .ok_or(WhirExtensionEncodingError::ResearchLimit("row read range"))?;
        if row_end > height {
            return Err(WhirExtensionEncodingError::Invalid(
                "row read exceeds the extension artifact",
            ));
        }
        let output_values = row_count.checked_mul(WHIR_EXTENSION_LIMBS_PER_ROW).ok_or(
            WhirExtensionEncodingError::ResearchLimit("row read output length"),
        )?;
        let mut output = Vec::new();
        output
            .try_reserve_exact(output_values)
            .map_err(|_| WhirExtensionEncodingError::ResearchLimit("row read allocation"))?;

        let mutex = self.file.as_ref().expect("live artifact owns its file");
        let mut file = mutex
            .lock()
            .map_err(|_| WhirExtensionEncodingError::LockPoisoned)?;
        self.verify_live_header(&mut file)?;
        let first_chunk = row_start / AUTH_CHUNK_ROWS;
        let last_chunk = (row_end - 1) / AUTH_CHUNK_ROWS;
        for chunk_index in first_chunk..=last_chunk {
            let chunk_start = chunk_index * AUTH_CHUNK_ROWS;
            let chunk_rows = (height - chunk_start).min(AUTH_CHUNK_ROWS);
            let bytes = read_encoded_rows(&mut file, &self.path, chunk_start, chunk_rows)?;
            let actual = authentication_digest(&self.prefix, chunk_index as u64, &bytes);
            if actual != self.authentication_digests[chunk_index] {
                return Err(WhirExtensionEncodingError::ChecksumMismatch);
            }
            validate_encoded_rows(&bytes)?;
            let selected_start = row_start.max(chunk_start) - chunk_start;
            let selected_end = row_end.min(chunk_start + chunk_rows) - chunk_start;
            let byte_start = selected_start * row_byte_width();
            let byte_end = selected_end * row_byte_width();
            decode_values(&bytes[byte_start..byte_end], &mut output);
        }
        self.verify_live_header(&mut file)?;
        if output.len() != output_values {
            return Err(WhirExtensionEncodingError::ChecksumMismatch);
        }
        Ok(output)
    }

    /// Reauthenticate one extension authentication chunk and hash its selected
    /// canonical rows into the exact unpadded WHIR BLAKE3 leaf format.
    ///
    /// The tree builder requests aligned 8192-row batches, so a production
    /// extension chunk is read and authenticated once rather than once per
    /// 256-digest Merkle authentication chunk.
    pub fn read_leaf_digests(
        &self,
        row_start: usize,
        row_count: usize,
    ) -> Result<Vec<Blake3MerkleDigest>, WhirExtensionEncodingError> {
        if row_count == 0 || row_count > BLAKE3_LEAF_BATCH_ROWS {
            return Err(WhirExtensionEncodingError::Invalid(
                "leaf digest read is empty or exceeds one extension chunk",
            ));
        }
        debug_assert_eq!(BLAKE3_LEAF_BATCH_ROWS, AUTH_CHUNK_ROWS);
        let height = usize::try_from(self.geometry.height)
            .map_err(|_| WhirExtensionEncodingError::ResearchLimit("extension height"))?;
        let row_end =
            row_start
                .checked_add(row_count)
                .ok_or(WhirExtensionEncodingError::ResearchLimit(
                    "leaf digest read range",
                ))?;
        if row_end > height || row_start / AUTH_CHUNK_ROWS != (row_end - 1) / AUTH_CHUNK_ROWS {
            return Err(WhirExtensionEncodingError::Invalid(
                "leaf digest read crosses an extension authentication chunk",
            ));
        }
        let chunk_index = row_start / AUTH_CHUNK_ROWS;
        let chunk_start = chunk_index * AUTH_CHUNK_ROWS;
        let chunk_rows = (height - chunk_start).min(AUTH_CHUNK_ROWS);
        let mutex = self.file.as_ref().expect("live artifact owns its file");
        let mut file = mutex
            .lock()
            .map_err(|_| WhirExtensionEncodingError::LockPoisoned)?;
        self.verify_live_header(&mut file)?;
        let bytes = read_encoded_rows(&mut file, &self.path, chunk_start, chunk_rows)?;
        let actual = authentication_digest(&self.prefix, chunk_index as u64, &bytes);
        if actual != self.authentication_digests[chunk_index] {
            return Err(WhirExtensionEncodingError::ChecksumMismatch);
        }
        validate_encoded_rows(&bytes)?;
        let selected_start = row_start - chunk_start;
        let selected_end = selected_start + row_count;
        let byte_start = selected_start * row_byte_width();
        let byte_end = selected_end * row_byte_width();
        let mut digests = Vec::new();
        digests
            .try_reserve_exact(row_count)
            .map_err(|_| WhirExtensionEncodingError::ResearchLimit("leaf digest allocation"))?;
        for row in bytes[byte_start..byte_end].chunks_exact(row_byte_width()) {
            digests.push(*blake3::hash(row).as_bytes());
        }
        self.verify_live_header(&mut file)?;
        Ok(digests)
    }

    fn verify_live_header(&self, file: &mut File) -> Result<(), WhirExtensionEncodingError> {
        let actual_bytes = file
            .metadata()
            .map_err(|source| io_error("reading metadata for", &self.path, source))?
            .len();
        if actual_bytes != self.geometry.artifact_bytes {
            return Err(WhirExtensionEncodingError::ChecksumMismatch);
        }
        let mut header = [0_u8; HEADER_BYTES];
        file.seek(SeekFrom::Start(0))
            .and_then(|_| file.read_exact(&mut header))
            .map_err(|source| io_error("reauthenticating header from", &self.path, source))?;
        if header[..PREFIX_BYTES] != self.prefix
            || header[PREFIX_BYTES..] != self.identity.artifact_digest
        {
            return Err(WhirExtensionEncodingError::ChecksumMismatch);
        }
        Ok(())
    }
}

impl Drop for AuthenticatedWhirExtensionCodeword {
    fn drop(&mut self) {
        let (Some(path), Some(mutex)) = (self.cleanup_path.take(), self.file.take()) else {
            return;
        };
        let file = mutex
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _ = remove_owned_file(&path, &file);
    }
}

impl MerkleRowSource for AuthenticatedWhirExtensionCodeword {
    fn height(&self) -> usize {
        usize::try_from(self.geometry.height).expect("bounded extension height fits usize")
    }

    fn width(&self) -> usize {
        WHIR_EXTENSION_LIMBS_PER_ROW
    }

    fn read_row(&self, row: usize) -> Result<Vec<u64>, MerkleStoreError> {
        self.read_canonical_rows(row, 1)
            .map_err(|error| MerkleStoreError::Source(error.to_string()))
    }

    fn read_rows(&self, row_start: usize, row_count: usize) -> Result<Vec<u64>, MerkleStoreError> {
        self.read_canonical_rows(row_start, row_count)
            .map_err(|error| MerkleStoreError::Source(error.to_string()))
    }
}

impl Blake3DigestSource for AuthenticatedWhirExtensionCodeword {
    fn height(&self) -> usize {
        MerkleRowSource::height(self)
    }

    fn read_digests(
        &self,
        row_start: usize,
        row_count: usize,
    ) -> Result<Vec<Blake3MerkleDigest>, Blake3MerkleStoreError> {
        self.read_leaf_digests(row_start, row_count)
            .map_err(|error| Blake3MerkleStoreError::Source(error.to_string()))
    }
}

/// Build and publish one exact WHIR extension codeword in prover scratch.
///
/// The directory is an explicitly private/exclusive prover scratch namespace.
/// Other code must not rename, replace, or create `cmfd-whir-extension-*`
/// entries while construction or a returned capability is live. Generated
/// provisional and final names are unique and created without overwrite;
/// cleanup also compares open-file identity with the current path before every
/// unlink because that comparison and unlink are not one portable atomic
/// filesystem operation.
pub fn encode_whir_extension_codeword(
    scratch_directory: impl AsRef<Path>,
    codeword_id: [u8; 32],
    expected_residual: &WhirResidualArtifactIdentity,
    residual: &AuthenticatedWhirResidualArtifact,
    log_inv_rate: u8,
) -> Result<AuthenticatedWhirExtensionCodeword, WhirExtensionEncodingError> {
    encode_with_limits(
        scratch_directory.as_ref(),
        codeword_id,
        expected_residual,
        residual,
        log_inv_rate,
        WHIR_EXTENSION_MAX_SOURCE_READ_ROWS,
        WHIR_EXTENSION_MAX_DFT_BUFFER_LIMBS,
    )
}

fn encode_with_limits(
    scratch_directory: &Path,
    codeword_id: [u8; 32],
    expected_residual: &WhirResidualArtifactIdentity,
    residual: &AuthenticatedWhirResidualArtifact,
    log_inv_rate: u8,
    source_read_rows: usize,
    dft_buffer_limbs: usize,
) -> Result<AuthenticatedWhirExtensionCodeword, WhirExtensionEncodingError> {
    if codeword_id == [0; 32] {
        return Err(WhirExtensionEncodingError::Invalid(
            "codeword identity must be nonzero",
        ));
    }
    let geometry = whir_extension_geometry(expected_residual, log_inv_rate)?;
    if geometry.height > WHIR_EXTENSION_REFERENCE_MAX_HEIGHT as u64 {
        return Err(WhirExtensionEncodingError::ResearchLimit(
            "reference encoder height exceeds 2^20",
        ));
    }
    if !(WHIR_EXTENSION_WIDTH..=WHIR_EXTENSION_MAX_SOURCE_READ_ROWS).contains(&source_read_rows)
        || !source_read_rows.is_multiple_of(WHIR_EXTENSION_WIDTH)
        || !(WHIR_EXTENSION_LIMBS_PER_ROW..=WHIR_EXTENSION_MAX_DFT_BUFFER_LIMBS)
            .contains(&dft_buffer_limbs)
        || !dft_buffer_limbs.is_multiple_of(WHIR_EXTENSION_LIMBS_PER_ROW)
    {
        return Err(WhirExtensionEncodingError::Invalid(
            "internal buffer limit is invalid",
        ));
    }
    if !scratch_directory.is_absolute() || !scratch_directory.is_dir() {
        return Err(WhirExtensionEncodingError::InvalidScratchDirectory(
            scratch_directory.to_path_buf(),
        ));
    }
    if residual.identity() != expected_residual
        || residual.geometry().row_count != geometry.residual_rows
    {
        return Err(WhirExtensionEncodingError::IdentityMismatch);
    }
    let available = fs2::available_space(scratch_directory)
        .map_err(|source| io_error("checking free space in", scratch_directory, source))?;
    if available < geometry.artifact_bytes {
        return Err(WhirExtensionEncodingError::InsufficientSpace {
            required: geometry.artifact_bytes,
            available,
        });
    }

    let (partial_path, final_path, file) = create_unique_staging(scratch_directory)?;
    let mut staging = OwnedFileLink::new(partial_path.clone(), file);
    let prefix = encode_prefix(codeword_id, expected_residual, log_inv_rate, &geometry);
    staging
        .file_mut()
        .write_all(&prefix)
        .and_then(|()| staging.file_mut().write_all(&[0_u8; DIGEST_BYTES]))
        .and_then(|()| {
            staging
                .file_mut()
                .set_len(HEADER_BYTES as u64 + geometry.data_bytes)
        })
        .map_err(|source| io_error("initializing", &partial_path, source))?;
    scatter_bit_reversed_residual(
        staging.file_mut(),
        &partial_path,
        residual,
        expected_residual,
        &geometry,
        source_read_rows,
    )?;
    run_external_dft(
        staging.file_mut(),
        &partial_path,
        usize::try_from(geometry.height)
            .map_err(|_| WhirExtensionEncodingError::ResearchLimit("extension height"))?,
        dft_buffer_limbs,
    )?;
    let (authentication_digests, artifact_digest) =
        seal_data(staging.file_mut(), &partial_path, &prefix, &geometry)?;
    let expected_identity = WhirExtensionCodewordIdentity {
        codeword_id,
        residual: expected_residual.clone(),
        folding: WHIR_EXTENSION_FOLDING as u8,
        log_inv_rate,
        height: geometry.height,
        width: WHIR_EXTENSION_WIDTH as u32,
        artifact_digest,
    };
    let staged = AuthenticatedWhirExtensionCodeword::open(&partial_path, &expected_identity)?;
    debug_assert_eq!(staged.authentication_digests, authentication_digests);

    ensure_path_names_file(&partial_path, staging.file_ref())?;
    let mut published = publish_verified_no_overwrite(
        &partial_path,
        &final_path,
        staging.file_ref(),
        ensure_path_names_file,
    )?;
    remove_owned_file(&partial_path, staging.file_ref())?;
    let mut artifact = AuthenticatedWhirExtensionCodeword::open(&final_path, &expected_identity)?;
    artifact.cleanup_path = Some(final_path.clone());
    published.disarm();
    staging.disarm();
    drop(staged);
    Ok(artifact)
}

fn publish_verified_no_overwrite<Verify>(
    partial_path: &Path,
    final_path: &Path,
    file: &File,
    verify: Verify,
) -> Result<OwnedFileLink, WhirExtensionEncodingError>
where
    Verify: FnOnce(&Path, &File) -> Result<(), WhirExtensionEncodingError>,
{
    // Clone the cleanup capability before publication so that every successful
    // hard-link creation is immediately covered by an owned-link guard.
    let cleanup_file = file
        .try_clone()
        .map_err(|source| io_error("cloning publication handle for", final_path, source))?;
    publish_no_overwrite(partial_path, final_path)?;
    let published = OwnedFileLink::new(final_path.to_path_buf(), cleanup_file);
    verify(final_path, published.file_ref())?;
    Ok(published)
}

fn publish_no_overwrite(
    partial_path: &Path,
    final_path: &Path,
) -> Result<(), WhirExtensionEncodingError> {
    match fs::hard_link(partial_path, final_path) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == io::ErrorKind::AlreadyExists => Err(
            WhirExtensionEncodingError::PublicationConflict(final_path.to_path_buf()),
        ),
        Err(source) => Err(io_error("publishing", final_path, source)),
    }
}

/// Keep the authenticated format independent of the exact bounded DFT engine.
/// A blocked or GPU implementation may replace this seam only after matching
/// the byte-for-byte regression and differential tests below.
fn run_external_dft(
    file: &mut File,
    path: &Path,
    height: usize,
    buffer_limbs: usize,
) -> Result<(), WhirExtensionEncodingError> {
    dft_goldilocks_rows_in_place(
        file,
        path,
        HEADER_BYTES as u64,
        height,
        WHIR_EXTENSION_LIMBS_PER_ROW,
        buffer_limbs,
    )?;
    Ok(())
}

fn create_unique_staging(
    scratch_directory: &Path,
) -> Result<(PathBuf, PathBuf, File), WhirExtensionEncodingError> {
    for _ in 0..CREATE_ATTEMPTS {
        let sequence = NEXT_ARTIFACT.fetch_add(1, Ordering::Relaxed);
        let stem = format!("cmfd-whir-extension-{}-{sequence}", std::process::id());
        let partial_path = scratch_directory.join(format!("{stem}.partial"));
        let final_path = scratch_directory.join(format!("{stem}.artifact"));
        if final_path.exists() {
            continue;
        }
        let file = match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&partial_path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(source) => return Err(io_error("creating", &partial_path, source)),
        };
        return Ok((partial_path, final_path, file));
    }
    Err(WhirExtensionEncodingError::NameExhausted(
        scratch_directory.to_path_buf(),
    ))
}

fn scatter_bit_reversed_residual(
    file: &mut File,
    path: &Path,
    residual: &AuthenticatedWhirResidualArtifact,
    expected_residual: &WhirResidualArtifactIdentity,
    geometry: &WhirExtensionGeometry,
    source_read_rows: usize,
) -> Result<(), WhirExtensionEncodingError> {
    let height = usize::try_from(geometry.height)
        .map_err(|_| WhirExtensionEncodingError::ResearchLimit("extension height"))?;
    let log_height = height.ilog2();
    let mut start = 0_u64;
    while start < geometry.residual_rows {
        let remaining = usize::try_from(geometry.residual_rows - start)
            .map_err(|_| WhirExtensionEncodingError::ResearchLimit("residual read size"))?;
        let count = remaining.min(source_read_rows);
        let rows = residual.read_rows(start, count)?;
        if residual.identity() != expected_residual
            || residual.geometry().row_count != geometry.residual_rows
            || rows.len() != count
        {
            return Err(WhirExtensionEncodingError::IdentityMismatch);
        }
        for (local_row, group) in rows.chunks_exact(WHIR_EXTENSION_WIDTH).enumerate() {
            let natural_row = usize::try_from(start / WHIR_EXTENSION_WIDTH as u64)
                .ok()
                .and_then(|base| base.checked_add(local_row))
                .ok_or(WhirExtensionEncodingError::ResearchLimit(
                    "coefficient row index",
                ))?;
            let physical_row = reverse_bits_len(natural_row, log_height);
            let mut encoded_row = [0_u64; WHIR_EXTENSION_LIMBS_PER_ROW];
            for (element, residual_row) in group.iter().enumerate() {
                let target = element * WHIR_EXTENSION_LIMBS_PER_ELEMENT;
                encoded_row[target..target + WHIR_EXTENSION_LIMBS_PER_ELEMENT]
                    .copy_from_slice(&residual_row[..WHIR_EXTENSION_LIMBS_PER_ELEMENT]);
            }
            write_encoded_row(file, path, physical_row, &encoded_row)?;
        }
        start =
            start
                .checked_add(count as u64)
                .ok_or(WhirExtensionEncodingError::ResearchLimit(
                    "residual read cursor",
                ))?;
    }
    if residual.identity() != expected_residual
        || residual.geometry().row_count != geometry.residual_rows
    {
        return Err(WhirExtensionEncodingError::IdentityMismatch);
    }
    Ok(())
}

fn seal_data(
    file: &mut File,
    path: &Path,
    prefix: &[u8; PREFIX_BYTES],
    geometry: &WhirExtensionGeometry,
) -> Result<(Vec<[u8; DIGEST_BYTES]>, [u8; DIGEST_BYTES]), WhirExtensionEncodingError> {
    file.sync_data()
        .map_err(|source| io_error("synchronizing staged data for", path, source))?;
    let mut global = global_hasher(prefix);
    let authentication_digests =
        scan_and_authenticate_data(file, path, prefix, geometry, None, &mut global)?;
    file.seek(SeekFrom::Start(HEADER_BYTES as u64 + geometry.data_bytes))
        .map_err(|source| io_error("seeking in", path, source))?;
    let authentication_bytes = authentication_digests
        .len()
        .checked_mul(DIGEST_BYTES)
        .ok_or(WhirExtensionEncodingError::ResearchLimit(
            "extension authentication table byte length",
        ))?;
    let mut encoded_authentication = Vec::new();
    encoded_authentication
        .try_reserve_exact(authentication_bytes)
        .map_err(|_| WhirExtensionEncodingError::ResearchLimit("extension authentication table"))?;
    for digest in &authentication_digests {
        encoded_authentication.extend_from_slice(digest);
        global.update(digest);
    }
    file.write_all(&encoded_authentication)
        .map_err(|source| io_error("writing authentication table to", path, source))?;
    let artifact_digest = *global.finalize().as_bytes();
    file.seek(SeekFrom::Start(PREFIX_BYTES as u64))
        .and_then(|_| file.write_all(&artifact_digest))
        .and_then(|()| file.sync_all())
        .map_err(|source| io_error("sealing", path, source))?;
    Ok((authentication_digests, artifact_digest))
}

fn authenticate_complete(
    file: &mut File,
    path: &Path,
    prefix: &[u8; PREFIX_BYTES],
    geometry: &WhirExtensionGeometry,
    authentication_digests: &[[u8; DIGEST_BYTES]],
    expected_global: [u8; DIGEST_BYTES],
) -> Result<(), WhirExtensionEncodingError> {
    let mut global = global_hasher(prefix);
    scan_and_authenticate_data(
        file,
        path,
        prefix,
        geometry,
        Some(authentication_digests),
        &mut global,
    )?;
    for digest in authentication_digests {
        global.update(digest);
    }
    if *global.finalize().as_bytes() != expected_global {
        return Err(WhirExtensionEncodingError::ChecksumMismatch);
    }
    Ok(())
}

fn scan_and_authenticate_data(
    file: &mut File,
    path: &Path,
    prefix: &[u8; PREFIX_BYTES],
    geometry: &WhirExtensionGeometry,
    expected: Option<&[[u8; DIGEST_BYTES]]>,
    global: &mut Hasher,
) -> Result<Vec<[u8; DIGEST_BYTES]>, WhirExtensionEncodingError> {
    let height = usize::try_from(geometry.height)
        .map_err(|_| WhirExtensionEncodingError::ResearchLimit("extension height"))?;
    let expected_count = usize::try_from(geometry.authentication_chunks)
        .map_err(|_| WhirExtensionEncodingError::ResearchLimit("extension authentication table"))?;
    if expected.is_some_and(|digests| digests.len() != expected_count) {
        return Err(WhirExtensionEncodingError::ChecksumMismatch);
    }
    let mut digests = Vec::new();
    digests
        .try_reserve_exact(expected_count)
        .map_err(|_| WhirExtensionEncodingError::ResearchLimit("extension authentication table"))?;
    for (chunk_index, chunk_start) in (0..height).step_by(AUTH_CHUNK_ROWS).enumerate() {
        let rows = (height - chunk_start).min(AUTH_CHUNK_ROWS);
        let bytes = read_encoded_rows(file, path, chunk_start, rows)?;
        let digest = authentication_digest(prefix, chunk_index as u64, &bytes);
        if expected.is_some_and(|values| values[chunk_index] != digest) {
            return Err(WhirExtensionEncodingError::ChecksumMismatch);
        }
        validate_encoded_rows(&bytes)?;
        global.update(&bytes);
        digests.push(digest);
    }
    if digests.len() != expected_count {
        return Err(WhirExtensionEncodingError::ChecksumMismatch);
    }
    Ok(digests)
}

fn read_authentication_table(
    file: &mut File,
    path: &Path,
    geometry: &WhirExtensionGeometry,
) -> Result<Vec<[u8; DIGEST_BYTES]>, WhirExtensionEncodingError> {
    let count = usize::try_from(geometry.authentication_chunks)
        .map_err(|_| WhirExtensionEncodingError::ResearchLimit("extension authentication table"))?;
    let encoded_len =
        count
            .checked_mul(DIGEST_BYTES)
            .ok_or(WhirExtensionEncodingError::ResearchLimit(
                "extension authentication table byte length",
            ))?;
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(encoded_len)
        .map_err(|_| WhirExtensionEncodingError::ResearchLimit("extension authentication table"))?;
    encoded.resize(encoded_len, 0);
    let mut digests = Vec::new();
    digests
        .try_reserve_exact(count)
        .map_err(|_| WhirExtensionEncodingError::ResearchLimit("extension authentication table"))?;
    file.seek(SeekFrom::Start(HEADER_BYTES as u64 + geometry.data_bytes))
        .map_err(|source| io_error("seeking in", path, source))?;
    file.read_exact(&mut encoded)
        .map_err(|source| io_error("reading authentication table from", path, source))?;
    digests.extend(encoded.chunks_exact(DIGEST_BYTES).map(|digest| {
        <[u8; DIGEST_BYTES]>::try_from(digest).expect("complete authentication digest")
    }));
    Ok(digests)
}

fn global_hasher(prefix: &[u8; PREFIX_BYTES]) -> Hasher {
    let mut hasher = Hasher::new_derive_key(GLOBAL_DOMAIN);
    hasher.update(prefix);
    hasher
}

fn authentication_digest(
    prefix: &[u8; PREFIX_BYTES],
    chunk_index: u64,
    bytes: &[u8],
) -> [u8; DIGEST_BYTES] {
    let mut hasher = Hasher::new_derive_key(AUTH_DOMAIN);
    hasher.update(prefix);
    hasher.update(&chunk_index.to_le_bytes());
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn write_encoded_row(
    file: &mut File,
    path: &Path,
    row: usize,
    values: &[u64; WHIR_EXTENSION_LIMBS_PER_ROW],
) -> Result<(), WhirExtensionEncodingError> {
    if values.iter().any(|&value| value >= GOLDILOCKS_MODULUS) {
        return Err(WhirExtensionEncodingError::Invalid(
            "residual returned a noncanonical cubic-extension limb",
        ));
    }
    let mut encoded = [0_u8; WHIR_EXTENSION_LIMBS_PER_ROW * size_of::<u64>()];
    for (value, bytes) in values
        .iter()
        .zip(encoded.chunks_exact_mut(size_of::<u64>()))
    {
        bytes.copy_from_slice(&value.to_le_bytes());
    }
    file.seek(SeekFrom::Start(data_offset(row)?))
        .and_then(|_| file.write_all(&encoded))
        .map_err(|source| io_error("scattering residual rows into", path, source))
}

fn read_encoded_rows(
    file: &mut File,
    path: &Path,
    row_start: usize,
    row_count: usize,
) -> Result<Vec<u8>, WhirExtensionEncodingError> {
    let byte_count = row_count.checked_mul(row_byte_width()).ok_or(
        WhirExtensionEncodingError::ResearchLimit("encoded row byte count"),
    )?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(byte_count)
        .map_err(|_| WhirExtensionEncodingError::ResearchLimit("encoded row allocation"))?;
    bytes.resize(byte_count, 0);
    file.seek(SeekFrom::Start(data_offset(row_start)?))
        .and_then(|_| file.read_exact(&mut bytes))
        .map_err(|source| io_error("reading authenticated rows from", path, source))?;
    Ok(bytes)
}

fn validate_encoded_rows(bytes: &[u8]) -> Result<(), WhirExtensionEncodingError> {
    if !bytes.len().is_multiple_of(size_of::<u64>()) {
        return Err(WhirExtensionEncodingError::Invalid(
            "encoded extension row length is not limb aligned",
        ));
    }
    if bytes.chunks_exact(size_of::<u64>()).any(|chunk| {
        u64::from_le_bytes(chunk.try_into().expect("eight-byte limb")) >= GOLDILOCKS_MODULUS
    }) {
        return Err(WhirExtensionEncodingError::Invalid(
            "extension artifact contains a noncanonical Goldilocks limb",
        ));
    }
    Ok(())
}

fn decode_values(bytes: &[u8], output: &mut Vec<u64>) {
    output.extend(
        bytes
            .chunks_exact(size_of::<u64>())
            .map(|chunk| u64::from_le_bytes(chunk.try_into().expect("eight-byte limb"))),
    );
}

const fn row_byte_width() -> usize {
    WHIR_EXTENSION_LIMBS_PER_ROW * size_of::<u64>()
}

fn data_offset(row: usize) -> Result<u64, WhirExtensionEncodingError> {
    row.checked_mul(row_byte_width())
        .and_then(|offset| offset.checked_add(HEADER_BYTES))
        .and_then(|offset| u64::try_from(offset).ok())
        .ok_or(WhirExtensionEncodingError::ResearchLimit(
            "extension row offset",
        ))
}

fn reverse_bits_len(value: usize, bits: u32) -> usize {
    value.reverse_bits() >> (usize::BITS - bits)
}

fn encode_prefix(
    codeword_id: [u8; 32],
    residual: &WhirResidualArtifactIdentity,
    log_inv_rate: u8,
    geometry: &WhirExtensionGeometry,
) -> [u8; PREFIX_BYTES] {
    let mut prefix = [0_u8; PREFIX_BYTES];
    prefix[0..8].copy_from_slice(MAGIC);
    prefix[8..12].copy_from_slice(&VERSION.to_le_bytes());
    prefix[12..16].copy_from_slice(&(HEADER_BYTES as u32).to_le_bytes());
    prefix[16..48].copy_from_slice(&codeword_id);
    prefix[48..80].copy_from_slice(&residual.spec.source_digest);
    prefix[80..112].copy_from_slice(&residual.spec.context_digest);
    prefix[112..144].copy_from_slice(&residual.artifact_digest);
    prefix[144..148].copy_from_slice(&residual.spec.num_variables.to_le_bytes());
    prefix[148..152].copy_from_slice(&residual.spec.generation.to_le_bytes());
    prefix[152..160].copy_from_slice(&residual.row_count.to_le_bytes());
    prefix[160] = WHIR_EXTENSION_FOLDING as u8;
    prefix[161] = log_inv_rate;
    prefix[162] = NATURAL_ROW_LAYOUT;
    prefix[163] = CANONICAL_U64_LE_ENCODING;
    prefix[164..168].copy_from_slice(&(WHIR_EXTENSION_WIDTH as u32).to_le_bytes());
    prefix[168..172].copy_from_slice(&(WHIR_EXTENSION_LIMBS_PER_ELEMENT as u32).to_le_bytes());
    prefix[172..176].copy_from_slice(&(WHIR_EXTENSION_LIMBS_PER_ROW as u32).to_le_bytes());
    prefix[176..184].copy_from_slice(&geometry.coefficient_rows.to_le_bytes());
    prefix[184..192].copy_from_slice(&geometry.height.to_le_bytes());
    prefix[192..200].copy_from_slice(&geometry.data_bytes.to_le_bytes());
    prefix[200..208].copy_from_slice(&geometry.authentication_chunks.to_le_bytes());
    prefix[208..216].copy_from_slice(&(AUTH_CHUNK_ROWS as u64).to_le_bytes());
    prefix[216..224].copy_from_slice(&geometry.artifact_bytes.to_le_bytes());
    prefix
}

struct DecodedPrefix {
    codeword_id: [u8; 32],
    residual: WhirResidualArtifactIdentity,
    log_inv_rate: u8,
    geometry: WhirExtensionGeometry,
}

fn decode_prefix(prefix: &[u8; PREFIX_BYTES]) -> Result<DecodedPrefix, WhirExtensionEncodingError> {
    if &prefix[0..8] != MAGIC
        || read_u32(prefix, 8)? != VERSION
        || read_u32(prefix, 12)? != HEADER_BYTES as u32
        || prefix[160] != WHIR_EXTENSION_FOLDING as u8
        || prefix[162] != NATURAL_ROW_LAYOUT
        || prefix[163] != CANONICAL_U64_LE_ENCODING
        || read_u32(prefix, 164)? != WHIR_EXTENSION_WIDTH as u32
        || read_u32(prefix, 168)? != WHIR_EXTENSION_LIMBS_PER_ELEMENT as u32
        || read_u32(prefix, 172)? != WHIR_EXTENSION_LIMBS_PER_ROW as u32
        || read_u64(prefix, 208)? != AUTH_CHUNK_ROWS as u64
        || prefix[224..].iter().any(|&byte| byte != 0)
    {
        return Err(WhirExtensionEncodingError::Invalid(
            "header suite, layout, or reserved bytes are not canonical",
        ));
    }
    let codeword_id = prefix[16..48].try_into().expect("fixed codeword digest");
    if codeword_id == [0; 32] {
        return Err(WhirExtensionEncodingError::Invalid(
            "codeword identity must be nonzero",
        ));
    }
    let residual = WhirResidualArtifactIdentity {
        spec: crate::whir_residual::WhirResidualArtifactSpec {
            source_digest: prefix[48..80].try_into().expect("fixed source digest"),
            context_digest: prefix[80..112].try_into().expect("fixed context digest"),
            num_variables: read_u32(prefix, 144)?,
            generation: read_u32(prefix, 148)?,
        },
        row_count: read_u64(prefix, 152)?,
        artifact_digest: prefix[112..144]
            .try_into()
            .expect("fixed residual artifact digest"),
    };
    let log_inv_rate = prefix[161];
    let geometry = whir_extension_geometry(&residual, log_inv_rate)?;
    if read_u64(prefix, 176)? != geometry.coefficient_rows
        || read_u64(prefix, 184)? != geometry.height
        || read_u64(prefix, 192)? != geometry.data_bytes
        || read_u64(prefix, 200)? != geometry.authentication_chunks
        || read_u64(prefix, 216)? != geometry.artifact_bytes
    {
        return Err(WhirExtensionEncodingError::Invalid(
            "header geometry is inconsistent",
        ));
    }
    Ok(DecodedPrefix {
        codeword_id,
        residual,
        log_inv_rate,
        geometry,
    })
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, WhirExtensionEncodingError> {
    bytes
        .get(offset..offset + size_of::<u32>())
        .and_then(|slice| slice.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(WhirExtensionEncodingError::Invalid("truncated header"))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, WhirExtensionEncodingError> {
    bytes
        .get(offset..offset + size_of::<u64>())
        .and_then(|slice| slice.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or(WhirExtensionEncodingError::Invalid("truncated header"))
}

fn remove_owned_file(path: &Path, file: &File) -> Result<(), WhirExtensionEncodingError> {
    ensure_path_names_file(path, file)?;
    fs::remove_file(path).map_err(|source| io_error("removing", path, source))
}

fn ensure_path_names_file(path: &Path, file: &File) -> Result<(), WhirExtensionEncodingError> {
    let owned_handle = Handle::from_file(
        file.try_clone()
            .map_err(|source| io_error("cloning cleanup handle for", path, source))?,
    )
    .map_err(|source| io_error("identifying owned file at", path, source))?;
    let path_handle = Handle::from_path(path)
        .map_err(|source| io_error("identifying cleanup path", path, source))?;
    if owned_handle != path_handle {
        return Err(WhirExtensionEncodingError::CleanupTargetChanged(
            path.to_path_buf(),
        ));
    }
    Ok(())
}

fn io_error(operation: &'static str, path: &Path, source: io::Error) -> WhirExtensionEncodingError {
    WhirExtensionEncodingError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

struct OwnedFileLink {
    cleanup_path: Option<PathBuf>,
    file: Option<File>,
}

impl OwnedFileLink {
    fn new(path: PathBuf, file: File) -> Self {
        Self {
            cleanup_path: Some(path),
            file: Some(file),
        }
    }

    fn file_mut(&mut self) -> &mut File {
        self.file.as_mut().expect("live staging file")
    }

    fn file_ref(&self) -> &File {
        self.file.as_ref().expect("live staging file")
    }

    fn disarm(&mut self) {
        self.cleanup_path.take();
        self.file.take();
    }
}

impl Drop for OwnedFileLink {
    fn drop(&mut self) {
        let (Some(path), Some(file)) = (self.cleanup_path.take(), self.file.take()) else {
            return;
        };
        let _ = remove_owned_file(&path, &file);
    }
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::io::{Read, Seek, SeekFrom, Write};

    use p3_blake3::Blake3;
    use p3_commit::{ExtensionMmcs, Mmcs};
    use p3_dft::{Radix2DFTSmallBatch, TwoAdicSubgroupDft};
    use p3_field::extension::CubicTrinomialExtensionField;
    use p3_field::{BasedVectorSpace, PrimeField64};
    use p3_goldilocks::Goldilocks;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_merkle_tree::MerkleTreeMmcs;
    use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};

    use super::*;
    use crate::whir_residual::{
        WHIR_RESIDUAL_LIMBS_PER_ROW, WhirResidualArtifactSpec, WhirResidualArtifactWriter,
    };

    type TestEF = CubicTrinomialExtensionField<Goldilocks>;
    type FieldHash = SerializingHasher<Blake3>;
    type Compress = CompressionFunctionFromHasher<Blake3, 2, 32>;
    type WhirMmcs = MerkleTreeMmcs<Goldilocks, u8, FieldHash, Compress, 2, 32>;

    fn test_directory(label: &str) -> PathBuf {
        let sequence = NEXT_ARTIFACT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "cmfd-whir-extension-test-{label}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    fn residual_spec(variables: u32) -> WhirResidualArtifactSpec {
        WhirResidualArtifactSpec {
            source_digest: [0x31; 32],
            context_digest: [0x72; 32],
            num_variables: variables,
            generation: 3,
        }
    }

    fn residual_row(index: u64) -> [u64; WHIR_RESIDUAL_LIMBS_PER_ROW] {
        core::array::from_fn(|limb| {
            (index
                .wrapping_mul(0x9e37_79b9)
                .wrapping_add((limb as u64 + 1) * 0x1_0000_01b3)
                .wrapping_add(17))
                % GOLDILOCKS_MODULUS
        })
    }

    fn build_residual(directory: &Path, variables: u32) -> AuthenticatedWhirResidualArtifact {
        let mut writer =
            WhirResidualArtifactWriter::create(directory, residual_spec(variables)).unwrap();
        let row_count = 1_u64 << variables;
        let mut start = 0_u64;
        while start < row_count {
            let count = usize::try_from((row_count - start).min(97)).unwrap();
            let rows = (0..count)
                .map(|offset| residual_row(start + offset as u64))
                .collect::<Vec<_>>();
            writer.write_rows(start, &rows).unwrap();
            start += count as u64;
        }
        writer.finish().unwrap()
    }

    fn expected_codeword(variables: u32, log_inv_rate: u8) -> Vec<u64> {
        type EF = CubicTrinomialExtensionField<Goldilocks>;

        let source_rows = 1_usize << variables;
        let height =
            1_usize << (variables as usize - WHIR_EXTENSION_FOLDING + log_inv_rate as usize);
        let zero = EF::from_basis_coefficients_fn(|_| Goldilocks::new(0));
        let mut coefficients = vec![zero; height * WHIR_EXTENSION_WIDTH];
        for natural_row in 0..source_rows / WHIR_EXTENSION_WIDTH {
            for element in 0..WHIR_EXTENSION_WIDTH {
                let source = residual_row((natural_row * WHIR_EXTENSION_WIDTH + element) as u64);
                coefficients[natural_row * WHIR_EXTENSION_WIDTH + element] =
                    EF::from_basis_coefficients_fn(|limb| Goldilocks::new(source[limb]));
            }
        }
        Radix2DFTSmallBatch::<Goldilocks>::new(height)
            .dft_algebra_batch(RowMajorMatrix::new(coefficients, WHIR_EXTENSION_WIDTH))
            .values
            .into_iter()
            .flat_map(|value| {
                <EF as BasedVectorSpace<Goldilocks>>::as_basis_coefficients_slice(&value).to_vec()
            })
            .map(|limb| limb.as_canonical_u64())
            .collect()
    }

    fn read_all(artifact: &AuthenticatedWhirExtensionCodeword) -> Vec<u64> {
        let height = usize::try_from(artifact.geometry().height).unwrap();
        let mut output = Vec::new();
        for start in (0..height).step_by(WHIR_EXTENSION_MAX_READ_ROWS) {
            let rows = (height - start).min(WHIR_EXTENSION_MAX_READ_ROWS);
            output.extend(artifact.read_canonical_rows(start, rows).unwrap());
        }
        output
    }

    fn synthetic_residual_identity(variables: u32) -> WhirResidualArtifactIdentity {
        WhirResidualArtifactIdentity {
            spec: residual_spec(variables),
            row_count: 1_u64 << variables,
            artifact_digest: [0xa5; 32],
        }
    }

    #[test]
    fn production_geometry_is_checked_without_allocating_the_codeword() {
        let geometry = whir_extension_geometry(&synthetic_residual_identity(29), 2).unwrap();
        assert_eq!(geometry.residual_rows, 1_u64 << 29);
        assert_eq!(geometry.coefficient_rows, 1_u64 << 27);
        assert_eq!(geometry.height, 1_u64 << 29);
        assert_eq!(geometry.data_bytes, 48_u64 * 1024 * 1024 * 1024);
        assert_eq!(geometry.authentication_chunks, 1_u64 << 16);
        assert_eq!(
            geometry.artifact_bytes,
            48_u64 * 1024 * 1024 * 1024 + 2_097_152 + HEADER_BYTES as u64
        );
        assert_eq!(
            WHIR_EXTENSION_MAX_DFT_BUFFER_LIMBS % WHIR_EXTENSION_LIMBS_PER_ROW,
            0
        );

        let mut inconsistent = synthetic_residual_identity(29);
        inconsistent.row_count -= 1;
        assert!(matches!(
            whir_extension_geometry(&inconsistent, 2),
            Err(WhirExtensionEncodingError::Invalid(_))
        ));
        assert!(matches!(
            whir_extension_geometry(&synthetic_residual_identity(30), 2),
            Err(WhirExtensionEncodingError::ResearchLimit(_))
        ));
    }

    #[test]
    fn reference_cap_rejects_production_before_source_use_or_file_creation() {
        let directory = test_directory("reference-cap");
        let residual = build_residual(&directory, 2);
        let entries_before = fs::read_dir(&directory).unwrap().count();
        let sequence = NEXT_ARTIFACT.fetch_add(1, Ordering::Relaxed);
        let missing_directory = std::env::temp_dir().join(format!(
            "cmfd-whir-extension-test-reference-cap-missing-{}-{sequence}",
            std::process::id()
        ));
        assert!(!missing_directory.exists());
        let result = encode_whir_extension_codeword(
            &missing_directory,
            [0x41; 32],
            &synthetic_residual_identity(29),
            &residual,
            2,
        );
        assert!(matches!(
            result,
            Err(WhirExtensionEncodingError::ResearchLimit(
                "reference encoder height exceeds 2^20"
            ))
        ));
        assert_eq!(fs::read_dir(&directory).unwrap().count(), entries_before);
        drop(residual);
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn external_dft_matches_small_batch_for_cubic_rows_and_partitions() {
        for (variables, log_inv_rate) in [(2, 1), (3, 1), (4, 2), (6, 1), (7, 2)] {
            let directory = test_directory("differential");
            let residual = build_residual(&directory, variables);
            let residual_identity = residual.identity().clone();
            let expected = expected_codeword(variables, log_inv_rate);
            let mut stable_digest = None;
            for (source_rows, dft_limbs) in [(4, 12), (12, 60), (32, 96)] {
                let artifact = encode_with_limits(
                    &directory,
                    [0x52; 32],
                    &residual_identity,
                    &residual,
                    log_inv_rate,
                    source_rows,
                    dft_limbs,
                )
                .unwrap();
                assert_eq!(artifact.identity().width, 4);
                assert_eq!(artifact.identity().folding, 2);
                assert_eq!(read_all(&artifact), expected);
                assert_eq!(
                    MerkleRowSource::read_rows(&artifact, 0, 1).unwrap(),
                    expected[..WHIR_EXTENSION_LIMBS_PER_ROW]
                );
                if let Some(digest) = stable_digest {
                    assert_eq!(artifact.identity().artifact_digest, digest);
                } else {
                    stable_digest = Some(artifact.identity().artifact_digest);
                }
                drop(artifact);
            }
            drop(residual);
            assert_eq!(fs::read_dir(&directory).unwrap().count(), 0);
            fs::remove_dir(directory).unwrap();
        }
    }

    #[test]
    fn artifact_digest_pins_the_reference_encoding_bytes() {
        let directory = test_directory("digest-regression");
        let residual = build_residual(&directory, 6);
        let artifact = encode_whir_extension_codeword(
            &directory,
            [0x63; 32],
            residual.identity(),
            &residual,
            2,
        )
        .unwrap();
        assert_eq!(
            artifact.identity().artifact_digest,
            [
                0x68, 0xf9, 0x49, 0x6d, 0xae, 0xca, 0xff, 0x3a, 0x22, 0xa2, 0xc6, 0x6c, 0xb9, 0xf6,
                0x86, 0x48, 0x70, 0x24, 0x9d, 0x8d, 0xf2, 0xf9, 0xca, 0x28, 0x61, 0x0e, 0x85, 0x69,
                0x7e, 0xcc, 0xab, 0xe3,
            ]
        );
        let reopened =
            AuthenticatedWhirExtensionCodeword::open(artifact.path(), artifact.identity()).unwrap();
        assert_eq!(
            reopened.read_canonical_rows(3, 2).unwrap(),
            artifact.read_canonical_rows(3, 2).unwrap()
        );
        drop(reopened);
        assert!(artifact.path().exists());
        drop(artifact);
        drop(residual);
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn flattened_rows_match_the_extension_mmcs_commitment() {
        let directory = test_directory("extension-mmcs");
        let residual = build_residual(&directory, 6);
        let artifact = encode_whir_extension_codeword(
            &directory,
            [0x69; 32],
            residual.identity(),
            &residual,
            2,
        )
        .unwrap();
        let expected = expected_codeword(6, 2);
        let extension_values = expected
            .chunks_exact(WHIR_EXTENSION_LIMBS_PER_ELEMENT)
            .map(|limbs| TestEF::from_basis_coefficients_fn(|index| Goldilocks::new(limbs[index])))
            .collect::<Vec<_>>();
        let base_mmcs = WhirMmcs::new(FieldHash::new(Blake3), Compress::new(Blake3), 0);
        let extension_mmcs = ExtensionMmcs::<Goldilocks, TestEF, _>::new(base_mmcs);
        let (commitment, _) = extension_mmcs.commit(vec![RowMajorMatrix::new(
            extension_values,
            WHIR_EXTENSION_WIDTH,
        )]);
        let tree_path = directory.join("extension-tree");
        let store = crate::blake3_merkle_store::build_authenticated_blake3_merkle_store(
            &tree_path,
            [0x9a; 32],
            &[&artifact],
        )
        .unwrap()
        .remove_on_drop();
        assert_eq!(store.root().unwrap(), commitment.roots()[0]);

        let height = MerkleRowSource::height(&artifact);
        let leaf_digests = artifact.read_leaf_digests(0, height).unwrap();
        let expected_leaf_digests = expected
            .chunks_exact(WHIR_EXTENSION_LIMBS_PER_ROW)
            .map(|row| {
                let encoded = row
                    .iter()
                    .flat_map(|value| value.to_le_bytes())
                    .collect::<Vec<_>>();
                *blake3::hash(&encoded).as_bytes()
            })
            .collect::<Vec<_>>();
        assert_eq!(leaf_digests, expected_leaf_digests);
        let supplied_tree_path = directory.join("extension-tree-supplied-leaves");
        let supplied_store = crate::blake3_merkle_store::build_authenticated_blake3_merkle_store_with_first_digest_layer(
            &supplied_tree_path,
            [0x9b; 32],
            &[&artifact],
            &artifact,
        )
        .unwrap()
        .remove_on_drop();
        assert_eq!(supplied_store.root().unwrap(), commitment.roots()[0]);

        drop(supplied_store);
        drop(store);
        drop(artifact);
        drop(residual);
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn exact_identity_and_live_corruption_fail_closed() {
        let directory = test_directory("identity-corruption");
        let residual = build_residual(&directory, 6);
        let artifact = encode_whir_extension_codeword(
            &directory,
            [0x74; 32],
            residual.identity(),
            &residual,
            2,
        )
        .unwrap();
        let path = artifact.path().to_path_buf();
        let identity = artifact.identity().clone();
        let mut wrong = identity.clone();
        wrong.residual.spec.context_digest[0] ^= 1;

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.seek(SeekFrom::Start(HEADER_BYTES as u64 + 17))
            .unwrap();
        let mut byte = [0_u8; 1];
        file.read_exact(&mut byte).unwrap();
        byte[0] ^= 0x80;
        file.seek(SeekFrom::Start(HEADER_BYTES as u64 + 17))
            .unwrap();
        file.write_all(&byte).unwrap();
        file.sync_all().unwrap();
        drop(file);
        assert!(matches!(
            AuthenticatedWhirExtensionCodeword::open(&path, &wrong),
            Err(WhirExtensionEncodingError::IdentityMismatch)
        ));
        assert!(matches!(
            artifact.read_canonical_rows(0, 1),
            Err(WhirExtensionEncodingError::ChecksumMismatch)
                | Err(WhirExtensionEncodingError::Invalid(_))
        ));
        assert!(matches!(
            artifact.read_leaf_digests(0, 1),
            Err(WhirExtensionEncodingError::ChecksumMismatch)
                | Err(WhirExtensionEncodingError::Invalid(_))
        ));
        assert!(matches!(
            AuthenticatedWhirExtensionCodeword::open(&path, &identity),
            Err(WhirExtensionEncodingError::ChecksumMismatch)
                | Err(WhirExtensionEncodingError::Invalid(_))
        ));
        drop(artifact);
        assert!(!path.exists());
        drop(residual);
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn truncation_and_trailing_bytes_are_rejected() {
        for append in [false, true] {
            let directory = test_directory(if append { "append" } else { "truncate" });
            let residual = build_residual(&directory, 4);
            let artifact = encode_whir_extension_codeword(
                &directory,
                [0x85; 32],
                residual.identity(),
                &residual,
                1,
            )
            .unwrap();
            let path = artifact.path().to_path_buf();
            let identity = artifact.identity().clone();
            if append {
                let mut file = OpenOptions::new().append(true).open(&path).unwrap();
                file.write_all(&[1]).unwrap();
                file.sync_all().unwrap();
            } else {
                let file = OpenOptions::new().write(true).open(&path).unwrap();
                file.set_len(artifact.geometry().artifact_bytes - 1)
                    .unwrap();
                file.sync_all().unwrap();
            }
            assert!(matches!(
                AuthenticatedWhirExtensionCodeword::open(&path, &identity),
                Err(WhirExtensionEncodingError::ChecksumMismatch)
            ));
            drop(artifact);
            assert!(!path.exists());
            drop(residual);
            fs::remove_dir(directory).unwrap();
        }
    }

    #[test]
    fn owned_cleanup_refuses_replaced_artifact_and_partial_paths() {
        let directory = test_directory("cleanup-substitution");
        let residual = build_residual(&directory, 3);
        let artifact = encode_whir_extension_codeword(
            &directory,
            [0x96; 32],
            residual.identity(),
            &residual,
            1,
        )
        .unwrap();
        let path = artifact.path().to_path_buf();
        let moved = directory.join("moved-owned-artifact");
        fs::rename(&path, &moved).unwrap();
        fs::write(&path, b"replacement owned elsewhere").unwrap();
        assert!(matches!(
            artifact.remove(),
            Err(WhirExtensionEncodingError::CleanupTargetChanged(changed)) if changed == path
        ));
        assert_eq!(fs::read(&path).unwrap(), b"replacement owned elsewhere");
        assert!(moved.exists());
        fs::remove_file(path).unwrap();
        fs::remove_file(moved).unwrap();

        let (partial, final_path, file) = create_unique_staging(&directory).unwrap();
        let staging = OwnedFileLink::new(partial.clone(), file);
        let moved_partial = directory.join("moved-owned-partial");
        fs::rename(&partial, &moved_partial).unwrap();
        fs::write(&partial, b"replacement partial").unwrap();
        drop(staging);
        assert_eq!(fs::read(&partial).unwrap(), b"replacement partial");
        assert!(moved_partial.exists());
        assert!(!final_path.exists());
        fs::remove_file(partial).unwrap();
        fs::remove_file(moved_partial).unwrap();

        drop(residual);
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn post_publication_verification_failure_removes_only_the_owned_link() {
        let directory = test_directory("publication-verification-error");
        let (partial, final_path, file) = create_unique_staging(&directory).unwrap();
        let staging = OwnedFileLink::new(partial.clone(), file);
        let neighbor = directory.join("unrelated");
        fs::write(&neighbor, b"keep me").unwrap();

        assert!(matches!(
            publish_verified_no_overwrite(&partial, &final_path, staging.file_ref(), |_, _| Err(
                WhirExtensionEncodingError::Invalid(
                    "injected post-publication verification failure"
                )
            ),),
            Err(WhirExtensionEncodingError::Invalid(
                "injected post-publication verification failure"
            ))
        ));
        assert!(!final_path.exists());
        assert!(partial.exists());
        assert_eq!(fs::read(&neighbor).unwrap(), b"keep me");

        drop(staging);
        assert!(!partial.exists());
        fs::remove_file(neighbor).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn publication_never_overwrites_an_existing_target() {
        let directory = test_directory("no-overwrite");
        let (partial, final_path, file) = create_unique_staging(&directory).unwrap();
        let staging = OwnedFileLink::new(partial.clone(), file);
        fs::write(&final_path, b"keep me").unwrap();
        assert!(matches!(
            publish_no_overwrite(&partial, &final_path),
            Err(WhirExtensionEncodingError::PublicationConflict(path)) if path == final_path
        ));
        assert_eq!(fs::read(&final_path).unwrap(), b"keep me");
        drop(staging);
        assert!(!partial.exists());
        fs::remove_file(final_path).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn invalid_identity_geometry_and_scratch_fail_before_staging() {
        let directory = test_directory("preflight");
        let residual = build_residual(&directory, 4);
        let entries = fs::read_dir(&directory).unwrap().count();
        assert!(matches!(
            encode_whir_extension_codeword(&directory, [0; 32], residual.identity(), &residual, 1,),
            Err(WhirExtensionEncodingError::Invalid(_))
        ));
        let mut wrong = residual.identity().clone();
        wrong.artifact_digest[0] ^= 1;
        assert!(matches!(
            encode_whir_extension_codeword(&directory, [1; 32], &wrong, &residual, 1),
            Err(WhirExtensionEncodingError::IdentityMismatch)
        ));
        assert_eq!(fs::read_dir(&directory).unwrap().count(), entries);
        assert!(matches!(
            encode_whir_extension_codeword(
                Path::new("relative"),
                [1; 32],
                residual.identity(),
                &residual,
                1,
            ),
            Err(WhirExtensionEncodingError::InvalidScratchDirectory(_))
        ));
        drop(residual);
        fs::remove_dir(directory).unwrap();
    }
}
