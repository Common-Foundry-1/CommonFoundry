//! Bounded external-memory encoding for WHIR's initial Suffix commitment.
//!
//! The pinned protocol uses folding two and starting log inverse rate one.
//! A table with `2^n` values is therefore copied into the first half of a
//! `2^(n-1) x 4` coefficient matrix, zero padded, and transformed column-wise.
//! This module stages that transform on disk and publishes only a completely
//! authenticated natural-row artifact. It is a research prover primitive; it
//! does not alter consensus or raise the production proof limits.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use blake3::Hasher;
use p3_field::{PrimeCharacteristicRing, PrimeField64, TwoAdicField};
use p3_goldilocks::Goldilocks;
use p3_matrix::Matrix;
use same_file::Handle;
use thiserror::Error;

use crate::blake3_merkle_store::{
    BLAKE3_LEAF_BATCH_ROWS, Blake3DigestSource, Blake3MerkleDigest, Blake3MerkleStoreError,
};
use crate::external_radix2::{
    ExternalRadix2Error, dft_goldilocks_natural_rows_in_place_cancellable,
    dft_goldilocks_rows_in_place,
};
use crate::merkle_store::{GOLDILOCKS_MODULUS, MerkleRowSource, MerkleStoreError};
use crate::whir_initial_source::{
    AuthenticatedWhirInitialSourceFile, WHIR_INITIAL_SOURCE_HEADER_BYTES,
    WhirInitialSourceArtifactIdentity,
};

/// Smallest table supported by folding two.
pub const WHIR_INITIAL_MIN_VARIABLES: usize = 2;
/// Legacy maximum used by the version-one initial WHIR oracle identity.
pub const WHIR_INITIAL_MAX_VARIABLES: usize = 19;
/// Largest table geometry admitted by the version-one artifact format.
pub const WHIR_INITIAL_ARTIFACT_MAX_VARIABLES: usize = 31;
/// Largest table the bounded reference encoder will execute.
pub const WHIR_INITIAL_REFERENCE_ENCODER_MAX_VARIABLES: usize = WHIR_INITIAL_MAX_VARIABLES;
/// Fixed row width selected by folding two.
pub const WHIR_INITIAL_WIDTH: usize = 4;
/// Maximum canonical source values requested in one call.
pub const WHIR_INITIAL_MAX_SOURCE_READ_LIMBS: usize = 8 * 1024;
/// Maximum field values held in either butterfly half-buffer.
pub const WHIR_INITIAL_MAX_DFT_BUFFER_LIMBS: usize = 8 * 1024;
/// Maximum rows returned by one authenticated artifact read.
pub const WHIR_INITIAL_MAX_READ_ROWS: usize = 256;

const MAGIC: &[u8; 8] = b"CMFDWIH1";
const VERSION: u32 = 1;
const FOLDING: u8 = 2;
const STARTING_LOG_INV_RATE: u8 = 1;
const NATURAL_ROW_LAYOUT: u8 = 1;
const CANONICAL_U64_LE_ENCODING: u8 = 1;
const PREFIX_BYTES: usize = 128;
const DIGEST_BYTES: usize = 32;
const HEADER_BYTES: usize = PREFIX_BYTES + DIGEST_BYTES;
const AUTH_CHUNK_ROWS: usize = 256;
const AUTH_SCAN_ROWS: usize = 8 * 1024;
const AUTH_DIGEST_IO_COUNT: usize = 2 * 1024;
const AUTH_DOMAIN: &[u8] = b"CMFD-WHIR-INITIAL-AUTH-V1";
const IDENTITY_BINDING_DOMAIN: &str = "Common Foundry WHIR initial codeword identity binding v1";
const N31_VARIABLES: u32 = 31;
const N31_SIDE: usize = 1 << 15;
const N31_TRANSPOSE_TILE: usize = 2 * 1024;
const N31_FFT_STRIP: usize = 256;
const N31_PROGRESS_REPORT_BYTES: u64 = 256 * 1024 * 1024;
const PRODUCTION_STAGING_ATTEMPTS: usize = 256;

static NEXT_PRODUCTION_STAGING_FILE: AtomicU64 = AtomicU64::new(0);

/// Exact nonallocating resource plan for the separate 31-variable encoder.
///
/// These are prover-local storage bounds. They do not enter Fiat-Shamir or
/// change the frozen `CMFDWIH1` artifact bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WhirInitialN31Plan {
    pub source_elements: u64,
    pub source_artifact_bytes: u64,
    pub codeword_height: u64,
    pub codeword_artifact_bytes: u64,
    pub demand_tree_artifact_bytes: u64,
    pub encoder_peak_bytes: u64,
    pub codeword_and_tree_bytes: u64,
    pub persistent_source_codeword_tree_bytes: u64,
    pub max_transform_memory_bytes: u64,
}

/// Deterministic stage of one exact 31-variable initial-codeword build.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WhirInitialN31Stage {
    Transpose,
    FirstFft,
    SecondFft,
    Seal,
    Verify,
}

/// Logical bytes completed within one exact n31 build stage.
///
/// These counters describe deterministic logical data processed, not physical
/// disk traffic or a wall-clock estimate. They reset to zero at each stage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WhirInitialN31Progress {
    pub stage: WhirInitialN31Stage,
    pub completed_bytes: u64,
    pub total_bytes: u64,
}

/// Result of a cooperatively controlled exact n31 build.
#[derive(Debug)]
// Boxing the normal success path would add an allocation to every production build.
#[allow(clippy::large_enum_variant)]
pub enum WhirInitialN31Outcome {
    Published(AuthenticatedWhirInitialCodeword),
    Cancelled(WhirInitialN31Progress),
}

enum ControlledSixStepError {
    Encoding(WhirInitialEncodingError),
    Cancelled(WhirInitialN31Progress),
}

impl From<WhirInitialEncodingError> for ControlledSixStepError {
    fn from(error: WhirInitialEncodingError) -> Self {
        Self::Encoding(error)
    }
}

type ControlledSixStepResult<T> = Result<T, ControlledSixStepError>;

struct N31ProgressController<'a> {
    cancelled: &'a AtomicBool,
    observe: &'a mut dyn FnMut(WhirInitialN31Progress),
    progress: Option<WhirInitialN31Progress>,
    last_reported_bytes: u64,
    stage_work_complete: bool,
}

impl<'a> N31ProgressController<'a> {
    fn new(cancelled: &'a AtomicBool, observe: &'a mut dyn FnMut(WhirInitialN31Progress)) -> Self {
        Self {
            cancelled,
            observe,
            progress: None,
            last_reported_bytes: 0,
            stage_work_complete: false,
        }
    }

    fn start_stage(
        &mut self,
        stage: WhirInitialN31Stage,
        total_bytes: u64,
    ) -> ControlledSixStepResult<()> {
        if total_bytes == 0
            || self
                .progress
                .is_some_and(|previous| previous.completed_bytes != previous.total_bytes)
            || self
                .progress
                .is_some_and(|previous| next_n31_stage(previous.stage) != Some(stage))
            || self.progress.is_none() && stage != WhirInitialN31Stage::Transpose
        {
            return Err(WhirInitialEncodingError::Invalid(
                "n31 progress stage transition is invalid",
            )
            .into());
        }
        self.progress = Some(WhirInitialN31Progress {
            stage,
            completed_bytes: 0,
            total_bytes,
        });
        self.last_reported_bytes = 0;
        self.stage_work_complete = false;
        self.check_cancelled()?;
        self.report()
    }

    fn checkpoint(&self) -> ControlledSixStepResult<()> {
        self.check_cancelled()
    }

    fn advance(&mut self, bytes: u64) -> ControlledSixStepResult<()> {
        if self.stage_work_complete {
            return Err(WhirInitialEncodingError::Invalid(
                "n31 progress advanced after stage work completed",
            )
            .into());
        }
        let (completed_bytes, total_bytes) = {
            let progress = self.progress.as_mut().ok_or_else(|| {
                ControlledSixStepError::from(WhirInitialEncodingError::Invalid(
                    "n31 progress stage has not started",
                ))
            })?;
            let completed_bytes = progress.completed_bytes.checked_add(bytes).ok_or_else(|| {
                ControlledSixStepError::from(WhirInitialEncodingError::Invalid(
                    "n31 progress byte count overflow",
                ))
            })?;
            if completed_bytes > progress.total_bytes {
                return Err(WhirInitialEncodingError::Invalid(
                    "n31 progress exceeds its stage total",
                )
                .into());
            }
            (completed_bytes, progress.total_bytes)
        };
        if completed_bytes == total_bytes {
            self.stage_work_complete = true;
            return self.check_cancelled();
        }
        self.progress
            .as_mut()
            .expect("n31 progress stage exists while advancing")
            .completed_bytes = completed_bytes;
        self.check_cancelled()?;
        if completed_bytes - self.last_reported_bytes >= N31_PROGRESS_REPORT_BYTES {
            self.report()?;
        }
        Ok(())
    }

    fn finish_stage(&mut self) -> ControlledSixStepResult<()> {
        if self.progress.is_none() {
            return Err(
                WhirInitialEncodingError::Invalid("n31 progress stage has not started").into(),
            );
        }
        if !self.stage_work_complete {
            return Err(
                WhirInitialEncodingError::Invalid("n31 progress stage is incomplete").into(),
            );
        }
        self.check_cancelled()?;
        let progress = self
            .progress
            .as_mut()
            .expect("n31 progress stage exists while finishing");
        progress.completed_bytes = progress.total_bytes;
        self.report()
    }

    fn check_cancelled(&self) -> ControlledSixStepResult<()> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err(self.cancellation_error());
        }
        Ok(())
    }

    fn cancellation_error(&self) -> ControlledSixStepError {
        ControlledSixStepError::Cancelled(
            self.progress.expect("n31 cancellation follows stage start"),
        )
    }

    fn report(&mut self) -> ControlledSixStepResult<()> {
        let progress = self.progress.ok_or_else(|| {
            ControlledSixStepError::from(WhirInitialEncodingError::Invalid(
                "n31 progress stage has not started",
            ))
        })?;
        (self.observe)(progress);
        self.last_reported_bytes = progress.completed_bytes;
        self.check_cancelled()
    }
}

const fn next_n31_stage(stage: WhirInitialN31Stage) -> Option<WhirInitialN31Stage> {
    match stage {
        WhirInitialN31Stage::Transpose => Some(WhirInitialN31Stage::FirstFft),
        WhirInitialN31Stage::FirstFft => Some(WhirInitialN31Stage::SecondFft),
        WhirInitialN31Stage::SecondFft => Some(WhirInitialN31Stage::Seal),
        WhirInitialN31Stage::Seal => Some(WhirInitialN31Stage::Verify),
        WhirInitialN31Stage::Verify => None,
    }
}

/// Return the exact 31-variable source, codeword, tree, disk, and transform
/// geometry without allocating a source row or opening a file.
pub const fn whir_initial_n31_plan() -> WhirInitialN31Plan {
    const SOURCE_ELEMENTS: u64 = 1 << 31;
    const SOURCE_DATA_BYTES: u64 = SOURCE_ELEMENTS * 8;
    const SOURCE_AUTH_BYTES: u64 =
        (SOURCE_ELEMENTS / WHIR_INITIAL_MAX_SOURCE_READ_LIMBS as u64) * DIGEST_BYTES as u64;
    const SOURCE_ARTIFACT_BYTES: u64 =
        WHIR_INITIAL_SOURCE_HEADER_BYTES as u64 + SOURCE_DATA_BYTES + SOURCE_AUTH_BYTES;
    const CODEWORD_HEIGHT: u64 = 1 << 30;
    const CODEWORD_DATA_BYTES: u64 = CODEWORD_HEIGHT * WHIR_INITIAL_WIDTH as u64 * 8;
    const CODEWORD_AUTH_BYTES: u64 =
        (CODEWORD_HEIGHT / AUTH_CHUNK_ROWS as u64) * DIGEST_BYTES as u64;
    const CODEWORD_ARTIFACT_BYTES: u64 =
        HEADER_BYTES as u64 + CODEWORD_DATA_BYTES + CODEWORD_AUTH_BYTES;
    const TREE_DIGESTS: u64 = CODEWORD_HEIGHT * 2 - 1;
    const DEMAND_TREE_ARTIFACT_BYTES: u64 = 256 + TREE_DIGESTS * DIGEST_BYTES as u64;
    const ENCODER_PEAK_BYTES: u64 = CODEWORD_DATA_BYTES * 2 + HEADER_BYTES as u64;
    const MAX_TRANSFORM_MEMORY_BYTES: u64 =
        N31_SIDE as u64 * N31_FFT_STRIP as u64 * WHIR_INITIAL_WIDTH as u64 * 8
            + N31_SIDE as u64 * WHIR_INITIAL_WIDTH as u64 * 8;

    WhirInitialN31Plan {
        source_elements: SOURCE_ELEMENTS,
        source_artifact_bytes: SOURCE_ARTIFACT_BYTES,
        codeword_height: CODEWORD_HEIGHT,
        codeword_artifact_bytes: CODEWORD_ARTIFACT_BYTES,
        demand_tree_artifact_bytes: DEMAND_TREE_ARTIFACT_BYTES,
        encoder_peak_bytes: ENCODER_PEAK_BYTES,
        codeword_and_tree_bytes: CODEWORD_ARTIFACT_BYTES + DEMAND_TREE_ARTIFACT_BYTES,
        persistent_source_codeword_tree_bytes: SOURCE_ARTIFACT_BYTES
            + CODEWORD_ARTIFACT_BYTES
            + DEMAND_TREE_ARTIFACT_BYTES,
        max_transform_memory_bytes: MAX_TRANSFORM_MEMORY_BYTES,
    }
}

/// Exact external identity of the authenticated table being encoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WhirInitialSourceIdentity {
    pub source_id: [u8; 32],
    pub num_variables: u32,
}

/// Fallible random-access source of canonical Goldilocks values.
///
/// Implementations must authenticate every returned range against the
/// externally retained [`WhirInitialSourceIdentity`] and fail if their backing
/// artifact changes. The encoder never requests more than
/// [`WHIR_INITIAL_MAX_SOURCE_READ_LIMBS`] values at once.
pub trait AuthenticatedWhirInitialSource: Sync {
    fn identity(&self) -> &WhirInitialSourceIdentity;

    fn len(&self) -> usize;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn read_elements(&self, start: usize, count: usize)
    -> Result<Vec<u64>, WhirInitialSourceError>;
}

/// Error surfaced by an authenticated source implementation.
#[derive(Debug, Error)]
#[error("{message}")]
pub struct WhirInitialSourceError {
    message: String,
}

impl WhirInitialSourceError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// Caller-retained identity required to reopen one natural-row artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WhirInitialCodewordIdentity {
    pub artifact_id: [u8; 32],
    pub source: WhirInitialSourceIdentity,
    pub height: u64,
    pub width: u32,
    pub artifact_digest: [u8; 32],
}

impl WhirInitialCodewordIdentity {
    /// Bind every caller-trusted identity field, derived geometry field, and
    /// fixed artifact-protocol field into one domain-separated digest.
    ///
    /// This identifies the exact authenticated initial codeword consumed by a
    /// demand tree. It is prover-local metadata and is not transcript input.
    pub fn binding_digest(&self) -> Result<[u8; 32], WhirInitialEncodingError> {
        let geometry = validate_geometry(self.artifact_id, &self.source)?;
        if self.height != geometry.height as u64 || self.width != WHIR_INITIAL_WIDTH as u32 {
            return Err(WhirInitialEncodingError::IdentityMismatch);
        }

        let mut hasher = Hasher::new_derive_key(IDENTITY_BINDING_DOMAIN);
        hasher.update(MAGIC);
        hasher.update(&VERSION.to_le_bytes());
        hasher.update(&(PREFIX_BYTES as u32).to_le_bytes());
        hasher.update(&(HEADER_BYTES as u32).to_le_bytes());
        hasher.update(&self.artifact_id);
        hasher.update(&self.source.source_id);
        hasher.update(&self.source.num_variables.to_le_bytes());
        hasher.update(&[FOLDING, STARTING_LOG_INV_RATE, NATURAL_ROW_LAYOUT]);
        hasher.update(&[CANONICAL_U64_LE_ENCODING]);
        hasher.update(&self.height.to_le_bytes());
        hasher.update(&self.width.to_le_bytes());
        hasher.update(&self.artifact_digest);
        hasher.update(&(geometry.source_elements as u64).to_le_bytes());
        hasher.update(&(geometry.height as u64).to_le_bytes());
        hasher.update(&geometry.data_bytes.to_le_bytes());
        hasher.update(&geometry.auth_count.to_le_bytes());
        hasher.update(&(AUTH_CHUNK_ROWS as u64).to_le_bytes());
        hasher.update(&(DIGEST_BYTES as u32).to_le_bytes());
        hasher.update(AUTH_DOMAIN);
        Ok(*hasher.finalize().as_bytes())
    }
}

#[derive(Debug, Error)]
pub enum WhirInitialEncodingError {
    #[error("invalid WHIR initial encoding: {0}")]
    Invalid(&'static str),
    #[error("WHIR initial encoding research limit exceeded: {0}")]
    ResearchLimit(&'static str),
    #[error("WHIR initial source failed: {0}")]
    Source(#[from] WhirInitialSourceError),
    #[error("WHIR initial artifact already exists at {0}")]
    AlreadyExists(PathBuf),
    #[error("WHIR initial n31 output must be absolute with an existing parent: {0}")]
    InvalidOutputPath(PathBuf),
    #[error(
        "WHIR initial n31 output has insufficient free space: need {required} bytes, have {available} bytes"
    )]
    InsufficientSpace { required: u64, available: u64 },
    #[error("could not allocate a unique WHIR initial n31 staging file in {0}")]
    NameExhausted(PathBuf),
    #[error("WHIR initial n31 cleanup path no longer names the owned file: {0}")]
    CleanupTargetChanged(PathBuf),
    #[error(
        "durable parent-directory synchronization is unsupported for WHIR initial n31 output {path}: {source}"
    )]
    ParentDirectorySyncUnsupported {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("WHIR initial artifact I/O failed while {operation} {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("WHIR initial artifact checksum does not match")]
    ChecksumMismatch,
    #[error("WHIR initial artifact identity does not match")]
    IdentityMismatch,
    #[error("WHIR initial artifact file lock is poisoned")]
    LockPoisoned,
}

impl From<ExternalRadix2Error> for WhirInitialEncodingError {
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

/// Fully authenticated natural-row initial WHIR codeword.
pub struct AuthenticatedWhirInitialCodeword {
    file: Mutex<File>,
    path: PathBuf,
    identity: WhirInitialCodewordIdentity,
    height: usize,
    prefix: [u8; PREFIX_BYTES],
    auth_digests: Vec<[u8; DIGEST_BYTES]>,
    cleanup: Option<ArtifactCleanup>,
}

struct ArtifactCleanup(PathBuf);

impl Drop for ArtifactCleanup {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

impl std::fmt::Debug for AuthenticatedWhirInitialCodeword {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthenticatedWhirInitialCodeword")
            .field("path", &self.path)
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl AuthenticatedWhirInitialCodeword {
    /// Open an artifact and require exact caller-retained identity.
    pub fn open(
        path: impl AsRef<Path>,
        expected: &WhirInitialCodewordIdentity,
    ) -> Result<Self, WhirInitialEncodingError> {
        let artifact = Self::open_integrity_only(path.as_ref())?;
        if &artifact.identity != expected {
            return Err(WhirInitialEncodingError::IdentityMismatch);
        }
        Ok(artifact)
    }

    fn open_integrity_only(path: &Path) -> Result<Self, WhirInitialEncodingError> {
        match Self::open_integrity_only_inner(path, None) {
            Ok(artifact) => Ok(artifact),
            Err(ControlledSixStepError::Encoding(error)) => Err(error),
            Err(ControlledSixStepError::Cancelled(_)) => {
                unreachable!("integrity verification without control cannot be cancelled")
            }
        }
    }

    fn open_integrity_only_with_control(
        path: &Path,
        controller: &mut N31ProgressController<'_>,
    ) -> ControlledSixStepResult<Self> {
        Self::open_integrity_only_inner(path, Some(controller))
    }

    fn open_integrity_only_inner(
        path: &Path,
        mut controller: Option<&mut N31ProgressController<'_>>,
    ) -> ControlledSixStepResult<Self> {
        let path = path.to_path_buf();
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
        let total_bytes = (HEADER_BYTES as u64)
            .checked_add(decoded.data_bytes)
            .and_then(|value| value.checked_add(decoded.auth_count * DIGEST_BYTES as u64))
            .ok_or(WhirInitialEncodingError::Invalid(
                "artifact length overflow",
            ))?;
        let actual_bytes = file
            .metadata()
            .map_err(|source| io_error("reading metadata for", &path, source))?
            .len();
        if actual_bytes != total_bytes {
            return Err(
                WhirInitialEncodingError::Invalid("artifact length does not match header").into(),
            );
        }

        let auth_count = usize::try_from(decoded.auth_count)
            .map_err(|_| WhirInitialEncodingError::ResearchLimit("authentication table"))?;
        file.seek(SeekFrom::Start(HEADER_BYTES as u64 + decoded.data_bytes))
            .map_err(|source| io_error("reading authentication table from", &path, source))?;
        let auth_digests = read_auth_digests_with_control(
            &mut file,
            &path,
            auth_count,
            controller.as_deref_mut(),
        )?;

        authenticate_complete_with_control(
            &mut file,
            &path,
            &prefix,
            decoded.height,
            &auth_digests,
            stored_digest,
            controller,
        )?;
        Ok(Self {
            file: Mutex::new(file),
            path,
            identity: WhirInitialCodewordIdentity {
                artifact_id: decoded.artifact_id,
                source: WhirInitialSourceIdentity {
                    source_id: decoded.source_id,
                    num_variables: decoded.num_variables,
                },
                height: decoded.height as u64,
                width: WHIR_INITIAL_WIDTH as u32,
                artifact_digest: stored_digest,
            },
            height: decoded.height,
            prefix,
            auth_digests,
            cleanup: None,
        })
    }

    pub const fn identity(&self) -> &WhirInitialCodewordIdentity {
        &self.identity
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn remove_on_drop(mut self) -> Self {
        self.cleanup = Some(ArtifactCleanup(self.path.clone()));
        self
    }

    /// Read and independently authenticate consecutive natural rows.
    pub fn read_canonical_rows(
        &self,
        row_start: usize,
        row_count: usize,
    ) -> Result<Vec<u64>, WhirInitialEncodingError> {
        self.read_authenticated_rows(row_start, row_count, WHIR_INITIAL_MAX_READ_ROWS)
    }

    fn read_authenticated_rows(
        &self,
        row_start: usize,
        row_count: usize,
        maximum_rows: usize,
    ) -> Result<Vec<u64>, WhirInitialEncodingError> {
        let row_end = row_start
            .checked_add(row_count)
            .ok_or(WhirInitialEncodingError::Invalid("row range overflow"))?;
        if row_count == 0 || row_count > maximum_rows || row_end > self.height {
            return Err(WhirInitialEncodingError::Invalid(
                "row range is outside the bounded artifact",
            ));
        }
        let value_count =
            row_count
                .checked_mul(WHIR_INITIAL_WIDTH)
                .ok_or(WhirInitialEncodingError::Invalid(
                    "row value count overflow",
                ))?;
        let mut output = Vec::new();
        output
            .try_reserve_exact(value_count)
            .map_err(|_| WhirInitialEncodingError::ResearchLimit("row output"))?;
        let first_chunk = row_start / AUTH_CHUNK_ROWS;
        let last_chunk = (row_end - 1) / AUTH_CHUNK_ROWS;
        let authenticated_start = first_chunk * AUTH_CHUNK_ROWS;
        let authenticated_end = last_chunk
            .checked_add(1)
            .and_then(|chunks| chunks.checked_mul(AUTH_CHUNK_ROWS))
            .ok_or(WhirInitialEncodingError::Invalid(
                "authenticated row range overflow",
            ))?
            .min(self.height);
        let mut file = self
            .file
            .lock()
            .map_err(|_| WhirInitialEncodingError::LockPoisoned)?;
        let bytes = read_encoded_rows(
            &mut file,
            &self.path,
            authenticated_start,
            authenticated_end - authenticated_start,
        )?;
        validate_encoded_rows(&bytes)?;
        for chunk_index in first_chunk..=last_chunk {
            let chunk_start = chunk_index * AUTH_CHUNK_ROWS;
            let chunk_rows = (self.height - chunk_start).min(AUTH_CHUNK_ROWS);
            let byte_start = (chunk_start - authenticated_start) * WHIR_INITIAL_WIDTH * 8;
            let byte_end = byte_start + chunk_rows * WHIR_INITIAL_WIDTH * 8;
            if auth_digest(&self.prefix, chunk_index, &bytes[byte_start..byte_end])
                != self.auth_digests[chunk_index]
            {
                return Err(WhirInitialEncodingError::ChecksumMismatch);
            }
        }
        let byte_start = (row_start - authenticated_start) * WHIR_INITIAL_WIDTH * 8;
        let byte_end = (row_end - authenticated_start) * WHIR_INITIAL_WIDTH * 8;
        decode_values(&bytes[byte_start..byte_end], &mut output);
        Ok(output)
    }
}

impl Matrix<Goldilocks> for AuthenticatedWhirInitialCodeword {
    fn width(&self) -> usize {
        WHIR_INITIAL_WIDTH
    }

    fn height(&self) -> usize {
        self.height
    }

    unsafe fn row_subseq_unchecked(
        &self,
        row: usize,
        start: usize,
        end: usize,
    ) -> impl IntoIterator<Item = Goldilocks, IntoIter = impl Iterator<Item = Goldilocks> + Send + Sync>
    {
        debug_assert!(row < self.height);
        debug_assert!(start <= end && end <= WHIR_INITIAL_WIDTH);
        let values = self
            .read_canonical_rows(row, 1)
            .unwrap_or_else(|error| panic!("authenticated WHIR codeword read failed: {error}"));
        values[start..end]
            .iter()
            .copied()
            .map(Goldilocks::new)
            .collect::<Vec<_>>()
            .into_iter()
    }
}

impl MerkleRowSource for AuthenticatedWhirInitialCodeword {
    fn height(&self) -> usize {
        self.height
    }

    fn width(&self) -> usize {
        WHIR_INITIAL_WIDTH
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

impl Blake3DigestSource for AuthenticatedWhirInitialCodeword {
    fn height(&self) -> usize {
        self.height
    }

    fn read_digests(
        &self,
        row_start: usize,
        row_count: usize,
    ) -> Result<Vec<Blake3MerkleDigest>, Blake3MerkleStoreError> {
        if row_count == 0 || row_count > BLAKE3_LEAF_BATCH_ROWS {
            return Err(Blake3MerkleStoreError::Invalid(
                "initial leaf digest read is empty or exceeds the batch limit",
            ));
        }
        let row_end = row_start
            .checked_add(row_count)
            .ok_or(Blake3MerkleStoreError::Invalid(
                "initial leaf digest range overflow",
            ))?;
        if row_end > self.height {
            return Err(Blake3MerkleStoreError::Invalid(
                "initial leaf digest range is outside the codeword",
            ));
        }

        let mut digests = Vec::new();
        digests
            .try_reserve_exact(row_count)
            .map_err(|_| Blake3MerkleStoreError::ResearchLimit("initial leaf digest allocation"))?;
        let values = self
            .read_authenticated_rows(row_start, row_count, BLAKE3_LEAF_BATCH_ROWS)
            .map_err(|error| Blake3MerkleStoreError::Source(error.to_string()))?;
        if values.len() != row_count * WHIR_INITIAL_WIDTH {
            return Err(Blake3MerkleStoreError::Source(
                "authenticated initial row count changed".to_owned(),
            ));
        }
        for row in values.chunks_exact(WHIR_INITIAL_WIDTH) {
            let mut hasher = Hasher::new();
            for value in row {
                hasher.update(&value.to_le_bytes());
            }
            digests.push(*hasher.finalize().as_bytes());
        }
        Ok(digests)
    }
}

/// Encode and atomically publish one exact initial WHIR Suffix codeword.
///
/// Over-cap or malformed geometry is rejected before any source range is read
/// or partial file is created. `artifact_id` and `source.source_id` must be
/// externally selected, nonzero identities.
pub fn encode_whir_initial_suffix(
    final_path: impl AsRef<Path>,
    artifact_id: [u8; 32],
    expected_source: &WhirInitialSourceIdentity,
    source: &dyn AuthenticatedWhirInitialSource,
) -> Result<AuthenticatedWhirInitialCodeword, WhirInitialEncodingError> {
    encode_with_limits(
        final_path.as_ref(),
        artifact_id,
        expected_source,
        source,
        WHIR_INITIAL_MAX_SOURCE_READ_LIMBS,
        WHIR_INITIAL_MAX_DFT_BUFFER_LIMBS,
    )
}

/// Encode and publish the exact 31-variable initial WHIR codeword with a
/// bounded same-directory six-step transform.
///
/// This is intentionally separate from [`encode_whir_initial_suffix`], whose
/// version-one reference limit remains 19 variables. The source must be the
/// exact authenticated artifact identified by `expected_source`; accepting a
/// caller-implemented source here would weaken that provenance boundary.
/// The output parent must remain access-controlled against untrusted writers
/// for the call and for every later path-based use of the returned artifact.
/// Portable path-based publication and cleanup cannot be made race-free
/// against another actor that can rename entries in the same directory.
pub fn encode_whir_initial_suffix_n31(
    final_path: impl AsRef<Path>,
    artifact_id: [u8; 32],
    expected_source: &WhirInitialSourceArtifactIdentity,
    source: &AuthenticatedWhirInitialSourceFile,
) -> Result<AuthenticatedWhirInitialCodeword, WhirInitialEncodingError> {
    let cancelled = AtomicBool::new(false);
    match encode_whir_initial_suffix_n31_with_control(
        final_path,
        artifact_id,
        expected_source,
        source,
        &cancelled,
        |_| {},
    )? {
        WhirInitialN31Outcome::Published(artifact) => Ok(artifact),
        WhirInitialN31Outcome::Cancelled(_) => {
            unreachable!("a false n31 cancellation token cannot cancel encoding")
        }
    }
}

/// Encode the exact 31-variable initial WHIR codeword with deterministic
/// progress reporting and cooperative cross-thread cancellation.
///
/// The observer runs synchronously on the encoding thread at stage start,
/// approximately every 256 MiB of logical progress, and stage completion. A
/// panic in the observer unwinds through the existing owned-staging cleanup.
/// `cancelled` is read with acquire ordering at bounded work checkpoints and
/// must be treated as a one-way token. Cancellation after the final
/// pre-publication check is intentionally ignored so the hard-link and
/// directory-synchronization commit sequence remains indivisible.
pub fn encode_whir_initial_suffix_n31_with_control<F>(
    final_path: impl AsRef<Path>,
    artifact_id: [u8; 32],
    expected_source: &WhirInitialSourceArtifactIdentity,
    source: &AuthenticatedWhirInitialSourceFile,
    cancelled: &AtomicBool,
    mut observe: F,
) -> Result<WhirInitialN31Outcome, WhirInitialEncodingError>
where
    F: FnMut(WhirInitialN31Progress),
{
    #[cfg(not(target_pointer_width = "64"))]
    return Err(WhirInitialEncodingError::ResearchLimit(
        "n31 encoder requires a 64-bit target",
    ));

    let plan = whir_initial_n31_plan();
    if expected_source.source.num_variables != N31_VARIABLES
        || expected_source.element_count != plan.source_elements
    {
        return Err(WhirInitialEncodingError::Invalid(
            "n31 encoder requires exactly 31 source variables",
        ));
    }
    if source.artifact_identity() != expected_source {
        return Err(WhirInitialEncodingError::IdentityMismatch);
    }
    let mut controller = N31ProgressController::new(cancelled, &mut observe);
    match encode_six_step_suffix_with_control(
        final_path.as_ref(),
        artifact_id,
        &expected_source.source,
        source,
        N31_TRANSPOSE_TILE,
        N31_FFT_STRIP,
        &mut controller,
    ) {
        Ok(artifact) => Ok(WhirInitialN31Outcome::Published(artifact)),
        Err(ControlledSixStepError::Cancelled(progress)) => {
            Ok(WhirInitialN31Outcome::Cancelled(progress))
        }
        Err(ControlledSixStepError::Encoding(error)) => Err(error),
    }
}

#[cfg(test)]
fn encode_six_step_suffix(
    final_path: &Path,
    artifact_id: [u8; 32],
    expected_source: &WhirInitialSourceIdentity,
    source: &dyn AuthenticatedWhirInitialSource,
    transpose_tile: usize,
    fft_strip: usize,
) -> Result<AuthenticatedWhirInitialCodeword, WhirInitialEncodingError> {
    let cancelled = AtomicBool::new(false);
    let mut observe = |_| {};
    let mut controller = N31ProgressController::new(&cancelled, &mut observe);
    match encode_six_step_suffix_with_control(
        final_path,
        artifact_id,
        expected_source,
        source,
        transpose_tile,
        fft_strip,
        &mut controller,
    ) {
        Ok(artifact) => Ok(artifact),
        Err(ControlledSixStepError::Encoding(error)) => Err(error),
        Err(ControlledSixStepError::Cancelled(_)) => {
            unreachable!("a false six-step cancellation token cannot cancel encoding")
        }
    }
}

fn encode_six_step_suffix_with_control(
    final_path: &Path,
    artifact_id: [u8; 32],
    expected_source: &WhirInitialSourceIdentity,
    source: &dyn AuthenticatedWhirInitialSource,
    transpose_tile: usize,
    fft_strip: usize,
    controller: &mut N31ProgressController<'_>,
) -> ControlledSixStepResult<AuthenticatedWhirInitialCodeword> {
    let geometry = validate_geometry(artifact_id, expected_source)?;
    let height_log = geometry.height.ilog2() as usize;
    if !height_log.is_multiple_of(2) {
        return Err(WhirInitialEncodingError::Invalid(
            "six-step codeword height must have an even logarithm",
        )
        .into());
    }
    let side = 1_usize.checked_shl((height_log / 2) as u32).ok_or(
        WhirInitialEncodingError::ResearchLimit("six-step matrix side"),
    )?;
    if side.checked_mul(side) != Some(geometry.height)
        || geometry.source_elements / WHIR_INITIAL_WIDTH != geometry.height / 2
        || transpose_tile == 0
        || transpose_tile > side
        || !side.is_multiple_of(transpose_tile)
        || transpose_tile
            .checked_mul(WHIR_INITIAL_WIDTH)
            .is_none_or(|limbs| limbs > WHIR_INITIAL_MAX_SOURCE_READ_LIMBS)
        || fft_strip == 0
        || fft_strip > side
        || !side.is_multiple_of(fft_strip)
    {
        return Err(WhirInitialEncodingError::Invalid(
            "six-step geometry or buffer partition is invalid",
        )
        .into());
    }
    if source.identity() != expected_source {
        return Err(WhirInitialEncodingError::IdentityMismatch.into());
    }
    if source.len() != geometry.source_elements {
        return Err(WhirInitialEncodingError::Invalid(
            "source length does not match num_variables",
        )
        .into());
    }

    let parent = production_artifact_parent(final_path)?;
    if final_path
        .try_exists()
        .map_err(|source| io_error("checking publication target", final_path, source))?
    {
        return Err(WhirInitialEncodingError::AlreadyExists(final_path.to_path_buf()).into());
    }
    let required = geometry
        .data_bytes
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(HEADER_BYTES as u64))
        .ok_or(WhirInitialEncodingError::ResearchLimit(
            "six-step scratch byte length",
        ))?;
    require_available_space(&parent, required)?;

    let source_data_bytes = u64::try_from(geometry.source_elements)
        .ok()
        .and_then(|elements| elements.checked_mul(8))
        .ok_or(WhirInitialEncodingError::ResearchLimit(
            "six-step source progress byte length",
        ))?;
    let sealed_bytes = geometry
        .auth_count
        .checked_mul(DIGEST_BYTES as u64)
        .and_then(|auth_bytes| geometry.data_bytes.checked_add(auth_bytes))
        .ok_or(WhirInitialEncodingError::ResearchLimit(
            "six-step sealed progress byte length",
        ))?;
    controller.start_stage(WhirInitialN31Stage::Transpose, source_data_bytes)?;

    let (first_path, first_file) = create_unique_production_staging(final_path, "transpose-1")?;
    let mut first = OwnedProductionFile::new(first_path.clone(), first_file);
    first
        .file_mut()
        .set_len(geometry.data_bytes)
        .map_err(|source| io_error("sizing", &first_path, source))?;
    transpose_source_into_first(
        first.file_mut(),
        &first_path,
        source,
        expected_source,
        &geometry,
        side,
        transpose_tile,
        controller,
    )?;
    first
        .file_mut()
        .sync_data()
        .map_err(|source| io_error("synchronizing", &first_path, source))?;
    controller.finish_stage()?;
    controller.start_stage(WhirInitialN31Stage::FirstFft, geometry.data_bytes)?;

    let (second_path, second_file) = create_unique_production_staging(final_path, "transpose-2")?;
    let mut second = OwnedProductionFile::new(second_path.clone(), second_file);
    second
        .file_mut()
        .set_len(geometry.data_bytes)
        .map_err(|source| io_error("sizing", &second_path, source))?;
    six_step_first_fft(
        first.file_mut(),
        &first_path,
        second.file_mut(),
        &second_path,
        side,
        fft_strip,
        controller,
    )?;
    second
        .file_mut()
        .sync_data()
        .map_err(|source| io_error("synchronizing", &second_path, source))?;
    controller.finish_stage()?;
    first.remove()?;

    controller.start_stage(WhirInitialN31Stage::SecondFft, geometry.data_bytes)?;

    let (output_path, output_file) = create_unique_production_staging(final_path, "codeword")?;
    let mut output = OwnedProductionFile::new(output_path.clone(), output_file);
    let prefix = encode_prefix(artifact_id, expected_source, &geometry);
    output
        .file_mut()
        .write_all(&prefix)
        .and_then(|()| output.file_mut().write_all(&[0_u8; DIGEST_BYTES]))
        .and_then(|()| {
            output
                .file_mut()
                .set_len(HEADER_BYTES as u64 + geometry.data_bytes)
        })
        .map_err(|source| io_error("initializing", &output_path, source))?;
    six_step_second_fft(
        second.file_mut(),
        &second_path,
        output.file_mut(),
        &output_path,
        side,
        fft_strip,
        controller,
    )?;
    output
        .file_mut()
        .sync_data()
        .map_err(|source| io_error("synchronizing", &output_path, source))?;
    controller.finish_stage()?;
    second.remove()?;

    controller.start_stage(WhirInitialN31Stage::Seal, sealed_bytes)?;
    let (_, artifact_digest) = seal_data_with_control(
        output.file_mut(),
        &output_path,
        &prefix,
        geometry.height,
        controller,
    )?;
    controller.finish_stage()?;

    controller.start_stage(WhirInitialN31Stage::Verify, sealed_bytes)?;
    let staged = AuthenticatedWhirInitialCodeword::open_integrity_only_with_control(
        &output_path,
        controller,
    )?;
    controller.finish_stage()?;
    debug_assert_eq!(staged.identity.artifact_digest, artifact_digest);
    controller.checkpoint()?;
    publish_verified_production_artifact(output, final_path, &parent, staged)
        .map_err(ControlledSixStepError::from)
}

fn encode_with_limits(
    final_path: &Path,
    artifact_id: [u8; 32],
    expected_source: &WhirInitialSourceIdentity,
    source: &dyn AuthenticatedWhirInitialSource,
    source_read_limbs: usize,
    dft_buffer_limbs: usize,
) -> Result<AuthenticatedWhirInitialCodeword, WhirInitialEncodingError> {
    if expected_source.num_variables
        > u32::try_from(WHIR_INITIAL_REFERENCE_ENCODER_MAX_VARIABLES)
            .expect("reference encoder cap fits u32")
    {
        return Err(WhirInitialEncodingError::ResearchLimit(
            "reference encoder num_variables exceeds 19",
        ));
    }
    let geometry = validate_geometry(artifact_id, expected_source)?;
    if source_read_limbs == 0
        || source_read_limbs > WHIR_INITIAL_MAX_SOURCE_READ_LIMBS
        || !source_read_limbs.is_multiple_of(WHIR_INITIAL_WIDTH)
        || !(WHIR_INITIAL_WIDTH..=WHIR_INITIAL_MAX_DFT_BUFFER_LIMBS).contains(&dft_buffer_limbs)
        || !dft_buffer_limbs.is_multiple_of(WHIR_INITIAL_WIDTH)
    {
        return Err(WhirInitialEncodingError::Invalid(
            "internal buffer limit is invalid",
        ));
    }
    if source.identity() != expected_source {
        return Err(WhirInitialEncodingError::IdentityMismatch);
    }
    if source.len() != geometry.source_elements {
        return Err(WhirInitialEncodingError::Invalid(
            "source length does not match num_variables",
        ));
    }
    if final_path.exists() {
        return Err(WhirInitialEncodingError::AlreadyExists(
            final_path.to_path_buf(),
        ));
    }
    let partial_path = partial_path_for(final_path)?;
    let prefix = encode_prefix(artifact_id, expected_source, &geometry);
    let mut cleanup = PartialCleanup(Some(partial_path.clone()));
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&partial_path)
        .map_err(|source| {
            if source.kind() == io::ErrorKind::AlreadyExists {
                WhirInitialEncodingError::AlreadyExists(partial_path.clone())
            } else {
                io_error("creating", &partial_path, source)
            }
        })?;
    file.write_all(&prefix)
        .and_then(|()| file.write_all(&[0_u8; DIGEST_BYTES]))
        .and_then(|()| file.set_len(HEADER_BYTES as u64 + geometry.data_bytes))
        .map_err(|source| io_error("initializing", &partial_path, source))?;

    scatter_bit_reversed_source(
        &mut file,
        &partial_path,
        source,
        expected_source,
        &geometry,
        source_read_limbs,
    )?;
    dft_goldilocks_rows_in_place(
        &mut file,
        &partial_path,
        HEADER_BYTES as u64,
        geometry.height,
        WHIR_INITIAL_WIDTH,
        dft_buffer_limbs,
    )?;
    let (auth_digests, artifact_digest) =
        seal_data(&mut file, &partial_path, &prefix, geometry.height)?;
    drop(file);

    let staged_artifact = AuthenticatedWhirInitialCodeword::open_integrity_only(&partial_path)?;
    debug_assert_eq!(staged_artifact.auth_digests, auth_digests);
    debug_assert_eq!(staged_artifact.identity.artifact_digest, artifact_digest);
    let expected_identity = staged_artifact.identity.clone();
    fs::hard_link(&partial_path, final_path)
        .map_err(|source| io_error("publishing", final_path, source))?;
    let artifact = match AuthenticatedWhirInitialCodeword::open(final_path, &expected_identity) {
        Ok(artifact) => artifact,
        Err(error) => {
            let _ = fs::remove_file(final_path);
            return Err(error);
        }
    };
    drop(staged_artifact);
    if let Err(source) = fs::remove_file(&partial_path) {
        let _ = fs::remove_file(final_path);
        return Err(io_error("removing staging file", &partial_path, source));
    }
    cleanup.0 = None;
    Ok(artifact)
}

#[derive(Clone, Copy)]
struct Geometry {
    source_elements: usize,
    height: usize,
    data_bytes: u64,
    auth_count: u64,
}

fn validate_geometry(
    artifact_id: [u8; 32],
    source: &WhirInitialSourceIdentity,
) -> Result<Geometry, WhirInitialEncodingError> {
    if artifact_id == [0; 32] || source.source_id == [0; 32] {
        return Err(WhirInitialEncodingError::Invalid(
            "artifact and source identities must be nonzero",
        ));
    }
    let variables = usize::try_from(source.num_variables)
        .map_err(|_| WhirInitialEncodingError::ResearchLimit("variable count"))?;
    if variables < WHIR_INITIAL_MIN_VARIABLES {
        return Err(WhirInitialEncodingError::Invalid(
            "num_variables is smaller than folding",
        ));
    }
    if variables > WHIR_INITIAL_ARTIFACT_MAX_VARIABLES {
        return Err(WhirInitialEncodingError::ResearchLimit(
            "num_variables exceeds 31",
        ));
    }
    let source_elements = 1_usize.checked_shl(source.num_variables).ok_or(
        WhirInitialEncodingError::ResearchLimit("source element count"),
    )?;
    let height = 1_usize
        .checked_shl(source.num_variables - 1)
        .ok_or(WhirInitialEncodingError::ResearchLimit("codeword height"))?;
    let data_bytes = u64::try_from(height)
        .ok()
        .and_then(|rows| rows.checked_mul(WHIR_INITIAL_WIDTH as u64))
        .and_then(|values| values.checked_mul(8))
        .ok_or(WhirInitialEncodingError::ResearchLimit(
            "artifact byte length",
        ))?;
    let auth_count = u64::try_from(height.div_ceil(AUTH_CHUNK_ROWS))
        .map_err(|_| WhirInitialEncodingError::ResearchLimit("authentication table"))?;
    Ok(Geometry {
        source_elements,
        height,
        data_bytes,
        auth_count,
    })
}

// These parameters mirror the authenticated source, scratch-file, geometry,
// and controller boundary; grouping them would add a single-use abstraction.
#[allow(clippy::too_many_arguments)]
fn transpose_source_into_first(
    output: &mut File,
    output_path: &Path,
    source: &dyn AuthenticatedWhirInitialSource,
    expected_source: &WhirInitialSourceIdentity,
    geometry: &Geometry,
    side: usize,
    tile_side: usize,
    controller: &mut N31ProgressController<'_>,
) -> ControlledSixStepResult<()> {
    let populated_rows = side / 2;
    let tile_cells = tile_side
        .checked_mul(tile_side)
        .and_then(|cells| cells.checked_mul(WHIR_INITIAL_WIDTH))
        .ok_or(WhirInitialEncodingError::ResearchLimit(
            "six-step transpose tile",
        ))?;
    let mut tile = allocate_u64_buffer(tile_cells, "six-step transpose tile")?;
    let segment_values = tile_side * WHIR_INITIAL_WIDTH;
    let mut encoded =
        allocate_byte_buffer(segment_values * 8, "six-step transpose encoded segment")?;

    for row_base in (0..populated_rows).step_by(tile_side) {
        let tile_rows = (populated_rows - row_base).min(tile_side);
        for column_base in (0..side).step_by(tile_side) {
            for local_row in 0..tile_rows {
                controller.checkpoint()?;
                let source_cell = (row_base + local_row)
                    .checked_mul(side)
                    .and_then(|cell| cell.checked_add(column_base))
                    .ok_or(WhirInitialEncodingError::Invalid(
                        "six-step source offset overflow",
                    ))?;
                let source_start = source_cell.checked_mul(WHIR_INITIAL_WIDTH).ok_or(
                    WhirInitialEncodingError::Invalid("six-step source offset overflow"),
                )?;
                let values = source
                    .read_elements(source_start, segment_values)
                    .map_err(WhirInitialEncodingError::from)?;
                controller.checkpoint()?;
                if source.identity() != expected_source
                    || source.len() != geometry.source_elements
                    || values.len() != segment_values
                {
                    return Err(WhirInitialEncodingError::Invalid(
                        "source geometry changed while reading",
                    )
                    .into());
                }
                if values.iter().any(|value| *value >= GOLDILOCKS_MODULUS) {
                    return Err(WhirInitialEncodingError::Invalid(
                        "source returned a noncanonical Goldilocks value",
                    )
                    .into());
                }
                let tile_start = local_row * segment_values;
                tile[tile_start..tile_start + segment_values].copy_from_slice(&values);
            }

            for local_column in 0..tile_side {
                controller.checkpoint()?;
                for local_row in 0..tile_rows {
                    let tile_cell = (local_row * tile_side + local_column) * WHIR_INITIAL_WIDTH;
                    let output_cell = local_row * WHIR_INITIAL_WIDTH;
                    for column in 0..WHIR_INITIAL_WIDTH {
                        encoded[(output_cell + column) * 8..(output_cell + column + 1) * 8]
                            .copy_from_slice(&tile[tile_cell + column].to_le_bytes());
                    }
                }
                write_raw_cells(
                    output,
                    output_path,
                    side,
                    column_base + local_column,
                    row_base,
                    &encoded[..tile_rows * WHIR_INITIAL_WIDTH * 8],
                )?;
            }
            let completed_bytes = tile_rows
                .checked_mul(tile_side)
                .and_then(|cells| cells.checked_mul(WHIR_INITIAL_WIDTH * 8))
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or(WhirInitialEncodingError::Invalid(
                    "six-step transpose progress byte count overflow",
                ))?;
            controller.advance(completed_bytes)?;
        }
    }
    if source.identity() != expected_source || source.len() != geometry.source_elements {
        return Err(
            WhirInitialEncodingError::Invalid("source geometry changed after reading").into(),
        );
    }
    Ok(())
}

fn six_step_first_fft(
    input: &mut File,
    input_path: &Path,
    output: &mut File,
    output_path: &Path,
    side: usize,
    strip_rows: usize,
    controller: &mut N31ProgressController<'_>,
) -> ControlledSixStepResult<()> {
    let strip_width = strip_rows.checked_mul(WHIR_INITIAL_WIDTH).ok_or(
        WhirInitialEncodingError::ResearchLimit("six-step FFT strip width"),
    )?;
    let mut strip = allocate_u64_buffer(
        side.checked_mul(strip_width)
            .ok_or(WhirInitialEncodingError::ResearchLimit(
                "six-step FFT strip",
            ))?,
        "six-step FFT strip",
    )?;
    let mut encoded_row =
        allocate_byte_buffer(side * WHIR_INITIAL_WIDTH * 8, "six-step encoded row")?;
    let root = Goldilocks::two_adic_generator((side.ilog2() * 2) as usize);

    for row_base in (0..side).step_by(strip_rows) {
        for local_row in 0..strip_rows {
            controller.checkpoint()?;
            read_raw_cells(
                input,
                input_path,
                side,
                row_base + local_row,
                0,
                &mut encoded_row,
            )?;
            controller.checkpoint()?;
            for (column_index, bytes) in encoded_row.chunks_exact(8).enumerate() {
                let value = decode_canonical_limb(bytes)?;
                let cell = column_index / WHIR_INITIAL_WIDTH;
                let column = column_index % WHIR_INITIAL_WIDTH;
                strip[cell * strip_width + local_row * WHIR_INITIAL_WIDTH + column] = value;
            }
        }

        let cancelled =
            dft_goldilocks_natural_rows_in_place_cancellable(&mut strip, side, strip_width, || {
                controller.cancelled.load(Ordering::Acquire)
            })
            .map_err(WhirInitialEncodingError::from)?;
        if cancelled {
            return Err(controller.cancellation_error());
        }
        let row_base_step = root.exp_u64(row_base as u64);
        let mut frequency_start = Goldilocks::ONE;
        let mut frequency_step = Goldilocks::ONE;
        for frequency in 0..side {
            controller.checkpoint()?;
            let row_start = frequency * strip_width;
            let mut twiddle = frequency_start;
            for local_row in 0..strip_rows {
                let cell_start = row_start + local_row * WHIR_INITIAL_WIDTH;
                for column in 0..WHIR_INITIAL_WIDTH {
                    strip[cell_start + column] =
                        (Goldilocks::new(strip[cell_start + column]) * twiddle).as_canonical_u64();
                }
                twiddle *= frequency_step;
            }
            frequency_start *= row_base_step;
            frequency_step *= root;
            let encoded_segment = &mut encoded_row[..strip_width * 8];
            encode_canonical_limbs(&strip[row_start..row_start + strip_width], encoded_segment);
            write_raw_cells(
                output,
                output_path,
                side,
                frequency,
                row_base,
                encoded_segment,
            )?;
        }
        let completed_bytes = side
            .checked_mul(strip_rows)
            .and_then(|rows| rows.checked_mul(WHIR_INITIAL_WIDTH * 8))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(WhirInitialEncodingError::Invalid(
                "six-step first FFT progress byte count overflow",
            ))?;
        controller.advance(completed_bytes)?;
    }
    Ok(())
}

fn six_step_second_fft(
    input: &mut File,
    input_path: &Path,
    output: &mut File,
    output_path: &Path,
    side: usize,
    strip_rows: usize,
    controller: &mut N31ProgressController<'_>,
) -> ControlledSixStepResult<()> {
    let strip_width = strip_rows.checked_mul(WHIR_INITIAL_WIDTH).ok_or(
        WhirInitialEncodingError::ResearchLimit("six-step FFT strip width"),
    )?;
    let mut strip = allocate_u64_buffer(
        side.checked_mul(strip_width)
            .ok_or(WhirInitialEncodingError::ResearchLimit(
                "six-step FFT strip",
            ))?,
        "six-step FFT strip",
    )?;
    let mut encoded_row =
        allocate_byte_buffer(side * WHIR_INITIAL_WIDTH * 8, "six-step encoded row")?;

    for row_base in (0..side).step_by(strip_rows) {
        for local_row in 0..strip_rows {
            controller.checkpoint()?;
            read_raw_cells(
                input,
                input_path,
                side,
                row_base + local_row,
                0,
                &mut encoded_row,
            )?;
            controller.checkpoint()?;
            for (column_index, bytes) in encoded_row.chunks_exact(8).enumerate() {
                let value = decode_canonical_limb(bytes)?;
                let cell = column_index / WHIR_INITIAL_WIDTH;
                let column = column_index % WHIR_INITIAL_WIDTH;
                strip[cell * strip_width + local_row * WHIR_INITIAL_WIDTH + column] = value;
            }
        }

        let cancelled =
            dft_goldilocks_natural_rows_in_place_cancellable(&mut strip, side, strip_width, || {
                controller.cancelled.load(Ordering::Acquire)
            })
            .map_err(WhirInitialEncodingError::from)?;
        if cancelled {
            return Err(controller.cancellation_error());
        }
        for output_row in 0..side {
            controller.checkpoint()?;
            let strip_start = output_row * strip_width;
            let encoded_segment = &mut encoded_row[..strip_width * 8];
            encode_canonical_limbs(
                &strip[strip_start..strip_start + strip_width],
                encoded_segment,
            );
            let natural_row = output_row
                .checked_mul(side)
                .and_then(|row| row.checked_add(row_base))
                .ok_or(WhirInitialEncodingError::Invalid(
                    "six-step output row overflow",
                ))?;
            output
                .seek(SeekFrom::Start(data_offset(natural_row)?))
                .and_then(|_| output.write_all(encoded_segment))
                .map_err(|source| io_error("writing six-step codeword to", output_path, source))?;
        }
        let completed_bytes = side
            .checked_mul(strip_rows)
            .and_then(|rows| rows.checked_mul(WHIR_INITIAL_WIDTH * 8))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(WhirInitialEncodingError::Invalid(
                "six-step second FFT progress byte count overflow",
            ))?;
        controller.advance(completed_bytes)?;
    }
    Ok(())
}

fn allocate_u64_buffer(
    values: usize,
    limit: &'static str,
) -> Result<Vec<u64>, WhirInitialEncodingError> {
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(values)
        .map_err(|_| WhirInitialEncodingError::ResearchLimit(limit))?;
    buffer.resize(values, 0);
    Ok(buffer)
}

fn allocate_byte_buffer(
    bytes: usize,
    limit: &'static str,
) -> Result<Vec<u8>, WhirInitialEncodingError> {
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(bytes)
        .map_err(|_| WhirInitialEncodingError::ResearchLimit(limit))?;
    buffer.resize(bytes, 0);
    Ok(buffer)
}

fn decode_canonical_limb(bytes: &[u8]) -> Result<u64, WhirInitialEncodingError> {
    let value = u64::from_le_bytes(bytes.try_into().expect("eight-byte limb"));
    if value >= GOLDILOCKS_MODULUS {
        return Err(WhirInitialEncodingError::Invalid(
            "six-step scratch contains a noncanonical Goldilocks value",
        ));
    }
    Ok(value)
}

fn encode_canonical_limbs(values: &[u64], output: &mut [u8]) {
    debug_assert_eq!(output.len(), values.len() * 8);
    for (value, bytes) in values.iter().zip(output.chunks_exact_mut(8)) {
        debug_assert!(*value < GOLDILOCKS_MODULUS);
        bytes.copy_from_slice(&value.to_le_bytes());
    }
}

fn raw_cell_offset(
    row: usize,
    column: usize,
    side: usize,
) -> Result<u64, WhirInitialEncodingError> {
    if row >= side || column >= side {
        return Err(WhirInitialEncodingError::Invalid(
            "six-step scratch cell is out of bounds",
        ));
    }
    let row = u64::try_from(row)
        .map_err(|_| WhirInitialEncodingError::Invalid("six-step scratch row overflow"))?;
    let column = u64::try_from(column)
        .map_err(|_| WhirInitialEncodingError::Invalid("six-step scratch column overflow"))?;
    let side = u64::try_from(side)
        .map_err(|_| WhirInitialEncodingError::Invalid("six-step scratch side overflow"))?;
    row.checked_mul(side)
        .and_then(|cell| cell.checked_add(column))
        .and_then(|cell| cell.checked_mul((WHIR_INITIAL_WIDTH * 8) as u64))
        .ok_or(WhirInitialEncodingError::Invalid(
            "six-step scratch offset overflow",
        ))
}

fn read_raw_cells(
    file: &mut File,
    path: &Path,
    side: usize,
    row: usize,
    column: usize,
    output: &mut [u8],
) -> Result<(), WhirInitialEncodingError> {
    let cells = output.len() / (WHIR_INITIAL_WIDTH * 8);
    if !output.len().is_multiple_of(WHIR_INITIAL_WIDTH * 8)
        || column.checked_add(cells).is_none_or(|end| end > side)
    {
        return Err(WhirInitialEncodingError::Invalid(
            "six-step scratch read is not a whole in-bounds row segment",
        ));
    }
    file.seek(SeekFrom::Start(raw_cell_offset(row, column, side)?))
        .and_then(|_| file.read_exact(output))
        .map_err(|source| io_error("reading six-step scratch from", path, source))
}

fn write_raw_cells(
    file: &mut File,
    path: &Path,
    side: usize,
    row: usize,
    column: usize,
    bytes: &[u8],
) -> Result<(), WhirInitialEncodingError> {
    let cells = bytes.len() / (WHIR_INITIAL_WIDTH * 8);
    if !bytes.len().is_multiple_of(WHIR_INITIAL_WIDTH * 8)
        || column.checked_add(cells).is_none_or(|end| end > side)
    {
        return Err(WhirInitialEncodingError::Invalid(
            "six-step scratch write is not a whole in-bounds row segment",
        ));
    }
    file.seek(SeekFrom::Start(raw_cell_offset(row, column, side)?))
        .and_then(|_| file.write_all(bytes))
        .map_err(|source| io_error("writing six-step scratch to", path, source))
}

fn scatter_bit_reversed_source(
    file: &mut File,
    path: &Path,
    source: &dyn AuthenticatedWhirInitialSource,
    expected_source: &WhirInitialSourceIdentity,
    geometry: &Geometry,
    source_read_limbs: usize,
) -> Result<(), WhirInitialEncodingError> {
    let log_height = geometry.height.ilog2();
    let mut start = 0_usize;
    while start < geometry.source_elements {
        let count = (geometry.source_elements - start).min(source_read_limbs);
        let values = source.read_elements(start, count)?;
        if source.identity() != expected_source
            || source.len() != geometry.source_elements
            || values.len() != count
        {
            return Err(WhirInitialEncodingError::Invalid(
                "source geometry changed while reading",
            ));
        }
        if values.iter().any(|value| *value >= GOLDILOCKS_MODULUS) {
            return Err(WhirInitialEncodingError::Invalid(
                "source returned a noncanonical Goldilocks value",
            ));
        }
        for (local_row, row) in values.chunks_exact(WHIR_INITIAL_WIDTH).enumerate() {
            let natural_row = start / WHIR_INITIAL_WIDTH + local_row;
            let physical_row = reverse_bits_len(natural_row, log_height);
            write_encoded_row(file, path, physical_row, row)?;
        }
        start += count;
    }
    if source.identity() != expected_source || source.len() != geometry.source_elements {
        return Err(WhirInitialEncodingError::Invalid(
            "source geometry changed after reading",
        ));
    }
    Ok(())
}

fn seal_data(
    file: &mut File,
    path: &Path,
    prefix: &[u8; PREFIX_BYTES],
    height: usize,
) -> Result<(Vec<[u8; 32]>, [u8; 32]), WhirInitialEncodingError> {
    match seal_data_inner(file, path, prefix, height, None) {
        Ok(sealed) => Ok(sealed),
        Err(ControlledSixStepError::Encoding(error)) => Err(error),
        Err(ControlledSixStepError::Cancelled(_)) => {
            unreachable!("sealing without control cannot be cancelled")
        }
    }
}

fn seal_data_with_control(
    file: &mut File,
    path: &Path,
    prefix: &[u8; PREFIX_BYTES],
    height: usize,
    controller: &mut N31ProgressController<'_>,
) -> ControlledSixStepResult<(Vec<[u8; 32]>, [u8; 32])> {
    seal_data_inner(file, path, prefix, height, Some(controller))
}

fn seal_data_inner(
    file: &mut File,
    path: &Path,
    prefix: &[u8; PREFIX_BYTES],
    height: usize,
    mut controller: Option<&mut N31ProgressController<'_>>,
) -> ControlledSixStepResult<(Vec<[u8; 32]>, [u8; 32])> {
    if let Some(controller) = controller.as_deref_mut() {
        controller.checkpoint()?;
    }
    file.sync_data()
        .map_err(|source| io_error("synchronizing staged data for", path, source))?;
    if let Some(controller) = controller.as_deref_mut() {
        controller.checkpoint()?;
    }
    let mut global = Hasher::new();
    global.update(prefix);
    let mut auth_digests = Vec::new();
    auth_digests
        .try_reserve_exact(height.div_ceil(AUTH_CHUNK_ROWS))
        .map_err(|_| WhirInitialEncodingError::ResearchLimit("authentication table"))?;
    for batch_start in (0..height).step_by(AUTH_SCAN_ROWS) {
        if let Some(controller) = controller.as_deref_mut() {
            controller.checkpoint()?;
        }
        let rows = (height - batch_start).min(AUTH_SCAN_ROWS);
        let bytes = read_encoded_rows(file, path, batch_start, rows)?;
        if let Some(controller) = controller.as_deref_mut() {
            controller.checkpoint()?;
        }
        validate_encoded_rows(&bytes)?;
        global.update(&bytes);
        for chunk in bytes.chunks(AUTH_CHUNK_ROWS * WHIR_INITIAL_WIDTH * 8) {
            auth_digests.push(auth_digest(prefix, auth_digests.len(), chunk));
        }
        if let Some(controller) = controller.as_deref_mut() {
            controller.advance(bytes.len() as u64)?;
        }
    }
    file.seek(SeekFrom::End(0))
        .map_err(|source| io_error("seeking in", path, source))?;
    for digest in &auth_digests {
        global.update(digest);
    }
    write_auth_digests_with_control(file, path, &auth_digests, controller)?;
    let digest = *global.finalize().as_bytes();
    file.seek(SeekFrom::Start(PREFIX_BYTES as u64))
        .and_then(|_| file.write_all(&digest))
        .and_then(|()| file.sync_all())
        .map_err(|source| io_error("sealing", path, source))?;
    Ok((auth_digests, digest))
}

fn authenticate_complete_with_control(
    file: &mut File,
    path: &Path,
    prefix: &[u8; PREFIX_BYTES],
    height: usize,
    auth_digests: &[[u8; 32]],
    expected_global: [u8; 32],
    mut controller: Option<&mut N31ProgressController<'_>>,
) -> ControlledSixStepResult<()> {
    if auth_digests.len() != height.div_ceil(AUTH_CHUNK_ROWS) {
        return Err(WhirInitialEncodingError::Invalid(
            "authentication count does not match height",
        )
        .into());
    }
    let mut global = Hasher::new();
    global.update(prefix);
    let mut chunk_index = 0_usize;
    for batch_start in (0..height).step_by(AUTH_SCAN_ROWS) {
        if let Some(controller) = controller.as_deref_mut() {
            controller.checkpoint()?;
        }
        let rows = (height - batch_start).min(AUTH_SCAN_ROWS);
        let bytes = read_encoded_rows(file, path, batch_start, rows)?;
        if let Some(controller) = controller.as_deref_mut() {
            controller.checkpoint()?;
        }
        validate_encoded_rows(&bytes)?;
        for chunk in bytes.chunks(AUTH_CHUNK_ROWS * WHIR_INITIAL_WIDTH * 8) {
            if auth_digest(prefix, chunk_index, chunk) != auth_digests[chunk_index] {
                return Err(WhirInitialEncodingError::ChecksumMismatch.into());
            }
            chunk_index += 1;
        }
        global.update(&bytes);
        if let Some(controller) = controller.as_deref_mut() {
            controller.advance(bytes.len() as u64)?;
        }
    }
    for digest in auth_digests {
        global.update(digest);
    }
    if *global.finalize().as_bytes() != expected_global {
        return Err(WhirInitialEncodingError::ChecksumMismatch.into());
    }
    Ok(())
}

fn read_auth_digests_with_control(
    file: &mut File,
    path: &Path,
    count: usize,
    mut controller: Option<&mut N31ProgressController<'_>>,
) -> ControlledSixStepResult<Vec<[u8; DIGEST_BYTES]>> {
    let mut digests = Vec::new();
    digests
        .try_reserve_exact(count)
        .map_err(|_| WhirInitialEncodingError::ResearchLimit("authentication table"))?;
    let mut remaining = count;
    let mut bytes = allocate_byte_buffer(
        AUTH_DIGEST_IO_COUNT * DIGEST_BYTES,
        "authentication table I/O buffer",
    )?;
    while remaining != 0 {
        if let Some(controller) = controller.as_deref_mut() {
            controller.checkpoint()?;
        }
        let batch = remaining.min(AUTH_DIGEST_IO_COUNT);
        let byte_count = batch * DIGEST_BYTES;
        file.read_exact(&mut bytes[..byte_count])
            .map_err(|source| io_error("reading authentication table from", path, source))?;
        if let Some(controller) = controller.as_deref_mut() {
            controller.checkpoint()?;
        }
        digests.extend(
            bytes[..byte_count]
                .chunks_exact(DIGEST_BYTES)
                .map(|digest| {
                    <[u8; DIGEST_BYTES]>::try_from(digest)
                        .expect("fixed-size authentication digest")
                }),
        );
        remaining -= batch;
        if let Some(controller) = controller.as_deref_mut() {
            controller.advance(byte_count as u64)?;
        }
    }
    Ok(digests)
}

fn write_auth_digests_with_control(
    file: &mut File,
    path: &Path,
    digests: &[[u8; DIGEST_BYTES]],
    mut controller: Option<&mut N31ProgressController<'_>>,
) -> ControlledSixStepResult<()> {
    let mut bytes = allocate_byte_buffer(
        AUTH_DIGEST_IO_COUNT * DIGEST_BYTES,
        "authentication table I/O buffer",
    )?;
    for batch in digests.chunks(AUTH_DIGEST_IO_COUNT) {
        if let Some(controller) = controller.as_deref_mut() {
            controller.checkpoint()?;
        }
        let byte_count = batch.len() * DIGEST_BYTES;
        for (digest, output) in batch
            .iter()
            .zip(bytes[..byte_count].chunks_exact_mut(DIGEST_BYTES))
        {
            output.copy_from_slice(digest);
        }
        file.write_all(&bytes[..byte_count])
            .map_err(|source| io_error("writing authentication table to", path, source))?;
        if let Some(controller) = controller.as_deref_mut() {
            controller.checkpoint()?;
            controller.advance(byte_count as u64)?;
        }
    }
    Ok(())
}

fn auth_digest(prefix: &[u8; PREFIX_BYTES], chunk_index: usize, bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(AUTH_DOMAIN);
    hasher.update(prefix);
    hasher.update(&(chunk_index as u64).to_le_bytes());
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn write_encoded_row(
    file: &mut File,
    path: &Path,
    row: usize,
    values: &[u64],
) -> Result<(), WhirInitialEncodingError> {
    debug_assert_eq!(values.len(), WHIR_INITIAL_WIDTH);
    let mut encoded = [0_u8; WHIR_INITIAL_WIDTH * 8];
    for (value, bytes) in values.iter().zip(encoded.chunks_exact_mut(8)) {
        bytes.copy_from_slice(&value.to_le_bytes());
    }
    file.seek(SeekFrom::Start(data_offset(row)?))
        .and_then(|_| file.write_all(&encoded))
        .map_err(|source| io_error("scattering source rows into", path, source))
}

fn read_encoded_rows(
    file: &mut File,
    path: &Path,
    row_start: usize,
    row_count: usize,
) -> Result<Vec<u8>, WhirInitialEncodingError> {
    let byte_count = row_count
        .checked_mul(WHIR_INITIAL_WIDTH * 8)
        .ok_or(WhirInitialEncodingError::Invalid("row byte count overflow"))?;
    let mut bytes = vec![0_u8; byte_count];
    file.seek(SeekFrom::Start(data_offset(row_start)?))
        .and_then(|_| file.read_exact(&mut bytes))
        .map_err(|source| io_error("reading authenticated rows from", path, source))?;
    Ok(bytes)
}

fn data_offset(row: usize) -> Result<u64, WhirInitialEncodingError> {
    u64::try_from(row)
        .ok()
        .and_then(|row| row.checked_mul((WHIR_INITIAL_WIDTH * 8) as u64))
        .and_then(|offset| offset.checked_add(HEADER_BYTES as u64))
        .ok_or(WhirInitialEncodingError::Invalid("row offset overflow"))
}

fn validate_encoded_rows(bytes: &[u8]) -> Result<(), WhirInitialEncodingError> {
    if !bytes.len().is_multiple_of(8) {
        return Err(WhirInitialEncodingError::Invalid(
            "encoded row length is not aligned",
        ));
    }
    if bytes.chunks_exact(8).any(|chunk| {
        u64::from_le_bytes(chunk.try_into().expect("eight-byte chunk")) >= GOLDILOCKS_MODULUS
    }) {
        return Err(WhirInitialEncodingError::Invalid(
            "artifact contains a noncanonical Goldilocks value",
        ));
    }
    Ok(())
}

fn decode_values(bytes: &[u8], output: &mut Vec<u64>) {
    output.extend(
        bytes
            .chunks_exact(8)
            .map(|chunk| u64::from_le_bytes(chunk.try_into().expect("eight-byte chunk"))),
    );
}

fn reverse_bits_len(value: usize, bits: u32) -> usize {
    value.reverse_bits() >> (usize::BITS - bits)
}

fn encode_prefix(
    artifact_id: [u8; 32],
    source: &WhirInitialSourceIdentity,
    geometry: &Geometry,
) -> [u8; PREFIX_BYTES] {
    let mut prefix = [0_u8; PREFIX_BYTES];
    prefix[0..8].copy_from_slice(MAGIC);
    prefix[8..12].copy_from_slice(&VERSION.to_le_bytes());
    prefix[12..16].copy_from_slice(&(HEADER_BYTES as u32).to_le_bytes());
    prefix[16..48].copy_from_slice(&artifact_id);
    prefix[48..80].copy_from_slice(&source.source_id);
    prefix[80..84].copy_from_slice(&source.num_variables.to_le_bytes());
    prefix[84] = FOLDING;
    prefix[85] = STARTING_LOG_INV_RATE;
    prefix[86] = NATURAL_ROW_LAYOUT;
    prefix[88..92].copy_from_slice(&(WHIR_INITIAL_WIDTH as u32).to_le_bytes());
    prefix[96..104].copy_from_slice(&(geometry.source_elements as u64).to_le_bytes());
    prefix[104..112].copy_from_slice(&(geometry.height as u64).to_le_bytes());
    prefix[112..120].copy_from_slice(&geometry.data_bytes.to_le_bytes());
    prefix[120..128].copy_from_slice(&geometry.auth_count.to_le_bytes());
    prefix
}

struct DecodedPrefix {
    artifact_id: [u8; 32],
    source_id: [u8; 32],
    num_variables: u32,
    height: usize,
    data_bytes: u64,
    auth_count: u64,
}

fn decode_prefix(prefix: &[u8; PREFIX_BYTES]) -> Result<DecodedPrefix, WhirInitialEncodingError> {
    if &prefix[0..8] != MAGIC
        || u32::from_le_bytes(prefix[8..12].try_into().expect("four bytes")) != VERSION
        || u32::from_le_bytes(prefix[12..16].try_into().expect("four bytes")) != HEADER_BYTES as u32
        || prefix[84] != FOLDING
        || prefix[85] != STARTING_LOG_INV_RATE
        || prefix[86] != NATURAL_ROW_LAYOUT
        || prefix[87] != 0
        || prefix[92..96] != [0; 4]
        || u32::from_le_bytes(prefix[88..92].try_into().expect("four bytes"))
            != WHIR_INITIAL_WIDTH as u32
    {
        return Err(WhirInitialEncodingError::Invalid(
            "header suite or layout is not canonical",
        ));
    }
    let artifact_id = prefix[16..48].try_into().expect("32 bytes");
    let source_id = prefix[48..80].try_into().expect("32 bytes");
    let num_variables = u32::from_le_bytes(prefix[80..84].try_into().expect("four bytes"));
    let geometry = validate_geometry(
        artifact_id,
        &WhirInitialSourceIdentity {
            source_id,
            num_variables,
        },
    )?;
    let source_elements = u64::from_le_bytes(prefix[96..104].try_into().expect("eight bytes"));
    let height_u64 = u64::from_le_bytes(prefix[104..112].try_into().expect("eight bytes"));
    let data_bytes = u64::from_le_bytes(prefix[112..120].try_into().expect("eight bytes"));
    let auth_count = u64::from_le_bytes(prefix[120..128].try_into().expect("eight bytes"));
    if source_elements != geometry.source_elements as u64
        || height_u64 != geometry.height as u64
        || data_bytes != geometry.data_bytes
        || auth_count != geometry.auth_count
    {
        return Err(WhirInitialEncodingError::Invalid(
            "header geometry is inconsistent",
        ));
    }
    Ok(DecodedPrefix {
        artifact_id,
        source_id,
        num_variables,
        height: geometry.height,
        data_bytes,
        auth_count,
    })
}

fn partial_path_for(path: &Path) -> Result<PathBuf, WhirInitialEncodingError> {
    let name = path.file_name().ok_or(WhirInitialEncodingError::Invalid(
        "artifact path has no file name",
    ))?;
    let mut partial = name.to_os_string();
    partial.push(".partial");
    Ok(path.with_file_name(partial))
}

fn io_error(operation: &'static str, path: &Path, source: io::Error) -> WhirInitialEncodingError {
    WhirInitialEncodingError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

fn production_artifact_parent(path: &Path) -> Result<PathBuf, WhirInitialEncodingError> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(WhirInitialEncodingError::InvalidOutputPath(
            path.to_path_buf(),
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| WhirInitialEncodingError::InvalidOutputPath(path.to_path_buf()))?
        .to_path_buf();
    if !parent.is_dir() {
        return Err(WhirInitialEncodingError::InvalidOutputPath(parent));
    }
    Ok(parent)
}

fn require_available_space(parent: &Path, required: u64) -> Result<(), WhirInitialEncodingError> {
    let available = fs2::available_space(parent)
        .map_err(|source| io_error("checking free space in", parent, source))?;
    require_space(required, available)
}

fn require_space(required: u64, available: u64) -> Result<(), WhirInitialEncodingError> {
    if available < required {
        return Err(WhirInitialEncodingError::InsufficientSpace {
            required,
            available,
        });
    }
    Ok(())
}

fn create_unique_production_staging(
    final_path: &Path,
    label: &str,
) -> Result<(PathBuf, File), WhirInitialEncodingError> {
    let parent = production_artifact_parent(final_path)?;
    let file_name = final_path
        .file_name()
        .ok_or_else(|| WhirInitialEncodingError::InvalidOutputPath(final_path.to_path_buf()))?;
    for _ in 0..PRODUCTION_STAGING_ATTEMPTS {
        let sequence = NEXT_PRODUCTION_STAGING_FILE.fetch_add(1, Ordering::Relaxed);
        let mut staging_name = file_name.to_os_string();
        staging_name.push(format!(
            ".n31.{label}.{}.{sequence}.partial",
            std::process::id()
        ));
        let staging_path = parent.join(staging_name);
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&staging_path)
        {
            Ok(file) => return Ok((staging_path, file)),
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(source) => return Err(io_error("creating", &staging_path, source)),
        }
    }
    Err(WhirInitialEncodingError::NameExhausted(parent))
}

fn publish_verified_production_artifact(
    staging: OwnedProductionFile,
    final_path: &Path,
    parent: &Path,
    mut artifact: AuthenticatedWhirInitialCodeword,
) -> Result<AuthenticatedWhirInitialCodeword, WhirInitialEncodingError> {
    ensure_path_names_file(&staging.path, staging.file_ref())?;
    let cleanup_file = staging
        .file_ref()
        .try_clone()
        .map_err(|source| io_error("cloning publication handle for", final_path, source))?;
    match fs::hard_link(&staging.path, final_path) {
        Ok(()) => {}
        Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
            return Err(WhirInitialEncodingError::AlreadyExists(
                final_path.to_path_buf(),
            ));
        }
        Err(source) => return Err(io_error("publishing", final_path, source)),
    }
    let mut published = OwnedProductionFile::new(final_path.to_path_buf(), cleanup_file);
    ensure_path_names_file(final_path, published.file_ref())?;
    {
        let file = artifact
            .file
            .lock()
            .map_err(|_| WhirInitialEncodingError::LockPoisoned)?;
        ensure_path_names_file(final_path, &file)?;
    }
    sync_parent_directory(parent)?;
    staging.remove()?;
    sync_parent_directory(parent)?;
    artifact.path = final_path.to_path_buf();
    published.disarm();
    Ok(artifact)
}

fn sync_parent_directory(parent: &Path) -> Result<(), WhirInitialEncodingError> {
    #[cfg(unix)]
    let directory = File::open(parent)
        .map_err(|source| io_error("opening parent directory for sync", parent, source))?;

    #[cfg(windows)]
    let directory = {
        use std::os::windows::fs::OpenOptionsExt;

        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(parent)
            .map_err(|source| map_parent_sync_error(parent, source))?
    };

    #[cfg(not(any(unix, windows)))]
    return Err(WhirInitialEncodingError::ParentDirectorySyncUnsupported {
        path: parent.to_path_buf(),
        source: io::Error::new(
            io::ErrorKind::Unsupported,
            "this target has no implemented directory synchronization primitive",
        ),
    });

    #[cfg(any(unix, windows))]
    directory
        .sync_all()
        .map_err(|source| map_parent_sync_error(parent, source))
}

fn map_parent_sync_error(parent: &Path, source: io::Error) -> WhirInitialEncodingError {
    #[cfg(windows)]
    if source.kind() == io::ErrorKind::Unsupported
        || matches!(source.raw_os_error(), Some(1 | 5 | 50))
    {
        return WhirInitialEncodingError::ParentDirectorySyncUnsupported {
            path: parent.to_path_buf(),
            source,
        };
    }

    WhirInitialEncodingError::Io {
        operation: "synchronizing parent directory",
        path: parent.to_path_buf(),
        source,
    }
}

fn ensure_path_names_file(path: &Path, file: &File) -> Result<(), WhirInitialEncodingError> {
    let owned_handle = Handle::from_file(
        file.try_clone()
            .map_err(|source| io_error("cloning cleanup handle for", path, source))?,
    )
    .map_err(|source| io_error("identifying owned file at", path, source))?;
    let path_handle = Handle::from_path(path)
        .map_err(|source| io_error("identifying cleanup path", path, source))?;
    if owned_handle != path_handle {
        return Err(WhirInitialEncodingError::CleanupTargetChanged(
            path.to_path_buf(),
        ));
    }
    Ok(())
}

fn remove_owned_file(path: &Path, file: &File) -> Result<(), WhirInitialEncodingError> {
    ensure_path_names_file(path, file)?;
    fs::remove_file(path).map_err(|source| io_error("removing", path, source))
}

struct OwnedProductionFile {
    path: PathBuf,
    file: Option<File>,
}

impl OwnedProductionFile {
    fn new(path: PathBuf, file: File) -> Self {
        Self {
            path,
            file: Some(file),
        }
    }

    fn file_mut(&mut self) -> &mut File {
        self.file.as_mut().expect("live production staging file")
    }

    fn file_ref(&self) -> &File {
        self.file.as_ref().expect("live production staging file")
    }

    fn remove(mut self) -> Result<(), WhirInitialEncodingError> {
        remove_owned_file(&self.path, self.file_ref())?;
        self.file.take();
        Ok(())
    }

    fn disarm(&mut self) {
        self.file.take();
    }
}

impl Drop for OwnedProductionFile {
    fn drop(&mut self) {
        if let Some(file) = self.file.take() {
            let _ = remove_owned_file(&self.path, &file);
        }
    }
}

struct PartialCleanup(Option<PathBuf>);

impl Drop for PartialCleanup {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = fs::remove_file(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::io::{Seek, SeekFrom, Write};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use p3_blake3::Blake3;
    use p3_commit::Mmcs;
    use p3_dft::{Radix2DFTSmallBatch, TwoAdicSubgroupDft};
    use p3_field::PrimeField64;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_merkle_tree::MerkleTreeMmcs;
    use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};

    use super::*;
    use crate::whir_initial_source::WhirInitialSourceArtifactWriter;

    static NEXT_PATH: AtomicUsize = AtomicUsize::new(0);

    type FieldHash = SerializingHasher<Blake3>;
    type Compress = CompressionFunctionFromHasher<Blake3, 2, 32>;
    type WhirMmcs = MerkleTreeMmcs<Goldilocks, u8, FieldHash, Compress, 2, 32>;

    struct DenseSource {
        identity: WhirInitialSourceIdentity,
        values: Vec<u64>,
        reads: AtomicUsize,
        max_read: AtomicUsize,
        fail_at: Option<usize>,
        change_len_after_read: bool,
    }

    impl DenseSource {
        fn new(values: Vec<u64>) -> Self {
            let variables = values.len().ilog2() as usize;
            Self {
                identity: identity(variables),
                values,
                reads: AtomicUsize::new(0),
                max_read: AtomicUsize::new(0),
                fail_at: None,
                change_len_after_read: false,
            }
        }

        fn with_identity(values: Vec<u64>, identity: WhirInitialSourceIdentity) -> Self {
            Self {
                identity,
                values,
                reads: AtomicUsize::new(0),
                max_read: AtomicUsize::new(0),
                fail_at: None,
                change_len_after_read: false,
            }
        }
    }

    struct CancelAfterFirstReadSource<'a> {
        inner: &'a dyn AuthenticatedWhirInitialSource,
        cancelled: &'a AtomicBool,
        reads: AtomicUsize,
    }

    impl AuthenticatedWhirInitialSource for CancelAfterFirstReadSource<'_> {
        fn identity(&self) -> &WhirInitialSourceIdentity {
            self.inner.identity()
        }

        fn len(&self) -> usize {
            self.inner.len()
        }

        fn read_elements(
            &self,
            start: usize,
            count: usize,
        ) -> Result<Vec<u64>, WhirInitialSourceError> {
            let values = self.inner.read_elements(start, count)?;
            if self.reads.fetch_add(1, Ordering::SeqCst) == 0 {
                self.cancelled.store(true, Ordering::Release);
            }
            Ok(values)
        }
    }

    impl AuthenticatedWhirInitialSource for DenseSource {
        fn identity(&self) -> &WhirInitialSourceIdentity {
            &self.identity
        }

        fn len(&self) -> usize {
            if self.change_len_after_read && self.reads.load(Ordering::SeqCst) != 0 {
                self.values.len() - 1
            } else {
                self.values.len()
            }
        }

        fn read_elements(
            &self,
            start: usize,
            count: usize,
        ) -> Result<Vec<u64>, WhirInitialSourceError> {
            let call = self.reads.fetch_add(1, Ordering::SeqCst);
            self.max_read.fetch_max(count, Ordering::SeqCst);
            if self.fail_at == Some(call) {
                return Err(WhirInitialSourceError::new("injected source failure"));
            }
            self.values
                .get(start..start + count)
                .map(<[u64]>::to_vec)
                .ok_or_else(|| WhirInitialSourceError::new("out of bounds"))
        }
    }

    struct ForbiddenSourceAccess;

    impl AuthenticatedWhirInitialSource for ForbiddenSourceAccess {
        fn identity(&self) -> &WhirInitialSourceIdentity {
            panic!("over-cap reference encoding touched the source identity")
        }

        fn len(&self) -> usize {
            panic!("over-cap reference encoding touched the source length")
        }

        fn read_elements(
            &self,
            _start: usize,
            _count: usize,
        ) -> Result<Vec<u64>, WhirInitialSourceError> {
            panic!("over-cap reference encoding read the source")
        }
    }

    fn test_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "cmfd-whir-initial-{label}-{}-{}",
            std::process::id(),
            NEXT_PATH.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn identity(variables: usize) -> WhirInitialSourceIdentity {
        WhirInitialSourceIdentity {
            source_id: [variables as u8 + 1; 32],
            num_variables: variables as u32,
        }
    }

    fn table(variables: usize) -> Vec<u64> {
        (0..1_usize << variables)
            .map(|index| {
                ((index as u64).wrapping_mul(0x9e37_79b9).wrapping_add(17)) % GOLDILOCKS_MODULUS
            })
            .collect()
    }

    fn expected_codeword(values: &[u64], variables: usize) -> Vec<u64> {
        let height = 1 << (variables - 1);
        let mut padded = vec![Goldilocks::new(0); height * WHIR_INITIAL_WIDTH];
        for (output, value) in padded.iter_mut().zip(values) {
            *output = Goldilocks::new(*value);
        }
        Radix2DFTSmallBatch::new(height)
            .dft_batch(RowMajorMatrix::new(padded, WHIR_INITIAL_WIDTH))
            .values
            .into_iter()
            .map(|value| value.as_canonical_u64())
            .collect()
    }

    fn expected_leaf_digests(values: &[u64]) -> Vec<Blake3MerkleDigest> {
        assert!(values.len().is_multiple_of(WHIR_INITIAL_WIDTH));
        values
            .chunks_exact(WHIR_INITIAL_WIDTH)
            .map(|row| {
                let mut hasher = Hasher::new();
                for value in row {
                    hasher.update(&value.to_le_bytes());
                }
                *hasher.finalize().as_bytes()
            })
            .collect()
    }

    fn read_all(artifact: &AuthenticatedWhirInitialCodeword) -> Vec<u64> {
        let mut values = Vec::new();
        for start in (0..artifact.height).step_by(WHIR_INITIAL_MAX_READ_ROWS) {
            let rows = (artifact.height - start).min(WHIR_INITIAL_MAX_READ_ROWS);
            values.extend(artifact.read_canonical_rows(start, rows).unwrap());
        }
        values
    }

    fn run_controlled_six_step<F>(
        path: &Path,
        artifact_id: [u8; 32],
        expected_source: &WhirInitialSourceIdentity,
        source: &dyn AuthenticatedWhirInitialSource,
        cancelled: &AtomicBool,
        mut observe: F,
    ) -> Result<WhirInitialN31Outcome, WhirInitialEncodingError>
    where
        F: FnMut(WhirInitialN31Progress),
    {
        let variables = expected_source.num_variables as usize;
        let side = 1 << ((variables - 1) / 2);
        let mut controller = N31ProgressController::new(cancelled, &mut observe);
        match encode_six_step_suffix_with_control(
            path,
            artifact_id,
            expected_source,
            source,
            side.min(N31_TRANSPOSE_TILE),
            side.min(N31_FFT_STRIP),
            &mut controller,
        ) {
            Ok(artifact) => Ok(WhirInitialN31Outcome::Published(artifact)),
            Err(ControlledSixStepError::Cancelled(progress)) => {
                Ok(WhirInitialN31Outcome::Cancelled(progress))
            }
            Err(ControlledSixStepError::Encoding(error)) => Err(error),
        }
    }

    fn expected_small_six_step_progress(variables: usize) -> Vec<WhirInitialN31Progress> {
        let (source_bytes, codeword_bytes, sealed_bytes) = match variables {
            5 => (256, 512, 544),
            9 => (4_096, 8_192, 8_224),
            17 => (1_048_576, 2_097_152, 2_105_344),
            _ => panic!("unexpected six-step test geometry"),
        };
        let mut progress = Vec::with_capacity(10);
        for (stage, total_bytes) in [
            (WhirInitialN31Stage::Transpose, source_bytes),
            (WhirInitialN31Stage::FirstFft, codeword_bytes),
            (WhirInitialN31Stage::SecondFft, codeword_bytes),
            (WhirInitialN31Stage::Seal, sealed_bytes),
            (WhirInitialN31Stage::Verify, sealed_bytes),
        ] {
            progress.push(WhirInitialN31Progress {
                stage,
                completed_bytes: 0,
                total_bytes,
            });
            progress.push(WhirInitialN31Progress {
                stage,
                completed_bytes: total_bytes,
                total_bytes,
            });
        }
        progress
    }

    fn assert_no_six_step_output(path: &Path) {
        assert!(!path.exists());
        let staging_prefix = format!("{}.n31.", path.file_name().unwrap().to_string_lossy());
        assert!(
            fs::read_dir(path.parent().unwrap())
                .unwrap()
                .filter_map(Result::ok)
                .all(|entry| !entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(&staging_prefix))
        );
    }

    #[test]
    fn external_dft_matches_small_batch_for_small_shapes_and_partitions() {
        for variables in 2..=9 {
            let values = table(variables);
            let expected = expected_codeword(&values, variables);
            for source_chunk in [4, 12, 256] {
                let source = DenseSource::new(values.clone());
                let path = test_path("differential");
                let artifact = encode_with_limits(
                    &path,
                    [0x41; 32],
                    &identity(variables),
                    &source,
                    source_chunk,
                    32,
                )
                .unwrap()
                .remove_on_drop();
                assert_eq!(read_all(&artifact), expected);
                assert!(source.max_read.load(Ordering::SeqCst) <= source_chunk);
            }
        }
    }

    #[test]
    fn artifact_digest_is_stable_across_external_dft_refactors() {
        let variables = 6;
        let source = DenseSource::new(table(variables));
        let path = test_path("artifact-digest-regression");
        let artifact = encode_with_limits(&path, [0x42; 32], &identity(variables), &source, 16, 32)
            .unwrap()
            .remove_on_drop();
        assert_eq!(
            artifact.identity().artifact_digest,
            [
                0x44, 0x68, 0x01, 0x3f, 0xbc, 0xf6, 0x59, 0x19, 0x20, 0x64, 0x0c, 0xae, 0x8d, 0xad,
                0x9e, 0x4b, 0xca, 0x01, 0x9e, 0x96, 0xc6, 0x44, 0x44, 0x29, 0x1e, 0xbf, 0xd6, 0xbb,
                0xe2, 0x79, 0xcd, 0xd3,
            ]
        );
    }

    #[test]
    fn codeword_binding_changes_or_rejects_every_identity_dimension() {
        let identity = WhirInitialCodewordIdentity {
            artifact_id: [0x12; 32],
            source: WhirInitialSourceIdentity {
                source_id: [0x23; 32],
                num_variables: 6,
            },
            height: 1 << 5,
            width: WHIR_INITIAL_WIDTH as u32,
            artifact_digest: [0x34; 32],
        };
        let binding = identity.binding_digest().unwrap();
        assert_eq!(
            binding,
            [
                0xc1, 0xa5, 0xad, 0xe5, 0xc3, 0xc0, 0x20, 0xbc, 0x77, 0x54, 0x0c, 0x42, 0x82, 0x17,
                0xf4, 0x36, 0x8a, 0x5f, 0x25, 0x0f, 0xcf, 0x87, 0x80, 0x37, 0xfe, 0xc0, 0x0b, 0x61,
                0x01, 0x7b, 0x60, 0x9a,
            ]
        );

        for mutate in [
            |value: &mut WhirInitialCodewordIdentity| value.artifact_id[0] ^= 1,
            |value: &mut WhirInitialCodewordIdentity| value.source.source_id[0] ^= 1,
            |value: &mut WhirInitialCodewordIdentity| value.artifact_digest[0] ^= 1,
        ] {
            let mut changed = identity.clone();
            mutate(&mut changed);
            assert_ne!(changed.binding_digest().unwrap(), binding);
        }

        let mut changed_geometry = identity.clone();
        changed_geometry.source.num_variables += 1;
        changed_geometry.height *= 2;
        assert_ne!(changed_geometry.binding_digest().unwrap(), binding);

        for invalidate in [
            |value: &mut WhirInitialCodewordIdentity| value.height += 1,
            |value: &mut WhirInitialCodewordIdentity| value.width += 1,
            |value: &mut WhirInitialCodewordIdentity| value.artifact_id = [0; 32],
            |value: &mut WhirInitialCodewordIdentity| value.source.source_id = [0; 32],
        ] {
            let mut changed = identity.clone();
            invalidate(&mut changed);
            assert!(changed.binding_digest().is_err());
        }
    }

    #[test]
    fn n16_boundary_is_natural_order_and_bounded() {
        let variables = 16;
        let values = table(variables);
        let expected = expected_codeword(&values, variables);
        let source = DenseSource::new(values);
        let path = test_path("n16");
        let artifact = encode_whir_initial_suffix(&path, [0x51; 32], &identity(variables), &source)
            .unwrap()
            .remove_on_drop();
        assert_eq!(artifact.identity.height, 1 << 15);
        assert_eq!(Matrix::<Goldilocks>::width(&artifact), 4);
        assert_eq!(read_all(&artifact), expected);
        let matrix_row = artifact
            .row(12_345)
            .unwrap()
            .into_iter()
            .map(|value| value.as_canonical_u64())
            .collect::<Vec<_>>();
        assert_eq!(
            matrix_row,
            expected[12_345 * WHIR_INITIAL_WIDTH..12_346 * WHIR_INITIAL_WIDTH]
        );
        assert!(source.max_read.load(Ordering::SeqCst) <= WHIR_INITIAL_MAX_SOURCE_READ_LIMBS);
    }

    #[test]
    fn n31_artifact_geometry_is_exact_without_allocation() {
        const SOURCE_ELEMENTS: u64 = 2_147_483_648;
        const HEIGHT: u64 = 1_073_741_824;
        const DATA_BYTES: u64 = 34_359_738_368;
        const AUTH_DIGESTS: u64 = 4_194_304;
        const AUTH_BYTES: u64 = 134_217_728;
        const TOTAL_ARTIFACT_BYTES: u64 = 34_493_956_256;

        assert_eq!(WHIR_INITIAL_MAX_VARIABLES, 19);
        assert_eq!(WHIR_INITIAL_ARTIFACT_MAX_VARIABLES, 31);
        assert_eq!(WHIR_INITIAL_REFERENCE_ENCODER_MAX_VARIABLES, 19);
        let artifact_id = [0x53; 32];
        let source = identity(WHIR_INITIAL_ARTIFACT_MAX_VARIABLES);
        let geometry = validate_geometry(artifact_id, &source).unwrap();
        assert_eq!(geometry.source_elements as u64, SOURCE_ELEMENTS);
        assert_eq!(geometry.height as u64, HEIGHT);
        assert_eq!(geometry.data_bytes, DATA_BYTES);
        assert_eq!(geometry.auth_count, AUTH_DIGESTS);
        let auth_bytes = geometry.auth_count * DIGEST_BYTES as u64;
        assert_eq!(auth_bytes, AUTH_BYTES);
        assert_eq!(
            HEADER_BYTES as u64 + geometry.data_bytes + auth_bytes,
            TOTAL_ARTIFACT_BYTES
        );

        let prefix = encode_prefix(artifact_id, &source, &geometry);
        let decoded = decode_prefix(&prefix).unwrap();
        assert_eq!(decoded.artifact_id, artifact_id);
        assert_eq!(decoded.source_id, source.source_id);
        assert_eq!(decoded.num_variables, 31);
        assert_eq!(decoded.height as u64, HEIGHT);
        assert_eq!(decoded.data_bytes, DATA_BYTES);
        assert_eq!(decoded.auth_count, AUTH_DIGESTS);

        assert!(matches!(
            validate_geometry([0x54; 32], &identity(32)),
            Err(WhirInitialEncodingError::ResearchLimit(_))
        ));
    }

    #[test]
    fn n31_six_step_plan_is_exact_and_nonallocating() {
        let plan = whir_initial_n31_plan();
        assert_eq!(plan.source_elements, 2_147_483_648);
        assert_eq!(plan.source_artifact_bytes, 17_188_257_952);
        assert_eq!(plan.codeword_height, 1_073_741_824);
        assert_eq!(plan.codeword_artifact_bytes, 34_493_956_256);
        assert_eq!(plan.demand_tree_artifact_bytes, 68_719_476_960);
        assert_eq!(plan.encoder_peak_bytes, 68_719_476_896);
        assert_eq!(plan.codeword_and_tree_bytes, 103_213_433_216);
        assert_eq!(plan.persistent_source_codeword_tree_bytes, 120_401_691_168);
        assert_eq!(plan.max_transform_memory_bytes, 269_484_032);
        assert_eq!(plan.source_elements * 8, 17_179_869_184);
        let codeword_data_bytes = plan.codeword_height * WHIR_INITIAL_WIDTH as u64 * 8;
        let codeword_auth_bytes =
            plan.codeword_artifact_bytes - HEADER_BYTES as u64 - codeword_data_bytes;
        assert_eq!(codeword_data_bytes, 34_359_738_368);
        assert_eq!(codeword_auth_bytes, 134_217_728);
        assert_eq!(codeword_data_bytes + codeword_auth_bytes, 34_493_956_096);
        assert!(matches!(
            require_space(plan.encoder_peak_bytes, plan.encoder_peak_bytes - 1),
            Err(WhirInitialEncodingError::InsufficientSpace { .. })
        ));
        require_space(plan.encoder_peak_bytes, plan.encoder_peak_bytes).unwrap();
    }

    #[test]
    fn six_step_artifact_bytes_match_the_frozen_reference() {
        for variables in [5, 9, 17] {
            let values = table(variables);
            let expected_source = identity(variables);
            let artifact_id = [0x59; 32];
            let reference_path = test_path("six-step-reference");
            let reference_source = DenseSource::new(values.clone());
            let reference = encode_whir_initial_suffix(
                &reference_path,
                artifact_id,
                &expected_source,
                &reference_source,
            )
            .unwrap()
            .remove_on_drop();

            let six_step_path = test_path("six-step-candidate");
            let six_step_source = DenseSource::new(values);
            let side = 1 << ((variables - 1) / 2);
            let candidate = encode_six_step_suffix(
                &six_step_path,
                artifact_id,
                &expected_source,
                &six_step_source,
                side.min(N31_TRANSPOSE_TILE),
                side.min(N31_FFT_STRIP),
            )
            .unwrap()
            .remove_on_drop();

            assert_eq!(candidate.identity(), reference.identity());
            assert_eq!(
                fs::read(&six_step_path).unwrap(),
                fs::read(&reference_path).unwrap()
            );
        }
    }

    #[test]
    fn controlled_six_step_matches_frozen_bytes_and_exact_ordered_progress() {
        for variables in [5, 9, 17] {
            let values = table(variables);
            let expected_source = identity(variables);
            let artifact_id = [0x5d; 32];
            let reference_path = test_path("controlled-reference");
            let reference_source = DenseSource::new(values.clone());
            let reference = encode_whir_initial_suffix(
                &reference_path,
                artifact_id,
                &expected_source,
                &reference_source,
            )
            .unwrap()
            .remove_on_drop();

            let controlled_path = test_path("controlled-six-step");
            let controlled_source = DenseSource::new(values);
            let cancelled = AtomicBool::new(false);
            let mut progress = Vec::new();
            let controlled = match run_controlled_six_step(
                &controlled_path,
                artifact_id,
                &expected_source,
                &controlled_source,
                &cancelled,
                |update| progress.push(update),
            )
            .unwrap()
            {
                WhirInitialN31Outcome::Published(artifact) => artifact.remove_on_drop(),
                WhirInitialN31Outcome::Cancelled(update) => {
                    panic!("never-cancelled build stopped at {update:?}")
                }
            };

            assert_eq!(controlled.identity(), reference.identity());
            assert_eq!(
                fs::read(&controlled_path).unwrap(),
                fs::read(&reference_path).unwrap()
            );
            assert_eq!(progress, expected_small_six_step_progress(variables));
        }
    }

    #[test]
    fn controlled_progress_withholds_completion_until_the_stage_boundary() {
        let cancelled = AtomicBool::new(false);
        let mut observed = Vec::new();
        let result = {
            let mut observe = |update| observed.push(update);
            let mut controller = N31ProgressController::new(&cancelled, &mut observe);
            assert!(
                controller
                    .start_stage(WhirInitialN31Stage::Transpose, 16)
                    .is_ok()
            );
            assert!(controller.advance(16).is_ok());
            cancelled.store(true, Ordering::Release);
            controller.finish_stage()
        };

        assert!(matches!(
            result,
            Err(ControlledSixStepError::Cancelled(WhirInitialN31Progress {
                stage: WhirInitialN31Stage::Transpose,
                completed_bytes: 0,
                total_bytes: 16,
            }))
        ));
        assert_eq!(
            observed,
            vec![WhirInitialN31Progress {
                stage: WhirInitialN31Stage::Transpose,
                completed_bytes: 0,
                total_bytes: 16,
            }]
        );

        let cancelled = AtomicBool::new(false);
        let mut observed = Vec::new();
        let result = {
            let mut observe = |update| observed.push(update);
            let mut controller = N31ProgressController::new(&cancelled, &mut observe);
            assert!(
                controller
                    .start_stage(WhirInitialN31Stage::Transpose, 16)
                    .is_ok()
            );
            assert!(controller.advance(16).is_ok());
            controller.finish_stage()
        };
        assert!(result.is_ok());
        assert_eq!(
            observed,
            vec![
                WhirInitialN31Progress {
                    stage: WhirInitialN31Stage::Transpose,
                    completed_bytes: 0,
                    total_bytes: 16,
                },
                WhirInitialN31Progress {
                    stage: WhirInitialN31Stage::Transpose,
                    completed_bytes: 16,
                    total_bytes: 16,
                },
            ]
        );
    }

    #[test]
    fn controlled_six_step_pre_cancel_reads_and_creates_nothing() {
        let variables = 5;
        let expected_source = identity(variables);
        let source = DenseSource::new(table(variables));
        let path = test_path("controlled-pre-cancel");
        let cancelled = AtomicBool::new(true);
        let mut progress = Vec::new();
        let outcome = run_controlled_six_step(
            &path,
            [0x5e; 32],
            &expected_source,
            &source,
            &cancelled,
            |update| progress.push(update),
        )
        .unwrap();

        assert!(matches!(
            outcome,
            WhirInitialN31Outcome::Cancelled(WhirInitialN31Progress {
                stage: WhirInitialN31Stage::Transpose,
                completed_bytes: 0,
                total_bytes: 256,
            })
        ));
        assert!(progress.is_empty());
        assert_eq!(source.reads.load(Ordering::SeqCst), 0);
        assert_no_six_step_output(&path);
    }

    #[test]
    fn controlled_six_step_cancels_immediately_after_first_authenticated_read() {
        let variables = 5;
        let expected_source = identity(variables);
        let source_path = test_path("controlled-first-read-source");
        let mut writer =
            WhirInitialSourceArtifactWriter::create(&source_path, expected_source.clone()).unwrap();
        writer.write_elements(&table(variables)).unwrap();
        let authenticated_source = writer.finish().unwrap().remove_on_drop();
        let cancelled = AtomicBool::new(false);
        let source = CancelAfterFirstReadSource {
            inner: &authenticated_source,
            cancelled: &cancelled,
            reads: AtomicUsize::new(0),
        };
        let path = test_path("controlled-first-read-cancel");
        let mut progress = Vec::new();
        let outcome = run_controlled_six_step(
            &path,
            [0x5f; 32],
            &expected_source,
            &source,
            &cancelled,
            |update| progress.push(update),
        )
        .unwrap();

        assert!(matches!(
            outcome,
            WhirInitialN31Outcome::Cancelled(WhirInitialN31Progress {
                stage: WhirInitialN31Stage::Transpose,
                completed_bytes: 0,
                total_bytes: 256,
            })
        ));
        assert_eq!(
            progress,
            vec![WhirInitialN31Progress {
                stage: WhirInitialN31Stage::Transpose,
                completed_bytes: 0,
                total_bytes: 256,
            }]
        );
        assert_eq!(source.reads.load(Ordering::SeqCst), 1);
        assert_no_six_step_output(&path);
    }

    #[test]
    fn controlled_six_step_cancellation_at_each_stage_cleans_owned_files() {
        for (index, stage) in [
            WhirInitialN31Stage::Transpose,
            WhirInitialN31Stage::FirstFft,
            WhirInitialN31Stage::SecondFft,
            WhirInitialN31Stage::Seal,
            WhirInitialN31Stage::Verify,
        ]
        .into_iter()
        .enumerate()
        {
            let variables = 5;
            let expected_source = identity(variables);
            let source = DenseSource::new(table(variables));
            let path = test_path("controlled-stage-cancel");
            let cancelled = AtomicBool::new(false);
            let outcome = run_controlled_six_step(
                &path,
                [0x70 + index as u8; 32],
                &expected_source,
                &source,
                &cancelled,
                |update| {
                    if update.stage == stage && update.completed_bytes == 0 {
                        cancelled.store(true, Ordering::Release);
                    }
                },
            )
            .unwrap();

            assert!(matches!(
                outcome,
                WhirInitialN31Outcome::Cancelled(update)
                    if update.stage == stage && update.completed_bytes == 0
            ));
            assert_no_six_step_output(&path);
        }
    }

    #[test]
    fn controlled_six_step_verify_completion_can_cancel_before_publication() {
        let variables = 5;
        let expected_source = identity(variables);
        let source = DenseSource::new(table(variables));
        let path = test_path("controlled-verified-cancel");
        let cancelled = AtomicBool::new(false);
        let outcome = run_controlled_six_step(
            &path,
            [0x76; 32],
            &expected_source,
            &source,
            &cancelled,
            |update| {
                if update.stage == WhirInitialN31Stage::Verify
                    && update.completed_bytes == update.total_bytes
                {
                    cancelled.store(true, Ordering::Release);
                }
            },
        )
        .unwrap();

        assert!(matches!(
            outcome,
            WhirInitialN31Outcome::Cancelled(WhirInitialN31Progress {
                stage: WhirInitialN31Stage::Verify,
                completed_bytes: 544,
                total_bytes: 544,
            })
        ));
        assert_no_six_step_output(&path);
    }

    #[test]
    fn controlled_six_step_already_exists_precedes_cancellation() {
        let variables = 5;
        let expected_source = identity(variables);
        let source = DenseSource::new(table(variables));
        let path = test_path("controlled-existing-target");
        fs::write(&path, b"preserve").unwrap();
        let cancelled = AtomicBool::new(true);
        assert!(matches!(
            run_controlled_six_step(
                &path,
                [0x77; 32],
                &expected_source,
                &source,
                &cancelled,
                |_| panic!("preflight failure must not report progress"),
            ),
            Err(WhirInitialEncodingError::AlreadyExists(existing)) if existing == path
        ));
        assert_eq!(source.reads.load(Ordering::SeqCst), 0);
        assert_eq!(fs::read(&path).unwrap(), b"preserve");
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn controlled_six_step_observer_panic_unwinds_owned_staging_cleanup() {
        let variables = 5;
        let expected_source = identity(variables);
        let source = DenseSource::new(table(variables));
        let path = test_path("controlled-observer-panic");
        let cancelled = AtomicBool::new(false);
        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = run_controlled_six_step(
                &path,
                [0x78; 32],
                &expected_source,
                &source,
                &cancelled,
                |update| {
                    if update.stage == WhirInitialN31Stage::FirstFft && update.completed_bytes == 0
                    {
                        panic!("injected observer panic");
                    }
                },
            );
        }));

        assert!(unwind.is_err());
        assert_no_six_step_output(&path);
    }

    #[test]
    fn six_step_preflight_and_source_failures_publish_nothing() {
        let malformed_path = test_path("six-step-malformed");
        assert!(matches!(
            encode_six_step_suffix(
                &malformed_path,
                [0x5a; 32],
                &identity(4),
                &ForbiddenSourceAccess,
                2,
                2,
            ),
            Err(WhirInitialEncodingError::Invalid(_))
        ));
        assert!(!malformed_path.exists());

        let values = table(5);
        let mut failing = DenseSource::new(values);
        failing.fail_at = Some(1);
        let failing_path = test_path("six-step-failing");
        assert!(
            encode_six_step_suffix(&failing_path, [0x5b; 32], &identity(5), &failing, 4, 4,)
                .is_err()
        );
        assert!(!failing_path.exists());
        let staging_prefix = format!(
            "{}.n31.",
            failing_path.file_name().unwrap().to_string_lossy()
        );
        assert!(
            fs::read_dir(failing_path.parent().unwrap())
                .unwrap()
                .filter_map(Result::ok)
                .all(|entry| !entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(&staging_prefix))
        );

        fs::write(&failing_path, b"preserve").unwrap();
        let source = DenseSource::new(table(5));
        assert!(matches!(
            encode_six_step_suffix(&failing_path, [0x5c; 32], &identity(5), &source, 4, 4,),
            Err(WhirInitialEncodingError::AlreadyExists(_))
        ));
        assert_eq!(source.reads.load(Ordering::SeqCst), 0);
        assert_eq!(fs::read(&failing_path).unwrap(), b"preserve");
        fs::remove_file(failing_path).unwrap();
    }

    #[test]
    fn six_step_cleanup_refuses_to_remove_a_replacement() {
        let final_path = test_path("six-step-cleanup-owner");
        let (staging_path, staging_file) =
            create_unique_production_staging(&final_path, "cleanup-test").unwrap();
        let staging = OwnedProductionFile::new(staging_path.clone(), staging_file);
        fs::remove_file(&staging_path).unwrap();
        fs::write(&staging_path, b"replacement").unwrap();

        assert!(matches!(
            staging.remove(),
            Err(WhirInitialEncodingError::CleanupTargetChanged(path)) if path == staging_path
        ));
        assert_eq!(fs::read(&staging_path).unwrap(), b"replacement");
        fs::remove_file(staging_path).unwrap();
    }

    #[test]
    fn digest_source_matches_unpadded_rows_across_chunks_and_at_max_batch() {
        let variables = 15;
        let values = table(variables);
        let expected = expected_codeword(&values, variables);
        let source = DenseSource::new(values);
        let path = test_path("leaf-digests");
        let artifact = encode_whir_initial_suffix(&path, [0x55; 32], &identity(variables), &source)
            .unwrap()
            .remove_on_drop();
        assert_eq!(Blake3DigestSource::height(&artifact), 1 << 14);

        for (row_start, row_count) in [(250, 20), (4_096, BLAKE3_LEAF_BATCH_ROWS)] {
            let actual = artifact.read_digests(row_start, row_count).unwrap();
            let word_start = row_start * WHIR_INITIAL_WIDTH;
            let word_end = (row_start + row_count) * WHIR_INITIAL_WIDTH;
            assert_eq!(
                actual,
                expected_leaf_digests(&expected[word_start..word_end])
            );
        }
    }

    #[test]
    fn digest_source_rejects_invalid_ranges_and_corruption() {
        let variables = 10;
        let source = DenseSource::new(table(variables));
        let path = test_path("leaf-digest-failures");
        let artifact = encode_whir_initial_suffix(&path, [0x56; 32], &identity(variables), &source)
            .unwrap()
            .remove_on_drop();
        let height = Blake3DigestSource::height(&artifact);
        for (row_start, row_count) in [
            (0, 0),
            (0, BLAKE3_LEAF_BATCH_ROWS + 1),
            (height, 1),
            (height - 1, 2),
            (usize::MAX, 2),
        ] {
            assert!(matches!(
                artifact.read_digests(row_start, row_count),
                Err(Blake3MerkleStoreError::Invalid(_))
            ));
        }

        let original = artifact.read_canonical_rows(256, 1).unwrap()[0];
        let replacement = u64::from(original == 0);
        let mut writer = OpenOptions::new().write(true).open(&path).unwrap();
        writer
            .seek(SeekFrom::Start(data_offset(256).unwrap()))
            .unwrap();
        writer.write_all(&replacement.to_le_bytes()).unwrap();
        writer.sync_all().unwrap();
        assert!(matches!(
            artifact.read_digests(250, 20),
            Err(Blake3MerkleStoreError::Source(_))
        ));
    }

    #[test]
    fn n19_reference_encoder_cap_matches_small_batch() {
        let variables = WHIR_INITIAL_REFERENCE_ENCODER_MAX_VARIABLES;
        let values = table(variables);
        let expected = expected_codeword(&values, variables);
        let source = DenseSource::new(values);
        let path = test_path("n19");
        let artifact = encode_whir_initial_suffix(&path, [0x52; 32], &identity(variables), &source)
            .unwrap()
            .remove_on_drop();
        assert_eq!(artifact.identity.height, 1 << 18);
        let authenticated_values = read_all(&artifact);
        assert_eq!(authenticated_values, expected);
        assert_eq!(
            MerkleRowSource::read_rows(&artifact, (1 << 17) - 3, 7).unwrap(),
            expected[((1 << 17) - 3) * WHIR_INITIAL_WIDTH..((1 << 17) + 4) * WHIR_INITIAL_WIDTH]
        );

        let cpu = WhirMmcs::new(FieldHash::new(Blake3), Compress::new(Blake3), 0);
        let matrix = RowMajorMatrix::new(
            authenticated_values
                .into_iter()
                .map(Goldilocks::new)
                .collect(),
            WHIR_INITIAL_WIDTH,
        );
        let (commitment, prover_data) = cpu.commit(vec![matrix]);
        let tree_path = test_path("n19-tree");
        let store = crate::blake3_merkle_store::build_authenticated_blake3_merkle_store(
            &tree_path,
            [0xa5; 32],
            &[&artifact],
        )
        .unwrap()
        .remove_on_drop();
        assert_eq!(store.root().unwrap(), commitment.roots()[0]);
        for index in [0, 1, 255, 256, 1 << 17, (1 << 18) - 1] {
            assert_eq!(
                store.opening_path(index).unwrap(),
                cpu.open_batch(index, &prover_data).opening_proof
            );
        }
    }

    #[test]
    fn reference_cap_and_bad_geometry_fail_before_source_or_file_access() {
        let over_cap = identity(WHIR_INITIAL_REFERENCE_ENCODER_MAX_VARIABLES + 1);
        let path = test_path("reference-cap-public");
        let partial_path = partial_path_for(&path).unwrap();
        fs::write(&path, b"existing target").unwrap();
        fs::write(&partial_path, b"existing partial").unwrap();
        assert!(matches!(
            encode_whir_initial_suffix(&path, [0x61; 32], &over_cap, &ForbiddenSourceAccess),
            Err(WhirInitialEncodingError::ResearchLimit(_))
        ));
        assert_eq!(fs::read(&path).unwrap(), b"existing target");
        assert_eq!(fs::read(&partial_path).unwrap(), b"existing partial");
        fs::remove_file(&path).unwrap();
        fs::remove_file(&partial_path).unwrap();

        let path = test_path("reference-cap-internal");
        assert!(matches!(
            encode_with_limits(
                &path,
                [0x61; 32],
                &over_cap,
                &ForbiddenSourceAccess,
                WHIR_INITIAL_WIDTH,
                WHIR_INITIAL_WIDTH,
            ),
            Err(WhirInitialEncodingError::ResearchLimit(_))
        ));
        assert!(!path.exists());
        assert!(!partial_path_for(&path).unwrap().exists());

        let source = DenseSource::new(vec![0; 4]);
        let path = test_path("bad-geometry-preflight");
        assert!(matches!(
            encode_whir_initial_suffix(&path, [0x61; 32], &identity(1), &source),
            Err(WhirInitialEncodingError::Invalid(_))
        ));
        assert_eq!(source.reads.load(Ordering::SeqCst), 0);
        assert!(!path.exists());
        assert!(!partial_path_for(&path).unwrap().exists());

        let path = test_path("wrong-source-identity");
        let expected = identity(4);
        let mut wrong = expected.clone();
        wrong.source_id[0] ^= 1;
        let source = DenseSource::with_identity(table(4), wrong);
        assert!(matches!(
            encode_whir_initial_suffix(&path, [0x62; 32], &expected, &source),
            Err(WhirInitialEncodingError::IdentityMismatch)
        ));
        assert_eq!(source.reads.load(Ordering::SeqCst), 0);
        assert!(!path.exists());
        assert!(!partial_path_for(&path).unwrap().exists());
    }

    #[test]
    fn source_failures_and_geometry_changes_never_publish() {
        let values = table(6);
        let mut failing = DenseSource::new(values.clone());
        failing.fail_at = Some(1);
        let mut changing = DenseSource::new(values);
        changing.change_len_after_read = true;
        for source in [&failing, &changing] {
            let path = test_path("source-failure");
            assert!(encode_with_limits(&path, [0x71; 32], &identity(6), source, 16, 16).is_err());
            assert!(!path.exists());
            assert!(!partial_path_for(&path).unwrap().exists());
        }
    }

    #[test]
    fn no_overwrite_and_noncanonical_source_fail_closed() {
        let path = test_path("no-overwrite");
        fs::write(&path, b"keep").unwrap();
        let source = DenseSource::new(table(4));
        assert!(matches!(
            encode_whir_initial_suffix(&path, [0x81; 32], &identity(4), &source),
            Err(WhirInitialEncodingError::AlreadyExists(_))
        ));
        assert_eq!(fs::read(&path).unwrap(), b"keep");
        fs::remove_file(&path).unwrap();

        let path = test_path("noncanonical");
        let mut values = table(4);
        values[3] = GOLDILOCKS_MODULUS;
        let source = DenseSource::new(values);
        assert!(matches!(
            encode_whir_initial_suffix(&path, [0x82; 32], &identity(4), &source),
            Err(WhirInitialEncodingError::Invalid(_))
        ));
        assert!(!path.exists());
    }

    #[test]
    fn dft_staging_read_rejects_noncanonical_words() {
        let path = test_path("noncanonical-staging");
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.set_len((HEADER_BYTES + 2 * WHIR_INITIAL_WIDTH * 8) as u64)
            .unwrap();
        file.seek(SeekFrom::Start(data_offset(0).unwrap())).unwrap();
        file.write_all(&GOLDILOCKS_MODULUS.to_le_bytes()).unwrap();
        assert!(matches!(
            dft_goldilocks_rows_in_place(
                &mut file,
                &path,
                HEADER_BYTES as u64,
                2,
                WHIR_INITIAL_WIDTH,
                WHIR_INITIAL_WIDTH,
            ),
            Err(ExternalRadix2Error::Invalid(_))
        ));
        drop(file);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn corruption_is_rejected_on_reopen_and_random_read() {
        let path = test_path("corruption");
        let source = DenseSource::new(table(6));
        let artifact =
            encode_whir_initial_suffix(&path, [0x91; 32], &identity(6), &source).unwrap();
        let expected = artifact.identity().clone();
        let mut writer = OpenOptions::new().write(true).open(&path).unwrap();
        writer
            .seek(SeekFrom::Start(HEADER_BYTES as u64 + 8))
            .unwrap();
        writer.write_all(&123_u64.to_le_bytes()).unwrap();
        writer.sync_all().unwrap();
        assert!(matches!(
            artifact.read_canonical_rows(0, 1),
            Err(WhirInitialEncodingError::ChecksumMismatch)
        ));
        drop(artifact);
        assert!(matches!(
            AuthenticatedWhirInitialCodeword::open(&path, &expected),
            Err(WhirInitialEncodingError::ChecksumMismatch)
        ));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn trusted_identity_rejects_a_self_consistent_artifact_substitution() {
        let original_path = test_path("original");
        let substitute_path = test_path("substitute");
        let source_identity = identity(6);
        let original_source = DenseSource::new(table(6));
        let original = encode_whir_initial_suffix(
            &original_path,
            [0xa1; 32],
            &source_identity,
            &original_source,
        )
        .unwrap();
        let trusted_identity = original.identity().clone();
        drop(original);

        let mut substitute_values = table(6);
        substitute_values[7] += 1;
        let substitute_source = DenseSource::with_identity(substitute_values, source_identity);
        let substitute = encode_whir_initial_suffix(
            &substitute_path,
            [0xa1; 32],
            &trusted_identity.source,
            &substitute_source,
        )
        .unwrap();
        assert_ne!(
            substitute.identity().artifact_digest,
            trusted_identity.artifact_digest
        );
        drop(substitute);

        assert!(matches!(
            AuthenticatedWhirInitialCodeword::open(&substitute_path, &trusted_identity),
            Err(WhirInitialEncodingError::IdentityMismatch)
        ));
        fs::remove_file(original_path).unwrap();
        fs::remove_file(substitute_path).unwrap();
    }
}
