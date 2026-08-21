//! Demand-authenticated, production-geometry BLAKE3 paths for WHIR.
//!
//! Format v2 stores Plonky3's exact layer-major binary BLAKE3 tree without a
//! proportional in-memory authentication table. Reopening performs two fixed
//! `Read` calls totaling 288 bytes (plus seeks and two file-metadata queries)
//! against a caller-retained identity. A proof-facing path is returned only
//! together with an authenticated canonical extension-codeword row and only
//! after that row and the on-disk siblings reconstruct the pinned root.
//!
//! This is a correctness/reference primitive. Building the production
//! `2^29`-row tree still writes about 32 GiB and has not yet been matched by the
//! production GPU construction path. This module is not wired into consensus
//! and does not raise any proof-activation cap.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use blake3::Hasher;
use same_file::Handle;
use thiserror::Error;

use crate::blake3_merkle_store::{BLAKE3_LEAF_BATCH_ROWS, Blake3DigestSource, Blake3MerkleDigest};
use crate::merkle_store::GOLDILOCKS_MODULUS;
use crate::whir_extension::{
    AuthenticatedWhirExtensionCodeword, WHIR_EXTENSION_LIMBS_PER_ROW,
    WhirExtensionCodewordIdentity, WhirExtensionEncodingError,
};

const MAGIC: &[u8; 8] = b"CMFDB3P2";
const VERSION: u32 = 2;
const HEADER_BYTES: usize = 256;
const DIGEST_BYTES: usize = 32;
const MATRIX_COUNT: u32 = 1;
const WIDTH: u32 = WHIR_EXTENSION_LIMBS_PER_ROW as u32;
const CAP_HEIGHT: u32 = 0;
const HEADER_DIGEST_START: usize = 160;
const HEADER_DIGEST_END: usize = HEADER_DIGEST_START + DIGEST_BYTES;
const HEADER_DOMAIN: &str = "Common Foundry demand BLAKE3 path-store header v2";
const MAX_HEIGHT: u64 = 1 << 29;
const PARENT_BATCH: usize = 8 * 1024;
const CREATE_ATTEMPTS: usize = 256;

static NEXT_STAGING_FILE: AtomicU64 = AtomicU64::new(0);

/// Checked fixed-format geometry. Construction allocates only bounded batches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DemandBlake3TreeGeometry {
    pub height: u64,
    pub layer_count: u32,
    pub total_digests: u64,
    pub tree_bytes: u64,
    pub artifact_bytes: u64,
}

/// Exact caller-retained identity required to adopt or reopen one path store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DemandBlake3TreeIdentity {
    pub store_id: [u8; 32],
    pub source_binding: [u8; 32],
    pub height: u64,
    pub width: u32,
    pub tree_root: Blake3MerkleDigest,
    pub artifact_bytes: u64,
}

#[derive(Debug, Error)]
pub enum DemandBlake3TreeError {
    #[error("invalid demand-authenticated BLAKE3 tree: {0}")]
    Invalid(&'static str),
    #[error("demand-authenticated BLAKE3 source failed: {0}")]
    Source(String),
    #[error("demand-authenticated BLAKE3 tree already exists at {0}")]
    AlreadyExists(PathBuf),
    #[error("demand-authenticated BLAKE3 output must be absolute with an existing parent: {0}")]
    InvalidOutputPath(PathBuf),
    #[error(
        "demand-authenticated BLAKE3 output has insufficient free space: need {required} bytes, have {available} bytes"
    )]
    InsufficientSpace { required: u64, available: u64 },
    #[error("could not allocate a unique demand-authenticated BLAKE3 staging file in {0}")]
    NameExhausted(PathBuf),
    #[error("demand-authenticated BLAKE3 I/O failed while {operation} {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("demand-authenticated BLAKE3 header digest does not match")]
    HeaderDigestMismatch,
    #[error("demand-authenticated BLAKE3 identity does not match")]
    IdentityMismatch,
    #[error("demand-authenticated BLAKE3 stored root does not match its pinned root")]
    RootMismatch,
    #[error("demand-authenticated BLAKE3 opening does not reconstruct the pinned root")]
    OpeningMismatch,
    #[error("demand-authenticated BLAKE3 cleanup path no longer names the owned file: {0}")]
    CleanupTargetChanged(PathBuf),
    #[error(
        "durable parent-directory synchronization is unsupported for demand-authenticated BLAKE3 output {path}: {source}"
    )]
    ParentDirectorySyncUnsupported {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("demand-authenticated BLAKE3 file lock is poisoned")]
    LockPoisoned,
    #[error("WHIR extension codeword failed: {0}")]
    Extension(#[from] WhirExtensionEncodingError),
}

/// Validate v2 geometry without allocating proportional to its height.
pub fn demand_blake3_tree_geometry(
    height: u64,
) -> Result<DemandBlake3TreeGeometry, DemandBlake3TreeError> {
    if height == 0 || !height.is_power_of_two() {
        return Err(DemandBlake3TreeError::Invalid(
            "height must be a nonzero power of two",
        ));
    }
    if height > MAX_HEIGHT {
        return Err(DemandBlake3TreeError::Invalid("height exceeds 2^29"));
    }
    let layer_count = height
        .ilog2()
        .checked_add(1)
        .ok_or(DemandBlake3TreeError::Invalid("layer count overflow"))?;
    let total_digests = height
        .checked_mul(2)
        .and_then(|value| value.checked_sub(1))
        .ok_or(DemandBlake3TreeError::Invalid(
            "total digest count overflow",
        ))?;
    let tree_bytes = total_digests
        .checked_mul(DIGEST_BYTES as u64)
        .ok_or(DemandBlake3TreeError::Invalid("tree byte length overflow"))?;
    let artifact_bytes =
        (HEADER_BYTES as u64)
            .checked_add(tree_bytes)
            .ok_or(DemandBlake3TreeError::Invalid(
                "artifact byte length overflow",
            ))?;
    Ok(DemandBlake3TreeGeometry {
        height,
        layer_count,
        total_digests,
        tree_bytes,
        artifact_bytes,
    })
}

/// Immutable v2 path-store capability authenticated against external identity.
pub struct AuthenticatedDemandBlake3Tree {
    file: Option<Mutex<File>>,
    path: PathBuf,
    identity: DemandBlake3TreeIdentity,
    geometry: DemandBlake3TreeGeometry,
    header: [u8; HEADER_BYTES],
    cleanup_path: Option<PathBuf>,
}

impl std::fmt::Debug for AuthenticatedDemandBlake3Tree {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthenticatedDemandBlake3Tree")
            .field("path", &self.path)
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl AuthenticatedDemandBlake3Tree {
    /// Reopen using two fixed-size `Read` calls: the 256-byte header and final
    /// root. Exact-length race checks additionally issue two metadata queries;
    /// the 288-byte claim does not count those metadata operations or seeks.
    pub fn open(
        path: impl AsRef<Path>,
        expected: &DemandBlake3TreeIdentity,
    ) -> Result<Self, DemandBlake3TreeError> {
        let path = path.as_ref().to_path_buf();
        let mut file = File::open(&path).map_err(|source| io_error("opening", &path, source))?;
        let file_len = file
            .metadata()
            .map_err(|source| io_error("reading metadata for", &path, source))?
            .len();
        let (header, geometry) = read_and_verify_envelope(&mut file, file_len, expected)?;
        let file_len_after = file
            .metadata()
            .map_err(|source| io_error("rechecking metadata for", &path, source))?
            .len();
        if file_len_after != file_len {
            return Err(DemandBlake3TreeError::Invalid(
                "file length changed while opening",
            ));
        }
        Ok(Self {
            file: Some(Mutex::new(file)),
            path,
            identity: *expected,
            geometry,
            header,
            cleanup_path: None,
        })
    }

    pub const fn identity(&self) -> &DemandBlake3TreeIdentity {
        &self.identity
    }

    pub const fn geometry(&self) -> DemandBlake3TreeGeometry {
        self.geometry
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Opt into same-file-guarded removal when this capability is dropped.
    pub fn remove_on_drop(mut self) -> Self {
        self.cleanup_path = Some(self.path.clone());
        self
    }

    /// Close and explicitly remove the exact file represented by this handle.
    pub fn remove(mut self) -> Result<(), DemandBlake3TreeError> {
        let path = self
            .cleanup_path
            .take()
            .unwrap_or_else(|| self.path.clone());
        let mutex = self.file.take().expect("live path store owns its file");
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

    /// Read one sibling per layer and return the path only after `leaf` folds
    /// to the caller-pinned root. This deliberately remains crate-private;
    /// proof-facing callers use [`WhirExtensionOracle`].
    fn authenticate_leaf(
        &self,
        index: usize,
        leaf: Blake3MerkleDigest,
    ) -> Result<Vec<Blake3MerkleDigest>, DemandBlake3TreeError> {
        let height = usize::try_from(self.geometry.height)
            .map_err(|_| DemandBlake3TreeError::Invalid("height does not fit memory"))?;
        if index >= height {
            return Err(DemandBlake3TreeError::Invalid(
                "opening index is out of bounds",
            ));
        }
        let mut path = Vec::new();
        path.try_reserve_exact(self.geometry.layer_count.saturating_sub(1) as usize)
            .map_err(|_| DemandBlake3TreeError::Invalid("opening path allocation failed"))?;

        let mutex = self.file.as_ref().expect("live path store owns its file");
        let mut file = mutex
            .lock()
            .map_err(|_| DemandBlake3TreeError::LockPoisoned)?;
        self.verify_live_envelope(&mut file)?;
        let mut layer_start = 0_u64;
        let mut layer_len = height as u64;
        let mut current = index as u64;
        let mut reconstructed = leaf;
        while layer_len > 1 {
            let sibling = read_digest(
                &mut file,
                &self.path,
                self.geometry,
                layer_start
                    .checked_add(current ^ 1)
                    .ok_or(DemandBlake3TreeError::Invalid("sibling offset overflow"))?,
            )?;
            path.push(sibling);
            reconstructed = if current & 1 == 0 {
                compress([reconstructed, sibling])
            } else {
                compress([sibling, reconstructed])
            };
            layer_start = layer_start
                .checked_add(layer_len)
                .ok_or(DemandBlake3TreeError::Invalid("layer offset overflow"))?;
            layer_len >>= 1;
            current >>= 1;
        }
        self.verify_live_envelope(&mut file)?;
        if reconstructed != self.identity.tree_root {
            return Err(DemandBlake3TreeError::OpeningMismatch);
        }
        Ok(path)
    }

    fn verify_live_envelope(&self, file: &mut File) -> Result<(), DemandBlake3TreeError> {
        let file_len = file
            .metadata()
            .map_err(|source| io_error("reauthenticating metadata for", &self.path, source))?
            .len();
        let (header, geometry) = read_and_verify_envelope(file, file_len, &self.identity)?;
        if header != self.header || geometry != self.geometry {
            return Err(DemandBlake3TreeError::IdentityMismatch);
        }
        Ok(())
    }
}

impl Drop for AuthenticatedDemandBlake3Tree {
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

/// Authenticated extension row and its leaf-to-root sibling path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedWhirExtensionOpening {
    row: [u64; WHIR_EXTENSION_LIMBS_PER_ROW],
    authentication_path: Vec<Blake3MerkleDigest>,
}

impl AuthenticatedWhirExtensionOpening {
    pub const fn row(&self) -> &[u64; WHIR_EXTENSION_LIMBS_PER_ROW] {
        &self.row
    }

    pub fn authentication_path(&self) -> &[Blake3MerkleDigest] {
        &self.authentication_path
    }
}

/// Exact adoption boundary joining an authenticated extension codeword to its
/// demand-authenticated BLAKE3 tree.
pub struct WhirExtensionOracle {
    codeword: AuthenticatedWhirExtensionCodeword,
    tree: AuthenticatedDemandBlake3Tree,
}

impl std::fmt::Debug for WhirExtensionOracle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WhirExtensionOracle")
            .field("codeword", self.codeword.identity())
            .field("tree", self.tree.identity())
            .finish_non_exhaustive()
    }
}

impl WhirExtensionOracle {
    /// Adopt only an exact identity/geometry binding. No artifact metadata is
    /// added to the proof transcript by this local capability.
    pub fn new(
        codeword: AuthenticatedWhirExtensionCodeword,
        tree: AuthenticatedDemandBlake3Tree,
    ) -> Result<Self, DemandBlake3TreeError> {
        let source_binding = codeword.identity().binding_digest()?;
        if tree.identity.source_binding != source_binding
            || tree.identity.height != codeword.geometry().height
            || tree.identity.width != WIDTH
        {
            return Err(DemandBlake3TreeError::IdentityMismatch);
        }
        Ok(Self { codeword, tree })
    }

    pub const fn codeword_identity(&self) -> &WhirExtensionCodewordIdentity {
        self.codeword.identity()
    }

    pub const fn tree_identity(&self) -> &DemandBlake3TreeIdentity {
        self.tree.identity()
    }

    /// Authenticate the canonical row in the codeword, then authenticate its
    /// exact p3 BLAKE3 path. Nothing is returned unless both checks succeed.
    pub fn authenticated_opening(
        &self,
        index: usize,
    ) -> Result<AuthenticatedWhirExtensionOpening, DemandBlake3TreeError> {
        if self.tree.identity.source_binding != self.codeword.identity().binding_digest()? {
            return Err(DemandBlake3TreeError::IdentityMismatch);
        }
        let values = self.codeword.read_canonical_rows(index, 1)?;
        let row: [u64; WHIR_EXTENSION_LIMBS_PER_ROW] = values
            .try_into()
            .map_err(|_| DemandBlake3TreeError::Invalid("extension row width changed"))?;
        if row.iter().any(|value| *value >= GOLDILOCKS_MODULUS) {
            return Err(DemandBlake3TreeError::Invalid(
                "extension row is not canonical",
            ));
        }
        let leaf = hash_canonical_row(&row);
        let authentication_path = self.tree.authenticate_leaf(index, leaf)?;
        Ok(AuthenticatedWhirExtensionOpening {
            row,
            authentication_path,
        })
    }

    /// Explicitly remove both scratch artifacts. The codeword's builder-owned
    /// cleanup capability remains armed if removing the tree fails first.
    pub fn remove(self) -> Result<(), DemandBlake3TreeError> {
        let Self { codeword, tree } = self;
        tree.remove()?;
        codeword.remove()?;
        Ok(())
    }
}

/// Build exact p3 layer-major bytes using bounded leaf and parent batches.
///
/// `source_binding` must identify the authenticated codeword that produced the
/// supplied leaves. [`WhirExtensionOracle::new`] independently enforces that
/// equality before any proof-facing opening is available.
pub fn build_whir_extension_demand_blake3_tree(
    final_path: impl AsRef<Path>,
    store_id: [u8; 32],
    codeword: &AuthenticatedWhirExtensionCodeword,
) -> Result<AuthenticatedDemandBlake3Tree, DemandBlake3TreeError> {
    build_demand_blake3_tree(
        final_path,
        store_id,
        codeword.identity().binding_digest()?,
        codeword,
    )
}

/// Lower-level builder for an already bound leaf-digest producer.
///
/// Prefer [`build_whir_extension_demand_blake3_tree`] for an extension
/// codeword. This seam exists so a future GPU leaf producer can emit the same
/// exact layer bytes while retaining an independently computed source binding.
pub fn build_demand_blake3_tree(
    final_path: impl AsRef<Path>,
    store_id: [u8; 32],
    source_binding: [u8; 32],
    source: &dyn Blake3DigestSource,
) -> Result<AuthenticatedDemandBlake3Tree, DemandBlake3TreeError> {
    build_demand_blake3_tree_with_sync(
        final_path.as_ref(),
        store_id,
        source_binding,
        source,
        sync_parent_directory,
    )
}

fn build_demand_blake3_tree_with_sync<SyncParent>(
    final_path: &Path,
    store_id: [u8; 32],
    source_binding: [u8; 32],
    source: &dyn Blake3DigestSource,
    mut sync_parent: SyncParent,
) -> Result<AuthenticatedDemandBlake3Tree, DemandBlake3TreeError>
where
    SyncParent: FnMut(&Path) -> Result<(), DemandBlake3TreeError>,
{
    if store_id == [0; 32] {
        return Err(DemandBlake3TreeError::Invalid(
            "store identity must be nonzero",
        ));
    }
    let height = u64::try_from(source.height())
        .map_err(|_| DemandBlake3TreeError::Invalid("source height does not fit u64"))?;
    let geometry = demand_blake3_tree_geometry(height)?;
    let final_path = final_path.to_path_buf();
    let parent = artifact_parent(&final_path)?;
    if final_path
        .try_exists()
        .map_err(|source| io_error("checking publication target", &final_path, source))?
    {
        return Err(DemandBlake3TreeError::AlreadyExists(final_path));
    }
    let available = fs2::available_space(&parent)
        .map_err(|source| io_error("checking free space in", &parent, source))?;
    if available < geometry.artifact_bytes {
        return Err(DemandBlake3TreeError::InsufficientSpace {
            required: geometry.artifact_bytes,
            available,
        });
    }

    let (partial_path, file) = create_unique_staging(&final_path)?;
    let mut staging = OwnedFileLink::new(partial_path.clone(), file);
    staging
        .file_mut()
        .write_all(&[0_u8; HEADER_BYTES])
        .map_err(|source| io_error("writing provisional header to", &partial_path, source))?;

    let height_usize = usize::try_from(height)
        .map_err(|_| DemandBlake3TreeError::Invalid("height does not fit memory"))?;
    for row_start in (0..height_usize).step_by(BLAKE3_LEAF_BATCH_ROWS) {
        let row_count = (height_usize - row_start).min(BLAKE3_LEAF_BATCH_ROWS);
        validate_source_height(source, height_usize)?;
        let leaves = source
            .read_digests(row_start, row_count)
            .map_err(|error| DemandBlake3TreeError::Source(error.to_string()))?;
        validate_source_height(source, height_usize)?;
        if leaves.len() != row_count {
            return Err(DemandBlake3TreeError::Invalid(
                "source returned the wrong leaf count",
            ));
        }
        write_digest_batch(staging.file_mut(), &partial_path, &leaves)?;
    }
    staging
        .file_mut()
        .flush()
        .map_err(|source| io_error("flushing leaves in", &partial_path, source))?;

    let mut reader = File::open(&partial_path)
        .map_err(|source| io_error("opening construction reader for", &partial_path, source))?;
    let mut previous_start = HEADER_BYTES as u64;
    let mut previous_len = height;
    while previous_len > 1 {
        reader
            .seek(SeekFrom::Start(previous_start))
            .map_err(|source| io_error("seeking construction reader in", &partial_path, source))?;
        let mut remaining_parents = previous_len / 2;
        while remaining_parents != 0 {
            let parent_count = usize::try_from(remaining_parents.min(PARENT_BATCH as u64))
                .expect("bounded parent batch fits usize");
            let children = read_digest_batch(&mut reader, &partial_path, parent_count * 2)?;
            let parents = children
                .chunks_exact(2)
                .map(|pair| compress([pair[0], pair[1]]))
                .collect::<Vec<_>>();
            write_digest_batch(staging.file_mut(), &partial_path, &parents)?;
            remaining_parents -= parent_count as u64;
        }
        staging
            .file_mut()
            .flush()
            .map_err(|source| io_error("flushing parent layer in", &partial_path, source))?;
        previous_start = previous_start
            .checked_add(previous_len * DIGEST_BYTES as u64)
            .ok_or(DemandBlake3TreeError::Invalid("layer offset overflow"))?;
        previous_len >>= 1;
    }
    drop(reader);
    validate_source_height(source, height_usize)?;

    let root = read_root(staging.file_mut(), &partial_path, geometry)?;
    let identity = DemandBlake3TreeIdentity {
        store_id,
        source_binding,
        height,
        width: WIDTH,
        tree_root: root,
        artifact_bytes: geometry.artifact_bytes,
    };
    let header = encode_header(&identity, geometry);
    staging
        .file_mut()
        .seek(SeekFrom::Start(0))
        .and_then(|_| staging.file_mut().write_all(&header))
        .and_then(|_| staging.file_mut().flush())
        .and_then(|_| staging.file_mut().sync_all())
        .map_err(|source| io_error("sealing", &partial_path, source))?;
    let actual_len = staging
        .file_ref()
        .metadata()
        .map_err(|source| io_error("reading staged metadata for", &partial_path, source))?
        .len();
    if actual_len != geometry.artifact_bytes {
        return Err(DemandBlake3TreeError::Invalid(
            "constructed artifact length is inconsistent",
        ));
    }

    let staged = AuthenticatedDemandBlake3Tree::open(&partial_path, &identity)?;
    ensure_path_names_file(&partial_path, staging.file_ref())?;
    let mut published =
        publish_verified_no_overwrite(&partial_path, &final_path, staging.file_ref())?;
    let tree = AuthenticatedDemandBlake3Tree::open(&final_path, &identity)?;
    sync_parent(&parent)?;
    remove_owned_file(&partial_path, staging.file_ref())?;
    sync_parent(&parent)?;
    staging.disarm();
    published.disarm();
    drop(staged);
    Ok(tree)
}

fn validate_source_height(
    source: &dyn Blake3DigestSource,
    expected: usize,
) -> Result<(), DemandBlake3TreeError> {
    if source.height() != expected {
        return Err(DemandBlake3TreeError::Invalid(
            "source height changed during construction",
        ));
    }
    Ok(())
}

fn hash_canonical_row(row: &[u64; WHIR_EXTENSION_LIMBS_PER_ROW]) -> Blake3MerkleDigest {
    let mut hasher = Hasher::new();
    for value in row {
        hasher.update(&value.to_le_bytes());
    }
    *hasher.finalize().as_bytes()
}

fn compress(children: [Blake3MerkleDigest; 2]) -> Blake3MerkleDigest {
    let mut hasher = Hasher::new();
    hasher.update(&children[0]);
    hasher.update(&children[1]);
    *hasher.finalize().as_bytes()
}

fn encode_header(
    identity: &DemandBlake3TreeIdentity,
    geometry: DemandBlake3TreeGeometry,
) -> [u8; HEADER_BYTES] {
    let mut header = [0_u8; HEADER_BYTES];
    header[0..8].copy_from_slice(MAGIC);
    header[8..12].copy_from_slice(&VERSION.to_le_bytes());
    header[12..16].copy_from_slice(&(HEADER_BYTES as u32).to_le_bytes());
    header[16..48].copy_from_slice(&identity.store_id);
    header[48..80].copy_from_slice(&identity.source_binding);
    header[80..88].copy_from_slice(&identity.height.to_le_bytes());
    header[88..92].copy_from_slice(&MATRIX_COUNT.to_le_bytes());
    header[92..96].copy_from_slice(&geometry.layer_count.to_le_bytes());
    header[96..104].copy_from_slice(&geometry.total_digests.to_le_bytes());
    header[104..112].copy_from_slice(&geometry.tree_bytes.to_le_bytes());
    header[112..120].copy_from_slice(&identity.artifact_bytes.to_le_bytes());
    header[120..124].copy_from_slice(&identity.width.to_le_bytes());
    header[124..128].copy_from_slice(&CAP_HEIGHT.to_le_bytes());
    header[128..160].copy_from_slice(&identity.tree_root);
    let digest = header_digest(&header);
    header[HEADER_DIGEST_START..HEADER_DIGEST_END].copy_from_slice(&digest);
    header
}

fn header_digest(header: &[u8; HEADER_BYTES]) -> [u8; DIGEST_BYTES] {
    let mut canonical = *header;
    canonical[HEADER_DIGEST_START..HEADER_DIGEST_END].fill(0);
    let mut hasher = Hasher::new_derive_key(HEADER_DOMAIN);
    hasher.update(&canonical);
    *hasher.finalize().as_bytes()
}

fn decode_header(
    header: &[u8; HEADER_BYTES],
) -> Result<(DemandBlake3TreeIdentity, DemandBlake3TreeGeometry), DemandBlake3TreeError> {
    if &header[0..8] != MAGIC
        || read_u32(header, 8) != VERSION
        || read_u32(header, 12) != HEADER_BYTES as u32
        || read_u32(header, 88) != MATRIX_COUNT
        || read_u32(header, 120) != WIDTH
        || read_u32(header, 124) != CAP_HEIGHT
        || header[192..].iter().any(|byte| *byte != 0)
    {
        return Err(DemandBlake3TreeError::Invalid(
            "header suite, shape, or reserved bytes are not canonical",
        ));
    }
    let stored_header_digest: [u8; 32] = header[HEADER_DIGEST_START..HEADER_DIGEST_END]
        .try_into()
        .expect("fixed header digest slice");
    if stored_header_digest != header_digest(header) {
        return Err(DemandBlake3TreeError::HeaderDigestMismatch);
    }
    let store_id: [u8; 32] = header[16..48].try_into().expect("fixed store-ID slice");
    if store_id == [0; 32] {
        return Err(DemandBlake3TreeError::Invalid(
            "store identity must be nonzero",
        ));
    }
    let height = read_u64(header, 80);
    let geometry = demand_blake3_tree_geometry(height)?;
    if read_u32(header, 92) != geometry.layer_count
        || read_u64(header, 96) != geometry.total_digests
        || read_u64(header, 104) != geometry.tree_bytes
        || read_u64(header, 112) != geometry.artifact_bytes
    {
        return Err(DemandBlake3TreeError::Invalid(
            "header geometry is inconsistent",
        ));
    }
    let identity = DemandBlake3TreeIdentity {
        store_id,
        source_binding: header[48..80]
            .try_into()
            .expect("fixed source-binding slice"),
        height,
        width: WIDTH,
        tree_root: header[128..160].try_into().expect("fixed root slice"),
        artifact_bytes: geometry.artifact_bytes,
    };
    Ok((identity, geometry))
}

fn read_and_verify_envelope<R: Read + Seek>(
    reader: &mut R,
    file_len: u64,
    expected: &DemandBlake3TreeIdentity,
) -> Result<([u8; HEADER_BYTES], DemandBlake3TreeGeometry), DemandBlake3TreeError> {
    let mut header = [0_u8; HEADER_BYTES];
    reader
        .seek(SeekFrom::Start(0))
        .and_then(|_| reader.read_exact(&mut header))
        .map_err(|_| DemandBlake3TreeError::Invalid("could not read fixed header"))?;
    let (actual, geometry) = decode_header(&header)?;
    if &actual != expected {
        return Err(DemandBlake3TreeError::IdentityMismatch);
    }
    if file_len != geometry.artifact_bytes || file_len != expected.artifact_bytes {
        return Err(DemandBlake3TreeError::Invalid(
            "artifact length does not match exact identity",
        ));
    }
    let mut stored_root = [0_u8; DIGEST_BYTES];
    let root_offset = geometry
        .artifact_bytes
        .checked_sub(DIGEST_BYTES as u64)
        .ok_or(DemandBlake3TreeError::Invalid("root offset underflow"))?;
    reader
        .seek(SeekFrom::Start(root_offset))
        .and_then(|_| reader.read_exact(&mut stored_root))
        .map_err(|_| DemandBlake3TreeError::Invalid("could not read stored root"))?;
    if stored_root != expected.tree_root {
        return Err(DemandBlake3TreeError::RootMismatch);
    }
    Ok((header, geometry))
}

fn read_root(
    file: &mut File,
    path: &Path,
    geometry: DemandBlake3TreeGeometry,
) -> Result<Blake3MerkleDigest, DemandBlake3TreeError> {
    let offset = geometry
        .artifact_bytes
        .checked_sub(DIGEST_BYTES as u64)
        .ok_or(DemandBlake3TreeError::Invalid("root offset underflow"))?;
    let mut root = [0_u8; DIGEST_BYTES];
    file.seek(SeekFrom::Start(offset))
        .and_then(|_| file.read_exact(&mut root))
        .map_err(|source| io_error("reading constructed root from", path, source))?;
    Ok(root)
}

fn read_digest(
    file: &mut File,
    path: &Path,
    geometry: DemandBlake3TreeGeometry,
    global_index: u64,
) -> Result<Blake3MerkleDigest, DemandBlake3TreeError> {
    if global_index >= geometry.total_digests {
        return Err(DemandBlake3TreeError::Invalid(
            "digest index is out of bounds",
        ));
    }
    let offset = (HEADER_BYTES as u64)
        .checked_add(
            global_index
                .checked_mul(DIGEST_BYTES as u64)
                .ok_or(DemandBlake3TreeError::Invalid("digest offset overflow"))?,
        )
        .ok_or(DemandBlake3TreeError::Invalid("digest offset overflow"))?;
    let mut digest = [0_u8; DIGEST_BYTES];
    file.seek(SeekFrom::Start(offset))
        .and_then(|_| file.read_exact(&mut digest))
        .map_err(|source| io_error("reading sibling from", path, source))?;
    Ok(digest)
}

fn write_digest_batch(
    file: &mut File,
    path: &Path,
    digests: &[Blake3MerkleDigest],
) -> Result<(), DemandBlake3TreeError> {
    if digests.len() > 2 * PARENT_BATCH {
        return Err(DemandBlake3TreeError::Invalid(
            "digest write exceeds bounded batch",
        ));
    }
    let byte_len = digests
        .len()
        .checked_mul(DIGEST_BYTES)
        .ok_or(DemandBlake3TreeError::Invalid("digest batch overflow"))?;
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(byte_len)
        .map_err(|_| DemandBlake3TreeError::Invalid("digest batch allocation failed"))?;
    for digest in digests {
        encoded.extend_from_slice(digest);
    }
    file.write_all(&encoded)
        .map_err(|source| io_error("writing digest batch to", path, source))
}

fn read_digest_batch(
    file: &mut File,
    path: &Path,
    count: usize,
) -> Result<Vec<Blake3MerkleDigest>, DemandBlake3TreeError> {
    if count == 0 || count > 2 * PARENT_BATCH {
        return Err(DemandBlake3TreeError::Invalid(
            "digest read exceeds bounded batch",
        ));
    }
    let byte_len = count
        .checked_mul(DIGEST_BYTES)
        .ok_or(DemandBlake3TreeError::Invalid("digest batch overflow"))?;
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(byte_len)
        .map_err(|_| DemandBlake3TreeError::Invalid("digest batch allocation failed"))?;
    encoded.resize(byte_len, 0);
    file.read_exact(&mut encoded)
        .map_err(|source| io_error("reading digest batch from", path, source))?;
    Ok(encoded
        .chunks_exact(DIGEST_BYTES)
        .map(|bytes| bytes.try_into().expect("complete digest"))
        .collect())
}

const fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

const fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

fn artifact_parent(path: &Path) -> Result<PathBuf, DemandBlake3TreeError> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(DemandBlake3TreeError::InvalidOutputPath(path.to_path_buf()));
    }
    let parent = path
        .parent()
        .ok_or_else(|| DemandBlake3TreeError::InvalidOutputPath(path.to_path_buf()))?
        .to_path_buf();
    if !parent.is_dir() {
        return Err(DemandBlake3TreeError::InvalidOutputPath(parent));
    }
    Ok(parent)
}

/// Durably order a directory-entry change after the already-synchronized file.
///
/// Unix exposes directory `fsync` through an ordinary read-only directory
/// handle. Windows requires `FILE_FLAG_BACKUP_SEMANTICS`; filesystems that do
/// not implement `FlushFileBuffers` for such a handle fail with the explicit
/// `ParentDirectorySyncUnsupported` boundary instead of silently weakening
/// publication durability.
fn sync_parent_directory(parent: &Path) -> Result<(), DemandBlake3TreeError> {
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
    return Err(DemandBlake3TreeError::ParentDirectorySyncUnsupported {
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

fn map_parent_sync_error(parent: &Path, source: io::Error) -> DemandBlake3TreeError {
    #[cfg(windows)]
    if source.kind() == io::ErrorKind::Unsupported
        || matches!(source.raw_os_error(), Some(1 | 5 | 50))
    {
        return DemandBlake3TreeError::ParentDirectorySyncUnsupported {
            path: parent.to_path_buf(),
            source,
        };
    }

    DemandBlake3TreeError::Io {
        operation: "synchronizing parent directory",
        path: parent.to_path_buf(),
        source,
    }
}

fn create_unique_staging(final_path: &Path) -> Result<(PathBuf, File), DemandBlake3TreeError> {
    let parent = artifact_parent(final_path)?;
    let file_name = final_path
        .file_name()
        .ok_or_else(|| DemandBlake3TreeError::InvalidOutputPath(final_path.to_path_buf()))?;
    for _ in 0..CREATE_ATTEMPTS {
        let sequence = NEXT_STAGING_FILE.fetch_add(1, Ordering::Relaxed);
        let mut staging_name = file_name.to_os_string();
        staging_name.push(format!(".{}.{sequence}.partial", std::process::id()));
        let partial_path = parent.join(staging_name);
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&partial_path)
        {
            Ok(file) => return Ok((partial_path, file)),
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(source) => return Err(io_error("creating", &partial_path, source)),
        }
    }
    Err(DemandBlake3TreeError::NameExhausted(parent))
}

fn publish_verified_no_overwrite(
    partial_path: &Path,
    final_path: &Path,
    file: &File,
) -> Result<OwnedFileLink, DemandBlake3TreeError> {
    let cleanup_file = file
        .try_clone()
        .map_err(|source| io_error("cloning publication handle for", final_path, source))?;
    match fs::hard_link(partial_path, final_path) {
        Ok(()) => {}
        Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
            return Err(DemandBlake3TreeError::AlreadyExists(
                final_path.to_path_buf(),
            ));
        }
        Err(source) => return Err(io_error("publishing", final_path, source)),
    }
    let published = OwnedFileLink::new(final_path.to_path_buf(), cleanup_file);
    ensure_path_names_file(final_path, published.file_ref())?;
    Ok(published)
}

fn remove_owned_file(path: &Path, file: &File) -> Result<(), DemandBlake3TreeError> {
    ensure_path_names_file(path, file)?;
    fs::remove_file(path).map_err(|source| io_error("removing", path, source))
}

fn ensure_path_names_file(path: &Path, file: &File) -> Result<(), DemandBlake3TreeError> {
    let owned_handle = Handle::from_file(
        file.try_clone()
            .map_err(|source| io_error("cloning cleanup handle for", path, source))?,
    )
    .map_err(|source| io_error("identifying owned file at", path, source))?;
    let path_handle = Handle::from_path(path)
        .map_err(|source| io_error("identifying cleanup path", path, source))?;
    if owned_handle != path_handle {
        return Err(DemandBlake3TreeError::CleanupTargetChanged(
            path.to_path_buf(),
        ));
    }
    Ok(())
}

fn io_error(operation: &'static str, path: &Path, source: io::Error) -> DemandBlake3TreeError {
    DemandBlake3TreeError::Io {
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
    use std::io::{Cursor, ErrorKind};
    use std::sync::atomic::AtomicUsize;

    use p3_blake3::Blake3;
    use p3_commit::{ExtensionMmcs, Mmcs};
    use p3_field::BasedVectorSpace;
    use p3_field::extension::CubicTrinomialExtensionField;
    use p3_goldilocks::Goldilocks;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_merkle_tree::MerkleTreeMmcs;
    use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};

    use super::*;
    use crate::blake3_merkle_store::Blake3MerkleStoreError;
    use crate::whir_extension::encode_whir_extension_codeword;
    use crate::whir_residual::{
        WHIR_RESIDUAL_LIMBS_PER_ROW, WhirResidualArtifactSpec, WhirResidualArtifactWriter,
    };

    type TestEF = CubicTrinomialExtensionField<Goldilocks>;
    type FieldHash = SerializingHasher<Blake3>;
    type Compress = CompressionFunctionFromHasher<Blake3, 2, 32>;
    type WhirMmcs = MerkleTreeMmcs<Goldilocks, u8, FieldHash, Compress, 2, 32>;

    fn test_directory(label: &str) -> PathBuf {
        let sequence = NEXT_STAGING_FILE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "cmfd-demand-tree-test-{label}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    fn row(row: usize) -> [u64; WHIR_EXTENSION_LIMBS_PER_ROW] {
        core::array::from_fn(|column| {
            ((row as u64 + 1)
                .wrapping_mul(0x9e37_79b9)
                .wrapping_add((column as u64 + 3) * 0x1_0000_01b3)
                .wrapping_add(29))
                % GOLDILOCKS_MODULUS
        })
    }

    #[derive(Clone)]
    struct DenseRows {
        rows: Vec<[u64; WHIR_EXTENSION_LIMBS_PER_ROW]>,
    }

    impl DenseRows {
        fn new(height: usize) -> Self {
            Self {
                rows: (0..height).map(row).collect(),
            }
        }
    }

    impl Blake3DigestSource for DenseRows {
        fn height(&self) -> usize {
            self.rows.len()
        }

        fn read_digests(
            &self,
            row_start: usize,
            row_count: usize,
        ) -> Result<Vec<Blake3MerkleDigest>, Blake3MerkleStoreError> {
            let row_end = row_start
                .checked_add(row_count)
                .ok_or(Blake3MerkleStoreError::Invalid("test source range"))?;
            self.rows
                .get(row_start..row_end)
                .map(|rows| rows.iter().map(hash_canonical_row).collect())
                .ok_or(Blake3MerkleStoreError::Invalid("test source range"))
        }
    }

    struct CountingSource {
        height: usize,
        reads: AtomicUsize,
        fail_at: Option<usize>,
    }

    impl Blake3DigestSource for CountingSource {
        fn height(&self) -> usize {
            self.height
        }

        fn read_digests(
            &self,
            row_start: usize,
            row_count: usize,
        ) -> Result<Vec<Blake3MerkleDigest>, Blake3MerkleStoreError> {
            let call = self.reads.fetch_add(1, Ordering::Relaxed);
            if self.fail_at == Some(call) {
                return Err(Blake3MerkleStoreError::Source(
                    "injected leaf failure".to_owned(),
                ));
            }
            Ok((row_start..row_start + row_count)
                .map(|index| *blake3::hash(&(index as u64).to_le_bytes()).as_bytes())
                .collect())
        }
    }

    fn extension_values(rows: &DenseRows) -> Vec<TestEF> {
        rows.rows
            .iter()
            .flat_map(|row| {
                row.chunks_exact(3).map(|limbs| {
                    TestEF::from_basis_coefficients_fn(|index| Goldilocks::new(limbs[index]))
                })
            })
            .collect()
    }

    fn build_dense(
        directory: &Path,
        label: &str,
        source: &DenseRows,
    ) -> AuthenticatedDemandBlake3Tree {
        build_demand_blake3_tree(directory.join(label), [0x31; 32], [0x72; 32], source).unwrap()
    }

    fn mutate_byte(path: &Path, offset: u64) {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        file.seek(SeekFrom::Start(offset)).unwrap();
        let mut byte = [0_u8; 1];
        file.read_exact(&mut byte).unwrap();
        byte[0] ^= 0x80;
        file.seek(SeekFrom::Start(offset)).unwrap();
        file.write_all(&byte).unwrap();
        file.sync_all().unwrap();
    }

    #[test]
    fn production_geometry_is_exact_and_nonallocating() {
        let geometry = demand_blake3_tree_geometry(1 << 29).unwrap();
        assert_eq!(geometry.layer_count, 30);
        assert_eq!(geometry.total_digests, 1_073_741_823);
        assert_eq!(geometry.tree_bytes, 34_359_738_336);
        assert_eq!(geometry.artifact_bytes, 34_359_738_592);
        assert!(matches!(
            demand_blake3_tree_geometry(0),
            Err(DemandBlake3TreeError::Invalid(_))
        ));
        assert!(matches!(
            demand_blake3_tree_geometry(3),
            Err(DemandBlake3TreeError::Invalid(_))
        ));
        assert!(matches!(
            demand_blake3_tree_geometry((1 << 29) + 1),
            Err(DemandBlake3TreeError::Invalid(_))
        ));
    }

    #[test]
    fn parent_directory_sync_is_available_on_test_filesystem() {
        let directory = test_directory("directory-sync-probe");
        sync_parent_directory(&directory).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn publication_syncs_after_link_and_after_staging_unlink() {
        let directory = test_directory("directory-sync-order");
        let final_path = directory.join("tree");
        let source = DenseRows::new(8);
        let mut observations = Vec::new();
        let tree = build_demand_blake3_tree_with_sync(
            &final_path,
            [0x17; 32],
            [0x28; 32],
            &source,
            |parent| {
                let partials = fs::read_dir(parent)
                    .unwrap()
                    .filter_map(Result::ok)
                    .filter(|entry| entry.file_name().to_string_lossy().ends_with(".partial"))
                    .count();
                observations.push((final_path.exists(), partials));
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(observations, [(true, 1), (true, 0)]);
        tree.remove().unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn unsupported_parent_sync_is_explicit_and_cleans_owned_links() {
        let directory = test_directory("directory-sync-error");
        let source = DenseRows::new(8);
        for fail_call in [1, 2] {
            let final_path = directory.join(format!("tree-{fail_call}"));
            let mut calls = 0;
            let result = build_demand_blake3_tree_with_sync(
                &final_path,
                [0x39; 32],
                [0x4a; 32],
                &source,
                |parent| {
                    calls += 1;
                    if calls == fail_call {
                        Err(DemandBlake3TreeError::ParentDirectorySyncUnsupported {
                            path: parent.to_path_buf(),
                            source: io::Error::new(ErrorKind::Unsupported, "injected"),
                        })
                    } else {
                        Ok(())
                    }
                },
            );
            assert!(matches!(
                result,
                Err(DemandBlake3TreeError::ParentDirectorySyncUnsupported { path, .. })
                    if path == directory
            ));
            assert_eq!(calls, fail_call);
            assert!(!final_path.exists());
            assert_eq!(fs::read_dir(&directory).unwrap().count(), 0);
        }
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn fixed_header_layout_and_digest_are_canonical() {
        let geometry = demand_blake3_tree_geometry(8).unwrap();
        let identity = DemandBlake3TreeIdentity {
            store_id: [0x11; 32],
            source_binding: [0x22; 32],
            height: 8,
            width: 12,
            tree_root: [0x33; 32],
            artifact_bytes: geometry.artifact_bytes,
        };
        let header = encode_header(&identity, geometry);
        assert_eq!(&header[0..8], b"CMFDB3P2");
        assert_eq!(read_u32(&header, 8), 2);
        assert_eq!(read_u32(&header, 12), 256);
        assert_eq!(&header[16..48], &[0x11; 32]);
        assert_eq!(&header[48..80], &[0x22; 32]);
        assert_eq!(read_u64(&header, 80), 8);
        assert_eq!(read_u32(&header, 88), 1);
        assert_eq!(read_u32(&header, 92), 4);
        assert_eq!(read_u64(&header, 96), 15);
        assert_eq!(read_u64(&header, 104), 480);
        assert_eq!(read_u64(&header, 112), 736);
        assert_eq!(read_u32(&header, 120), 12);
        assert_eq!(read_u32(&header, 124), 0);
        assert_eq!(&header[128..160], &[0x33; 32]);
        assert_eq!(header[160..192], header_digest(&header));
        assert_eq!(
            &header[160..192],
            &[
                0xad, 0x45, 0x36, 0x2d, 0xec, 0x90, 0x87, 0x35, 0xbd, 0xd6, 0x85, 0xd4, 0xcc, 0x8c,
                0x2a, 0x00, 0x9d, 0xe6, 0x63, 0x6f, 0x29, 0x97, 0xdd, 0x47, 0x69, 0x12, 0x2e, 0x39,
                0xfb, 0xbb, 0xc5, 0xdb,
            ]
        );
        assert!(header[192..].iter().all(|byte| *byte == 0));
        assert_eq!(decode_header(&header).unwrap(), (identity, geometry));
    }

    #[test]
    fn all_small_roots_and_paths_match_extension_mmcs() {
        for height in [1, 2, 4, 8, 16, 32, 64] {
            let directory = test_directory("p3-parity");
            let source = DenseRows::new(height);
            let tree = build_dense(&directory, "tree", &source).remove_on_drop();
            let base_mmcs = WhirMmcs::new(FieldHash::new(Blake3), Compress::new(Blake3), 0);
            let extension_mmcs = ExtensionMmcs::<Goldilocks, TestEF, _>::new(base_mmcs);
            let (commitment, prover_data) =
                extension_mmcs.commit(vec![RowMajorMatrix::new(extension_values(&source), 4)]);
            assert_eq!(tree.identity().tree_root, commitment.roots()[0]);
            for index in 0..height {
                let opening = tree
                    .authenticate_leaf(index, hash_canonical_row(&source.rows[index]))
                    .unwrap();
                let expected = extension_mmcs.open_batch(index, &prover_data);
                assert_eq!(opening, expected.opening_proof);
            }
            drop(tree);
            assert_eq!(fs::read_dir(&directory).unwrap().count(), 0);
            fs::remove_dir(directory).unwrap();
        }
    }

    struct SparseEnvelope {
        header: [u8; HEADER_BYTES],
        root: Blake3MerkleDigest,
        root_offset: u64,
        position: u64,
        reads: usize,
        bytes: usize,
    }

    impl Read for SparseEnvelope {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let source = if self.position == 0 {
                &self.header[..]
            } else if self.position == self.root_offset {
                &self.root[..]
            } else {
                return Err(io::Error::new(ErrorKind::UnexpectedEof, "sparse gap"));
            };
            let count = buffer.len().min(source.len());
            buffer[..count].copy_from_slice(&source[..count]);
            self.position += count as u64;
            self.reads += 1;
            self.bytes += count;
            Ok(count)
        }
    }

    impl Seek for SparseEnvelope {
        fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
            let SeekFrom::Start(position) = position else {
                return Err(io::Error::new(ErrorKind::Unsupported, "start only"));
            };
            self.position = position;
            Ok(position)
        }
    }

    #[test]
    fn production_envelope_open_reads_only_header_and_root() {
        let geometry = demand_blake3_tree_geometry(1 << 29).unwrap();
        let identity = DemandBlake3TreeIdentity {
            store_id: [0x44; 32],
            source_binding: [0x55; 32],
            height: 1 << 29,
            width: 12,
            tree_root: [0x66; 32],
            artifact_bytes: geometry.artifact_bytes,
        };
        let header = encode_header(&identity, geometry);
        let mut sparse = SparseEnvelope {
            header,
            root: identity.tree_root,
            root_offset: geometry.artifact_bytes - 32,
            position: 0,
            reads: 0,
            bytes: 0,
        };
        let (actual_header, actual_geometry) =
            read_and_verify_envelope(&mut sparse, geometry.artifact_bytes, &identity).unwrap();
        assert_eq!(actual_header, header);
        assert_eq!(actual_geometry, geometry);
        assert_eq!(sparse.reads, 2);
        assert_eq!(sparse.bytes, HEADER_BYTES + DIGEST_BYTES);
    }

    #[test]
    fn exact_identity_header_root_and_length_fail_closed() {
        let directory = test_directory("envelope-failures");

        let source = DenseRows::new(8);
        let tree = build_dense(&directory, "identity", &source);
        let identity = *tree.identity();
        let path = tree.path().to_path_buf();
        drop(tree);
        let mut wrong = identity;
        wrong.source_binding[0] ^= 1;
        assert!(matches!(
            AuthenticatedDemandBlake3Tree::open(&path, &wrong),
            Err(DemandBlake3TreeError::IdentityMismatch)
        ));
        fs::remove_file(path).unwrap();

        let tree = build_dense(&directory, "self-consistent-substitute", &source);
        let identity = *tree.identity();
        let geometry = tree.geometry();
        let path = tree.path().to_path_buf();
        drop(tree);
        let mut substitute = identity;
        substitute.source_binding[0] ^= 1;
        let substituted_header = encode_header(&substitute, geometry);
        let mut file = OpenOptions::new().write(true).open(&path).unwrap();
        file.write_all(&substituted_header).unwrap();
        file.sync_all().unwrap();
        drop(file);
        assert!(matches!(
            AuthenticatedDemandBlake3Tree::open(&path, &identity),
            Err(DemandBlake3TreeError::IdentityMismatch)
        ));
        fs::remove_file(path).unwrap();

        let tree = build_dense(&directory, "header", &source);
        let identity = *tree.identity();
        let path = tree.path().to_path_buf();
        drop(tree);
        mutate_byte(&path, 48);
        assert!(matches!(
            AuthenticatedDemandBlake3Tree::open(&path, &identity),
            Err(DemandBlake3TreeError::HeaderDigestMismatch)
        ));
        fs::remove_file(path).unwrap();

        let tree = build_dense(&directory, "root", &source);
        let identity = *tree.identity();
        let path = tree.path().to_path_buf();
        drop(tree);
        mutate_byte(&path, identity.artifact_bytes - 1);
        assert!(matches!(
            AuthenticatedDemandBlake3Tree::open(&path, &identity),
            Err(DemandBlake3TreeError::RootMismatch)
        ));
        fs::remove_file(path).unwrap();

        for (label, delta) in [("truncate", -1_i64), ("append", 1_i64)] {
            let tree = build_dense(&directory, label, &source);
            let identity = *tree.identity();
            let path = tree.path().to_path_buf();
            drop(tree);
            let file = OpenOptions::new().write(true).open(&path).unwrap();
            file.set_len((identity.artifact_bytes as i64 + delta) as u64)
                .unwrap();
            drop(file);
            assert!(matches!(
                AuthenticatedDemandBlake3Tree::open(&path, &identity),
                Err(DemandBlake3TreeError::Invalid(_))
            ));
            fs::remove_file(path).unwrap();
        }
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn sibling_corruption_and_source_substitution_return_no_path() {
        let directory = test_directory("opening-failures");
        let source = DenseRows::new(8);
        let substituted = DenseRows::new(8);
        let tree = build_dense(&directory, "substitution", &source).remove_on_drop();
        let mut wrong_row = substituted.rows[3];
        wrong_row[0] ^= 1;
        assert!(matches!(
            tree.authenticate_leaf(3, hash_canonical_row(&wrong_row)),
            Err(DemandBlake3TreeError::OpeningMismatch)
        ));

        let sibling_offset = HEADER_BYTES as u64 + ((3 ^ 1) * DIGEST_BYTES) as u64;
        mutate_byte(tree.path(), sibling_offset);
        assert!(matches!(
            tree.authenticate_leaf(3, hash_canonical_row(&source.rows[3])),
            Err(DemandBlake3TreeError::OpeningMismatch)
        ));
        drop(tree);
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 0);
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn post_open_envelope_mutation_returns_no_path() {
        let directory = test_directory("live-envelope-mutation");
        let source = DenseRows::new(8);
        let tree = build_dense(&directory, "tree", &source).remove_on_drop();
        mutate_byte(tree.path(), 48);
        assert!(matches!(
            tree.authenticate_leaf(0, hash_canonical_row(&source.rows[0])),
            Err(DemandBlake3TreeError::HeaderDigestMismatch)
        ));
        drop(tree);
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 0);
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn no_overwrite_and_failed_build_leave_no_staging_files() {
        let directory = test_directory("construction-cleanup");
        let conflict = directory.join("conflict");
        fs::write(&conflict, b"sentinel").unwrap();
        let source = CountingSource {
            height: 8,
            reads: AtomicUsize::new(0),
            fail_at: None,
        };
        assert!(matches!(
            build_demand_blake3_tree(&conflict, [1; 32], [2; 32], &source),
            Err(DemandBlake3TreeError::AlreadyExists(path)) if path == conflict
        ));
        assert_eq!(source.reads.load(Ordering::Relaxed), 0);
        assert_eq!(fs::read(&conflict).unwrap(), b"sentinel");
        assert!(matches!(
            build_demand_blake3_tree(Path::new("relative-demand-tree"), [1; 32], [2; 32], &source),
            Err(DemandBlake3TreeError::InvalidOutputPath(_))
        ));
        assert_eq!(source.reads.load(Ordering::Relaxed), 0);

        let failing = CountingSource {
            height: 1 << 14,
            reads: AtomicUsize::new(0),
            fail_at: Some(1),
        };
        let target = directory.join("failed-tree");
        assert!(matches!(
            build_demand_blake3_tree(&target, [3; 32], [4; 32], &failing),
            Err(DemandBlake3TreeError::Source(_))
        ));
        assert!(!target.exists());
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 1);
        fs::remove_file(conflict).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn cleanup_refuses_to_unlink_a_replacement() {
        let directory = test_directory("same-file-cleanup");
        let source = DenseRows::new(8);
        let tree = build_dense(&directory, "tree", &source).remove_on_drop();
        let path = tree.path().to_path_buf();
        let moved = directory.join("moved-tree");
        fs::rename(&path, &moved).unwrap();
        fs::write(&path, b"replacement").unwrap();
        assert!(matches!(
            tree.remove(),
            Err(DemandBlake3TreeError::CleanupTargetChanged(changed)) if changed == path
        ));
        assert_eq!(fs::read(&path).unwrap(), b"replacement");
        fs::remove_file(path).unwrap();
        fs::remove_file(moved).unwrap();
        fs::remove_dir(directory).unwrap();
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

    fn build_codeword(directory: &Path, codeword_id: u8) -> AuthenticatedWhirExtensionCodeword {
        let spec = WhirResidualArtifactSpec {
            source_digest: [0x91; 32],
            context_digest: [0xa2; 32],
            num_variables: 4,
            generation: 3,
        };
        let mut writer = WhirResidualArtifactWriter::create(directory, spec).unwrap();
        let rows = (0..16).map(residual_row).collect::<Vec<_>>();
        writer.write_rows(0, &rows).unwrap();
        let residual = writer.finish().unwrap();
        let codeword = encode_whir_extension_codeword(
            directory,
            [codeword_id; 32],
            residual.identity(),
            &residual,
            1,
        )
        .unwrap();
        drop(residual);
        codeword
    }

    #[test]
    fn extension_oracle_enforces_binding_and_returns_authenticated_rows() {
        let directory = test_directory("extension-oracle");
        let codeword = build_codeword(&directory, 0xb3);
        let expected_rows = codeword.read_canonical_rows(0, 8).unwrap();
        let source_binding = codeword.identity().binding_digest().unwrap();
        let tree =
            build_whir_extension_demand_blake3_tree(directory.join("tree"), [0xc4; 32], &codeword)
                .unwrap();
        assert_eq!(tree.identity().source_binding, source_binding);
        let oracle = WhirExtensionOracle::new(codeword, tree).unwrap();
        for index in 0..8 {
            let opening = oracle.authenticated_opening(index).unwrap();
            assert_eq!(
                opening.row().as_slice(),
                &expected_rows[index * WHIR_EXTENSION_LIMBS_PER_ROW
                    ..(index + 1) * WHIR_EXTENSION_LIMBS_PER_ROW]
            );
            assert_eq!(opening.authentication_path().len(), 3);
        }
        oracle.remove().unwrap();

        let codeword = build_codeword(&directory, 0xd5);
        let wrong_tree = build_demand_blake3_tree(
            directory.join("wrong-tree"),
            [0xe6; 32],
            [0xff; 32],
            &codeword,
        )
        .unwrap()
        .remove_on_drop();
        assert!(matches!(
            WhirExtensionOracle::new(codeword, wrong_tree),
            Err(DemandBlake3TreeError::IdentityMismatch)
        ));
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 0);
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn codeword_binding_changes_or_rejects_every_identity_dimension() {
        let directory = test_directory("binding");
        let codeword = build_codeword(&directory, 0x47);
        let identity = codeword.identity().clone();
        let binding = identity.binding_digest().unwrap();
        assert_eq!(
            binding,
            [
                0xad, 0xae, 0xb1, 0x8d, 0xfa, 0x75, 0xdb, 0x4e, 0x06, 0xf9, 0x0e, 0x0a, 0xfd, 0x85,
                0x16, 0x15, 0xc3, 0x27, 0x77, 0x4a, 0x96, 0xf2, 0xad, 0xa1, 0xe0, 0x73, 0x53, 0x75,
                0x75, 0xc3, 0x8d, 0xce,
            ]
        );

        for mutate in [
            |value: &mut WhirExtensionCodewordIdentity| value.codeword_id[0] ^= 1,
            |value: &mut WhirExtensionCodewordIdentity| value.residual.spec.source_digest[0] ^= 1,
            |value: &mut WhirExtensionCodewordIdentity| value.residual.spec.context_digest[0] ^= 1,
            |value: &mut WhirExtensionCodewordIdentity| value.residual.spec.generation ^= 1,
            |value: &mut WhirExtensionCodewordIdentity| value.residual.artifact_digest[0] ^= 1,
            |value: &mut WhirExtensionCodewordIdentity| value.artifact_digest[0] ^= 1,
        ] {
            let mut changed = identity.clone();
            mutate(&mut changed);
            assert_ne!(changed.binding_digest().unwrap(), binding);
        }

        let mut changed_rate = identity.clone();
        changed_rate.log_inv_rate += 1;
        changed_rate.height *= 2;
        assert_ne!(changed_rate.binding_digest().unwrap(), binding);
        for invalid in [
            |value: &mut WhirExtensionCodewordIdentity| value.folding ^= 1,
            |value: &mut WhirExtensionCodewordIdentity| value.width += 1,
            |value: &mut WhirExtensionCodewordIdentity| value.height += 1,
            |value: &mut WhirExtensionCodewordIdentity| value.residual.row_count -= 1,
        ] {
            let mut changed = identity.clone();
            invalid(&mut changed);
            assert!(changed.binding_digest().is_err());
        }
        drop(codeword);
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 0);
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn malformed_headers_do_not_decode() {
        let geometry = demand_blake3_tree_geometry(2).unwrap();
        let identity = DemandBlake3TreeIdentity {
            store_id: [1; 32],
            source_binding: [2; 32],
            height: 2,
            width: 12,
            tree_root: [3; 32],
            artifact_bytes: geometry.artifact_bytes,
        };
        let header = encode_header(&identity, geometry);
        for offset in [0, 8, 12, 88, 92, 96, 104, 112, 120, 124, 192, 255] {
            let mut malformed = header;
            malformed[offset] ^= 1;
            if (160..192).contains(&offset) {
                continue;
            }
            assert!(decode_header(&malformed).is_err(), "offset {offset}");
        }

        let mut cursor = Cursor::new(header);
        let mut wrong_length = identity;
        wrong_length.artifact_bytes += 1;
        assert!(matches!(
            read_and_verify_envelope(&mut cursor, geometry.artifact_bytes, &wrong_length),
            Err(DemandBlake3TreeError::IdentityMismatch)
        ));
    }
}
