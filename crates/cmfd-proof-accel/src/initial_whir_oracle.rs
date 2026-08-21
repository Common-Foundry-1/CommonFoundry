//! Identity-bound access to one initial WHIR codeword and its BLAKE3 tree.
//!
//! [`InitialWhirOracle`] is a prover-side capability, not a transcript or a
//! commitment scheme. It admits only the pinned natural-row Suffix geometry:
//! folding two, starting log inverse rate one, row width four, and one Merkle
//! matrix partition `[4]`. Its fixed-width identity binds a nonzero caller
//! context to the exact identities of both disk artifacts and to the expected
//! tree root. The caller context is intended to be derived from the model PCS
//! identity, table role, and proof-suite identity by a higher layer.
//!
//! Reopening authenticates both complete artifacts. Each opening then
//! reauthenticates the codeword row and every tree chunk it reads before
//! recomputing the path to the pinned root. No transcript state or challenge
//! derivation is implemented here.

use std::path::Path;

use blake3::Hasher;
use thiserror::Error;

use crate::blake3_merkle_store::{
    AuthenticatedBlake3MerkleStore, Blake3MerkleDigest, Blake3MerkleStoreError,
    Blake3MerkleStoreIdentity,
};
use crate::whir_initial::{
    AuthenticatedWhirInitialCodeword, WHIR_INITIAL_MAX_VARIABLES, WHIR_INITIAL_MIN_VARIABLES,
    WHIR_INITIAL_WIDTH, WhirInitialCodewordIdentity, WhirInitialEncodingError,
    WhirInitialSourceIdentity,
};
use crate::whir_initial_source::{
    AuthenticatedWhirInitialSourceFile, WhirInitialSourceArtifactError,
    WhirInitialSourceArtifactIdentity,
};

/// Canonical byte length of [`InitialWhirOracleIdentity`].
pub const INITIAL_WHIR_ORACLE_IDENTITY_BYTES: usize = 296;

/// Canonical byte length of [`InitialWhirProverIdentity`].
pub const INITIAL_WHIR_PROVER_IDENTITY_BYTES: usize = 416;

/// Pinned initial-commitment folding factor.
pub const INITIAL_WHIR_FOLDING: u8 = 2;

/// Pinned initial-commitment starting log inverse rate.
pub const INITIAL_WHIR_STARTING_LOG_INV_RATE: u8 = 1;

/// Pinned ordered Merkle matrix partition.
pub const INITIAL_WHIR_TREE_PARTITION: [usize; 1] = [WHIR_INITIAL_WIDTH];

const MAGIC: &[u8; 8] = b"CMFDWIO1";
const NATURAL_SUFFIX_LAYOUT: u8 = 1;
const MATRIX_COUNT: u8 = 1;
const CONTEXT_OFFSET: usize = 8;
const NUM_VARIABLES_OFFSET: usize = 44;
const CODEWORD_HEIGHT_OFFSET: usize = 48;
const TREE_HEIGHT_OFFSET: usize = 56;
const CODEWORD_WIDTH_OFFSET: usize = 64;
const PARTITION_WIDTH_OFFSET: usize = 68;
const CODEWORD_ARTIFACT_ID_OFFSET: usize = 72;
const SOURCE_ID_OFFSET: usize = 104;
const CODEWORD_DIGEST_OFFSET: usize = 136;
const TREE_STORE_ID_OFFSET: usize = 168;
const TREE_ROOT_OFFSET: usize = 200;
const TREE_GLOBAL_DIGEST_OFFSET: usize = 232;
const BINDING_OFFSET: usize = 264;
const IDENTITY_DOMAIN: &str = "Common Foundry initial WHIR oracle identity v1";
const PROVER_MAGIC: &[u8; 8] = b"CMFDWIP1";
const PROVER_ORACLE_OFFSET: usize = 8;
const PROVER_SOURCE_ID_OFFSET: usize = 304;
const PROVER_NUM_VARIABLES_OFFSET: usize = 336;
const PROVER_LAYOUT_OFFSET: usize = 340;
const PROVER_ENCODING_OFFSET: usize = 341;
const PROVER_ELEMENT_COUNT_OFFSET: usize = 344;
const PROVER_SOURCE_DIGEST_OFFSET: usize = 352;
const PROVER_BINDING_OFFSET: usize = 384;
const PROVER_NATURAL_MLE_LAYOUT: u8 = 1;
const PROVER_CANONICAL_U64_LE_ENCODING: u8 = 1;
const PROVER_IDENTITY_DOMAIN: &str = "Common Foundry initial WHIR prover identity v1";

/// One externally retained, canonical identity for an initial WHIR oracle.
///
/// The encoding is fixed at [`INITIAL_WHIR_ORACLE_IDENTITY_BYTES`] and binds
/// the caller context, natural Suffix geometry, exact codeword identity, exact
/// one-matrix Merkle-store identity, and pinned tree root. It deliberately
/// contains no variable-length matrix metadata.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct InitialWhirOracleIdentity {
    encoded: [u8; INITIAL_WHIR_ORACLE_IDENTITY_BYTES],
}

impl std::fmt::Debug for InitialWhirOracleIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InitialWhirOracleIdentity")
            .field("binding_digest", &self.binding_digest())
            .field("context_digest", &self.context_digest())
            .field("codeword", &self.codeword_identity())
            .field("tree", &self.merkle_store_identity())
            .finish()
    }
}

impl InitialWhirOracleIdentity {
    /// Bind exact component identities to one caller-selected context and root.
    pub fn bind(
        context_digest: [u8; 32],
        codeword: &WhirInitialCodewordIdentity,
        tree: &Blake3MerkleStoreIdentity,
        expected_root: Blake3MerkleDigest,
    ) -> Result<Self, InitialWhirOracleError> {
        if context_digest == [0_u8; 32] {
            return Err(InitialWhirOracleError::InvalidIdentity(
                "caller context digest must be nonzero",
            ));
        }
        if tree.tree_root != expected_root {
            return Err(InitialWhirOracleError::PinnedRootMismatch);
        }
        if tree.ordered_matrix_widths.as_slice() != INITIAL_WHIR_TREE_PARTITION {
            return Err(InitialWhirOracleError::InvalidIdentity(
                "Merkle partition must be exactly [4]",
            ));
        }
        let tree_height = u64::try_from(tree.height).map_err(|_| {
            InitialWhirOracleError::InvalidIdentity("Merkle height does not fit u64")
        })?;
        let partition_width = u32::try_from(tree.ordered_matrix_widths[0]).map_err(|_| {
            InitialWhirOracleError::InvalidIdentity("Merkle width does not fit u32")
        })?;

        let mut encoded = [0_u8; INITIAL_WHIR_ORACLE_IDENTITY_BYTES];
        encoded[..8].copy_from_slice(MAGIC);
        encoded[CONTEXT_OFFSET..CONTEXT_OFFSET + 32].copy_from_slice(&context_digest);
        encoded[40] = NATURAL_SUFFIX_LAYOUT;
        encoded[41] = INITIAL_WHIR_FOLDING;
        encoded[42] = INITIAL_WHIR_STARTING_LOG_INV_RATE;
        encoded[43] = MATRIX_COUNT;
        put_u32(
            &mut encoded,
            NUM_VARIABLES_OFFSET,
            codeword.source.num_variables,
        );
        put_u64(&mut encoded, CODEWORD_HEIGHT_OFFSET, codeword.height);
        put_u64(&mut encoded, TREE_HEIGHT_OFFSET, tree_height);
        put_u32(&mut encoded, CODEWORD_WIDTH_OFFSET, codeword.width);
        put_u32(&mut encoded, PARTITION_WIDTH_OFFSET, partition_width);
        copy_digest(
            &mut encoded,
            CODEWORD_ARTIFACT_ID_OFFSET,
            codeword.artifact_id,
        );
        copy_digest(&mut encoded, SOURCE_ID_OFFSET, codeword.source.source_id);
        copy_digest(
            &mut encoded,
            CODEWORD_DIGEST_OFFSET,
            codeword.artifact_digest,
        );
        copy_digest(&mut encoded, TREE_STORE_ID_OFFSET, tree.store_id);
        copy_digest(&mut encoded, TREE_ROOT_OFFSET, expected_root);
        copy_digest(
            &mut encoded,
            TREE_GLOBAL_DIGEST_OFFSET,
            tree.artifact_global_digest,
        );
        let binding = identity_binding(&encoded);
        copy_digest(&mut encoded, BINDING_OFFSET, binding);
        Self::from_bytes(encoded)
    }

    /// Decode and validate a canonical fixed-width identity.
    pub fn from_bytes(
        encoded: [u8; INITIAL_WHIR_ORACLE_IDENTITY_BYTES],
    ) -> Result<Self, InitialWhirOracleError> {
        let identity = Self { encoded };
        identity.validate()?;
        Ok(identity)
    }

    /// Return the canonical fixed-width encoding.
    pub const fn as_bytes(&self) -> &[u8; INITIAL_WHIR_ORACLE_IDENTITY_BYTES] {
        &self.encoded
    }

    /// Copy out the canonical fixed-width encoding.
    pub const fn to_bytes(self) -> [u8; INITIAL_WHIR_ORACLE_IDENTITY_BYTES] {
        self.encoded
    }

    pub fn binding_digest(&self) -> [u8; 32] {
        read_digest(&self.encoded, BINDING_OFFSET)
    }

    pub fn context_digest(&self) -> [u8; 32] {
        read_digest(&self.encoded, CONTEXT_OFFSET)
    }

    pub fn pinned_root(&self) -> Blake3MerkleDigest {
        read_digest(&self.encoded, TREE_ROOT_OFFSET)
    }

    pub fn codeword_identity(&self) -> WhirInitialCodewordIdentity {
        WhirInitialCodewordIdentity {
            artifact_id: read_digest(&self.encoded, CODEWORD_ARTIFACT_ID_OFFSET),
            source: WhirInitialSourceIdentity {
                source_id: read_digest(&self.encoded, SOURCE_ID_OFFSET),
                num_variables: read_u32(&self.encoded, NUM_VARIABLES_OFFSET),
            },
            height: read_u64(&self.encoded, CODEWORD_HEIGHT_OFFSET),
            width: read_u32(&self.encoded, CODEWORD_WIDTH_OFFSET),
            artifact_digest: read_digest(&self.encoded, CODEWORD_DIGEST_OFFSET),
        }
    }

    pub fn merkle_store_identity(&self) -> Blake3MerkleStoreIdentity {
        Blake3MerkleStoreIdentity {
            store_id: read_digest(&self.encoded, TREE_STORE_ID_OFFSET),
            height: usize::try_from(read_u64(&self.encoded, TREE_HEIGHT_OFFSET))
                .expect("validated WHIR Merkle height"),
            ordered_matrix_widths: vec![
                usize::try_from(read_u32(&self.encoded, PARTITION_WIDTH_OFFSET))
                    .expect("validated WHIR Merkle width"),
            ],
            tree_root: self.pinned_root(),
            artifact_global_digest: read_digest(&self.encoded, TREE_GLOBAL_DIGEST_OFFSET),
        }
    }

    fn require_context(&self, context_digest: [u8; 32]) -> Result<(), InitialWhirOracleError> {
        if context_digest == [0_u8; 32] || context_digest != self.context_digest() {
            return Err(InitialWhirOracleError::CallerContextMismatch);
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), InitialWhirOracleError> {
        if &self.encoded[..8] != MAGIC {
            return Err(InitialWhirOracleError::InvalidIdentity("wrong magic"));
        }
        if self.binding_digest() != identity_binding(&self.encoded) {
            return Err(InitialWhirOracleError::InvalidIdentity(
                "binding digest does not match",
            ));
        }
        if self.context_digest() == [0_u8; 32] {
            return Err(InitialWhirOracleError::InvalidIdentity(
                "caller context digest must be nonzero",
            ));
        }
        if self.encoded[40] != NATURAL_SUFFIX_LAYOUT
            || self.encoded[41] != INITIAL_WHIR_FOLDING
            || self.encoded[42] != INITIAL_WHIR_STARTING_LOG_INV_RATE
        {
            return Err(InitialWhirOracleError::InvalidIdentity(
                "only natural Suffix fold2/rate1 geometry is admitted",
            ));
        }
        if self.encoded[43] != MATRIX_COUNT
            || read_u32(&self.encoded, PARTITION_WIDTH_OFFSET)
                != u32::try_from(WHIR_INITIAL_WIDTH).expect("width four fits u32")
        {
            return Err(InitialWhirOracleError::InvalidIdentity(
                "Merkle partition must be exactly [4]",
            ));
        }
        let variables = usize::try_from(read_u32(&self.encoded, NUM_VARIABLES_OFFSET))
            .map_err(|_| InitialWhirOracleError::InvalidIdentity("variable count is invalid"))?;
        if !(WHIR_INITIAL_MIN_VARIABLES..=WHIR_INITIAL_MAX_VARIABLES).contains(&variables) {
            return Err(InitialWhirOracleError::InvalidIdentity(
                "variable count is outside the bounded WHIR range",
            ));
        }
        let height_exponent = variables
            .checked_add(usize::from(INITIAL_WHIR_STARTING_LOG_INV_RATE))
            .and_then(|value| value.checked_sub(usize::from(INITIAL_WHIR_FOLDING)))
            .ok_or(InitialWhirOracleError::InvalidIdentity(
                "WHIR height exponent underflow",
            ))?;
        let expected_height = 1_u64
            .checked_shl(u32::try_from(height_exponent).map_err(|_| {
                InitialWhirOracleError::InvalidIdentity("WHIR height exponent does not fit u32")
            })?)
            .ok_or(InitialWhirOracleError::InvalidIdentity(
                "WHIR height is not representable",
            ))?;
        if read_u64(&self.encoded, CODEWORD_HEIGHT_OFFSET) != expected_height
            || read_u64(&self.encoded, TREE_HEIGHT_OFFSET) != expected_height
            || read_u32(&self.encoded, CODEWORD_WIDTH_OFFSET)
                != u32::try_from(WHIR_INITIAL_WIDTH).expect("width four fits u32")
        {
            return Err(InitialWhirOracleError::InvalidIdentity(
                "component geometry does not match natural Suffix fold2/rate1",
            ));
        }
        if read_digest(&self.encoded, CODEWORD_ARTIFACT_ID_OFFSET) == [0_u8; 32]
            || read_digest(&self.encoded, SOURCE_ID_OFFSET) == [0_u8; 32]
            || read_digest(&self.encoded, TREE_STORE_ID_OFFSET) == [0_u8; 32]
        {
            return Err(InitialWhirOracleError::InvalidIdentity(
                "component IDs must be nonzero",
            ));
        }
        Ok(())
    }
}

/// Prover-only identity binding the exact original source artifact to one
/// already retained initial-codeword/tree oracle identity.
///
/// The existing `source_id` remains a caller-selected cross-artifact label.
/// `artifact_global_digest` is the cryptographic provenance check for the
/// original source file. This identity is not part of the proof transcript or
/// consensus wire format.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct InitialWhirProverIdentity {
    encoded: [u8; INITIAL_WHIR_PROVER_IDENTITY_BYTES],
}

impl std::fmt::Debug for InitialWhirProverIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InitialWhirProverIdentity")
            .field("binding_digest", &self.binding_digest())
            .field("oracle", &self.oracle_identity())
            .field("source_artifact", &self.source_artifact_identity())
            .finish()
    }
}

impl InitialWhirProverIdentity {
    /// Bind one exact authenticated source artifact to an exact oracle.
    pub fn bind(
        oracle: &InitialWhirOracleIdentity,
        source_artifact: &WhirInitialSourceArtifactIdentity,
    ) -> Result<Self, InitialWhirProverError> {
        validate_source_artifact_identity(source_artifact)?;
        if source_artifact.source != oracle.codeword_identity().source {
            return Err(InitialWhirProverError::SourceIdentityMismatch);
        }

        let mut encoded = [0_u8; INITIAL_WHIR_PROVER_IDENTITY_BYTES];
        encoded[..8].copy_from_slice(PROVER_MAGIC);
        encoded[PROVER_ORACLE_OFFSET..PROVER_ORACLE_OFFSET + INITIAL_WHIR_ORACLE_IDENTITY_BYTES]
            .copy_from_slice(oracle.as_bytes());
        encoded[PROVER_SOURCE_ID_OFFSET..PROVER_SOURCE_ID_OFFSET + 32]
            .copy_from_slice(&source_artifact.source.source_id);
        put_u32(
            &mut encoded,
            PROVER_NUM_VARIABLES_OFFSET,
            source_artifact.source.num_variables,
        );
        encoded[PROVER_LAYOUT_OFFSET] = PROVER_NATURAL_MLE_LAYOUT;
        encoded[PROVER_ENCODING_OFFSET] = PROVER_CANONICAL_U64_LE_ENCODING;
        put_u64(
            &mut encoded,
            PROVER_ELEMENT_COUNT_OFFSET,
            source_artifact.element_count,
        );
        encoded[PROVER_SOURCE_DIGEST_OFFSET..PROVER_SOURCE_DIGEST_OFFSET + 32]
            .copy_from_slice(&source_artifact.artifact_global_digest);
        let binding = prover_identity_binding(&encoded);
        encoded[PROVER_BINDING_OFFSET..].copy_from_slice(&binding);
        Self::from_bytes(encoded)
    }

    /// Decode and validate a canonical fixed-width prover identity.
    pub fn from_bytes(
        encoded: [u8; INITIAL_WHIR_PROVER_IDENTITY_BYTES],
    ) -> Result<Self, InitialWhirProverError> {
        let identity = Self { encoded };
        identity.validate()?;
        Ok(identity)
    }

    pub const fn as_bytes(&self) -> &[u8; INITIAL_WHIR_PROVER_IDENTITY_BYTES] {
        &self.encoded
    }

    pub const fn to_bytes(self) -> [u8; INITIAL_WHIR_PROVER_IDENTITY_BYTES] {
        self.encoded
    }

    pub fn binding_digest(&self) -> [u8; 32] {
        read_digest(&self.encoded, PROVER_BINDING_OFFSET)
    }

    pub fn oracle_identity(&self) -> InitialWhirOracleIdentity {
        let encoded = self.encoded
            [PROVER_ORACLE_OFFSET..PROVER_ORACLE_OFFSET + INITIAL_WHIR_ORACLE_IDENTITY_BYTES]
            .try_into()
            .expect("fixed initial WHIR oracle identity slice");
        InitialWhirOracleIdentity::from_bytes(encoded)
            .expect("validated initial WHIR prover identity contains a valid oracle")
    }

    pub fn source_artifact_identity(&self) -> WhirInitialSourceArtifactIdentity {
        WhirInitialSourceArtifactIdentity {
            source: WhirInitialSourceIdentity {
                source_id: read_digest(&self.encoded, PROVER_SOURCE_ID_OFFSET),
                num_variables: read_u32(&self.encoded, PROVER_NUM_VARIABLES_OFFSET),
            },
            element_count: read_u64(&self.encoded, PROVER_ELEMENT_COUNT_OFFSET),
            artifact_global_digest: read_digest(&self.encoded, PROVER_SOURCE_DIGEST_OFFSET),
        }
    }

    fn validate(&self) -> Result<(), InitialWhirProverError> {
        if &self.encoded[..8] != PROVER_MAGIC {
            return Err(InitialWhirProverError::InvalidIdentity("wrong magic"));
        }
        if self.binding_digest() != prover_identity_binding(&self.encoded) {
            return Err(InitialWhirProverError::InvalidIdentity(
                "binding digest does not match",
            ));
        }
        if self.encoded[PROVER_LAYOUT_OFFSET] != PROVER_NATURAL_MLE_LAYOUT
            || self.encoded[PROVER_ENCODING_OFFSET] != PROVER_CANONICAL_U64_LE_ENCODING
            || self.encoded[342..344] != [0_u8; 2]
        {
            return Err(InitialWhirProverError::InvalidIdentity(
                "source layout or encoding is not canonical",
            ));
        }
        let oracle_encoded = self.encoded
            [PROVER_ORACLE_OFFSET..PROVER_ORACLE_OFFSET + INITIAL_WHIR_ORACLE_IDENTITY_BYTES]
            .try_into()
            .expect("fixed initial WHIR oracle identity slice");
        let oracle = InitialWhirOracleIdentity::from_bytes(oracle_encoded)
            .map_err(InitialWhirProverError::Oracle)?;
        let source_artifact = self.source_artifact_identity();
        validate_source_artifact_identity(&source_artifact)?;
        if source_artifact.source != oracle.codeword_identity().source {
            return Err(InitialWhirProverError::SourceIdentityMismatch);
        }
        Ok(())
    }
}

fn validate_source_artifact_identity(
    source_artifact: &WhirInitialSourceArtifactIdentity,
) -> Result<(), InitialWhirProverError> {
    if source_artifact.source.source_id == [0_u8; 32]
        || source_artifact.artifact_global_digest == [0_u8; 32]
    {
        return Err(InitialWhirProverError::InvalidIdentity(
            "source IDs and digests must be nonzero",
        ));
    }
    let expected_elements = 1_u64
        .checked_shl(source_artifact.source.num_variables)
        .ok_or(InitialWhirProverError::InvalidIdentity(
            "source element count is not representable",
        ))?;
    if source_artifact.element_count != expected_elements {
        return Err(InitialWhirProverError::InvalidIdentity(
            "source element count does not match num_variables",
        ));
    }
    Ok(())
}

fn prover_identity_binding(encoded: &[u8; INITIAL_WHIR_PROVER_IDENTITY_BYTES]) -> [u8; 32] {
    let mut hasher = Hasher::new_derive_key(PROVER_IDENTITY_DOMAIN);
    hasher.update(&encoded[..PROVER_BINDING_OFFSET]);
    *hasher.finalize().as_bytes()
}

#[derive(Debug, Error)]
pub enum InitialWhirOracleError {
    #[error("invalid initial WHIR oracle identity: {0}")]
    InvalidIdentity(&'static str),
    #[error("initial WHIR oracle caller context does not match")]
    CallerContextMismatch,
    #[error("initial WHIR oracle pinned root does not match the Merkle identity")]
    PinnedRootMismatch,
    #[error("initial WHIR codeword identity does not match the oracle identity")]
    CodewordIdentityMismatch,
    #[error("initial WHIR Merkle identity does not match the oracle identity")]
    MerkleIdentityMismatch,
    #[error("initial WHIR opening does not reconstruct the pinned root")]
    OpeningRootMismatch,
    #[error("initial WHIR codeword access failed: {0}")]
    Codeword(#[source] WhirInitialEncodingError),
    #[error("initial WHIR Merkle access failed: {0}")]
    Merkle(#[source] Blake3MerkleStoreError),
}

#[derive(Debug, Error)]
pub enum InitialWhirProverError {
    #[error("invalid initial WHIR prover identity: {0}")]
    InvalidIdentity(&'static str),
    #[error("initial WHIR source identity does not match the oracle identity")]
    SourceIdentityMismatch,
    #[error("initial WHIR source artifact identity does not match")]
    SourceArtifactIdentityMismatch,
    #[error("initial WHIR oracle identity does not match the prover identity")]
    OracleIdentityMismatch,
    #[error("initial WHIR source artifact access failed: {0}")]
    SourceArtifact(#[source] WhirInitialSourceArtifactError),
    #[error("initial WHIR oracle access failed: {0}")]
    Oracle(#[source] InitialWhirOracleError),
}

/// One authenticated natural codeword row and its leaf-to-root sibling path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitialWhirOpening {
    row_index: usize,
    row: [u64; WHIR_INITIAL_WIDTH],
    authentication_path: Vec<Blake3MerkleDigest>,
}

impl InitialWhirOpening {
    pub const fn row_index(&self) -> usize {
        self.row_index
    }

    pub const fn row(&self) -> &[u64; WHIR_INITIAL_WIDTH] {
        &self.row
    }

    pub fn authentication_path(&self) -> &[Blake3MerkleDigest] {
        &self.authentication_path
    }
}

/// Authenticated access to one fixed initial WHIR codeword/tree pair.
pub struct InitialWhirOracle {
    identity: InitialWhirOracleIdentity,
    codeword: AuthenticatedWhirInitialCodeword,
    tree: AuthenticatedBlake3MerkleStore,
}

impl std::fmt::Debug for InitialWhirOracle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InitialWhirOracle")
            .field("identity", &self.identity)
            .field("codeword_path", &self.codeword.path())
            .field("tree_path", &self.tree.path())
            .finish_non_exhaustive()
    }
}

impl InitialWhirOracle {
    /// Reopen both artifacts against one retained identity.
    ///
    /// Context and descriptor validation happen before either path is opened.
    pub fn reopen(
        caller_context_digest: [u8; 32],
        expected: &InitialWhirOracleIdentity,
        codeword_path: impl AsRef<Path>,
        tree_path: impl AsRef<Path>,
    ) -> Result<Self, InitialWhirOracleError> {
        expected.validate()?;
        expected.require_context(caller_context_digest)?;
        let codeword =
            AuthenticatedWhirInitialCodeword::open(codeword_path, &expected.codeword_identity())
                .map_err(map_codeword_open_error)?;
        let tree =
            AuthenticatedBlake3MerkleStore::open(tree_path, &expected.merkle_store_identity())
                .map_err(map_merkle_open_error)?;
        Self::adopt_validated(expected, codeword, tree)
    }

    /// Adopt already-open authenticated components under one retained identity.
    pub fn adopt(
        caller_context_digest: [u8; 32],
        expected: &InitialWhirOracleIdentity,
        codeword: AuthenticatedWhirInitialCodeword,
        tree: AuthenticatedBlake3MerkleStore,
    ) -> Result<Self, InitialWhirOracleError> {
        expected.validate()?;
        expected.require_context(caller_context_digest)?;
        Self::adopt_validated(expected, codeword, tree)
    }

    fn adopt_validated(
        expected: &InitialWhirOracleIdentity,
        codeword: AuthenticatedWhirInitialCodeword,
        tree: AuthenticatedBlake3MerkleStore,
    ) -> Result<Self, InitialWhirOracleError> {
        if codeword.identity() != &expected.codeword_identity() {
            return Err(InitialWhirOracleError::CodewordIdentityMismatch);
        }
        let actual_tree_identity = tree.identity().map_err(InitialWhirOracleError::Merkle)?;
        if actual_tree_identity != expected.merkle_store_identity() {
            return Err(InitialWhirOracleError::MerkleIdentityMismatch);
        }
        Ok(Self {
            identity: *expected,
            codeword,
            tree,
        })
    }

    pub const fn identity(&self) -> &InitialWhirOracleIdentity {
        &self.identity
    }

    pub fn height(&self) -> usize {
        self.identity.merkle_store_identity().height
    }

    /// Authenticate one natural row and sibling path, then check the root.
    pub fn opening(&self, row_index: usize) -> Result<InitialWhirOpening, InitialWhirOracleError> {
        let values = self
            .codeword
            .read_canonical_rows(row_index, 1)
            .map_err(InitialWhirOracleError::Codeword)?;
        let row: [u64; WHIR_INITIAL_WIDTH] = values.try_into().map_err(|_| {
            InitialWhirOracleError::InvalidIdentity("codeword row width changed after adoption")
        })?;
        let authentication_path = self
            .tree
            .opening_path(row_index)
            .map_err(InitialWhirOracleError::Merkle)?;
        let expected_path_len =
            usize::try_from(self.height().ilog2()).expect("bounded tree path length fits usize");
        if authentication_path.len() != expected_path_len
            || opening_root(row_index, &row, &authentication_path) != self.identity.pinned_root()
        {
            return Err(InitialWhirOracleError::OpeningRootMismatch);
        }
        Ok(InitialWhirOpening {
            row_index,
            row,
            authentication_path,
        })
    }
}

/// Authenticated access to one original source, initial codeword, and Merkle
/// tree under a single externally retained prover identity.
pub struct InitialWhirProverOracle {
    identity: InitialWhirProverIdentity,
    source: AuthenticatedWhirInitialSourceFile,
    oracle: InitialWhirOracle,
}

impl std::fmt::Debug for InitialWhirProverOracle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InitialWhirProverOracle")
            .field("identity", &self.identity)
            .field("source_path", &self.source.path())
            .field("oracle", &self.oracle)
            .finish_non_exhaustive()
    }
}

impl InitialWhirProverOracle {
    /// Reopen all three artifacts against one retained identity.
    ///
    /// The caller context and fixed identity are checked before any path is
    /// opened. No partially validated capability is returned.
    pub fn reopen(
        caller_context_digest: [u8; 32],
        expected: &InitialWhirProverIdentity,
        source_path: impl AsRef<Path>,
        codeword_path: impl AsRef<Path>,
        tree_path: impl AsRef<Path>,
    ) -> Result<Self, InitialWhirProverError> {
        expected.validate()?;
        let oracle_identity = expected.oracle_identity();
        oracle_identity
            .require_context(caller_context_digest)
            .map_err(InitialWhirProverError::Oracle)?;
        let source_identity = expected.source_artifact_identity();
        let source = AuthenticatedWhirInitialSourceFile::open(source_path, &source_identity)
            .map_err(map_source_artifact_open_error)?;
        let oracle = InitialWhirOracle::reopen(
            caller_context_digest,
            &oracle_identity,
            codeword_path,
            tree_path,
        )
        .map_err(InitialWhirProverError::Oracle)?;
        Self::adopt_validated(expected, source, oracle)
    }

    /// Adopt already-open authenticated components under one retained identity.
    pub fn adopt(
        caller_context_digest: [u8; 32],
        expected: &InitialWhirProverIdentity,
        source: AuthenticatedWhirInitialSourceFile,
        oracle: InitialWhirOracle,
    ) -> Result<Self, InitialWhirProverError> {
        expected.validate()?;
        expected
            .oracle_identity()
            .require_context(caller_context_digest)
            .map_err(InitialWhirProverError::Oracle)?;
        Self::adopt_validated(expected, source, oracle)
    }

    fn adopt_validated(
        expected: &InitialWhirProverIdentity,
        source: AuthenticatedWhirInitialSourceFile,
        oracle: InitialWhirOracle,
    ) -> Result<Self, InitialWhirProverError> {
        if source.artifact_identity() != &expected.source_artifact_identity() {
            return Err(InitialWhirProverError::SourceArtifactIdentityMismatch);
        }
        if oracle.identity() != &expected.oracle_identity() {
            return Err(InitialWhirProverError::OracleIdentityMismatch);
        }
        Ok(Self {
            identity: *expected,
            source,
            oracle,
        })
    }

    pub const fn identity(&self) -> &InitialWhirProverIdentity {
        &self.identity
    }

    pub const fn source(&self) -> &AuthenticatedWhirInitialSourceFile {
        &self.source
    }

    pub const fn oracle(&self) -> &InitialWhirOracle {
        &self.oracle
    }

    pub fn into_parts(self) -> (AuthenticatedWhirInitialSourceFile, InitialWhirOracle) {
        (self.source, self.oracle)
    }
}

fn map_source_artifact_open_error(error: WhirInitialSourceArtifactError) -> InitialWhirProverError {
    match error {
        WhirInitialSourceArtifactError::IdentityMismatch => {
            InitialWhirProverError::SourceArtifactIdentityMismatch
        }
        other => InitialWhirProverError::SourceArtifact(other),
    }
}

fn map_codeword_open_error(error: WhirInitialEncodingError) -> InitialWhirOracleError {
    match error {
        WhirInitialEncodingError::IdentityMismatch => {
            InitialWhirOracleError::CodewordIdentityMismatch
        }
        other => InitialWhirOracleError::Codeword(other),
    }
}

fn map_merkle_open_error(error: Blake3MerkleStoreError) -> InitialWhirOracleError {
    match error {
        Blake3MerkleStoreError::IdentityMismatch => InitialWhirOracleError::MerkleIdentityMismatch,
        other => InitialWhirOracleError::Merkle(other),
    }
}

fn opening_root(
    row_index: usize,
    row: &[u64; WHIR_INITIAL_WIDTH],
    authentication_path: &[Blake3MerkleDigest],
) -> Blake3MerkleDigest {
    let mut leaf_hasher = Hasher::new();
    for value in row {
        leaf_hasher.update(&value.to_le_bytes());
    }
    let mut digest = *leaf_hasher.finalize().as_bytes();
    let mut index = row_index;
    for sibling in authentication_path {
        let mut hasher = Hasher::new();
        if index.is_multiple_of(2) {
            hasher.update(&digest);
            hasher.update(sibling);
        } else {
            hasher.update(sibling);
            hasher.update(&digest);
        }
        digest = *hasher.finalize().as_bytes();
        index /= 2;
    }
    digest
}

fn identity_binding(encoded: &[u8; INITIAL_WHIR_ORACLE_IDENTITY_BYTES]) -> [u8; 32] {
    let mut hasher = Hasher::new_derive_key(IDENTITY_DOMAIN);
    hasher.update(&encoded[..BINDING_OFFSET]);
    *hasher.finalize().as_bytes()
}

fn copy_digest(
    encoded: &mut [u8; INITIAL_WHIR_ORACLE_IDENTITY_BYTES],
    offset: usize,
    digest: [u8; 32],
) {
    encoded[offset..offset + 32].copy_from_slice(&digest);
}

fn read_digest(encoded: &[u8], offset: usize) -> [u8; 32] {
    encoded[offset..offset + 32]
        .try_into()
        .expect("fixed oracle identity digest slice")
}

fn put_u32(encoded: &mut [u8], offset: usize, value: u32) {
    encoded[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn read_u32(encoded: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        encoded[offset..offset + 4]
            .try_into()
            .expect("fixed oracle identity u32 slice"),
    )
}

fn put_u64(encoded: &mut [u8], offset: usize, value: u64) {
    encoded[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn read_u64(encoded: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        encoded[offset..offset + 8]
            .try_into()
            .expect("fixed oracle identity u64 slice"),
    )
}

#[cfg(test)]
mod tests {
    use std::fs::{self, OpenOptions};
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::blake3_merkle_store::build_authenticated_blake3_merkle_store;
    use crate::merkle_store::GOLDILOCKS_MODULUS;
    use crate::whir_initial::{
        AuthenticatedWhirInitialSource, WhirInitialSourceError, encode_whir_initial_suffix,
    };
    use crate::whir_initial_source::WhirInitialSourceArtifactWriter;

    use super::*;

    static NEXT_PATH: AtomicU64 = AtomicU64::new(0);
    const CONTEXT: [u8; 32] = [0xc1; 32];

    struct DenseSource {
        identity: WhirInitialSourceIdentity,
        values: Vec<u64>,
    }

    impl AuthenticatedWhirInitialSource for DenseSource {
        fn identity(&self) -> &WhirInitialSourceIdentity {
            &self.identity
        }

        fn len(&self) -> usize {
            self.values.len()
        }

        fn read_elements(
            &self,
            start: usize,
            count: usize,
        ) -> Result<Vec<u64>, WhirInitialSourceError> {
            let end = start
                .checked_add(count)
                .ok_or_else(|| WhirInitialSourceError::new("range overflow"))?;
            self.values
                .get(start..end)
                .map(<[u64]>::to_vec)
                .ok_or_else(|| WhirInitialSourceError::new("range out of bounds"))
        }
    }

    struct TestPaths {
        source: PathBuf,
        codeword: PathBuf,
        tree: PathBuf,
    }

    impl TestPaths {
        fn new(label: &str) -> Self {
            let sequence = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
            let base = std::env::temp_dir().join(format!(
                "cmfd-initial-whir-oracle-{label}-{}-{sequence}",
                std::process::id()
            ));
            Self {
                source: base.with_extension("source"),
                codeword: base.with_extension("codeword"),
                tree: base.with_extension("tree"),
            }
        }
    }

    impl Drop for TestPaths {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.source);
            let _ = fs::remove_file(&self.codeword);
            let _ = fs::remove_file(&self.tree);
        }
    }

    struct BuiltPair {
        paths: TestPaths,
        codeword: AuthenticatedWhirInitialCodeword,
        tree: AuthenticatedBlake3MerkleStore,
        identity: InitialWhirOracleIdentity,
    }

    fn build_pair(label: &str, content_seed: u64, identity_seed: u8) -> BuiltPair {
        let paths = TestPaths::new(label);
        let variables = 5_u32;
        let source_identity = WhirInitialSourceIdentity {
            source_id: [identity_seed; 32],
            num_variables: variables,
        };
        let values = (0..1_usize << variables)
            .map(|index| {
                content_seed.wrapping_add((index as u64).wrapping_mul(0x9e37_79b9))
                    % GOLDILOCKS_MODULUS
            })
            .collect();
        let source = DenseSource {
            identity: source_identity.clone(),
            values,
        };
        let codeword = encode_whir_initial_suffix(
            &paths.codeword,
            [identity_seed.wrapping_add(1); 32],
            &source_identity,
            &source,
        )
        .unwrap();
        let tree = build_authenticated_blake3_merkle_store(
            &paths.tree,
            [identity_seed.wrapping_add(2); 32],
            &[&codeword],
        )
        .unwrap();
        let tree_identity = tree.identity().unwrap();
        let identity = InitialWhirOracleIdentity::bind(
            CONTEXT,
            codeword.identity(),
            &tree_identity,
            tree_identity.tree_root,
        )
        .unwrap();
        BuiltPair {
            paths,
            codeword,
            tree,
            identity,
        }
    }

    struct BuiltTriple {
        paths: TestPaths,
        prover: InitialWhirProverOracle,
        identity: InitialWhirProverIdentity,
    }

    fn build_triple(label: &str, content_seed: u64, identity_seed: u8) -> BuiltTriple {
        let paths = TestPaths::new(label);
        let variables = 5_u32;
        let source_identity = WhirInitialSourceIdentity {
            source_id: [identity_seed; 32],
            num_variables: variables,
        };
        let values = (0..1_usize << variables)
            .map(|index| {
                content_seed.wrapping_add((index as u64).wrapping_mul(0x9e37_79b9))
                    % GOLDILOCKS_MODULUS
            })
            .collect::<Vec<_>>();
        let mut source_writer =
            WhirInitialSourceArtifactWriter::create(&paths.source, source_identity.clone())
                .unwrap();
        for chunk in values.chunks(7) {
            source_writer.write_elements(chunk).unwrap();
        }
        let source = source_writer.finish().unwrap();
        let codeword = encode_whir_initial_suffix(
            &paths.codeword,
            [identity_seed.wrapping_add(1); 32],
            &source_identity,
            &source,
        )
        .unwrap();
        let tree = build_authenticated_blake3_merkle_store(
            &paths.tree,
            [identity_seed.wrapping_add(2); 32],
            &[&codeword],
        )
        .unwrap();
        let tree_identity = tree.identity().unwrap();
        let oracle_identity = InitialWhirOracleIdentity::bind(
            CONTEXT,
            codeword.identity(),
            &tree_identity,
            tree_identity.tree_root,
        )
        .unwrap();
        let identity =
            InitialWhirProverIdentity::bind(&oracle_identity, source.artifact_identity()).unwrap();
        let oracle = InitialWhirOracle::adopt(CONTEXT, &oracle_identity, codeword, tree).unwrap();
        let prover = InitialWhirProverOracle::adopt(CONTEXT, &identity, source, oracle).unwrap();
        BuiltTriple {
            paths,
            prover,
            identity,
        }
    }

    #[test]
    fn fixed_identity_adopts_reopens_and_returns_verified_openings() {
        let pair = build_pair("happy", 0x101, 0x11);
        let bytes = pair.identity.to_bytes();
        assert_eq!(bytes.len(), INITIAL_WHIR_ORACLE_IDENTITY_BYTES);
        assert_eq!(
            InitialWhirOracleIdentity::from_bytes(bytes).unwrap(),
            pair.identity
        );
        let expected = pair.identity;
        let codeword_path = pair.paths.codeword.clone();
        let tree_path = pair.paths.tree.clone();
        let oracle =
            InitialWhirOracle::adopt(CONTEXT, &expected, pair.codeword, pair.tree).unwrap();
        assert_eq!(oracle.identity(), &expected);
        for row_index in [0, 1, 7, oracle.height() - 1] {
            let opening = oracle.opening(row_index).unwrap();
            assert_eq!(opening.row_index(), row_index);
            assert_eq!(opening.row().len(), WHIR_INITIAL_WIDTH);
            assert_eq!(
                opening.authentication_path().len(),
                oracle.height().ilog2() as usize
            );
            assert_eq!(
                opening_root(row_index, opening.row(), opening.authentication_path()),
                expected.pinned_root()
            );
        }
        drop(oracle);

        let reopened =
            InitialWhirOracle::reopen(CONTEXT, &expected, codeword_path, tree_path).unwrap();
        assert_eq!(reopened.opening(3).unwrap().row_index(), 3);
    }

    #[test]
    fn context_components_root_geometry_and_partition_fail_before_capability() {
        let first = build_pair("first", 0x201, 0x21);
        let second = build_pair("second", 0x202, 0x31);
        let expected = first.identity;

        assert!(matches!(
            InitialWhirOracle::reopen(
                [0xc2; 32],
                &expected,
                &first.paths.codeword,
                &first.paths.tree,
            ),
            Err(InitialWhirOracleError::CallerContextMismatch)
        ));
        assert!(matches!(
            InitialWhirOracle::reopen(
                CONTEXT,
                &expected,
                &second.paths.codeword,
                &first.paths.tree,
            ),
            Err(InitialWhirOracleError::CodewordIdentityMismatch)
        ));
        assert!(matches!(
            InitialWhirOracle::reopen(
                CONTEXT,
                &expected,
                &first.paths.codeword,
                &second.paths.tree,
            ),
            Err(InitialWhirOracleError::MerkleIdentityMismatch)
        ));

        let mut wrong_codeword = first.codeword.identity().clone();
        wrong_codeword.width = 8;
        let tree_identity = first.tree.identity().unwrap();
        assert!(matches!(
            InitialWhirOracleIdentity::bind(
                CONTEXT,
                &wrong_codeword,
                &tree_identity,
                tree_identity.tree_root,
            ),
            Err(InitialWhirOracleError::InvalidIdentity(_))
        ));

        let mut wrong_partition = tree_identity.clone();
        wrong_partition.ordered_matrix_widths = vec![2, 2];
        assert!(matches!(
            InitialWhirOracleIdentity::bind(
                CONTEXT,
                first.codeword.identity(),
                &wrong_partition,
                wrong_partition.tree_root,
            ),
            Err(InitialWhirOracleError::InvalidIdentity(_))
        ));
        let mut wrong_root = tree_identity.clone();
        wrong_root.tree_root[0] ^= 1;
        assert!(matches!(
            InitialWhirOracleIdentity::bind(
                CONTEXT,
                first.codeword.identity(),
                &tree_identity,
                wrong_root.tree_root,
            ),
            Err(InitialWhirOracleError::PinnedRootMismatch)
        ));
        assert!(matches!(
            InitialWhirOracleIdentity::bind(
                [0_u8; 32],
                first.codeword.identity(),
                &tree_identity,
                tree_identity.tree_root,
            ),
            Err(InitialWhirOracleError::InvalidIdentity(_))
        ));
    }

    #[test]
    fn retained_identity_rejects_self_consistent_whole_pair_substitution() {
        let original = build_pair("substitution-original", 0x301, 0x41);
        let substitute = build_pair("substitution-replacement", 0x302, 0x41);
        let original_identity = original.identity;
        let substitute_identity = substitute.identity;
        let original_codeword_path = original.paths.codeword.clone();
        let original_tree_path = original.paths.tree.clone();
        let substitute_codeword_path = substitute.paths.codeword.clone();
        let substitute_tree_path = substitute.paths.tree.clone();
        assert_ne!(substitute_identity, original_identity);
        drop(original.codeword);
        drop(original.tree);
        drop(substitute.codeword);
        drop(substitute.tree);

        let internally_consistent = InitialWhirOracle::reopen(
            CONTEXT,
            &substitute_identity,
            &substitute_codeword_path,
            &substitute_tree_path,
        )
        .unwrap();
        assert!(internally_consistent.opening(2).is_ok());
        drop(internally_consistent);

        fs::copy(&substitute_codeword_path, &original_codeword_path).unwrap();
        fs::copy(&substitute_tree_path, &original_tree_path).unwrap();
        assert!(matches!(
            InitialWhirOracle::reopen(
                CONTEXT,
                &original_identity,
                &original_codeword_path,
                &original_tree_path,
            ),
            Err(InitialWhirOracleError::CodewordIdentityMismatch)
        ));
    }

    #[test]
    fn post_open_component_mutation_fails_on_the_affected_read() {
        let codeword_pair = build_pair("mutated-codeword", 0x401, 0x51);
        let codeword_path = codeword_pair.paths.codeword.clone();
        let codeword_oracle = InitialWhirOracle::adopt(
            CONTEXT,
            &codeword_pair.identity,
            codeword_pair.codeword,
            codeword_pair.tree,
        )
        .unwrap();
        mutate_byte(&codeword_path, 160);
        assert!(matches!(
            codeword_oracle.opening(0),
            Err(InitialWhirOracleError::Codeword(
                WhirInitialEncodingError::ChecksumMismatch
            ))
        ));

        let tree_pair = build_pair("mutated-tree", 0x402, 0x61);
        let tree_path = tree_pair.paths.tree.clone();
        let tree_oracle = InitialWhirOracle::adopt(
            CONTEXT,
            &tree_pair.identity,
            tree_pair.codeword,
            tree_pair.tree,
        )
        .unwrap();
        let tree_header_len = read_tree_header_len(&tree_path);
        mutate_byte(&tree_path, tree_header_len);
        assert!(matches!(
            tree_oracle.opening(1),
            Err(InitialWhirOracleError::Merkle(
                Blake3MerkleStoreError::ChecksumMismatch
            ))
        ));
    }

    #[test]
    fn identity_encoding_tampering_is_rejected() {
        let pair = build_pair("identity-tamper", 0x501, 0x71);
        for offset in [CONTEXT_OFFSET, 40, PARTITION_WIDTH_OFFSET, TREE_ROOT_OFFSET] {
            let mut bytes = pair.identity.to_bytes();
            bytes[offset] ^= 1;
            assert!(matches!(
                InitialWhirOracleIdentity::from_bytes(bytes),
                Err(InitialWhirOracleError::InvalidIdentity(_))
            ));
        }
    }

    #[test]
    fn prover_identity_binds_the_exact_source_artifact() {
        let pair = build_pair("prover-identity", 0x601, 0x81);
        let source = pair.identity.codeword_identity().source;
        let source_artifact = WhirInitialSourceArtifactIdentity {
            source: source.clone(),
            element_count: 1_u64 << source.num_variables,
            artifact_global_digest: [0x91; 32],
        };
        let identity = InitialWhirProverIdentity::bind(&pair.identity, &source_artifact).unwrap();
        assert_eq!(
            identity.as_bytes().len(),
            INITIAL_WHIR_PROVER_IDENTITY_BYTES
        );
        assert_eq!(
            InitialWhirProverIdentity::from_bytes(identity.to_bytes()).unwrap(),
            identity
        );
        assert_eq!(identity.oracle_identity(), pair.identity);
        assert_eq!(identity.source_artifact_identity(), source_artifact);

        let mut replacement = source_artifact.clone();
        replacement.artifact_global_digest[0] ^= 1;
        assert_ne!(
            InitialWhirProverIdentity::bind(&pair.identity, &replacement).unwrap(),
            identity
        );

        let mut wrong_source = source_artifact.clone();
        wrong_source.source.source_id[0] ^= 1;
        assert!(matches!(
            InitialWhirProverIdentity::bind(&pair.identity, &wrong_source),
            Err(InitialWhirProverError::SourceIdentityMismatch)
        ));

        let mut wrong_count = source_artifact;
        wrong_count.element_count -= 1;
        assert!(matches!(
            InitialWhirProverIdentity::bind(&pair.identity, &wrong_count),
            Err(InitialWhirProverError::InvalidIdentity(_))
        ));

        let mut mutated = identity.to_bytes();
        mutated[PROVER_SOURCE_DIGEST_OFFSET] ^= 1;
        assert!(matches!(
            InitialWhirProverIdentity::from_bytes(mutated),
            Err(InitialWhirProverError::InvalidIdentity(_))
        ));
    }

    #[test]
    fn prover_oracle_reopens_three_components_and_rejects_cross_pairing() {
        let first = build_triple("prover-first", 0x701, 0xa1);
        let second = build_triple("prover-second", 0x702, 0xa1);
        assert_ne!(
            first
                .identity
                .source_artifact_identity()
                .artifact_global_digest,
            second
                .identity
                .source_artifact_identity()
                .artifact_global_digest
        );
        assert_eq!(
            first.identity.source_artifact_identity().source,
            second.identity.source_artifact_identity().source
        );
        assert_eq!(first.prover.source().read_elements(3, 5).unwrap().len(), 5);
        assert_eq!(first.prover.oracle().opening(2).unwrap().row_index(), 2);

        let first_identity = first.identity;
        let first_source_path = first.paths.source.clone();
        let first_codeword_path = first.paths.codeword.clone();
        let first_tree_path = first.paths.tree.clone();
        let second_source_path = second.paths.source.clone();
        drop(first.prover);
        drop(second.prover);

        let reopened = InitialWhirProverOracle::reopen(
            CONTEXT,
            &first_identity,
            &first_source_path,
            &first_codeword_path,
            &first_tree_path,
        )
        .unwrap();
        assert_eq!(reopened.identity(), &first_identity);
        assert_eq!(reopened.source().read_elements(1, 2).unwrap().len(), 2);
        drop(reopened);

        assert!(matches!(
            InitialWhirProverOracle::reopen(
                CONTEXT,
                &first_identity,
                &second_source_path,
                &first_codeword_path,
                &first_tree_path,
            ),
            Err(InitialWhirProverError::SourceArtifactIdentityMismatch)
        ));

        let missing = first_source_path.with_extension("missing");
        assert!(matches!(
            InitialWhirProverOracle::reopen(
                [0xff; 32],
                &first_identity,
                &missing,
                &missing,
                &missing,
            ),
            Err(InitialWhirProverError::Oracle(
                InitialWhirOracleError::CallerContextMismatch
            ))
        ));
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
        byte[0] ^= 1;
        file.seek(SeekFrom::Start(offset)).unwrap();
        file.write_all(&byte).unwrap();
        file.sync_all().unwrap();
    }

    fn read_tree_header_len(path: &Path) -> u64 {
        let mut file = OpenOptions::new().read(true).open(path).unwrap();
        file.seek(SeekFrom::Start(12)).unwrap();
        let mut encoded = [0_u8; 4];
        file.read_exact(&mut encoded).unwrap();
        u64::from(u32::from_le_bytes(encoded))
    }
}
