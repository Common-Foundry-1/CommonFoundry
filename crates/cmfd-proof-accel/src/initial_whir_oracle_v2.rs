//! Version-two identity-bound access to an initial WHIR codeword and its
//! independently versioned demand-authenticated BLAKE3 tree.
//!
//! These identities and capabilities are prover-local storage metadata. They
//! are deliberately separate from the version-one initial oracle so its bytes,
//! bounded geometry, and callers remain unchanged. A proof transcript observes
//! only the ordinary Merkle root, never either identity encoding.

use std::path::Path;

use blake3::Hasher;
use thiserror::Error;

use crate::blake3_merkle_store::Blake3MerkleDigest;
use crate::demand_blake3_tree::{
    AuthenticatedInitialDemandBlake3Tree, DemandBlake3TreeError, InitialDemandBlake3TreeIdentity,
    initial_whir_demand_blake3_tree_geometry,
};
use crate::whir_initial::{
    AuthenticatedWhirInitialCodeword, WHIR_INITIAL_ARTIFACT_MAX_VARIABLES,
    WHIR_INITIAL_MIN_VARIABLES, WHIR_INITIAL_WIDTH, WhirInitialCodewordIdentity,
    WhirInitialEncodingError, WhirInitialSourceIdentity,
};
use crate::whir_initial_source::{
    AuthenticatedWhirInitialSourceFile, WHIR_INITIAL_SOURCE_HEADER_BYTES,
    WhirInitialSourceArtifactError, WhirInitialSourceArtifactIdentity,
};

/// Canonical byte length of [`InitialWhirOracleIdentityV2`].
pub const INITIAL_WHIR_ORACLE_V2_IDENTITY_BYTES: usize = 320;
/// Canonical byte length of [`InitialWhirProverIdentityV2`].
pub const INITIAL_WHIR_PROVER_V2_IDENTITY_BYTES: usize = 448;

const ORACLE_MAGIC: &[u8; 8] = b"CMFDWIO2";
const PROVER_MAGIC: &[u8; 8] = b"CMFDWIP2";
const NATURAL_SUFFIX_LAYOUT: u8 = 1;
const FOLDING: u8 = 2;
const STARTING_LOG_INV_RATE: u8 = 1;
const MATRIX_COUNT: u8 = 1;
const TREE_FORMAT_VERSION: u32 = 1;
const TREE_HEADER_BYTES: u32 = 256;
const TREE_CAP_HEIGHT: u32 = 0;
const SOURCE_FORMAT_VERSION: u32 = 1;
const NATURAL_MLE_LAYOUT: u8 = 1;
const CANONICAL_U64_LE_ENCODING: u8 = 1;

const CONTEXT_OFFSET: usize = 8;
const NUM_VARIABLES_OFFSET: usize = 44;
const CODEWORD_HEIGHT_OFFSET: usize = 48;
const TREE_HEIGHT_OFFSET: usize = 56;
const CODEWORD_WIDTH_OFFSET: usize = 64;
const TREE_WIDTH_OFFSET: usize = 68;
const CODEWORD_ARTIFACT_ID_OFFSET: usize = 72;
const SOURCE_ID_OFFSET: usize = 104;
const CODEWORD_DIGEST_OFFSET: usize = 136;
const TREE_STORE_ID_OFFSET: usize = 168;
const TREE_ROOT_OFFSET: usize = 200;
const CODEWORD_BINDING_OFFSET: usize = 232;
const TREE_ARTIFACT_BYTES_OFFSET: usize = 264;
const TREE_FORMAT_VERSION_OFFSET: usize = 272;
const TREE_HEADER_BYTES_OFFSET: usize = 276;
const TREE_LAYER_COUNT_OFFSET: usize = 280;
const TREE_CAP_HEIGHT_OFFSET: usize = 284;
const ORACLE_BINDING_OFFSET: usize = 288;
const ORACLE_IDENTITY_DOMAIN: &str = "Common Foundry initial WHIR oracle identity v2";

const PROVER_ORACLE_OFFSET: usize = 8;
const PROVER_SOURCE_FORMAT_VERSION_OFFSET: usize = 328;
const PROVER_SOURCE_HEADER_BYTES_OFFSET: usize = 332;
const PROVER_SOURCE_ID_OFFSET: usize = 336;
const PROVER_NUM_VARIABLES_OFFSET: usize = 368;
const PROVER_LAYOUT_OFFSET: usize = 372;
const PROVER_ENCODING_OFFSET: usize = 373;
const PROVER_ELEMENT_COUNT_OFFSET: usize = 376;
const PROVER_SOURCE_DIGEST_OFFSET: usize = 384;
const PROVER_BINDING_OFFSET: usize = 416;
const PROVER_IDENTITY_DOMAIN: &str = "Common Foundry initial WHIR prover identity v2";

/// Exact retained identity for one production-geometry initial WHIR oracle.
///
/// Its fixed encoding binds the caller context, complete initial-codeword
/// identity, typed demand-tree identity, and the exact initial-tree format.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct InitialWhirOracleIdentityV2 {
    encoded: [u8; INITIAL_WHIR_ORACLE_V2_IDENTITY_BYTES],
}

impl std::fmt::Debug for InitialWhirOracleIdentityV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InitialWhirOracleIdentityV2")
            .field("binding_digest", &self.binding_digest())
            .field("context_digest", &self.context_digest())
            .field("codeword", &self.codeword_identity())
            .field("tree", &self.tree_identity())
            .finish()
    }
}

impl InitialWhirOracleIdentityV2 {
    /// Bind one exact authenticated initial codeword to its exact typed tree.
    pub fn bind(
        context_digest: [u8; 32],
        codeword: &WhirInitialCodewordIdentity,
        tree: &InitialDemandBlake3TreeIdentity,
    ) -> Result<Self, InitialWhirOracleV2Error> {
        if context_digest == [0; 32] {
            return Err(InitialWhirOracleV2Error::InvalidIdentity(
                "caller context digest must be nonzero",
            ));
        }
        let geometry = validate_component_identities(codeword, tree)?;

        let mut encoded = [0_u8; INITIAL_WHIR_ORACLE_V2_IDENTITY_BYTES];
        encoded[..8].copy_from_slice(ORACLE_MAGIC);
        encoded[CONTEXT_OFFSET..CONTEXT_OFFSET + 32].copy_from_slice(&context_digest);
        encoded[40] = NATURAL_SUFFIX_LAYOUT;
        encoded[41] = FOLDING;
        encoded[42] = STARTING_LOG_INV_RATE;
        encoded[43] = MATRIX_COUNT;
        put_u32(
            &mut encoded,
            NUM_VARIABLES_OFFSET,
            codeword.source.num_variables,
        );
        put_u64(&mut encoded, CODEWORD_HEIGHT_OFFSET, codeword.height);
        put_u64(&mut encoded, TREE_HEIGHT_OFFSET, tree.height);
        put_u32(&mut encoded, CODEWORD_WIDTH_OFFSET, codeword.width);
        put_u32(&mut encoded, TREE_WIDTH_OFFSET, tree.width());
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
        copy_digest(&mut encoded, TREE_ROOT_OFFSET, tree.tree_root);
        copy_digest(&mut encoded, CODEWORD_BINDING_OFFSET, tree.codeword_binding);
        put_u64(
            &mut encoded,
            TREE_ARTIFACT_BYTES_OFFSET,
            tree.artifact_bytes,
        );
        put_u32(
            &mut encoded,
            TREE_FORMAT_VERSION_OFFSET,
            TREE_FORMAT_VERSION,
        );
        put_u32(&mut encoded, TREE_HEADER_BYTES_OFFSET, TREE_HEADER_BYTES);
        put_u32(&mut encoded, TREE_LAYER_COUNT_OFFSET, geometry.layer_count);
        put_u32(&mut encoded, TREE_CAP_HEIGHT_OFFSET, TREE_CAP_HEIGHT);
        let binding = oracle_identity_binding(&encoded);
        copy_digest(&mut encoded, ORACLE_BINDING_OFFSET, binding);
        Self::from_bytes(encoded)
    }

    /// Decode and fully validate one canonical fixed-width identity.
    pub fn from_bytes(
        encoded: [u8; INITIAL_WHIR_ORACLE_V2_IDENTITY_BYTES],
    ) -> Result<Self, InitialWhirOracleV2Error> {
        let identity = Self { encoded };
        identity.validate()?;
        Ok(identity)
    }

    pub const fn as_bytes(&self) -> &[u8; INITIAL_WHIR_ORACLE_V2_IDENTITY_BYTES] {
        &self.encoded
    }

    pub const fn to_bytes(self) -> [u8; INITIAL_WHIR_ORACLE_V2_IDENTITY_BYTES] {
        self.encoded
    }

    pub fn binding_digest(&self) -> [u8; 32] {
        read_digest(&self.encoded, ORACLE_BINDING_OFFSET)
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

    pub fn tree_identity(&self) -> InitialDemandBlake3TreeIdentity {
        InitialDemandBlake3TreeIdentity {
            store_id: read_digest(&self.encoded, TREE_STORE_ID_OFFSET),
            codeword_binding: read_digest(&self.encoded, CODEWORD_BINDING_OFFSET),
            height: read_u64(&self.encoded, TREE_HEIGHT_OFFSET),
            tree_root: self.pinned_root(),
            artifact_bytes: read_u64(&self.encoded, TREE_ARTIFACT_BYTES_OFFSET),
        }
    }

    fn require_context(&self, context_digest: [u8; 32]) -> Result<(), InitialWhirOracleV2Error> {
        if context_digest == [0; 32] || context_digest != self.context_digest() {
            return Err(InitialWhirOracleV2Error::CallerContextMismatch);
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), InitialWhirOracleV2Error> {
        if &self.encoded[..8] != ORACLE_MAGIC {
            return Err(InitialWhirOracleV2Error::InvalidIdentity("wrong magic"));
        }
        if self.binding_digest() != oracle_identity_binding(&self.encoded) {
            return Err(InitialWhirOracleV2Error::InvalidIdentity(
                "binding digest does not match",
            ));
        }
        if self.context_digest() == [0; 32] {
            return Err(InitialWhirOracleV2Error::InvalidIdentity(
                "caller context digest must be nonzero",
            ));
        }
        if self.encoded[40] != NATURAL_SUFFIX_LAYOUT
            || self.encoded[41] != FOLDING
            || self.encoded[42] != STARTING_LOG_INV_RATE
            || self.encoded[43] != MATRIX_COUNT
            || read_u32(&self.encoded, CODEWORD_WIDTH_OFFSET) != WHIR_INITIAL_WIDTH as u32
            || read_u32(&self.encoded, TREE_WIDTH_OFFSET) != WHIR_INITIAL_WIDTH as u32
        {
            return Err(InitialWhirOracleV2Error::InvalidIdentity(
                "only one natural Suffix fold2/rate1 width-four matrix is admitted",
            ));
        }
        if read_u32(&self.encoded, TREE_FORMAT_VERSION_OFFSET) != TREE_FORMAT_VERSION
            || read_u32(&self.encoded, TREE_HEADER_BYTES_OFFSET) != TREE_HEADER_BYTES
            || read_u32(&self.encoded, TREE_CAP_HEIGHT_OFFSET) != TREE_CAP_HEIGHT
        {
            return Err(InitialWhirOracleV2Error::InvalidIdentity(
                "initial demand-tree format is not canonical",
            ));
        }
        let codeword = self.codeword_identity();
        let tree = self.tree_identity();
        let geometry = validate_component_identities(&codeword, &tree)?;
        if read_u32(&self.encoded, TREE_LAYER_COUNT_OFFSET) != geometry.layer_count {
            return Err(InitialWhirOracleV2Error::InvalidIdentity(
                "initial demand-tree layer count is inconsistent",
            ));
        }
        Ok(())
    }
}

fn validate_component_identities(
    codeword: &WhirInitialCodewordIdentity,
    tree: &InitialDemandBlake3TreeIdentity,
) -> Result<crate::demand_blake3_tree::DemandBlake3TreeGeometry, InitialWhirOracleV2Error> {
    let variables = usize::try_from(codeword.source.num_variables).map_err(|_| {
        InitialWhirOracleV2Error::InvalidIdentity("variable count does not fit usize")
    })?;
    if !(WHIR_INITIAL_MIN_VARIABLES..=WHIR_INITIAL_ARTIFACT_MAX_VARIABLES).contains(&variables) {
        return Err(InitialWhirOracleV2Error::InvalidIdentity(
            "variable count is outside 2..=31",
        ));
    }
    let codeword_binding = codeword
        .binding_digest()
        .map_err(InitialWhirOracleV2Error::Codeword)?;
    let geometry = initial_whir_demand_blake3_tree_geometry(codeword.source.num_variables)
        .map_err(InitialWhirOracleV2Error::Tree)?;
    if tree.store_id == [0; 32] {
        return Err(InitialWhirOracleV2Error::InvalidIdentity(
            "tree store identity must be nonzero",
        ));
    }
    if tree.codeword_binding == [0; 32] || tree.codeword_binding != codeword_binding {
        return Err(InitialWhirOracleV2Error::CodewordTreeBindingMismatch);
    }
    if tree.height != codeword.height
        || tree.height != geometry.height
        || tree.width() != WHIR_INITIAL_WIDTH as u32
        || tree.artifact_bytes != geometry.artifact_bytes
    {
        return Err(InitialWhirOracleV2Error::InvalidIdentity(
            "codeword and tree geometry do not match",
        ));
    }
    Ok(geometry)
}

/// Prover-only identity binding an exact source artifact to one V2 oracle.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct InitialWhirProverIdentityV2 {
    encoded: [u8; INITIAL_WHIR_PROVER_V2_IDENTITY_BYTES],
}

impl std::fmt::Debug for InitialWhirProverIdentityV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InitialWhirProverIdentityV2")
            .field("binding_digest", &self.binding_digest())
            .field("oracle", &self.oracle_identity())
            .field("source_artifact", &self.source_artifact_identity())
            .finish()
    }
}

impl InitialWhirProverIdentityV2 {
    pub fn bind(
        oracle: &InitialWhirOracleIdentityV2,
        source_artifact: &WhirInitialSourceArtifactIdentity,
    ) -> Result<Self, InitialWhirProverV2Error> {
        validate_source_artifact_identity(source_artifact)?;
        if source_artifact.source != oracle.codeword_identity().source {
            return Err(InitialWhirProverV2Error::SourceIdentityMismatch);
        }

        let mut encoded = [0_u8; INITIAL_WHIR_PROVER_V2_IDENTITY_BYTES];
        encoded[..8].copy_from_slice(PROVER_MAGIC);
        encoded[PROVER_ORACLE_OFFSET..PROVER_ORACLE_OFFSET + INITIAL_WHIR_ORACLE_V2_IDENTITY_BYTES]
            .copy_from_slice(oracle.as_bytes());
        put_u32(
            &mut encoded,
            PROVER_SOURCE_FORMAT_VERSION_OFFSET,
            SOURCE_FORMAT_VERSION,
        );
        put_u32(
            &mut encoded,
            PROVER_SOURCE_HEADER_BYTES_OFFSET,
            WHIR_INITIAL_SOURCE_HEADER_BYTES as u32,
        );
        copy_digest(
            &mut encoded,
            PROVER_SOURCE_ID_OFFSET,
            source_artifact.source.source_id,
        );
        put_u32(
            &mut encoded,
            PROVER_NUM_VARIABLES_OFFSET,
            source_artifact.source.num_variables,
        );
        encoded[PROVER_LAYOUT_OFFSET] = NATURAL_MLE_LAYOUT;
        encoded[PROVER_ENCODING_OFFSET] = CANONICAL_U64_LE_ENCODING;
        put_u64(
            &mut encoded,
            PROVER_ELEMENT_COUNT_OFFSET,
            source_artifact.element_count,
        );
        copy_digest(
            &mut encoded,
            PROVER_SOURCE_DIGEST_OFFSET,
            source_artifact.artifact_global_digest,
        );
        let binding = prover_identity_binding(&encoded);
        copy_digest(&mut encoded, PROVER_BINDING_OFFSET, binding);
        Self::from_bytes(encoded)
    }

    pub fn from_bytes(
        encoded: [u8; INITIAL_WHIR_PROVER_V2_IDENTITY_BYTES],
    ) -> Result<Self, InitialWhirProverV2Error> {
        let identity = Self { encoded };
        identity.validate()?;
        Ok(identity)
    }

    pub const fn as_bytes(&self) -> &[u8; INITIAL_WHIR_PROVER_V2_IDENTITY_BYTES] {
        &self.encoded
    }

    pub const fn to_bytes(self) -> [u8; INITIAL_WHIR_PROVER_V2_IDENTITY_BYTES] {
        self.encoded
    }

    pub fn binding_digest(&self) -> [u8; 32] {
        read_digest(&self.encoded, PROVER_BINDING_OFFSET)
    }

    pub fn oracle_identity(&self) -> InitialWhirOracleIdentityV2 {
        let encoded = self.encoded
            [PROVER_ORACLE_OFFSET..PROVER_ORACLE_OFFSET + INITIAL_WHIR_ORACLE_V2_IDENTITY_BYTES]
            .try_into()
            .expect("fixed V2 oracle identity slice");
        InitialWhirOracleIdentityV2::from_bytes(encoded)
            .expect("validated V2 prover identity contains a valid oracle")
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

    fn validate(&self) -> Result<(), InitialWhirProverV2Error> {
        if &self.encoded[..8] != PROVER_MAGIC {
            return Err(InitialWhirProverV2Error::InvalidIdentity("wrong magic"));
        }
        if self.binding_digest() != prover_identity_binding(&self.encoded) {
            return Err(InitialWhirProverV2Error::InvalidIdentity(
                "binding digest does not match",
            ));
        }
        if read_u32(&self.encoded, PROVER_SOURCE_FORMAT_VERSION_OFFSET) != SOURCE_FORMAT_VERSION
            || read_u32(&self.encoded, PROVER_SOURCE_HEADER_BYTES_OFFSET)
                != WHIR_INITIAL_SOURCE_HEADER_BYTES as u32
            || self.encoded[PROVER_LAYOUT_OFFSET] != NATURAL_MLE_LAYOUT
            || self.encoded[PROVER_ENCODING_OFFSET] != CANONICAL_U64_LE_ENCODING
            || self.encoded[374..376] != [0; 2]
        {
            return Err(InitialWhirProverV2Error::InvalidIdentity(
                "source artifact format is not canonical",
            ));
        }
        let oracle_encoded = self.encoded
            [PROVER_ORACLE_OFFSET..PROVER_ORACLE_OFFSET + INITIAL_WHIR_ORACLE_V2_IDENTITY_BYTES]
            .try_into()
            .expect("fixed V2 oracle identity slice");
        let oracle = InitialWhirOracleIdentityV2::from_bytes(oracle_encoded)
            .map_err(InitialWhirProverV2Error::Oracle)?;
        let source_artifact = self.source_artifact_identity();
        validate_source_artifact_identity(&source_artifact)?;
        if source_artifact.source != oracle.codeword_identity().source {
            return Err(InitialWhirProverV2Error::SourceIdentityMismatch);
        }
        Ok(())
    }
}

fn validate_source_artifact_identity(
    source_artifact: &WhirInitialSourceArtifactIdentity,
) -> Result<(), InitialWhirProverV2Error> {
    if source_artifact.source.source_id == [0; 32]
        || source_artifact.artifact_global_digest == [0; 32]
    {
        return Err(InitialWhirProverV2Error::InvalidIdentity(
            "source IDs and digests must be nonzero",
        ));
    }
    let variables = usize::try_from(source_artifact.source.num_variables).map_err(|_| {
        InitialWhirProverV2Error::InvalidIdentity("source variable count does not fit usize")
    })?;
    if !(WHIR_INITIAL_MIN_VARIABLES..=WHIR_INITIAL_ARTIFACT_MAX_VARIABLES).contains(&variables) {
        return Err(InitialWhirProverV2Error::InvalidIdentity(
            "source variable count is outside 2..=31",
        ));
    }
    let expected_elements = 1_u64
        .checked_shl(source_artifact.source.num_variables)
        .ok_or(InitialWhirProverV2Error::InvalidIdentity(
            "source element count is not representable",
        ))?;
    if source_artifact.element_count != expected_elements {
        return Err(InitialWhirProverV2Error::InvalidIdentity(
            "source element count does not match num_variables",
        ));
    }
    Ok(())
}

/// One authenticated width-four row and its demand-loaded sibling path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitialWhirOpeningV2 {
    row_index: usize,
    row: [u64; WHIR_INITIAL_WIDTH],
    authentication_path: Vec<Blake3MerkleDigest>,
}

impl InitialWhirOpeningV2 {
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

/// Authenticated access to one exact V2 initial codeword/tree pair.
pub struct InitialWhirOracleV2 {
    identity: InitialWhirOracleIdentityV2,
    codeword: AuthenticatedWhirInitialCodeword,
    tree: AuthenticatedInitialDemandBlake3Tree,
}

impl std::fmt::Debug for InitialWhirOracleV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InitialWhirOracleV2")
            .field("identity", &self.identity)
            .field("codeword_path", &self.codeword.path())
            .field("tree_path", &self.tree.path())
            .finish_non_exhaustive()
    }
}

impl InitialWhirOracleV2 {
    /// Validate descriptor and context before opening either artifact.
    pub fn reopen(
        caller_context_digest: [u8; 32],
        expected: &InitialWhirOracleIdentityV2,
        codeword_path: impl AsRef<Path>,
        tree_path: impl AsRef<Path>,
    ) -> Result<Self, InitialWhirOracleV2Error> {
        expected.validate()?;
        expected.require_context(caller_context_digest)?;
        let codeword =
            AuthenticatedWhirInitialCodeword::open(codeword_path, &expected.codeword_identity())
                .map_err(map_codeword_open_error)?;
        let tree = AuthenticatedInitialDemandBlake3Tree::open(tree_path, &expected.tree_identity())
            .map_err(map_tree_open_error)?;
        Self::adopt_validated(expected, codeword, tree)
    }

    pub fn adopt(
        caller_context_digest: [u8; 32],
        expected: &InitialWhirOracleIdentityV2,
        codeword: AuthenticatedWhirInitialCodeword,
        tree: AuthenticatedInitialDemandBlake3Tree,
    ) -> Result<Self, InitialWhirOracleV2Error> {
        expected.validate()?;
        expected.require_context(caller_context_digest)?;
        Self::adopt_validated(expected, codeword, tree)
    }

    fn adopt_validated(
        expected: &InitialWhirOracleIdentityV2,
        codeword: AuthenticatedWhirInitialCodeword,
        tree: AuthenticatedInitialDemandBlake3Tree,
    ) -> Result<Self, InitialWhirOracleV2Error> {
        if codeword.identity() != &expected.codeword_identity() {
            return Err(InitialWhirOracleV2Error::CodewordIdentityMismatch);
        }
        if tree.identity() != &expected.tree_identity() {
            return Err(InitialWhirOracleV2Error::TreeIdentityMismatch);
        }
        validate_component_identities(codeword.identity(), tree.identity())?;
        Ok(Self {
            identity: *expected,
            codeword,
            tree,
        })
    }

    pub const fn identity(&self) -> &InitialWhirOracleIdentityV2 {
        &self.identity
    }

    pub fn height(&self) -> usize {
        usize::try_from(self.identity.tree_identity().height)
            .expect("bounded V2 initial tree height fits usize")
    }

    /// Return a row and path only after both artifacts authenticate it.
    pub fn opening(
        &self,
        row_index: usize,
    ) -> Result<InitialWhirOpeningV2, InitialWhirOracleV2Error> {
        validate_component_identities(self.codeword.identity(), self.tree.identity())?;
        let values = self
            .codeword
            .read_canonical_rows(row_index, 1)
            .map_err(InitialWhirOracleV2Error::Codeword)?;
        let row: [u64; WHIR_INITIAL_WIDTH] = values.try_into().map_err(|_| {
            InitialWhirOracleV2Error::InvalidIdentity("codeword row width changed after adoption")
        })?;
        let leaf = hash_canonical_row(&row);
        let authentication_path = self
            .tree
            .authenticate_leaf(row_index, leaf)
            .map_err(InitialWhirOracleV2Error::Tree)?;
        Ok(InitialWhirOpeningV2 {
            row_index,
            row,
            authentication_path,
        })
    }

    pub fn into_parts(
        self,
    ) -> (
        AuthenticatedWhirInitialCodeword,
        AuthenticatedInitialDemandBlake3Tree,
    ) {
        (self.codeword, self.tree)
    }
}

/// Authenticated access to an exact source artifact and its exact V2 oracle.
pub struct InitialWhirProverOracleV2 {
    identity: InitialWhirProverIdentityV2,
    source: AuthenticatedWhirInitialSourceFile,
    oracle: InitialWhirOracleV2,
}

impl std::fmt::Debug for InitialWhirProverOracleV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InitialWhirProverOracleV2")
            .field("identity", &self.identity)
            .field("source_path", &self.source.path())
            .field("oracle", &self.oracle)
            .finish_non_exhaustive()
    }
}

impl InitialWhirProverOracleV2 {
    pub fn reopen(
        caller_context_digest: [u8; 32],
        expected: &InitialWhirProverIdentityV2,
        source_path: impl AsRef<Path>,
        codeword_path: impl AsRef<Path>,
        tree_path: impl AsRef<Path>,
    ) -> Result<Self, InitialWhirProverV2Error> {
        expected.validate()?;
        let oracle_identity = expected.oracle_identity();
        oracle_identity
            .require_context(caller_context_digest)
            .map_err(InitialWhirProverV2Error::Oracle)?;
        let source = AuthenticatedWhirInitialSourceFile::open(
            source_path,
            &expected.source_artifact_identity(),
        )
        .map_err(map_source_open_error)?;
        let oracle = InitialWhirOracleV2::reopen(
            caller_context_digest,
            &oracle_identity,
            codeword_path,
            tree_path,
        )
        .map_err(InitialWhirProverV2Error::Oracle)?;
        Self::adopt_validated(expected, source, oracle)
    }

    pub fn adopt(
        caller_context_digest: [u8; 32],
        expected: &InitialWhirProverIdentityV2,
        source: AuthenticatedWhirInitialSourceFile,
        oracle: InitialWhirOracleV2,
    ) -> Result<Self, InitialWhirProverV2Error> {
        expected.validate()?;
        expected
            .oracle_identity()
            .require_context(caller_context_digest)
            .map_err(InitialWhirProverV2Error::Oracle)?;
        Self::adopt_validated(expected, source, oracle)
    }

    fn adopt_validated(
        expected: &InitialWhirProverIdentityV2,
        source: AuthenticatedWhirInitialSourceFile,
        oracle: InitialWhirOracleV2,
    ) -> Result<Self, InitialWhirProverV2Error> {
        if source.artifact_identity() != &expected.source_artifact_identity() {
            return Err(InitialWhirProverV2Error::SourceArtifactIdentityMismatch);
        }
        if oracle.identity() != &expected.oracle_identity() {
            return Err(InitialWhirProverV2Error::OracleIdentityMismatch);
        }
        Ok(Self {
            identity: *expected,
            source,
            oracle,
        })
    }

    pub const fn identity(&self) -> &InitialWhirProverIdentityV2 {
        &self.identity
    }

    pub const fn source(&self) -> &AuthenticatedWhirInitialSourceFile {
        &self.source
    }

    pub const fn oracle(&self) -> &InitialWhirOracleV2 {
        &self.oracle
    }

    pub fn into_parts(self) -> (AuthenticatedWhirInitialSourceFile, InitialWhirOracleV2) {
        (self.source, self.oracle)
    }
}

#[derive(Debug, Error)]
pub enum InitialWhirOracleV2Error {
    #[error("invalid initial WHIR V2 oracle identity: {0}")]
    InvalidIdentity(&'static str),
    #[error("initial WHIR V2 caller context does not match")]
    CallerContextMismatch,
    #[error("initial WHIR V2 codeword binding does not match its tree")]
    CodewordTreeBindingMismatch,
    #[error("initial WHIR V2 codeword identity does not match")]
    CodewordIdentityMismatch,
    #[error("initial WHIR V2 tree identity does not match")]
    TreeIdentityMismatch,
    #[error("initial WHIR V2 codeword access failed: {0}")]
    Codeword(#[source] WhirInitialEncodingError),
    #[error("initial WHIR V2 tree access failed: {0}")]
    Tree(#[source] DemandBlake3TreeError),
}

#[derive(Debug, Error)]
pub enum InitialWhirProverV2Error {
    #[error("invalid initial WHIR V2 prover identity: {0}")]
    InvalidIdentity(&'static str),
    #[error("initial WHIR V2 source identity does not match the oracle")]
    SourceIdentityMismatch,
    #[error("initial WHIR V2 source artifact identity does not match")]
    SourceArtifactIdentityMismatch,
    #[error("initial WHIR V2 oracle identity does not match the prover identity")]
    OracleIdentityMismatch,
    #[error("initial WHIR V2 source artifact access failed: {0}")]
    SourceArtifact(#[source] WhirInitialSourceArtifactError),
    #[error("initial WHIR V2 oracle access failed: {0}")]
    Oracle(#[source] InitialWhirOracleV2Error),
}

fn map_codeword_open_error(error: WhirInitialEncodingError) -> InitialWhirOracleV2Error {
    match error {
        WhirInitialEncodingError::IdentityMismatch => {
            InitialWhirOracleV2Error::CodewordIdentityMismatch
        }
        other => InitialWhirOracleV2Error::Codeword(other),
    }
}

fn map_tree_open_error(error: DemandBlake3TreeError) -> InitialWhirOracleV2Error {
    match error {
        DemandBlake3TreeError::IdentityMismatch => InitialWhirOracleV2Error::TreeIdentityMismatch,
        other => InitialWhirOracleV2Error::Tree(other),
    }
}

fn map_source_open_error(error: WhirInitialSourceArtifactError) -> InitialWhirProverV2Error {
    match error {
        WhirInitialSourceArtifactError::IdentityMismatch => {
            InitialWhirProverV2Error::SourceArtifactIdentityMismatch
        }
        other => InitialWhirProverV2Error::SourceArtifact(other),
    }
}

fn hash_canonical_row(row: &[u64; WHIR_INITIAL_WIDTH]) -> Blake3MerkleDigest {
    let mut hasher = Hasher::new();
    for value in row {
        hasher.update(&value.to_le_bytes());
    }
    *hasher.finalize().as_bytes()
}

fn oracle_identity_binding(encoded: &[u8; INITIAL_WHIR_ORACLE_V2_IDENTITY_BYTES]) -> [u8; 32] {
    let mut hasher = Hasher::new_derive_key(ORACLE_IDENTITY_DOMAIN);
    hasher.update(&encoded[..ORACLE_BINDING_OFFSET]);
    *hasher.finalize().as_bytes()
}

fn prover_identity_binding(encoded: &[u8; INITIAL_WHIR_PROVER_V2_IDENTITY_BYTES]) -> [u8; 32] {
    let mut hasher = Hasher::new_derive_key(PROVER_IDENTITY_DOMAIN);
    hasher.update(&encoded[..PROVER_BINDING_OFFSET]);
    *hasher.finalize().as_bytes()
}

fn copy_digest(encoded: &mut [u8], offset: usize, digest: [u8; 32]) {
    encoded[offset..offset + 32].copy_from_slice(&digest);
}

fn read_digest(encoded: &[u8], offset: usize) -> [u8; 32] {
    encoded[offset..offset + 32]
        .try_into()
        .expect("fixed digest slice")
}

fn put_u32(encoded: &mut [u8], offset: usize, value: u32) {
    encoded[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn read_u32(encoded: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        encoded[offset..offset + 4]
            .try_into()
            .expect("fixed u32 slice"),
    )
}

fn put_u64(encoded: &mut [u8], offset: usize, value: u64) {
    encoded[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn read_u64(encoded: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        encoded[offset..offset + 8]
            .try_into()
            .expect("fixed u64 slice"),
    )
}

#[cfg(test)]
mod tests {
    use std::fs::{self, OpenOptions};
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::blake3_merkle_store::Blake3MerkleStoreIdentity;
    use crate::demand_blake3_tree::build_whir_initial_demand_blake3_tree;
    use crate::initial_whir_oracle::{InitialWhirOracleIdentity, InitialWhirProverIdentity};
    use crate::merkle_store::GOLDILOCKS_MODULUS;
    use crate::whir_initial::{AuthenticatedWhirInitialSource, encode_whir_initial_suffix};
    use crate::whir_initial_source::WhirInitialSourceArtifactWriter;

    use super::*;

    const CONTEXT: [u8; 32] = [0x5a; 32];
    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "cmfd-initial-whir-v2-{label}-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct BuiltTriple {
        source: AuthenticatedWhirInitialSourceFile,
        codeword: AuthenticatedWhirInitialCodeword,
        tree: AuthenticatedInitialDemandBlake3Tree,
        oracle_identity: InitialWhirOracleIdentityV2,
        prover_identity: InitialWhirProverIdentityV2,
        source_path: PathBuf,
        codeword_path: PathBuf,
        tree_path: PathBuf,
        _directory: TestDirectory,
    }

    fn build_triple(label: &str, content_seed: u64, identity_seed: u8) -> BuiltTriple {
        let directory = TestDirectory::new(label);
        let source_path = directory.join("source");
        let codeword_path = directory.join("codeword");
        let tree_path = directory.join("tree");
        let source_identity = WhirInitialSourceIdentity {
            source_id: [identity_seed; 32],
            num_variables: 5,
        };
        let values = (0..1_usize << source_identity.num_variables)
            .map(|index| {
                content_seed.wrapping_add((index as u64).wrapping_mul(0x9e37_79b9))
                    % GOLDILOCKS_MODULUS
            })
            .collect::<Vec<_>>();
        let mut writer =
            WhirInitialSourceArtifactWriter::create(&source_path, source_identity.clone()).unwrap();
        for chunk in values.chunks(7) {
            writer.write_elements(chunk).unwrap();
        }
        let source = writer.finish().unwrap();
        let codeword = encode_whir_initial_suffix(
            &codeword_path,
            [identity_seed.wrapping_add(1); 32],
            &source_identity,
            &source,
        )
        .unwrap();
        let tree = build_whir_initial_demand_blake3_tree(
            &tree_path,
            [identity_seed.wrapping_add(2); 32],
            &codeword,
        )
        .unwrap();
        let oracle_identity =
            InitialWhirOracleIdentityV2::bind(CONTEXT, codeword.identity(), tree.identity())
                .unwrap();
        let prover_identity =
            InitialWhirProverIdentityV2::bind(&oracle_identity, source.artifact_identity())
                .unwrap();
        BuiltTriple {
            source,
            codeword,
            tree,
            oracle_identity,
            prover_identity,
            source_path,
            codeword_path,
            tree_path,
            _directory: directory,
        }
    }

    fn synthetic_identities(
        num_variables: u32,
        seed: u8,
    ) -> (WhirInitialCodewordIdentity, InitialDemandBlake3TreeIdentity) {
        let geometry = initial_whir_demand_blake3_tree_geometry(num_variables).unwrap();
        let codeword = WhirInitialCodewordIdentity {
            artifact_id: [seed; 32],
            source: WhirInitialSourceIdentity {
                source_id: [seed.wrapping_add(1); 32],
                num_variables,
            },
            height: geometry.height,
            width: WHIR_INITIAL_WIDTH as u32,
            artifact_digest: [seed.wrapping_add(2); 32],
        };
        let tree = InitialDemandBlake3TreeIdentity {
            store_id: [seed.wrapping_add(3); 32],
            codeword_binding: codeword.binding_digest().unwrap(),
            height: geometry.height,
            tree_root: [seed.wrapping_add(4); 32],
            artifact_bytes: geometry.artifact_bytes,
        };
        (codeword, tree)
    }

    #[test]
    fn v2_identity_layout_roundtrips_and_has_fixed_known_answer() {
        let built = build_triple("kat", 0x101, 0x21);
        let oracle_bytes = built.oracle_identity.to_bytes();
        assert_eq!(oracle_bytes.len(), INITIAL_WHIR_ORACLE_V2_IDENTITY_BYTES);
        assert_eq!(&oracle_bytes[..8], b"CMFDWIO2");
        assert_eq!(&oracle_bytes[8..40], &CONTEXT);
        assert_eq!(&oracle_bytes[40..44], &[1, 2, 1, 1]);
        assert_eq!(read_u32(&oracle_bytes, NUM_VARIABLES_OFFSET), 5);
        assert_eq!(read_u32(&oracle_bytes, TREE_FORMAT_VERSION_OFFSET), 1);
        assert_eq!(read_u32(&oracle_bytes, TREE_HEADER_BYTES_OFFSET), 256);
        assert_eq!(read_u32(&oracle_bytes, TREE_LAYER_COUNT_OFFSET), 5);
        assert_eq!(read_u32(&oracle_bytes, TREE_CAP_HEIGHT_OFFSET), 0);
        assert_eq!(
            InitialWhirOracleIdentityV2::from_bytes(oracle_bytes).unwrap(),
            built.oracle_identity
        );

        let prover_bytes = built.prover_identity.to_bytes();
        assert_eq!(prover_bytes.len(), INITIAL_WHIR_PROVER_V2_IDENTITY_BYTES);
        assert_eq!(&prover_bytes[..8], b"CMFDWIP2");
        assert_eq!(
            read_u32(&prover_bytes, PROVER_SOURCE_FORMAT_VERSION_OFFSET),
            1
        );
        assert_eq!(
            read_u32(&prover_bytes, PROVER_SOURCE_HEADER_BYTES_OFFSET),
            160
        );
        assert_eq!(
            InitialWhirProverIdentityV2::from_bytes(prover_bytes).unwrap(),
            built.prover_identity
        );

        assert_eq!(
            *blake3::hash(&oracle_bytes).as_bytes(),
            [
                0xa4, 0x6e, 0xd2, 0x4f, 0x66, 0xbd, 0x90, 0x5b, 0xf6, 0x0d, 0x08, 0x6e, 0xe7, 0x40,
                0xaa, 0xc7, 0x75, 0x88, 0xb5, 0x66, 0x13, 0xeb, 0x89, 0x2f, 0x6a, 0x49, 0x8c, 0xde,
                0xe7, 0x94, 0x29, 0x69,
            ],
            "V2 oracle identity KAT changed"
        );
        assert_eq!(
            *blake3::hash(&prover_bytes).as_bytes(),
            [
                0x50, 0x70, 0xff, 0x60, 0xfa, 0xba, 0x16, 0x82, 0xdb, 0x3b, 0xfc, 0xe3, 0x98, 0x77,
                0xb9, 0x7f, 0x6e, 0xb3, 0x5c, 0x7d, 0xf0, 0xc8, 0xc3, 0x9f, 0x3f, 0xb9, 0x22, 0x7c,
                0x53, 0xa5, 0x94, 0xd8,
            ],
            "V2 prover identity KAT changed"
        );
    }

    #[test]
    fn v1_identity_known_answers_remain_frozen() {
        let (codeword, _) = synthetic_identities(5, 0x31);
        let tree = Blake3MerkleStoreIdentity {
            store_id: [0x41; 32],
            height: 16,
            ordered_matrix_widths: vec![4],
            tree_root: [0x42; 32],
            artifact_global_digest: [0x43; 32],
        };
        let oracle =
            InitialWhirOracleIdentity::bind(CONTEXT, &codeword, &tree, tree.tree_root).unwrap();
        let source = WhirInitialSourceArtifactIdentity {
            source: codeword.source,
            element_count: 32,
            artifact_global_digest: [0x44; 32],
        };
        let prover = InitialWhirProverIdentity::bind(&oracle, &source).unwrap();
        assert_eq!(oracle.as_bytes().len(), 296);
        assert_eq!(prover.as_bytes().len(), 416);
        assert_eq!(&oracle.as_bytes()[..8], b"CMFDWIO1");
        assert_eq!(&prover.as_bytes()[..8], b"CMFDWIP1");
        assert_eq!(
            *blake3::hash(oracle.as_bytes()).as_bytes(),
            [
                0x10, 0xc9, 0x4a, 0x86, 0x7d, 0x99, 0xec, 0x89, 0x0f, 0x99, 0xe7, 0xfe, 0xc7, 0x8d,
                0x7e, 0x97, 0x61, 0x28, 0x1b, 0x98, 0xfa, 0x2c, 0xdd, 0x02, 0xc9, 0xb7, 0x80, 0x78,
                0x8b, 0xbf, 0x3f, 0x16,
            ],
            "V1 oracle identity KAT changed"
        );
        assert_eq!(
            *blake3::hash(prover.as_bytes()).as_bytes(),
            [
                0x65, 0x0f, 0x98, 0x5d, 0x66, 0xec, 0x07, 0x50, 0x1e, 0xcc, 0x32, 0xa4, 0x5f, 0xce,
                0xde, 0xdc, 0x2f, 0x3a, 0x89, 0xc3, 0x2c, 0xac, 0x11, 0xf1, 0x6a, 0xf4, 0x88, 0x54,
                0xb2, 0xc2, 0x15, 0x13,
            ],
            "V1 prover identity KAT changed"
        );
    }

    #[test]
    fn synthetic_identities_admit_two_through_thirty_one_and_pin_n31_geometry() {
        for num_variables in 2..=31 {
            let (codeword, tree) = synthetic_identities(num_variables, num_variables as u8 + 1);
            let identity = InitialWhirOracleIdentityV2::bind(CONTEXT, &codeword, &tree).unwrap();
            assert_eq!(identity.codeword_identity(), codeword);
            assert_eq!(identity.tree_identity(), tree);
            let source = WhirInitialSourceArtifactIdentity {
                source: codeword.source.clone(),
                element_count: 1_u64 << num_variables,
                artifact_global_digest: [num_variables as u8 + 7; 32],
            };
            assert!(InitialWhirProverIdentityV2::bind(&identity, &source).is_ok());
        }

        let (codeword, tree) = synthetic_identities(31, 0xa1);
        assert_eq!(codeword.height, 1_073_741_824);
        assert_eq!(tree.height, 1_073_741_824);
        assert_eq!(tree.artifact_bytes, 68_719_476_960);
        let source = WhirInitialSourceArtifactIdentity {
            source: codeword.source.clone(),
            element_count: 2_147_483_648,
            artifact_global_digest: [0xa8; 32],
        };
        let identity = InitialWhirOracleIdentityV2::bind(CONTEXT, &codeword, &tree).unwrap();
        assert!(InitialWhirProverIdentityV2::bind(&identity, &source).is_ok());

        for invalid in [1, 32] {
            let geometry_n = if invalid == 1 { 2 } else { 31 };
            let (mut codeword, mut tree) = synthetic_identities(geometry_n, 0xb1);
            codeword.source.num_variables = invalid;
            tree.codeword_binding = [0xb2; 32];
            assert!(InitialWhirOracleIdentityV2::bind(CONTEXT, &codeword, &tree).is_err());
        }
    }

    #[test]
    fn descriptor_and_component_mutations_fail_before_capability() {
        let (codeword, tree) = synthetic_identities(5, 0x51);
        let identity = InitialWhirOracleIdentityV2::bind(CONTEXT, &codeword, &tree).unwrap();

        for offset in [
            CONTEXT_OFFSET,
            TREE_STORE_ID_OFFSET,
            TREE_ROOT_OFFSET,
            ORACLE_BINDING_OFFSET,
        ] {
            let mut bytes = identity.to_bytes();
            bytes[offset] ^= 1;
            assert!(
                InitialWhirOracleIdentityV2::from_bytes(bytes).is_err(),
                "unbound mutation at offset {offset} was admitted"
            );
        }

        for offset in [
            40,
            NUM_VARIABLES_OFFSET,
            CODEWORD_HEIGHT_OFFSET,
            TREE_HEIGHT_OFFSET,
            CODEWORD_WIDTH_OFFSET,
            TREE_WIDTH_OFFSET,
            CODEWORD_ARTIFACT_ID_OFFSET,
            CODEWORD_BINDING_OFFSET,
            TREE_ARTIFACT_BYTES_OFFSET,
            TREE_FORMAT_VERSION_OFFSET,
            TREE_HEADER_BYTES_OFFSET,
            TREE_LAYER_COUNT_OFFSET,
            TREE_CAP_HEIGHT_OFFSET,
        ] {
            let mut bytes = identity.to_bytes();
            bytes[offset] ^= 1;
            let binding = oracle_identity_binding(&bytes);
            copy_digest(&mut bytes, ORACLE_BINDING_OFFSET, binding);
            assert!(
                InitialWhirOracleIdentityV2::from_bytes(bytes).is_err(),
                "semantic mutation at offset {offset} was admitted"
            );
        }

        let mut wrong_binding = tree;
        wrong_binding.codeword_binding[0] ^= 1;
        assert!(matches!(
            InitialWhirOracleIdentityV2::bind(CONTEXT, &codeword, &wrong_binding),
            Err(InitialWhirOracleV2Error::CodewordTreeBindingMismatch)
        ));
        let mut wrong_bytes = wrong_binding;
        wrong_bytes.codeword_binding = codeword.binding_digest().unwrap();
        wrong_bytes.artifact_bytes += 1;
        assert!(InitialWhirOracleIdentityV2::bind(CONTEXT, &codeword, &wrong_bytes).is_err());
        let mut zero_store = wrong_binding;
        zero_store.codeword_binding = codeword.binding_digest().unwrap();
        zero_store.store_id = [0; 32];
        assert!(InitialWhirOracleIdentityV2::bind(CONTEXT, &codeword, &zero_store).is_err());
        assert!(InitialWhirOracleIdentityV2::bind([0; 32], &codeword, &tree).is_err());
    }

    #[test]
    fn v1_and_v2_identity_magics_are_not_cross_decodable() {
        let (codeword, tree) = synthetic_identities(5, 0x58);
        let v2 = InitialWhirOracleIdentityV2::bind(CONTEXT, &codeword, &tree).unwrap();
        let mut v2_as_v1 = [0_u8; 296];
        v2_as_v1.copy_from_slice(&v2.as_bytes()[..296]);
        assert!(InitialWhirOracleIdentity::from_bytes(v2_as_v1).is_err());

        let v1_tree = Blake3MerkleStoreIdentity {
            store_id: [0x61; 32],
            height: 16,
            ordered_matrix_widths: vec![4],
            tree_root: [0x62; 32],
            artifact_global_digest: [0x63; 32],
        };
        let v1 = InitialWhirOracleIdentity::bind(CONTEXT, &codeword, &v1_tree, v1_tree.tree_root)
            .unwrap();
        let mut v1_as_v2 = [0_u8; INITIAL_WHIR_ORACLE_V2_IDENTITY_BYTES];
        v1_as_v2[..296].copy_from_slice(v1.as_bytes());
        assert!(InitialWhirOracleIdentityV2::from_bytes(v1_as_v2).is_err());
    }

    #[test]
    fn prover_descriptor_mutations_and_source_cross_pairing_fail() {
        let built = build_triple("prover-mutations", 0x202, 0x61);
        for offset in [
            PROVER_SOURCE_FORMAT_VERSION_OFFSET,
            PROVER_SOURCE_HEADER_BYTES_OFFSET,
            PROVER_SOURCE_ID_OFFSET,
            PROVER_NUM_VARIABLES_OFFSET,
            PROVER_LAYOUT_OFFSET,
            PROVER_ENCODING_OFFSET,
            374,
            PROVER_ELEMENT_COUNT_OFFSET,
        ] {
            let mut bytes = built.prover_identity.to_bytes();
            bytes[offset] ^= 1;
            let binding = prover_identity_binding(&bytes);
            copy_digest(&mut bytes, PROVER_BINDING_OFFSET, binding);
            assert!(
                InitialWhirProverIdentityV2::from_bytes(bytes).is_err(),
                "semantic prover mutation at offset {offset} was admitted"
            );
        }

        let mut wrong_source = built.source.artifact_identity().clone();
        wrong_source.source.source_id[0] ^= 1;
        assert!(matches!(
            InitialWhirProverIdentityV2::bind(&built.oracle_identity, &wrong_source),
            Err(InitialWhirProverV2Error::SourceIdentityMismatch)
        ));
        let mut wrong_count = built.source.artifact_identity().clone();
        wrong_count.element_count -= 1;
        assert!(InitialWhirProverIdentityV2::bind(&built.oracle_identity, &wrong_count).is_err());
    }

    #[test]
    fn adopt_reopen_and_openings_authenticate_all_three_artifacts() {
        let built = build_triple("happy", 0x303, 0x71);
        let identity = built.oracle_identity;
        let prover_identity = built.prover_identity;
        let source_path = built.source_path.clone();
        let codeword_path = built.codeword_path.clone();
        let tree_path = built.tree_path.clone();
        let oracle =
            InitialWhirOracleV2::adopt(CONTEXT, &identity, built.codeword, built.tree).unwrap();
        for index in [0, 1, 7, oracle.height() - 1] {
            let opening = oracle.opening(index).unwrap();
            assert_eq!(opening.row_index(), index);
            assert_eq!(opening.row().len(), 4);
            assert_eq!(
                opening.authentication_path().len(),
                oracle.height().ilog2() as usize
            );
        }
        let prover =
            InitialWhirProverOracleV2::adopt(CONTEXT, &prover_identity, built.source, oracle)
                .unwrap();
        assert_eq!(prover.identity(), &prover_identity);
        assert_eq!(prover.source().read_elements(3, 2).unwrap().len(), 2);
        drop(prover);

        let reopened = InitialWhirProverOracleV2::reopen(
            CONTEXT,
            &prover_identity,
            source_path,
            codeword_path,
            tree_path,
        )
        .unwrap();
        assert_eq!(reopened.oracle().opening(3).unwrap().row_index(), 3);
    }

    #[test]
    fn retained_identity_rejects_cross_pairs_and_whole_pair_substitution() {
        let first = build_triple("cross-first", 0x404, 0x81);
        let second = build_triple("cross-second", 0x405, 0x91);
        let first_identity = first.oracle_identity;
        assert!(matches!(
            InitialWhirOracleV2::adopt(CONTEXT, &first_identity, second.codeword, first.tree,),
            Err(InitialWhirOracleV2Error::CodewordIdentityMismatch)
        ));

        let first = build_triple("substitution-first", 0x406, 0xa1);
        let second = build_triple("substitution-second", 0x407, 0xb1);
        let retained = first.oracle_identity;
        let replacement_codeword = second.codeword_path.clone();
        let replacement_tree = second.tree_path.clone();
        drop(first);
        drop(second.codeword);
        drop(second.tree);
        assert!(matches!(
            InitialWhirOracleV2::reopen(CONTEXT, &retained, replacement_codeword, replacement_tree,),
            Err(InitialWhirOracleV2Error::CodewordIdentityMismatch)
        ));
    }

    #[test]
    fn caller_context_and_post_open_mutations_return_no_opening() {
        let built = build_triple("context", 0x505, 0xc1);
        let missing = built.codeword_path.with_extension("missing");
        assert!(matches!(
            InitialWhirOracleV2::reopen([0xff; 32], &built.oracle_identity, &missing, &missing,),
            Err(InitialWhirOracleV2Error::CallerContextMismatch)
        ));
        drop(built);

        let built = build_triple("mutated-codeword", 0x506, 0xd1);
        let codeword_path = built.codeword_path.clone();
        let oracle =
            InitialWhirOracleV2::adopt(CONTEXT, &built.oracle_identity, built.codeword, built.tree)
                .unwrap();
        mutate_byte(&codeword_path, 160);
        assert!(matches!(
            oracle.opening(0),
            Err(InitialWhirOracleV2Error::Codeword(
                WhirInitialEncodingError::ChecksumMismatch
            ))
        ));
        drop(oracle);

        let built = build_triple("mutated-tree", 0x507, 0xe1);
        let tree_path = built.tree_path.clone();
        let oracle =
            InitialWhirOracleV2::adopt(CONTEXT, &built.oracle_identity, built.codeword, built.tree)
                .unwrap();
        mutate_byte(&tree_path, 256 + 32);
        assert!(matches!(
            oracle.opening(0),
            Err(InitialWhirOracleV2Error::Tree(
                DemandBlake3TreeError::OpeningMismatch
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
}
