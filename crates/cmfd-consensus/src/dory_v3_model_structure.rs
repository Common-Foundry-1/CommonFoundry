//! Frozen structural analysis for the production Dory V3 model payload.
//!
//! The analyzer deliberately rereads the raw payload independently of the
//! roots-file producer. It retains at most one weight layer and small indexes,
//! emits only the fixed CMFDSR01 codec, and accepts only opaque roots authority
//! minted by repeated full-payload verification.

use std::{
    collections::BTreeMap,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    MAX_MODEL_BYTE,
    dory_v3_model_ceremony_fs::{
        AuthenticatedInput, CeremonyFsError, ParentSyncOutcome, PendingOutput,
        TrustedCeremonyParent,
    },
    dory_v3_model_roots::ProductionDoryV3ModelRoots,
    dory_v3_suite::{DORY_V3_BATCH, DORY_V3_DIMENSION, DORY_V3_LAYERS, Digest32},
    model_bank::{add_layer_root, start_layer_aggregate},
};

pub const PRODUCTION_DORY_V3_MODEL_STRUCTURAL_REPORT_MAGIC: [u8; 8] = *b"CMFDSR01";
pub const PRODUCTION_DORY_V3_MODEL_STRUCTURAL_REPORT_VERSION: u16 = 1;
pub const PRODUCTION_DORY_V3_MODEL_STRUCTURAL_SECTION_COUNT: u32 = 385;
pub const PRODUCTION_DORY_V3_MODEL_STRUCTURAL_REPORT_BYTES: usize = 799_795;

const FROZEN_PRODUCTION_PAYLOAD_BYTES: u64 = 6_442_975_232;
const BASE_SECTION_INDEX: u32 = u32::MAX;
const HISTOGRAM_BINS: usize = MAX_MODEL_BYTE as usize + 1;
const STRUCTURAL_SECTION_RECORD_BYTES: usize = 1 + 4 + 4 + 4 + 8 + 32 + HISTOGRAM_BINS * 8 + 8 + 8;
const STRUCTURAL_HEADER_BYTES: usize = 8 + 2 + 32 + 8 + 32 + 32 + 4;
const STRUCTURAL_TRAILER_BYTES: usize = 8 + 8 + 8 + 4 + 4;
const DIAGNOSTIC_CONSTANT: u32 = 1 << 0;
const DIAGNOSTIC_DUPLICATE_ROW_OR_COLUMN: u32 = 1 << 1;
const DIAGNOSTIC_DUPLICATE_LAYER: u32 = 1 << 2;
const DIAGNOSTIC_ALLOWED_MASK: u32 =
    DIAGNOSTIC_CONSTANT | DIAGNOSTIC_DUPLICATE_ROW_OR_COLUMN | DIAGNOSTIC_DUPLICATE_LAYER;
const FATAL_HISTOGRAM: u32 = 1 << 0;
const FATAL_ROOT: u32 = 1 << 1;
const FATAL_ALLOWED_MASK: u32 = FATAL_HISTOGRAM | FATAL_ROOT;
const COLUMN_TRANSPOSE_BLOCK: usize = 64;
const COMPARE_BUFFER_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DoryV3ModelStructuralSectionKind {
    Base = 0,
    WeightLayer = 1,
}

impl DoryV3ModelStructuralSectionKind {
    fn decode(value: u8) -> Result<Self, ProductionDoryV3ModelStructureError> {
        match value {
            0 => Ok(Self::Base),
            1 => Ok(Self::WeightLayer),
            _ => Err(ProductionDoryV3ModelStructureError::InvalidSectionKind(
                value,
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoryV3ModelStructuralSection {
    kind: DoryV3ModelStructuralSectionKind,
    index: u32,
    rows: u32,
    columns: u32,
    section_bytes: u64,
    section_blake3_root: Digest32,
    histogram: [u64; HISTOGRAM_BINS],
    constant_rows: u64,
    constant_columns: u64,
}

impl DoryV3ModelStructuralSection {
    pub const fn kind(&self) -> DoryV3ModelStructuralSectionKind {
        self.kind
    }

    pub const fn index(&self) -> u32 {
        self.index
    }

    pub const fn rows(&self) -> u32 {
        self.rows
    }

    pub const fn columns(&self) -> u32 {
        self.columns
    }

    pub const fn section_bytes(&self) -> u64 {
        self.section_bytes
    }

    pub const fn section_blake3_root(&self) -> Digest32 {
        self.section_blake3_root
    }

    pub const fn histogram(&self) -> &[u64; HISTOGRAM_BINS] {
        &self.histogram
    }

    pub const fn constant_rows(&self) -> u64 {
        self.constant_rows
    }

    pub const fn constant_columns(&self) -> u64 {
        self.constant_columns
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionDoryV3ModelStructuralReport {
    ceremony_id: Digest32,
    payload_bytes: u64,
    raw_payload_blake3: Digest32,
    raw_payload_sha256: Digest32,
    sections: Vec<DoryV3ModelStructuralSection>,
    duplicate_row_pairs: u64,
    duplicate_column_pairs: u64,
    duplicate_layer_pairs: u64,
    diagnostic_mask: u32,
    fatal_mask: u32,
}

impl ProductionDoryV3ModelStructuralReport {
    pub const fn ceremony_id(&self) -> Digest32 {
        self.ceremony_id
    }

    pub const fn payload_bytes(&self) -> u64 {
        self.payload_bytes
    }

    pub const fn raw_payload_blake3(&self) -> Digest32 {
        self.raw_payload_blake3
    }

    pub const fn raw_payload_sha256(&self) -> Digest32 {
        self.raw_payload_sha256
    }

    pub fn sections(&self) -> &[DoryV3ModelStructuralSection] {
        &self.sections
    }

    pub const fn duplicate_row_pairs(&self) -> u64 {
        self.duplicate_row_pairs
    }

    pub const fn duplicate_column_pairs(&self) -> u64 {
        self.duplicate_column_pairs
    }

    pub const fn duplicate_layer_pairs(&self) -> u64 {
        self.duplicate_layer_pairs
    }

    pub const fn diagnostic_mask(&self) -> u32 {
        self.diagnostic_mask
    }

    pub const fn fatal_mask(&self) -> u32 {
        self.fatal_mask
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        encode_report(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionDoryV3ModelStructuralReportRun {
    pub output: PathBuf,
    pub report_bytes: u64,
    pub report_blake3: Digest32,
    pub report_sha256: Digest32,
    pub durability: ProductionDoryV3ModelStructuralReportDurability,
    pub report: ProductionDoryV3ModelStructuralReport,
}

/// What the platform could durably synchronize for the create-new report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductionDoryV3ModelStructuralReportDurability {
    FileAndParentDirectorySynced,
    FileSyncedParentDirectorySyncAccessDeniedOnWindows,
    FileSyncedParentDirectorySyncUnsupportedOnWindows,
    FileSyncedParentDirectorySyncUnsupportedOnPlatform,
}

#[derive(Debug, Error)]
pub enum ProductionDoryV3ModelStructureError {
    #[error("production structural geometry overflowed")]
    GeometryOverflow,
    #[error(
        "the compiled production structural geometry is not the frozen 128x4096 base plus 384 4096x4096 layers"
    )]
    ProductionGeometryMismatch,
    #[error("the decoded roots artifact does not have the frozen production geometry")]
    RootsGeometryMismatch,
    #[error("failed to inspect payload {path}: {source}")]
    InspectPayload {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("payload path is not a regular file: {0}")]
    PayloadNotRegular(PathBuf),
    #[error("payload path uses an unsafe or nonlocal parent boundary: {0}")]
    InvalidPayloadPath(PathBuf),
    #[error("payload path is a reparse point: {0}")]
    PayloadReparsePoint(PathBuf),
    #[error("payload must have exactly one hard link, found {links}: {path}")]
    PayloadHardLinks { path: PathBuf, links: u64 },
    #[error("payload length mismatch: expected {expected} bytes, found {actual}")]
    PayloadLength { expected: u64, actual: u64 },
    #[error("failed to open payload {path}: {source}")]
    OpenPayload {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("payload path was replaced while it was being analyzed: {0}")]
    PayloadIdentityMismatch(PathBuf),
    #[error("failed to read or seek the payload: {0}")]
    ReadPayload(#[source] std::io::Error),
    #[error(
        "payload ended early at byte {offset}; expected {expected} bytes in the section, read {actual}"
    )]
    EarlyEof {
        offset: u64,
        expected: u64,
        actual: u64,
    },
    #[error("payload has trailing data after {0} bytes")]
    TrailingBytes(u64),
    #[error("payload byte {value} at offset {offset} exceeds 250")]
    OutOfRange { offset: u64, value: u8 },
    #[error("a structural counter overflowed")]
    CounterOverflow,
    #[error(
        "structural analysis produced fatal mask 0x{0:08x}; no completed report may be emitted"
    )]
    FatalAnalysis(u32),
    #[error("structural report length mismatch: expected {expected} bytes, found {actual}")]
    ReportLength { expected: usize, actual: usize },
    #[error("invalid structural report magic")]
    InvalidMagic,
    #[error("unsupported structural report version {0}")]
    UnsupportedVersion(u16),
    #[error("structural report ceremony ID differs from the roots artifact")]
    CeremonyIdMismatch,
    #[error("structural report payload length is not canonical")]
    InvalidReportPayloadLength,
    #[error("structural report section count is not canonical")]
    InvalidSectionCount,
    #[error("invalid structural section kind {0}")]
    InvalidSectionKind(u8),
    #[error("structural section {position} has invalid order or geometry")]
    InvalidSectionGeometry { position: usize },
    #[error("structural section {position} has a counter outside its geometry")]
    InvalidSectionCounter { position: usize },
    #[error("diagnostic mask has nonzero reserved bits")]
    ReservedDiagnosticBits,
    #[error("diagnostic mask does not agree exactly with the report counters")]
    DiagnosticMaskMismatch,
    #[error("fatal mask has nonzero reserved bits")]
    ReservedFatalBits,
    #[error("fatal mask does not agree exactly with histogram and roots comparisons")]
    FatalMaskMismatch,
    #[error("a completed structural report has a nonzero fatal mask")]
    NonzeroFatalMask,
    #[error("structural report root fields differ from the payload-verified roots artifact")]
    RootMismatch,
    #[error("refusing to overwrite existing output: {0}")]
    OutputExists(PathBuf),
    #[error("output path uses disallowed platform syntax: {0}")]
    InvalidOutputPath(PathBuf),
    #[error("output parent is not an existing directory: {0}")]
    OutputParent(PathBuf),
    #[error("failed to inspect output {path}: {source}")]
    InspectOutput {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to create output {path}: {source}")]
    CreateOutput {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to write or synchronize output {path}: {source}")]
    WriteOutput {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to reopen output {path}: {source}")]
    ReopenOutput {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("reopened structural report differs from the report that was written")]
    ReopenedReportMismatch,
    #[error("structural report counters or roots do not reproduce from the payload")]
    PayloadReportMismatch,
    #[error("payload and structural report resolve to the same file")]
    PayloadReportSameFile,
    #[error("output path was replaced while it was being authenticated: {0}")]
    OutputIdentityMismatch(PathBuf),
    #[error("output path is a reparse point: {0}")]
    OutputReparsePoint(PathBuf),
    #[error("output must have exactly one hard link, found {links}: {path}")]
    OutputHardLinks { path: PathBuf, links: u64 },
    #[error("failed to set private output permissions on {path}: {source}")]
    SetOutputPermissions {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to sync output parent {path}: {source}")]
    SyncParent {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to remove unconfirmed structural report {path}: {source}")]
    CleanupOutput {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "unconfirmed structural report remains quarantined at {path}; original failure: {original}; cleanup failure: {cleanup}"
    )]
    QuarantinedOutput {
        path: PathBuf,
        original: String,
        cleanup: String,
    },
}

#[derive(Debug, Clone, Copy)]
struct StructuralGeometry {
    base_rows: u32,
    columns: u32,
    layer_rows: u32,
    layers: u32,
}

impl StructuralGeometry {
    fn production() -> Result<Self, ProductionDoryV3ModelStructureError> {
        let geometry = Self {
            base_rows: DORY_V3_BATCH,
            columns: DORY_V3_DIMENSION,
            layer_rows: DORY_V3_DIMENSION,
            layers: DORY_V3_LAYERS,
        };
        if geometry.base_rows != 128
            || geometry.columns != 4_096
            || geometry.layer_rows != 4_096
            || geometry.layers != 384
            || geometry.section_count()? != PRODUCTION_DORY_V3_MODEL_STRUCTURAL_SECTION_COUNT
            || geometry.payload_bytes()? != FROZEN_PRODUCTION_PAYLOAD_BYTES
        {
            return Err(ProductionDoryV3ModelStructureError::ProductionGeometryMismatch);
        }
        Ok(geometry)
    }

    fn section_count(self) -> Result<u32, ProductionDoryV3ModelStructureError> {
        self.layers
            .checked_add(1)
            .ok_or(ProductionDoryV3ModelStructureError::GeometryOverflow)
    }

    fn base_bytes(self) -> Result<u64, ProductionDoryV3ModelStructureError> {
        u64::from(self.base_rows)
            .checked_mul(u64::from(self.columns))
            .ok_or(ProductionDoryV3ModelStructureError::GeometryOverflow)
    }

    fn layer_bytes(self) -> Result<u64, ProductionDoryV3ModelStructureError> {
        u64::from(self.layer_rows)
            .checked_mul(u64::from(self.columns))
            .ok_or(ProductionDoryV3ModelStructureError::GeometryOverflow)
    }

    fn payload_bytes(self) -> Result<u64, ProductionDoryV3ModelStructureError> {
        u64::from(self.layers)
            .checked_mul(self.layer_bytes()?)
            .and_then(|layers| layers.checked_add(self.base_bytes().ok()?))
            .ok_or(ProductionDoryV3ModelStructureError::GeometryOverflow)
    }
}

#[derive(Debug, Clone)]
struct ExpectedRoots {
    ceremony_id: Digest32,
    payload_bytes: u64,
    raw_blake3: Digest32,
    raw_sha256: Digest32,
    base_root: Digest32,
    layer_roots: Vec<Digest32>,
    layer_aggregate: Digest32,
}

impl ExpectedRoots {
    fn from_production(
        roots: &ProductionDoryV3ModelRoots,
        geometry: StructuralGeometry,
    ) -> Result<Self, ProductionDoryV3ModelStructureError> {
        let expected_layers = usize::try_from(geometry.layers)
            .map_err(|_| ProductionDoryV3ModelStructureError::GeometryOverflow)?;
        if roots.payload_bytes() != geometry.payload_bytes()?
            || roots.layer_roots().len() != expected_layers
        {
            return Err(ProductionDoryV3ModelStructureError::RootsGeometryMismatch);
        }
        Ok(Self {
            ceremony_id: roots.ceremony_id(),
            payload_bytes: roots.payload_bytes(),
            raw_blake3: roots.raw_blake3(),
            raw_sha256: roots.raw_sha256(),
            base_root: roots.base_input_blake3_root(),
            layer_roots: roots.layer_roots().to_vec(),
            layer_aggregate: roots.layer_roots_aggregate(),
        })
    }
}

#[derive(Debug)]
struct LayerClass {
    representative_offset: u64,
    count: u64,
}

/// Analyze the exact production payload independently and compare every root
/// to the payload-verified roots artifact.
pub fn analyze_production_dory_v3_model_structure<R: Read + Seek>(
    reader: &mut R,
    roots: &ProductionDoryV3ModelRoots,
) -> Result<ProductionDoryV3ModelStructuralReport, ProductionDoryV3ModelStructureError> {
    let geometry = StructuralGeometry::production()?;
    let expected = ExpectedRoots::from_production(roots, geometry)?;
    analyze_with_geometry(reader, geometry, &expected)
}

/// Parse the fixed report, independently rescan the complete payload, and
/// require byte-for-byte equality with the reproduced canonical report.
pub fn verify_production_dory_v3_model_structural_report<R: Read + Seek>(
    reader: &mut R,
    report_bytes: &[u8],
    roots: &ProductionDoryV3ModelRoots,
) -> Result<ProductionDoryV3ModelStructuralReport, ProductionDoryV3ModelStructureError> {
    let geometry = StructuralGeometry::production()?;
    let expected = ExpectedRoots::from_production(roots, geometry)?;
    verify_with_geometry(reader, report_bytes, geometry, &expected)
}

fn verify_with_geometry<R: Read + Seek>(
    reader: &mut R,
    report_bytes: &[u8],
    geometry: StructuralGeometry,
    expected: &ExpectedRoots,
) -> Result<ProductionDoryV3ModelStructuralReport, ProductionDoryV3ModelStructureError> {
    let parsed = parse_and_validate_with_geometry(report_bytes, geometry, expected, true)?;
    let reproduced = analyze_with_geometry(reader, geometry, expected)?;
    if reproduced != parsed || reproduced.canonical_bytes() != report_bytes {
        return Err(ProductionDoryV3ModelStructureError::PayloadReportMismatch);
    }
    Ok(parsed)
}

/// Analyze, create-new write, synchronize, reopen, parse, and authenticate the
/// frozen production structural report.
pub fn run_production_dory_v3_model_structural_report(
    payload_path: &Path,
    roots: &ProductionDoryV3ModelRoots,
    output_path: &Path,
) -> Result<ProductionDoryV3ModelStructuralReportRun, ProductionDoryV3ModelStructureError> {
    let geometry = StructuralGeometry::production()?;
    let expected = ExpectedRoots::from_production(roots, geometry)?;
    run_with_geometry(payload_path, output_path, geometry, &expected, true)
}

/// Authenticate existing payload and report files by retained identity, rescan
/// the complete payload, then reread and reparse the unchanged report.
pub fn validate_production_dory_v3_model_structural_report_files(
    payload_path: &Path,
    report_path: &Path,
    roots: &ProductionDoryV3ModelRoots,
) -> Result<ProductionDoryV3ModelStructuralReport, ProductionDoryV3ModelStructureError> {
    let geometry = StructuralGeometry::production()?;
    let expected = ExpectedRoots::from_production(roots, geometry)?;
    validate_files_with_geometry(payload_path, report_path, geometry, &expected, true)
}

fn validate_files_with_geometry(
    payload_path: &Path,
    report_path: &Path,
    geometry: StructuralGeometry,
    expected: &ExpectedRoots,
    require_production_size: bool,
) -> Result<ProductionDoryV3ModelStructuralReport, ProductionDoryV3ModelStructureError> {
    let payload_bytes = geometry.payload_bytes()?;
    let payload_parent =
        TrustedCeremonyParent::for_artifact(payload_path).map_err(map_structure_payload_fs)?;
    let report_parent_holder = if report_path.parent() == payload_path.parent() {
        None
    } else {
        Some(
            TrustedCeremonyParent::for_artifact(report_path)
                .map_err(map_structure_report_input_fs)?,
        )
    };
    let report_parent = report_parent_holder.as_ref().unwrap_or(&payload_parent);
    let mut payload = AuthenticatedInput::open(&payload_parent, payload_path, Some(payload_bytes))
        .map_err(map_structure_payload_fs)?;
    let expected_report_bytes = encoded_report_bytes(
        usize::try_from(geometry.section_count()?)
            .map_err(|_| ProductionDoryV3ModelStructureError::GeometryOverflow)?,
    )?;
    if require_production_size
        && expected_report_bytes != PRODUCTION_DORY_V3_MODEL_STRUCTURAL_REPORT_BYTES
    {
        return Err(ProductionDoryV3ModelStructureError::ReportLength {
            expected: PRODUCTION_DORY_V3_MODEL_STRUCTURAL_REPORT_BYTES,
            actual: expected_report_bytes,
        });
    }
    let mut report_file = AuthenticatedInput::open(
        report_parent,
        report_path,
        Some(expected_report_bytes as u64),
    )
    .map_err(map_structure_report_input_fs)?;
    if payload.identity() == report_file.identity() {
        return Err(ProductionDoryV3ModelStructureError::PayloadReportSameFile);
    }
    let initial_read = report_file
        .read_bounded(expected_report_bytes)
        .map_err(map_structure_report_input_fs);
    let initial_recheck = report_file
        .recheck(report_parent, Some(expected_report_bytes as u64))
        .map_err(map_structure_report_input_fs);
    initial_recheck?;
    let initial_bytes = initial_read?;
    let analysis = (|| {
        let verified =
            verify_with_geometry(payload.file_mut(), &initial_bytes, geometry, expected)?;
        let final_reproduction = analyze_with_geometry(payload.file_mut(), geometry, expected)?;
        if final_reproduction != verified || final_reproduction.canonical_bytes() != initial_bytes {
            return Err(ProductionDoryV3ModelStructureError::PayloadReportMismatch);
        }
        Ok(verified)
    })();
    let payload_recheck = payload
        .recheck(&payload_parent, Some(payload_bytes))
        .map_err(map_structure_payload_fs);
    let report_recheck = report_file
        .recheck(report_parent, Some(expected_report_bytes as u64))
        .map_err(map_structure_report_input_fs);
    payload_recheck?;
    report_recheck?;
    let verified = analysis?;
    let final_read = report_file
        .read_bounded(expected_report_bytes)
        .map_err(map_structure_report_input_fs);
    let final_read_recheck = report_file
        .recheck(report_parent, Some(expected_report_bytes as u64))
        .map_err(map_structure_report_input_fs);
    final_read_recheck?;
    let final_bytes = final_read?;
    let final_validation = (|| {
        if final_bytes != initial_bytes {
            return Err(ProductionDoryV3ModelStructureError::ReopenedReportMismatch);
        }
        let final_report =
            parse_and_validate_with_geometry(&final_bytes, geometry, expected, true)?;
        if final_report != verified {
            return Err(ProductionDoryV3ModelStructureError::ReopenedReportMismatch);
        }
        Ok(final_report)
    })();
    let final_payload_recheck = payload
        .recheck(&payload_parent, Some(payload_bytes))
        .map_err(map_structure_payload_fs);
    let final_report_recheck = report_file
        .recheck(report_parent, Some(expected_report_bytes as u64))
        .map_err(map_structure_report_input_fs);
    final_payload_recheck?;
    final_report_recheck?;
    final_validation
}

fn analyze_with_geometry<R: Read + Seek>(
    reader: &mut R,
    geometry: StructuralGeometry,
    expected: &ExpectedRoots,
) -> Result<ProductionDoryV3ModelStructuralReport, ProductionDoryV3ModelStructureError> {
    if expected.payload_bytes != geometry.payload_bytes()?
        || expected.layer_roots.len()
            != usize::try_from(geometry.layers)
                .map_err(|_| ProductionDoryV3ModelStructureError::GeometryOverflow)?
    {
        return Err(ProductionDoryV3ModelStructureError::RootsGeometryMismatch);
    }

    reader
        .seek(SeekFrom::Start(0))
        .map_err(ProductionDoryV3ModelStructureError::ReadPayload)?;
    let section_capacity = usize::try_from(geometry.layer_bytes()?.max(geometry.base_bytes()?))
        .map_err(|_| ProductionDoryV3ModelStructureError::GeometryOverflow)?;
    let section_count = usize::try_from(geometry.section_count()?)
        .map_err(|_| ProductionDoryV3ModelStructureError::GeometryOverflow)?;
    let mut section_buffer = Vec::with_capacity(section_capacity);
    let mut compare_buffer = vec![0_u8; COMPARE_BUFFER_BYTES];
    let mut sections = Vec::with_capacity(section_count);
    let mut raw_blake3 = blake3::Hasher::new();
    let mut raw_sha256 = Sha256::new();
    let mut payload_offset = 0_u64;
    let mut duplicate_row_pairs = 0_u64;
    let mut duplicate_column_pairs = 0_u64;
    let mut duplicate_layer_pairs = 0_u64;
    let mut layer_classes: BTreeMap<[u8; 32], Vec<LayerClass>> = BTreeMap::new();

    let base = read_and_analyze_section(
        reader,
        &mut section_buffer,
        geometry.base_bytes()?,
        geometry.base_rows,
        geometry.columns,
        DoryV3ModelStructuralSectionKind::Base,
        BASE_SECTION_INDEX,
        &mut payload_offset,
        &mut raw_blake3,
        &mut raw_sha256,
    )?;
    duplicate_row_pairs = checked_add(duplicate_row_pairs, base.duplicate_rows)?;
    duplicate_column_pairs = checked_add(duplicate_column_pairs, base.duplicate_columns)?;
    sections.push(base.section);

    for layer_index in 0..geometry.layers {
        let layer_offset = payload_offset;
        let analyzed = read_and_analyze_section(
            reader,
            &mut section_buffer,
            geometry.layer_bytes()?,
            geometry.layer_rows,
            geometry.columns,
            DoryV3ModelStructuralSectionKind::WeightLayer,
            layer_index,
            &mut payload_offset,
            &mut raw_blake3,
            &mut raw_sha256,
        )?;
        duplicate_row_pairs = checked_add(duplicate_row_pairs, analyzed.duplicate_rows)?;
        duplicate_column_pairs = checked_add(duplicate_column_pairs, analyzed.duplicate_columns)?;

        let next_offset = payload_offset;
        let digest = analyzed.section.section_blake3_root.into_bytes();
        let classes = layer_classes.entry(digest).or_default();
        let mut matched = false;
        for class in classes.iter_mut() {
            if layer_bytes_equal(
                reader,
                class.representative_offset,
                &section_buffer,
                &mut compare_buffer,
            )? {
                duplicate_layer_pairs = checked_add(duplicate_layer_pairs, class.count)?;
                class.count = checked_add(class.count, 1)?;
                matched = true;
                break;
            }
        }
        if !matched {
            classes.push(LayerClass {
                representative_offset: layer_offset,
                count: 1,
            });
        }
        reader
            .seek(SeekFrom::Start(next_offset))
            .map_err(ProductionDoryV3ModelStructureError::ReadPayload)?;
        sections.push(analyzed.section);
    }

    if payload_offset != geometry.payload_bytes()? {
        return Err(ProductionDoryV3ModelStructureError::PayloadLength {
            expected: geometry.payload_bytes()?,
            actual: payload_offset,
        });
    }
    let mut trailing = [0_u8; 1];
    match reader.read(&mut trailing) {
        Ok(0) => {}
        Ok(_) => {
            return Err(ProductionDoryV3ModelStructureError::TrailingBytes(
                payload_offset,
            ));
        }
        Err(source) => return Err(ProductionDoryV3ModelStructureError::ReadPayload(source)),
    }

    let raw_payload_blake3 = Digest32::new(*raw_blake3.finalize().as_bytes());
    let raw_payload_sha256 = Digest32::new(finalize_sha256(raw_sha256));
    let diagnostic_mask = diagnostic_mask(
        &sections,
        duplicate_row_pairs,
        duplicate_column_pairs,
        duplicate_layer_pairs,
    )?;
    let fatal_mask = expected_fatal_mask(
        geometry,
        expected,
        raw_payload_blake3,
        raw_payload_sha256,
        &sections,
    )?;
    if fatal_mask != 0 {
        return Err(ProductionDoryV3ModelStructureError::FatalAnalysis(
            fatal_mask,
        ));
    }

    let report = ProductionDoryV3ModelStructuralReport {
        ceremony_id: expected.ceremony_id,
        payload_bytes: payload_offset,
        raw_payload_blake3,
        raw_payload_sha256,
        sections,
        duplicate_row_pairs,
        duplicate_column_pairs,
        duplicate_layer_pairs,
        diagnostic_mask,
        fatal_mask,
    };
    validate_report(&report, geometry, expected, true)?;
    Ok(report)
}

#[derive(Debug)]
struct AnalyzedSection {
    section: DoryV3ModelStructuralSection,
    duplicate_rows: u64,
    duplicate_columns: u64,
}

#[allow(clippy::too_many_arguments)]
fn read_and_analyze_section<R: Read>(
    reader: &mut R,
    buffer: &mut Vec<u8>,
    section_bytes: u64,
    rows: u32,
    columns: u32,
    kind: DoryV3ModelStructuralSectionKind,
    index: u32,
    payload_offset: &mut u64,
    raw_blake3: &mut blake3::Hasher,
    raw_sha256: &mut Sha256,
) -> Result<AnalyzedSection, ProductionDoryV3ModelStructureError> {
    let section_len = usize::try_from(section_bytes)
        .map_err(|_| ProductionDoryV3ModelStructureError::GeometryOverflow)?;
    buffer.clear();
    buffer.resize(section_len, 0);
    let section_start = *payload_offset;
    let mut read = 0_usize;
    while read != section_len {
        match reader.read(&mut buffer[read..]) {
            Ok(0) => {
                return Err(ProductionDoryV3ModelStructureError::EarlyEof {
                    offset: section_start,
                    expected: section_bytes,
                    actual: u64::try_from(read)
                        .map_err(|_| ProductionDoryV3ModelStructureError::GeometryOverflow)?,
                });
            }
            Ok(count) => {
                read = read
                    .checked_add(count)
                    .ok_or(ProductionDoryV3ModelStructureError::CounterOverflow)?;
            }
            Err(source) if source.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(source) => return Err(ProductionDoryV3ModelStructureError::ReadPayload(source)),
        }
    }

    let mut histogram = [0_u64; HISTOGRAM_BINS];
    for (relative, value) in buffer.iter().copied().enumerate() {
        if value > MAX_MODEL_BYTE {
            let relative = u64::try_from(relative)
                .map_err(|_| ProductionDoryV3ModelStructureError::GeometryOverflow)?;
            return Err(ProductionDoryV3ModelStructureError::OutOfRange {
                offset: section_start
                    .checked_add(relative)
                    .ok_or(ProductionDoryV3ModelStructureError::CounterOverflow)?,
                value,
            });
        }
        let slot = &mut histogram[usize::from(value)];
        *slot = slot
            .checked_add(1)
            .ok_or(ProductionDoryV3ModelStructureError::CounterOverflow)?;
    }

    raw_blake3.update(buffer);
    raw_sha256.update(buffer.as_slice());
    *payload_offset = payload_offset
        .checked_add(section_bytes)
        .ok_or(ProductionDoryV3ModelStructureError::CounterOverflow)?;
    let section_blake3_root = Digest32::new(*blake3::hash(buffer).as_bytes());
    let (constant_rows, duplicate_rows) = analyze_rows(buffer, rows, columns)?;
    let (constant_columns, duplicate_columns) = analyze_columns(buffer, rows, columns)?;

    Ok(AnalyzedSection {
        section: DoryV3ModelStructuralSection {
            kind,
            index,
            rows,
            columns,
            section_bytes,
            section_blake3_root,
            histogram,
            constant_rows,
            constant_columns,
        },
        duplicate_rows,
        duplicate_columns,
    })
}

fn analyze_rows(
    bytes: &[u8],
    rows: u32,
    columns: u32,
) -> Result<(u64, u64), ProductionDoryV3ModelStructureError> {
    let rows =
        usize::try_from(rows).map_err(|_| ProductionDoryV3ModelStructureError::GeometryOverflow)?;
    let columns = usize::try_from(columns)
        .map_err(|_| ProductionDoryV3ModelStructureError::GeometryOverflow)?;
    let mut constant = 0_u64;
    let mut digests = Vec::with_capacity(rows);
    for row in 0..rows {
        let start = row
            .checked_mul(columns)
            .ok_or(ProductionDoryV3ModelStructureError::GeometryOverflow)?;
        let end = start
            .checked_add(columns)
            .ok_or(ProductionDoryV3ModelStructureError::GeometryOverflow)?;
        let row_bytes = bytes
            .get(start..end)
            .ok_or(ProductionDoryV3ModelStructureError::GeometryOverflow)?;
        if row_bytes
            .first()
            .is_some_and(|first| row_bytes.iter().all(|value| value == first))
        {
            constant = checked_add(constant, 1)?;
        }
        digests.push(*blake3::hash(row_bytes).as_bytes());
    }
    let duplicates = count_exact_digest_pairs(&digests, |left, right| {
        let left_start = left * columns;
        let right_start = right * columns;
        bytes[left_start..left_start + columns] == bytes[right_start..right_start + columns]
    })?;
    Ok((constant, duplicates))
}

fn analyze_columns(
    bytes: &[u8],
    rows: u32,
    columns: u32,
) -> Result<(u64, u64), ProductionDoryV3ModelStructureError> {
    let rows =
        usize::try_from(rows).map_err(|_| ProductionDoryV3ModelStructureError::GeometryOverflow)?;
    let columns = usize::try_from(columns)
        .map_err(|_| ProductionDoryV3ModelStructureError::GeometryOverflow)?;
    let mut constant = 0_u64;
    let mut digests = vec![[0_u8; 32]; columns];
    let scratch_len = rows
        .checked_mul(COLUMN_TRANSPOSE_BLOCK.min(columns))
        .ok_or(ProductionDoryV3ModelStructureError::GeometryOverflow)?;
    let mut scratch = vec![0_u8; scratch_len];

    for block_start in (0..columns).step_by(COLUMN_TRANSPOSE_BLOCK) {
        let block_columns = COLUMN_TRANSPOSE_BLOCK.min(columns - block_start);
        let used = rows
            .checked_mul(block_columns)
            .ok_or(ProductionDoryV3ModelStructureError::GeometryOverflow)?;
        for row in 0..rows {
            let row_start = row
                .checked_mul(columns)
                .and_then(|offset| offset.checked_add(block_start))
                .ok_or(ProductionDoryV3ModelStructureError::GeometryOverflow)?;
            for local_column in 0..block_columns {
                scratch[local_column * rows + row] = bytes[row_start + local_column];
            }
        }
        for local_column in 0..block_columns {
            let start = local_column * rows;
            let column = &scratch[start..start + rows];
            if column
                .first()
                .is_some_and(|first| column.iter().all(|value| value == first))
            {
                constant = checked_add(constant, 1)?;
            }
            digests[block_start + local_column] = *blake3::hash(column).as_bytes();
        }
        scratch[..used].fill(0);
    }

    let duplicates = count_exact_digest_pairs(&digests, |left, right| {
        (0..rows).all(|row| bytes[row * columns + left] == bytes[row * columns + right])
    })?;
    Ok((constant, duplicates))
}

fn count_exact_digest_pairs<F>(
    digests: &[[u8; 32]],
    mut exact_equal: F,
) -> Result<u64, ProductionDoryV3ModelStructureError>
where
    F: FnMut(usize, usize) -> bool,
{
    let mut ordered = (0..digests.len()).collect::<Vec<_>>();
    ordered.sort_unstable_by_key(|index| digests[*index]);
    let mut total = 0_u64;
    let mut group_start = 0_usize;
    while group_start < ordered.len() {
        let digest = digests[ordered[group_start]];
        let mut group_end = group_start + 1;
        while group_end < ordered.len() && digests[ordered[group_end]] == digest {
            group_end += 1;
        }
        let mut classes: Vec<(usize, u64)> = Vec::new();
        for &index in &ordered[group_start..group_end] {
            let mut matched = false;
            for (representative, count) in &mut classes {
                if exact_equal(*representative, index) {
                    total = checked_add(total, *count)?;
                    *count = checked_add(*count, 1)?;
                    matched = true;
                    break;
                }
            }
            if !matched {
                classes.push((index, 1));
            }
        }
        group_start = group_end;
    }
    Ok(total)
}

fn layer_bytes_equal<R: Read + Seek>(
    reader: &mut R,
    prior_offset: u64,
    current: &[u8],
    scratch: &mut [u8],
) -> Result<bool, ProductionDoryV3ModelStructureError> {
    reader
        .seek(SeekFrom::Start(prior_offset))
        .map_err(ProductionDoryV3ModelStructureError::ReadPayload)?;
    let mut compared = 0_usize;
    while compared < current.len() {
        let take = scratch.len().min(current.len() - compared);
        reader
            .read_exact(&mut scratch[..take])
            .map_err(ProductionDoryV3ModelStructureError::ReadPayload)?;
        if scratch[..take] != current[compared..compared + take] {
            return Ok(false);
        }
        compared += take;
    }
    Ok(true)
}

fn checked_add(left: u64, right: u64) -> Result<u64, ProductionDoryV3ModelStructureError> {
    left.checked_add(right)
        .ok_or(ProductionDoryV3ModelStructureError::CounterOverflow)
}

fn finalize_sha256(hasher: Sha256) -> [u8; 32] {
    hasher.finalize().into()
}

fn diagnostic_mask(
    sections: &[DoryV3ModelStructuralSection],
    duplicate_row_pairs: u64,
    duplicate_column_pairs: u64,
    duplicate_layer_pairs: u64,
) -> Result<u32, ProductionDoryV3ModelStructureError> {
    let mut constant_rows = 0_u64;
    let mut constant_columns = 0_u64;
    for section in sections {
        constant_rows = checked_add(constant_rows, section.constant_rows)?;
        constant_columns = checked_add(constant_columns, section.constant_columns)?;
    }
    let mut mask = 0_u32;
    if constant_rows != 0 || constant_columns != 0 {
        mask |= DIAGNOSTIC_CONSTANT;
    }
    if duplicate_row_pairs != 0 || duplicate_column_pairs != 0 {
        mask |= DIAGNOSTIC_DUPLICATE_ROW_OR_COLUMN;
    }
    if duplicate_layer_pairs != 0 {
        mask |= DIAGNOSTIC_DUPLICATE_LAYER;
    }
    Ok(mask)
}

fn expected_fatal_mask(
    geometry: StructuralGeometry,
    expected: &ExpectedRoots,
    raw_blake3: Digest32,
    raw_sha256: Digest32,
    sections: &[DoryV3ModelStructuralSection],
) -> Result<u32, ProductionDoryV3ModelStructureError> {
    let mut histogram_mismatch = false;
    for section in sections {
        let mut sum = 0_u64;
        for count in section.histogram {
            sum = checked_add(sum, count)?;
        }
        histogram_mismatch |= sum != section.section_bytes;
    }

    let expected_section_count = usize::try_from(geometry.section_count()?)
        .map_err(|_| ProductionDoryV3ModelStructureError::GeometryOverflow)?;
    let mut root_mismatch = raw_blake3 != expected.raw_blake3
        || raw_sha256 != expected.raw_sha256
        || sections.len() != expected_section_count;
    if let Some(base) = sections.first() {
        root_mismatch |= base.section_blake3_root != expected.base_root;
    } else {
        root_mismatch = true;
    }
    if sections.len() == expected_section_count
        && expected.layer_roots.len()
            == usize::try_from(geometry.layers)
                .map_err(|_| ProductionDoryV3ModelStructureError::GeometryOverflow)?
    {
        let mut aggregate = start_layer_aggregate(geometry.layers);
        for (index, (section, expected_root)) in
            sections[1..].iter().zip(&expected.layer_roots).enumerate()
        {
            root_mismatch |= section.section_blake3_root != *expected_root;
            let index = u32::try_from(index)
                .map_err(|_| ProductionDoryV3ModelStructureError::GeometryOverflow)?;
            add_layer_root(
                &mut aggregate,
                index,
                blake3::Hash::from_bytes(section.section_blake3_root.into_bytes()),
            );
        }
        root_mismatch |=
            Digest32::new(*aggregate.finalize().as_bytes()) != expected.layer_aggregate;
    } else {
        root_mismatch = true;
    }

    let mut mask = 0_u32;
    if histogram_mismatch {
        mask |= FATAL_HISTOGRAM;
    }
    if root_mismatch {
        mask |= FATAL_ROOT;
    }
    Ok(mask)
}

fn validate_report(
    report: &ProductionDoryV3ModelStructuralReport,
    geometry: StructuralGeometry,
    expected: &ExpectedRoots,
    require_nonfatal: bool,
) -> Result<(), ProductionDoryV3ModelStructureError> {
    if report.ceremony_id != expected.ceremony_id {
        return Err(ProductionDoryV3ModelStructureError::CeremonyIdMismatch);
    }
    if report.payload_bytes != geometry.payload_bytes()?
        || report.payload_bytes != expected.payload_bytes
    {
        return Err(ProductionDoryV3ModelStructureError::InvalidReportPayloadLength);
    }
    if report.sections.len()
        != usize::try_from(geometry.section_count()?)
            .map_err(|_| ProductionDoryV3ModelStructureError::GeometryOverflow)?
    {
        return Err(ProductionDoryV3ModelStructureError::InvalidSectionCount);
    }

    let mut maximum_row_pairs = 0_u64;
    let mut maximum_column_pairs = 0_u64;
    for (position, section) in report.sections.iter().enumerate() {
        let (expected_kind, expected_index, expected_rows, expected_bytes) = if position == 0 {
            (
                DoryV3ModelStructuralSectionKind::Base,
                BASE_SECTION_INDEX,
                geometry.base_rows,
                geometry.base_bytes()?,
            )
        } else {
            (
                DoryV3ModelStructuralSectionKind::WeightLayer,
                u32::try_from(position - 1)
                    .map_err(|_| ProductionDoryV3ModelStructureError::GeometryOverflow)?,
                geometry.layer_rows,
                geometry.layer_bytes()?,
            )
        };
        if section.kind != expected_kind
            || section.index != expected_index
            || section.rows != expected_rows
            || section.columns != geometry.columns
            || section.section_bytes != expected_bytes
        {
            return Err(ProductionDoryV3ModelStructureError::InvalidSectionGeometry { position });
        }
        if section.constant_rows > u64::from(section.rows)
            || section.constant_columns > u64::from(section.columns)
        {
            return Err(ProductionDoryV3ModelStructureError::InvalidSectionCounter { position });
        }
        maximum_row_pairs = checked_add(maximum_row_pairs, unordered_pairs(section.rows)?)?;
        maximum_column_pairs =
            checked_add(maximum_column_pairs, unordered_pairs(section.columns)?)?;
    }
    if report.duplicate_row_pairs > maximum_row_pairs
        || report.duplicate_column_pairs > maximum_column_pairs
        || report.duplicate_layer_pairs > unordered_pairs(geometry.layers)?
    {
        return Err(ProductionDoryV3ModelStructureError::InvalidSectionCounter {
            position: report.sections.len(),
        });
    }

    if report.diagnostic_mask & !DIAGNOSTIC_ALLOWED_MASK != 0 {
        return Err(ProductionDoryV3ModelStructureError::ReservedDiagnosticBits);
    }
    let expected_diagnostic = diagnostic_mask(
        &report.sections,
        report.duplicate_row_pairs,
        report.duplicate_column_pairs,
        report.duplicate_layer_pairs,
    )?;
    if report.diagnostic_mask != expected_diagnostic {
        return Err(ProductionDoryV3ModelStructureError::DiagnosticMaskMismatch);
    }
    if report.fatal_mask & !FATAL_ALLOWED_MASK != 0 {
        return Err(ProductionDoryV3ModelStructureError::ReservedFatalBits);
    }
    let expected_fatal = expected_fatal_mask(
        geometry,
        expected,
        report.raw_payload_blake3,
        report.raw_payload_sha256,
        &report.sections,
    )?;
    if report.fatal_mask != expected_fatal {
        return Err(ProductionDoryV3ModelStructureError::FatalMaskMismatch);
    }
    if require_nonfatal && report.fatal_mask != 0 {
        return Err(ProductionDoryV3ModelStructureError::NonzeroFatalMask);
    }
    if expected_fatal & FATAL_ROOT != 0 {
        return Err(ProductionDoryV3ModelStructureError::RootMismatch);
    }
    Ok(())
}

fn unordered_pairs(count: u32) -> Result<u64, ProductionDoryV3ModelStructureError> {
    let count = u64::from(count);
    count
        .checked_mul(count.saturating_sub(1))
        .map(|product| product / 2)
        .ok_or(ProductionDoryV3ModelStructureError::CounterOverflow)
}

fn encoded_report_bytes(
    section_count: usize,
) -> Result<usize, ProductionDoryV3ModelStructureError> {
    section_count
        .checked_mul(STRUCTURAL_SECTION_RECORD_BYTES)
        .and_then(|sections| sections.checked_add(STRUCTURAL_HEADER_BYTES))
        .and_then(|bytes| bytes.checked_add(STRUCTURAL_TRAILER_BYTES))
        .ok_or(ProductionDoryV3ModelStructureError::GeometryOverflow)
}

fn encode_report(report: &ProductionDoryV3ModelStructuralReport) -> Vec<u8> {
    let capacity = encoded_report_bytes(report.sections.len()).unwrap_or(0);
    let mut bytes = Vec::with_capacity(capacity);
    bytes.extend_from_slice(&PRODUCTION_DORY_V3_MODEL_STRUCTURAL_REPORT_MAGIC);
    bytes.extend_from_slice(&PRODUCTION_DORY_V3_MODEL_STRUCTURAL_REPORT_VERSION.to_le_bytes());
    bytes.extend_from_slice(report.ceremony_id.as_bytes());
    bytes.extend_from_slice(&report.payload_bytes.to_le_bytes());
    bytes.extend_from_slice(report.raw_payload_blake3.as_bytes());
    bytes.extend_from_slice(report.raw_payload_sha256.as_bytes());
    bytes.extend_from_slice(
        &u32::try_from(report.sections.len())
            .expect("validated structural section count fits in u32")
            .to_le_bytes(),
    );
    for section in &report.sections {
        bytes.push(section.kind as u8);
        bytes.extend_from_slice(&section.index.to_le_bytes());
        bytes.extend_from_slice(&section.rows.to_le_bytes());
        bytes.extend_from_slice(&section.columns.to_le_bytes());
        bytes.extend_from_slice(&section.section_bytes.to_le_bytes());
        bytes.extend_from_slice(section.section_blake3_root.as_bytes());
        for count in section.histogram {
            bytes.extend_from_slice(&count.to_le_bytes());
        }
        bytes.extend_from_slice(&section.constant_rows.to_le_bytes());
        bytes.extend_from_slice(&section.constant_columns.to_le_bytes());
    }
    bytes.extend_from_slice(&report.duplicate_row_pairs.to_le_bytes());
    bytes.extend_from_slice(&report.duplicate_column_pairs.to_le_bytes());
    bytes.extend_from_slice(&report.duplicate_layer_pairs.to_le_bytes());
    bytes.extend_from_slice(&report.diagnostic_mask.to_le_bytes());
    bytes.extend_from_slice(&report.fatal_mask.to_le_bytes());
    debug_assert_eq!(bytes.len(), capacity);
    bytes
}

fn parse_and_validate_with_geometry(
    bytes: &[u8],
    geometry: StructuralGeometry,
    expected: &ExpectedRoots,
    require_nonfatal: bool,
) -> Result<ProductionDoryV3ModelStructuralReport, ProductionDoryV3ModelStructureError> {
    let expected_bytes = encoded_report_bytes(
        usize::try_from(geometry.section_count()?)
            .map_err(|_| ProductionDoryV3ModelStructureError::GeometryOverflow)?,
    )?;
    if bytes.len() != expected_bytes {
        return Err(ProductionDoryV3ModelStructureError::ReportLength {
            expected: expected_bytes,
            actual: bytes.len(),
        });
    }
    let mut decoder = Decoder::new(bytes);
    if decoder.take::<8>()? != PRODUCTION_DORY_V3_MODEL_STRUCTURAL_REPORT_MAGIC {
        return Err(ProductionDoryV3ModelStructureError::InvalidMagic);
    }
    let version = decoder.u16()?;
    if version != PRODUCTION_DORY_V3_MODEL_STRUCTURAL_REPORT_VERSION {
        return Err(ProductionDoryV3ModelStructureError::UnsupportedVersion(
            version,
        ));
    }
    let ceremony_id = Digest32::new(decoder.take::<32>()?);
    let payload_bytes = decoder.u64()?;
    let raw_payload_blake3 = Digest32::new(decoder.take::<32>()?);
    let raw_payload_sha256 = Digest32::new(decoder.take::<32>()?);
    let section_count = decoder.u32()?;
    if section_count != geometry.section_count()? {
        return Err(ProductionDoryV3ModelStructureError::InvalidSectionCount);
    }
    let mut sections = Vec::with_capacity(
        usize::try_from(section_count)
            .map_err(|_| ProductionDoryV3ModelStructureError::GeometryOverflow)?,
    );
    for _ in 0..section_count {
        let kind = DoryV3ModelStructuralSectionKind::decode(decoder.u8()?)?;
        let index = decoder.u32()?;
        let rows = decoder.u32()?;
        let columns = decoder.u32()?;
        let section_bytes = decoder.u64()?;
        let section_blake3_root = Digest32::new(decoder.take::<32>()?);
        let mut histogram = [0_u64; HISTOGRAM_BINS];
        for count in &mut histogram {
            *count = decoder.u64()?;
        }
        let constant_rows = decoder.u64()?;
        let constant_columns = decoder.u64()?;
        sections.push(DoryV3ModelStructuralSection {
            kind,
            index,
            rows,
            columns,
            section_bytes,
            section_blake3_root,
            histogram,
            constant_rows,
            constant_columns,
        });
    }
    let report = ProductionDoryV3ModelStructuralReport {
        ceremony_id,
        payload_bytes,
        raw_payload_blake3,
        raw_payload_sha256,
        sections,
        duplicate_row_pairs: decoder.u64()?,
        duplicate_column_pairs: decoder.u64()?,
        duplicate_layer_pairs: decoder.u64()?,
        diagnostic_mask: decoder.u32()?,
        fatal_mask: decoder.u32()?,
    };
    if !decoder.is_eof() {
        return Err(ProductionDoryV3ModelStructureError::ReportLength {
            expected: decoder.offset,
            actual: bytes.len(),
        });
    }
    validate_report(&report, geometry, expected, require_nonfatal)?;
    Ok(report)
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], ProductionDoryV3ModelStructureError> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(ProductionDoryV3ModelStructureError::GeometryOverflow)?;
        let value = self.bytes.get(self.offset..end).ok_or(
            ProductionDoryV3ModelStructureError::ReportLength {
                expected: end,
                actual: self.bytes.len(),
            },
        )?;
        self.offset = end;
        value
            .try_into()
            .map_err(|_| ProductionDoryV3ModelStructureError::GeometryOverflow)
    }

    fn u8(&mut self) -> Result<u8, ProductionDoryV3ModelStructureError> {
        Ok(self.take::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, ProductionDoryV3ModelStructureError> {
        Ok(u16::from_le_bytes(self.take()?))
    }

    fn u32(&mut self) -> Result<u32, ProductionDoryV3ModelStructureError> {
        Ok(u32::from_le_bytes(self.take()?))
    }

    fn u64(&mut self) -> Result<u64, ProductionDoryV3ModelStructureError> {
        Ok(u64::from_le_bytes(self.take()?))
    }

    fn is_eof(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

fn run_with_geometry(
    payload_path: &Path,
    output_path: &Path,
    geometry: StructuralGeometry,
    expected: &ExpectedRoots,
    require_production_size: bool,
) -> Result<ProductionDoryV3ModelStructuralReportRun, ProductionDoryV3ModelStructureError> {
    let payload_bytes = geometry.payload_bytes()?;
    let payload_parent =
        TrustedCeremonyParent::for_artifact(payload_path).map_err(map_structure_payload_fs)?;
    let output_parent_holder = if output_path.parent() == payload_path.parent() {
        None
    } else {
        Some(TrustedCeremonyParent::for_artifact(output_path).map_err(map_structure_output_fs)?)
    };
    let output_parent = output_parent_holder.as_ref().unwrap_or(&payload_parent);
    output_parent
        .preflight_output(output_path)
        .map_err(map_structure_output_fs)?;
    let mut payload = AuthenticatedInput::open(&payload_parent, payload_path, Some(payload_bytes))
        .map_err(map_structure_payload_fs)?;

    let analysis = (|| {
        let report = analyze_with_geometry(payload.file_mut(), geometry, expected)?;
        let final_reproduction = analyze_with_geometry(payload.file_mut(), geometry, expected)?;
        if final_reproduction != report
            || final_reproduction.canonical_bytes() != report.canonical_bytes()
        {
            return Err(ProductionDoryV3ModelStructureError::PayloadReportMismatch);
        }
        Ok(report)
    })();
    let payload_recheck = payload
        .recheck(&payload_parent, Some(payload_bytes))
        .map_err(map_structure_payload_fs);
    let output_recheck = output_parent.recheck().map_err(map_structure_output_fs);
    payload_recheck?;
    output_recheck?;
    let report = analysis?;

    let bytes = report.canonical_bytes();
    let expected_bytes = encoded_report_bytes(
        usize::try_from(geometry.section_count()?)
            .map_err(|_| ProductionDoryV3ModelStructureError::GeometryOverflow)?,
    )?;
    if bytes.len() != expected_bytes
        || (require_production_size
            && bytes.len() != PRODUCTION_DORY_V3_MODEL_STRUCTURAL_REPORT_BYTES)
    {
        return Err(ProductionDoryV3ModelStructureError::ReportLength {
            expected: if require_production_size {
                PRODUCTION_DORY_V3_MODEL_STRUCTURAL_REPORT_BYTES
            } else {
                expected_bytes
            },
            actual: bytes.len(),
        });
    }

    let mut output =
        PendingOutput::create(output_parent, output_path).map_err(map_structure_output_fs)?;
    let completion = (|| {
        output.write_all(&bytes).map_err(map_structure_output_fs)?;
        output.sync_file().map_err(map_structure_output_fs)?;
        let reopened_bytes = output
            .reopen_exact(output_parent, &bytes)
            .map_err(map_structure_output_fs)?;
        let reopened_report =
            parse_and_validate_with_geometry(&reopened_bytes, geometry, expected, true)?;
        if reopened_report != report {
            return Err(ProductionDoryV3ModelStructureError::ReopenedReportMismatch);
        }
        let durability = map_structure_durability(
            output
                .sync_parent(output_parent)
                .map_err(map_structure_output_fs)?,
        );
        payload
            .recheck(&payload_parent, Some(payload_bytes))
            .map_err(map_structure_payload_fs)?;
        let report_bytes = u64::try_from(reopened_bytes.len())
            .map_err(|_| ProductionDoryV3ModelStructureError::GeometryOverflow)?;
        let report_blake3 = Digest32::new(*blake3::hash(&reopened_bytes).as_bytes());
        let report_sha256 =
            Digest32::new(finalize_sha256(Sha256::new_with_prefix(&reopened_bytes)));
        Ok(ProductionDoryV3ModelStructuralReportRun {
            output: output_path.to_path_buf(),
            report_bytes,
            report_blake3,
            report_sha256,
            durability,
            report: reopened_report,
        })
    })();

    match completion {
        Ok(run) => match output.confirm(output_parent) {
            Ok(()) => Ok(run),
            Err(error) => Err(cleanup_structure_output_error(
                &mut output,
                output_parent,
                map_structure_output_fs(error),
            )),
        },
        Err(error) => Err(cleanup_structure_output_error(
            &mut output,
            output_parent,
            error,
        )),
    }
}
fn map_structure_durability(
    durability: ParentSyncOutcome,
) -> ProductionDoryV3ModelStructuralReportDurability {
    match durability {
        ParentSyncOutcome::Synced => {
            ProductionDoryV3ModelStructuralReportDurability::FileAndParentDirectorySynced
        }
        #[cfg(windows)]
        ParentSyncOutcome::WindowsAccessDenied => {
            ProductionDoryV3ModelStructuralReportDurability::FileSyncedParentDirectorySyncAccessDeniedOnWindows
        }
        #[cfg(windows)]
        ParentSyncOutcome::WindowsUnsupported => {
            ProductionDoryV3ModelStructuralReportDurability::FileSyncedParentDirectorySyncUnsupportedOnWindows
        }
        #[cfg(not(any(unix, windows)))]
        ParentSyncOutcome::PlatformUnsupported => {
            ProductionDoryV3ModelStructuralReportDurability::FileSyncedParentDirectorySyncUnsupportedOnPlatform
        }
    }
}

fn map_structure_payload_fs(error: CeremonyFsError) -> ProductionDoryV3ModelStructureError {
    match error {
        CeremonyFsError::InvalidArtifactPath(path) | CeremonyFsError::UnsafeParent(path) => {
            ProductionDoryV3ModelStructureError::InvalidPayloadPath(path)
        }
        CeremonyFsError::InspectParent { path, source } => {
            ProductionDoryV3ModelStructureError::InspectPayload { path, source }
        }
        CeremonyFsError::ParentIdentity(path) | CeremonyFsError::InputIdentity(path) => {
            ProductionDoryV3ModelStructureError::PayloadIdentityMismatch(path)
        }
        CeremonyFsError::OpenInput { path, source } => {
            ProductionDoryV3ModelStructureError::OpenPayload { path, source }
        }
        CeremonyFsError::InputNotRegular(path) => {
            ProductionDoryV3ModelStructureError::PayloadNotRegular(path)
        }
        CeremonyFsError::InputReparsePoint(path) => {
            ProductionDoryV3ModelStructureError::PayloadReparsePoint(path)
        }
        CeremonyFsError::InputHardLinks { path, links } => {
            ProductionDoryV3ModelStructureError::PayloadHardLinks { path, links }
        }
        CeremonyFsError::InputLength { expected, actual } => {
            ProductionDoryV3ModelStructureError::PayloadLength { expected, actual }
        }
        other => {
            let path = ceremony_fs_error_path(&other);
            ProductionDoryV3ModelStructureError::InspectPayload {
                path,
                source: std::io::Error::other(other.to_string()),
            }
        }
    }
}

fn map_structure_report_input_fs(error: CeremonyFsError) -> ProductionDoryV3ModelStructureError {
    match error {
        CeremonyFsError::InvalidArtifactPath(path) => {
            ProductionDoryV3ModelStructureError::InvalidOutputPath(path)
        }
        CeremonyFsError::UnsafeParent(path) => {
            ProductionDoryV3ModelStructureError::OutputParent(path)
        }
        CeremonyFsError::InspectParent { path, source }
        | CeremonyFsError::OpenInput { path, source } => {
            ProductionDoryV3ModelStructureError::InspectOutput { path, source }
        }
        CeremonyFsError::ParentIdentity(path)
        | CeremonyFsError::InputIdentity(path)
        | CeremonyFsError::InputNotRegular(path) => {
            ProductionDoryV3ModelStructureError::OutputIdentityMismatch(path)
        }
        CeremonyFsError::InputReparsePoint(path) => {
            ProductionDoryV3ModelStructureError::OutputReparsePoint(path)
        }
        CeremonyFsError::InputHardLinks { path, links } => {
            ProductionDoryV3ModelStructureError::OutputHardLinks { path, links }
        }
        CeremonyFsError::InputLength { expected, actual } => {
            ProductionDoryV3ModelStructureError::ReportLength {
                expected: usize::try_from(expected).unwrap_or(usize::MAX),
                actual: usize::try_from(actual).unwrap_or(usize::MAX),
            }
        }
        other => {
            let path = ceremony_fs_error_path(&other);
            ProductionDoryV3ModelStructureError::InspectOutput {
                path,
                source: std::io::Error::other(other.to_string()),
            }
        }
    }
}

fn map_structure_output_fs(error: CeremonyFsError) -> ProductionDoryV3ModelStructureError {
    match error {
        CeremonyFsError::InvalidArtifactPath(path) => {
            ProductionDoryV3ModelStructureError::InvalidOutputPath(path)
        }
        CeremonyFsError::UnsafeParent(path) => {
            ProductionDoryV3ModelStructureError::OutputParent(path)
        }
        CeremonyFsError::InspectParent { path, source } => {
            ProductionDoryV3ModelStructureError::InspectOutput { path, source }
        }
        CeremonyFsError::ParentIdentity(path) | CeremonyFsError::OutputIdentity(path) => {
            ProductionDoryV3ModelStructureError::OutputIdentityMismatch(path)
        }
        CeremonyFsError::OutputExists(path) => {
            ProductionDoryV3ModelStructureError::OutputExists(path)
        }
        CeremonyFsError::CreateOutput { path, source } => {
            ProductionDoryV3ModelStructureError::CreateOutput { path, source }
        }
        CeremonyFsError::SetOutputPermissions { path, source } => {
            ProductionDoryV3ModelStructureError::SetOutputPermissions { path, source }
        }
        CeremonyFsError::WriteOutput { path, source } => {
            ProductionDoryV3ModelStructureError::WriteOutput { path, source }
        }
        CeremonyFsError::ReopenOutput { path, source } => {
            ProductionDoryV3ModelStructureError::ReopenOutput { path, source }
        }
        CeremonyFsError::OutputNotRegular(path) => {
            ProductionDoryV3ModelStructureError::OutputIdentityMismatch(path)
        }
        CeremonyFsError::OutputReparsePoint(path) => {
            ProductionDoryV3ModelStructureError::OutputReparsePoint(path)
        }
        CeremonyFsError::OutputHardLinks { path, links } => {
            ProductionDoryV3ModelStructureError::OutputHardLinks { path, links }
        }
        CeremonyFsError::ReopenedOutputMismatch => {
            ProductionDoryV3ModelStructureError::ReopenedReportMismatch
        }
        CeremonyFsError::SyncParent { path, source } => {
            ProductionDoryV3ModelStructureError::SyncParent { path, source }
        }
        CeremonyFsError::CleanupOutput { path, source } => {
            ProductionDoryV3ModelStructureError::CleanupOutput { path, source }
        }
        CeremonyFsError::QuarantinedOutput {
            path,
            original,
            cleanup,
        } => ProductionDoryV3ModelStructureError::QuarantinedOutput {
            path,
            original,
            cleanup,
        },
        other => {
            let path = ceremony_fs_error_path(&other);
            ProductionDoryV3ModelStructureError::InspectOutput {
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

fn cleanup_structure_output_error(
    output: &mut PendingOutput,
    parent: &TrustedCeremonyParent,
    original: ProductionDoryV3ModelStructureError,
) -> ProductionDoryV3ModelStructureError {
    match output.remove_explicit(parent) {
        Ok(()) => original,
        Err(cleanup) if output.was_removed() => map_structure_output_fs(cleanup),
        Err(cleanup) => ProductionDoryV3ModelStructureError::QuarantinedOutput {
            path: ceremony_fs_error_path(&cleanup),
            original: original.to_string(),
            cleanup: cleanup.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(windows)]
    use std::fs::OpenOptions;
    use std::{
        fs,
        io::{Cursor, SeekFrom},
        sync::atomic::{AtomicU64, Ordering},
    };

    static TEST_NONCE: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "cmfd-structural-report-test-{}-{}",
                std::process::id(),
                TEST_NONCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            crate::dory_v3_model_ceremony_fs::prepare_test_parent(&path).unwrap();
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

    fn small_geometry() -> StructuralGeometry {
        StructuralGeometry {
            base_rows: 2,
            columns: 3,
            layer_rows: 3,
            layers: 3,
        }
    }

    fn small_payload() -> Vec<u8> {
        let mut payload = vec![1, 1, 1, 1, 2, 3];
        payload.extend_from_slice(&[7; 9]);
        payload.extend_from_slice(&[7; 9]);
        payload.extend_from_slice(&[0, 1, 2, 1, 2, 0, 2, 0, 1]);
        payload
    }

    fn expected_roots(geometry: StructuralGeometry, payload: &[u8]) -> ExpectedRoots {
        let base_bytes = usize::try_from(geometry.base_bytes().unwrap()).unwrap();
        let layer_bytes = usize::try_from(geometry.layer_bytes().unwrap()).unwrap();
        let mut layer_roots = Vec::new();
        let mut aggregate = start_layer_aggregate(geometry.layers);
        for layer_index in 0..geometry.layers {
            let start = base_bytes + usize::try_from(layer_index).unwrap() * layer_bytes;
            let root = blake3::hash(&payload[start..start + layer_bytes]);
            layer_roots.push(Digest32::new(*root.as_bytes()));
            add_layer_root(&mut aggregate, layer_index, root);
        }
        ExpectedRoots {
            ceremony_id: Digest32::new([0x42; 32]),
            payload_bytes: u64::try_from(payload.len()).unwrap(),
            raw_blake3: Digest32::new(*blake3::hash(payload).as_bytes()),
            raw_sha256: Digest32::new(finalize_sha256(Sha256::new_with_prefix(payload))),
            base_root: Digest32::new(*blake3::hash(&payload[..base_bytes]).as_bytes()),
            layer_roots,
            layer_aggregate: Digest32::new(*aggregate.finalize().as_bytes()),
        }
    }

    fn synthetic_production_report() -> (
        StructuralGeometry,
        ExpectedRoots,
        ProductionDoryV3ModelStructuralReport,
    ) {
        let geometry = StructuralGeometry::production().unwrap();
        let mut layer_roots = Vec::with_capacity(usize::try_from(geometry.layers).unwrap());
        let mut aggregate = start_layer_aggregate(geometry.layers);
        for index in 0..geometry.layers {
            let root = blake3::hash(&index.to_le_bytes());
            layer_roots.push(Digest32::new(*root.as_bytes()));
            add_layer_root(&mut aggregate, index, root);
        }
        let expected = ExpectedRoots {
            ceremony_id: Digest32::new([0x31; 32]),
            payload_bytes: geometry.payload_bytes().unwrap(),
            raw_blake3: Digest32::new([0x32; 32]),
            raw_sha256: Digest32::new([0x33; 32]),
            base_root: Digest32::new([0x34; 32]),
            layer_roots,
            layer_aggregate: Digest32::new(*aggregate.finalize().as_bytes()),
        };
        let mut sections =
            Vec::with_capacity(usize::try_from(geometry.section_count().unwrap()).unwrap());
        let mut base_histogram = [0_u64; HISTOGRAM_BINS];
        base_histogram[0] = geometry.base_bytes().unwrap();
        sections.push(DoryV3ModelStructuralSection {
            kind: DoryV3ModelStructuralSectionKind::Base,
            index: BASE_SECTION_INDEX,
            rows: geometry.base_rows,
            columns: geometry.columns,
            section_bytes: geometry.base_bytes().unwrap(),
            section_blake3_root: expected.base_root,
            histogram: base_histogram,
            constant_rows: u64::from(geometry.base_rows),
            constant_columns: u64::from(geometry.columns),
        });
        for (index, root) in expected.layer_roots.iter().copied().enumerate() {
            let mut histogram = [0_u64; HISTOGRAM_BINS];
            histogram[0] = geometry.layer_bytes().unwrap();
            sections.push(DoryV3ModelStructuralSection {
                kind: DoryV3ModelStructuralSectionKind::WeightLayer,
                index: u32::try_from(index).unwrap(),
                rows: geometry.layer_rows,
                columns: geometry.columns,
                section_bytes: geometry.layer_bytes().unwrap(),
                section_blake3_root: root,
                histogram,
                constant_rows: u64::from(geometry.layer_rows),
                constant_columns: u64::from(geometry.columns),
            });
        }
        let duplicate_row_pairs = checked_add(
            unordered_pairs(geometry.base_rows).unwrap(),
            unordered_pairs(geometry.layer_rows).unwrap() * u64::from(geometry.layers),
        )
        .unwrap();
        let duplicate_column_pairs = unordered_pairs(geometry.columns).unwrap()
            * u64::from(geometry.section_count().unwrap());
        let duplicate_layer_pairs = unordered_pairs(geometry.layers).unwrap();
        let report = ProductionDoryV3ModelStructuralReport {
            ceremony_id: expected.ceremony_id,
            payload_bytes: expected.payload_bytes,
            raw_payload_blake3: expected.raw_blake3,
            raw_payload_sha256: expected.raw_sha256,
            sections,
            duplicate_row_pairs,
            duplicate_column_pairs,
            duplicate_layer_pairs,
            diagnostic_mask: DIAGNOSTIC_ALLOWED_MASK,
            fatal_mask: 0,
        };
        (geometry, expected, report)
    }

    #[test]
    fn production_codec_is_exactly_799795_bytes_and_round_trips() {
        let (geometry, expected, report) = synthetic_production_report();
        let bytes = report.canonical_bytes();
        assert_eq!(
            bytes.len(),
            PRODUCTION_DORY_V3_MODEL_STRUCTURAL_REPORT_BYTES
        );
        assert_eq!(&bytes[..8], b"CMFDSR01");
        assert_eq!(
            encoded_report_bytes(PRODUCTION_DORY_V3_MODEL_STRUCTURAL_SECTION_COUNT as usize)
                .unwrap(),
            PRODUCTION_DORY_V3_MODEL_STRUCTURAL_REPORT_BYTES
        );
        assert_eq!(
            parse_and_validate_with_geometry(&bytes, geometry, &expected, true).unwrap(),
            report
        );
    }

    #[test]
    fn parser_rejects_noncanonical_length_magic_order_and_reserved_masks() {
        let (geometry, expected, report) = synthetic_production_report();
        let bytes = report.canonical_bytes();

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(matches!(
            parse_and_validate_with_geometry(&trailing, geometry, &expected, true),
            Err(ProductionDoryV3ModelStructureError::ReportLength { .. })
        ));

        let mut magic = bytes.clone();
        magic[0] ^= 1;
        assert!(matches!(
            parse_and_validate_with_geometry(&magic, geometry, &expected, true),
            Err(ProductionDoryV3ModelStructureError::InvalidMagic)
        ));

        let first_section_index_offset = STRUCTURAL_HEADER_BYTES + 1;
        let mut order = bytes.clone();
        order[first_section_index_offset..first_section_index_offset + 4]
            .copy_from_slice(&0_u32.to_le_bytes());
        assert!(matches!(
            parse_and_validate_with_geometry(&order, geometry, &expected, true),
            Err(ProductionDoryV3ModelStructureError::InvalidSectionGeometry { position: 0 })
        ));

        let mut diagnostic = bytes.clone();
        let diagnostic_offset = diagnostic.len() - 8;
        diagnostic[diagnostic_offset..diagnostic_offset + 4]
            .copy_from_slice(&(DIAGNOSTIC_ALLOWED_MASK | (1 << 31)).to_le_bytes());
        assert!(matches!(
            parse_and_validate_with_geometry(&diagnostic, geometry, &expected, true),
            Err(ProductionDoryV3ModelStructureError::ReservedDiagnosticBits)
        ));

        let mut fatal = bytes;
        let fatal_offset = fatal.len() - 4;
        fatal[fatal_offset..].copy_from_slice(&(1_u32 << 31).to_le_bytes());
        assert!(matches!(
            parse_and_validate_with_geometry(&fatal, geometry, &expected, true),
            Err(ProductionDoryV3ModelStructureError::ReservedFatalBits)
        ));
    }

    #[test]
    fn bounded_analyzer_counts_histograms_constants_and_exact_duplicates() {
        let geometry = small_geometry();
        let payload = small_payload();
        let expected = expected_roots(geometry, &payload);
        let report = analyze_with_geometry(&mut Cursor::new(payload), geometry, &expected).unwrap();

        assert_eq!(report.sections.len(), 4);
        assert_eq!(report.sections[0].constant_rows, 1);
        assert_eq!(report.sections[0].constant_columns, 1);
        assert_eq!(report.sections[1].constant_rows, 3);
        assert_eq!(report.sections[1].constant_columns, 3);
        assert_eq!(report.sections[2].constant_rows, 3);
        assert_eq!(report.sections[2].constant_columns, 3);
        assert_eq!(report.sections[3].constant_rows, 0);
        assert_eq!(report.sections[3].constant_columns, 0);
        assert_eq!(report.duplicate_row_pairs, 6);
        assert_eq!(report.duplicate_column_pairs, 6);
        assert_eq!(report.duplicate_layer_pairs, 1);
        assert_eq!(report.diagnostic_mask, DIAGNOSTIC_ALLOWED_MASK);
        assert_eq!(report.fatal_mask, 0);
        for section in &report.sections {
            assert_eq!(
                section.histogram.iter().copied().sum::<u64>(),
                section.section_bytes
            );
        }
    }

    #[test]
    fn independent_verifier_rejects_invented_structural_counts() {
        let geometry = small_geometry();
        let payload = small_payload();
        let expected = expected_roots(geometry, &payload);
        let report =
            analyze_with_geometry(&mut Cursor::new(&payload), geometry, &expected).unwrap();
        let canonical = report.canonical_bytes();
        assert_eq!(
            verify_with_geometry(&mut Cursor::new(&payload), &canonical, geometry, &expected)
                .unwrap(),
            report
        );

        let mut invented = report;
        invented.duplicate_row_pairs += 1;
        let invented_bytes = invented.canonical_bytes();
        assert!(
            parse_and_validate_with_geometry(&invented_bytes, geometry, &expected, true).is_ok()
        );
        assert!(matches!(
            verify_with_geometry(
                &mut Cursor::new(payload),
                &invented_bytes,
                geometry,
                &expected
            ),
            Err(ProductionDoryV3ModelStructureError::PayloadReportMismatch)
        ));
    }

    #[test]
    fn invalid_payload_or_roots_never_produce_a_report() {
        let geometry = small_geometry();
        let payload = small_payload();
        let expected = expected_roots(geometry, &payload);

        let mut short = payload.clone();
        short.pop();
        assert!(matches!(
            analyze_with_geometry(&mut Cursor::new(short), geometry, &expected),
            Err(ProductionDoryV3ModelStructureError::EarlyEof { .. })
        ));

        let mut trailing = payload.clone();
        trailing.push(0);
        assert!(matches!(
            analyze_with_geometry(&mut Cursor::new(trailing), geometry, &expected),
            Err(ProductionDoryV3ModelStructureError::TrailingBytes(_))
        ));

        let mut out_of_range = payload.clone();
        out_of_range[4] = 251;
        assert!(matches!(
            analyze_with_geometry(&mut Cursor::new(out_of_range), geometry, &expected),
            Err(ProductionDoryV3ModelStructureError::OutOfRange {
                offset: 4,
                value: 251
            })
        ));

        let mut wrong_roots = expected.clone();
        wrong_roots.layer_roots[1] = Digest32::new([0xff; 32]);
        assert!(matches!(
            analyze_with_geometry(&mut Cursor::new(payload), geometry, &wrong_roots),
            Err(ProductionDoryV3ModelStructureError::FatalAnalysis(mask))
                if mask == FATAL_ROOT
        ));
    }

    struct MutatingCursor {
        inner: Cursor<Vec<u8>>,
        rewinds: usize,
    }

    impl Read for MutatingCursor {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            self.inner.read(buffer)
        }
    }

    impl Seek for MutatingCursor {
        fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
            if position == SeekFrom::Start(0) {
                self.rewinds += 1;
                if self.rewinds == 2 {
                    self.inner.get_mut()[0] ^= 1;
                }
            }
            self.inner.seek(position)
        }
    }

    #[test]
    fn final_reproduction_detects_a_payload_changed_after_the_first_scan() {
        let geometry = small_geometry();
        let payload = small_payload();
        let expected = expected_roots(geometry, &payload);
        let mut reader = MutatingCursor {
            inner: Cursor::new(payload),
            rewinds: 0,
        };
        let first = analyze_with_geometry(&mut reader, geometry, &expected).unwrap();
        assert_eq!(first.fatal_mask, 0);
        assert!(matches!(
            analyze_with_geometry(&mut reader, geometry, &expected),
            Err(ProductionDoryV3ModelStructureError::FatalAnalysis(mask))
                if mask == FATAL_ROOT
        ));
    }

    #[test]
    fn runner_is_create_new_synced_reopened_and_authenticated() {
        let directory = TestDirectory::new();
        let payload_path = directory.join("payload.bin");
        let output_path = directory.join("structure.bin");
        let geometry = small_geometry();
        let payload = small_payload();
        let expected = expected_roots(geometry, &payload);
        fs::write(&payload_path, &payload).unwrap();

        let run =
            run_with_geometry(&payload_path, &output_path, geometry, &expected, false).unwrap();
        let disk = fs::read(&output_path).unwrap();
        assert_eq!(run.report_bytes, u64::try_from(disk.len()).unwrap());
        assert_eq!(
            run.report_blake3,
            Digest32::new(*blake3::hash(&disk).as_bytes())
        );
        assert_eq!(
            run.report_sha256,
            Digest32::new(finalize_sha256(Sha256::new_with_prefix(&disk)))
        );
        assert_eq!(
            parse_and_validate_with_geometry(&disk, geometry, &expected, true).unwrap(),
            run.report
        );
        assert_eq!(
            validate_files_with_geometry(&payload_path, &output_path, geometry, &expected, false)
                .unwrap(),
            run.report
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(&output_path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                run.durability,
                ProductionDoryV3ModelStructuralReportDurability::FileAndParentDirectorySynced
            );
        }

        let before = disk;
        assert!(matches!(
            run_with_geometry(
                &payload_path,
                &output_path,
                geometry,
                &expected,
                false
            ),
            Err(ProductionDoryV3ModelStructureError::OutputExists(path))
                if path == output_path
        ));
        assert_eq!(fs::read(output_path).unwrap(), before);
    }

    #[test]
    fn post_create_failure_removes_only_the_authenticated_report() {
        let directory = TestDirectory::new();
        let output_path = directory.join("partial.bin");
        let parent = TrustedCeremonyParent::for_artifact(&output_path).unwrap();
        let mut output = PendingOutput::create(&parent, &output_path).unwrap();
        output.write_all(b"partial").unwrap();

        let error = cleanup_structure_output_error(
            &mut output,
            &parent,
            ProductionDoryV3ModelStructureError::ReopenedReportMismatch,
        );
        assert!(matches!(
            error,
            ProductionDoryV3ModelStructureError::ReopenedReportMismatch
        ));
        assert!(!output_path.exists());
    }

    #[test]
    fn cleanup_quarantines_and_preserves_a_replacement_report() {
        let directory = TestDirectory::new();
        let output_path = directory.join("partial.bin");
        let displaced_path = directory.join("displaced.bin");
        let parent = TrustedCeremonyParent::for_artifact(&output_path).unwrap();
        let mut output = PendingOutput::create(&parent, &output_path).unwrap();
        output.write_all(b"original").unwrap();
        output.close_writer();
        fs::rename(&output_path, &displaced_path).unwrap();
        fs::write(&output_path, b"replacement").unwrap();

        let error = cleanup_structure_output_error(
            &mut output,
            &parent,
            ProductionDoryV3ModelStructureError::ReopenedReportMismatch,
        );
        assert!(matches!(
            error,
            ProductionDoryV3ModelStructureError::QuarantinedOutput {
                original,
                cleanup,
                ..
            } if original.contains("reopened structural report differs")
                && cleanup.contains("no longer names the create-new file")
        ));
        assert_eq!(fs::read(output_path).unwrap(), b"replacement");
        assert_eq!(fs::read(displaced_path).unwrap(), b"original");
    }

    #[cfg(windows)]
    #[test]
    fn authenticated_read_handle_denies_concurrent_write_and_delete() {
        let directory = TestDirectory::new();
        let path = directory.join("authenticated.bin");
        fs::write(&path, b"report").unwrap();
        let parent = TrustedCeremonyParent::for_artifact(&path).unwrap();
        let held = AuthenticatedInput::open(&parent, &path, Some(6)).unwrap();

        assert!(OpenOptions::new().write(true).open(&path).is_err());
        assert!(fs::remove_file(&path).is_err());

        drop(held);
        fs::remove_file(path).unwrap();
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn runner_rejects_a_multiply_linkable_payload() {
        let directory = TestDirectory::new();
        let payload_path = directory.join("payload.bin");
        let alias_path = directory.join("payload-alias.bin");
        let output_path = directory.join("structure.bin");
        let geometry = small_geometry();
        let payload = small_payload();
        let expected = expected_roots(geometry, &payload);
        fs::write(&payload_path, payload).unwrap();
        fs::hard_link(&payload_path, &alias_path).unwrap();

        assert!(matches!(
            run_with_geometry(
                &payload_path,
                &output_path,
                geometry,
                &expected,
                false
            ),
            Err(ProductionDoryV3ModelStructureError::PayloadHardLinks {
                path,
                links: 2
            }) if path == payload_path
        ));
        assert!(!output_path.exists());
    }
}
