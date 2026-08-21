//! Optional, non-consensus acceleration for Common Foundry proof generation.
//!
//! [`ProofDft`] uses Plonky3's CPU DFT by default. A prover may explicitly
//! select [`CudaProofDft`] with a caller-supplied library path and device, but
//! proof verification must remain independent of this crate and its backend.

pub mod blake3_merkle_store;
pub mod demand_blake3_tree;
mod external_radix2;
pub mod initial_whir_oracle;
pub mod merkle_store;
mod poseidon2;
pub mod spill;
pub mod whir_extension;
pub mod whir_initial;
pub mod whir_initial_source;
pub mod whir_residual;

pub use poseidon2::{
    CUDA_POSEIDON2_API_VERSION, CUDA_POSEIDON2_MAX_MATRICES, CUDA_POSEIDON2_MAX_ROW_WIDTH,
    CUDA_POSEIDON2_MAX_ROWS, CUDA_POSEIDON2_MAX_TOTAL_LIMBS, CudaProofPoseidon2,
    POSEIDON2_DIGEST_WIDTH,
};

use std::ffi::{c_char, c_void};
use std::fmt;
use std::marker::PhantomData;
use std::mem::{ManuallyDrop, align_of, size_of};
use std::path::{Path, PathBuf};
use std::ptr::NonNull;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use libloading::Library;
use p3_dft::{Layout, Radix2DitParallel, TwoAdicSubgroupDft};
use p3_field::{PrimeField64, TwoAdicField};
use p3_goldilocks::Goldilocks;
use p3_matrix::bitrev::{BitReversalPerm, BitReversedMatrixView};
use p3_matrix::dense::{RowMajorMatrix, RowMajorMatrixViewMut};

/// Version of the standalone proof-acceleration C ABI.
pub const CUDA_PROOF_API_VERSION: u32 = 2;

/// Maximum DFT/LDE height accepted by the CUDA v2 ABI.
pub const CUDA_MAX_HEIGHT: usize = 1 << 24;

/// Maximum matrix width accepted by the CUDA v2 ABI.
///
/// Plonky3's one-block BLAKE3 AIR has 9,168 columns, so the bound must cover
/// that supported proof shape while remaining explicit and finite.
pub const CUDA_MAX_WIDTH: usize = 1 << 14;

/// Maximum input or output element count accepted by the CUDA v2 ABI.
pub const CUDA_MAX_ELEMENTS: usize = 1 << 31;

/// Version of the stateful, bounded proof-stream C ABI.
pub const CUDA_PROOF_STREAM_API_VERSION: u32 = 1;

/// Maximum number of coefficient matrices in one proof stream.
pub const CUDA_PROOF_STREAM_MAX_MATRICES: usize = 64;

/// Maximum source height accepted by proof-stream ABI v1.
pub const CUDA_PROOF_STREAM_MAX_SOURCE_HEIGHT: usize = 1 << 20;

/// Maximum concatenated row width accepted by proof-stream ABI v1.
pub const CUDA_PROOF_STREAM_MAX_TOTAL_WIDTH: usize = 1 << 12;

/// Maximum low-degree-extension blowup exponent accepted by proof-stream ABI v1.
pub const CUDA_PROOF_STREAM_MAX_ADDED_BITS: usize = 7;

/// Maximum expanded row count accepted by proof-stream ABI v1.
pub const CUDA_PROOF_STREAM_MAX_ROWS: usize = 1 << 27;

/// Maximum source coefficient count accepted by proof-stream ABI v1.
pub const CUDA_PROOF_STREAM_MAX_INPUT_LIMBS: usize = 1 << 31;

/// Maximum number of rows returned by one proof-stream call.
pub const CUDA_PROOF_STREAM_MAX_CHUNK_ROWS: usize = 1 << 16;

const ERROR_BUFFER_BYTES: usize = 512;
const ORDER_NATURAL: u32 = 0;
const ORDER_PHYSICAL_BIT_REVERSED: u32 = 1;

/// Plonky3's logical natural-order view over physically bit-reversed rows.
pub type ProofEvaluations = BitReversedMatrixView<RowMajorMatrix<Goldilocks>>;

/// A checked error at the optional proof-acceleration boundary.
#[derive(Debug)]
pub enum ProofAccelError {
    LoadLibrary {
        path: PathBuf,
        message: String,
    },
    MissingSymbol {
        symbol: &'static str,
        message: String,
    },
    AbiVersion {
        expected: u32,
        actual: u32,
    },
    ProofStreamAbiVersion {
        expected: u32,
        actual: u32,
    },
    Poseidon2AbiVersion {
        expected: u32,
        actual: u32,
    },
    Backend {
        operation: &'static str,
        code: i32,
        message: String,
    },
    InvalidDeviceCount(i32),
    DeviceOutOfRange {
        requested: i32,
        count: i32,
    },
    InvalidDeviceInfo(String),
    NullContext,
    InvalidDimensions(String),
    NonCanonicalOutput {
        index: usize,
        value: u64,
    },
    ProofStreamPoisoned,
    ContextPoisoned,
}

impl fmt::Display for ProofAccelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LoadLibrary { path, message } => {
                write!(formatter, "could not load {}: {message}", path.display())
            }
            Self::MissingSymbol { symbol, message } => {
                write!(
                    formatter,
                    "proof CUDA backend is missing {symbol}: {message}"
                )
            }
            Self::AbiVersion { expected, actual } => write!(
                formatter,
                "proof CUDA ABI version {actual} does not match required version {expected}"
            ),
            Self::ProofStreamAbiVersion { expected, actual } => write!(
                formatter,
                "proof CUDA stream ABI version {actual} does not match required version {expected}"
            ),
            Self::Poseidon2AbiVersion { expected, actual } => write!(
                formatter,
                "proof CUDA Poseidon2 ABI version {actual} does not match required version {expected}"
            ),
            Self::Backend {
                operation,
                code,
                message,
            } if message.is_empty() => {
                write!(formatter, "proof CUDA {operation} failed with code {code}")
            }
            Self::Backend {
                operation,
                code,
                message,
            } => write!(
                formatter,
                "proof CUDA {operation} failed with code {code}: {message}"
            ),
            Self::InvalidDeviceCount(count) => {
                write!(
                    formatter,
                    "proof CUDA backend returned invalid device count {count}"
                )
            }
            Self::DeviceOutOfRange { requested, count } => write!(
                formatter,
                "proof CUDA device {requested} is outside the available range 0..{count}"
            ),
            Self::InvalidDeviceInfo(message) => {
                write!(
                    formatter,
                    "proof CUDA backend returned invalid device information: {message}"
                )
            }
            Self::NullContext => write!(formatter, "proof CUDA backend returned a null context"),
            Self::InvalidDimensions(message) => formatter.write_str(message),
            Self::NonCanonicalOutput { index, value } => write!(
                formatter,
                "proof CUDA backend returned noncanonical Goldilocks limb {value} at index {index}"
            ),
            Self::ProofStreamPoisoned => formatter.write_str(
                "proof CUDA stream is unusable after an earlier backend or output-validation failure",
            ),
            Self::ContextPoisoned => {
                write!(formatter, "proof CUDA context lock was poisoned")
            }
        }
    }
}

impl std::error::Error for ProofAccelError {}

type ApiVersionFn = unsafe extern "C" fn() -> u32;
type DeviceCountFn = unsafe extern "C" fn(*mut i32, *mut c_char, usize) -> i32;
type DeviceInfoFn = unsafe extern "C" fn(i32, *mut RawDeviceInfo, *mut c_char, usize) -> i32;
type CreateFn = unsafe extern "C" fn(i32, *mut *mut c_void, *mut c_char, usize) -> i32;
type DftFn = unsafe extern "C" fn(
    *mut c_void,
    *const u64,
    usize,
    u32,
    u32,
    u32,
    u32,
    u32,
    *mut u64,
    usize,
    *mut c_char,
    usize,
) -> i32;
type CosetLdeFn = unsafe extern "C" fn(
    *mut c_void,
    *const u64,
    usize,
    u32,
    u32,
    u32,
    u64,
    u32,
    u32,
    *mut u64,
    usize,
    *mut c_char,
    usize,
) -> i32;
type CoefficientsToCosetLdeFn = unsafe extern "C" fn(
    *mut c_void,
    *const u64,
    usize,
    u32,
    u32,
    u32,
    u64,
    *mut u64,
    usize,
    *mut c_char,
    usize,
) -> i32;
type DestroyFn = unsafe extern "C" fn(*mut c_void);

type ProofStreamCreateFn = unsafe extern "C" fn(
    i32,
    *const RawProofStreamMatrixV1,
    usize,
    u32,
    *mut *mut c_void,
    *mut c_char,
    usize,
) -> i32;
type ProofStreamNextFn = unsafe extern "C" fn(
    *mut c_void,
    u64,
    u32,
    *mut u64,
    usize,
    *mut u64,
    usize,
    *mut c_char,
    usize,
) -> i32;
type ProofStreamDestroyFn = unsafe extern "C" fn(*mut c_void);

#[repr(C)]
struct RawProofStreamMatrixV1 {
    physical_coefficients: *const u64,
    coefficients_len: usize,
    height: u32,
    width: u32,
    coset_shift: u64,
}

#[repr(C)]
struct RawDeviceInfo {
    api_version: u32,
    device_index: i32,
    compute_major: u32,
    compute_minor: u32,
    total_memory_bytes: u64,
    name: [c_char; 128],
}

impl Default for RawDeviceInfo {
    fn default() -> Self {
        Self {
            api_version: 0,
            device_index: -1,
            compute_major: 0,
            compute_minor: 0,
            total_memory_bytes: 0,
            name: [0; 128],
        }
    }
}

struct CudaApi {
    device_count: DeviceCountFn,
    device_info: DeviceInfoFn,
    create: CreateFn,
    dft: DftFn,
    coset_lde: CosetLdeFn,
    coefficients_to_coset_lde: CoefficientsToCosetLdeFn,
    destroy: DestroyFn,
    _library: Library,
}

impl CudaApi {
    fn load(path: &Path) -> Result<Self, ProofAccelError> {
        // SAFETY: every copied function pointer is checked against the
        // versioned C ABI and `library` remains owned by the returned API.
        unsafe {
            let library = Library::new(path).map_err(|error| ProofAccelError::LoadLibrary {
                path: path.to_path_buf(),
                message: error.to_string(),
            })?;
            let api_version: ApiVersionFn = load_symbol(
                &library,
                "cmfd_proof_cuda_api_version",
                b"cmfd_proof_cuda_api_version\0",
            )?;
            let actual = api_version();
            if actual != CUDA_PROOF_API_VERSION {
                return Err(ProofAccelError::AbiVersion {
                    expected: CUDA_PROOF_API_VERSION,
                    actual,
                });
            }
            Ok(Self {
                device_count: load_symbol(
                    &library,
                    "cmfd_proof_cuda_device_count",
                    b"cmfd_proof_cuda_device_count\0",
                )?,
                device_info: load_symbol(
                    &library,
                    "cmfd_proof_cuda_device_info",
                    b"cmfd_proof_cuda_device_info\0",
                )?,
                create: load_symbol(
                    &library,
                    "cmfd_proof_cuda_create",
                    b"cmfd_proof_cuda_create\0",
                )?,
                dft: load_symbol(&library, "cmfd_proof_cuda_dft", b"cmfd_proof_cuda_dft\0")?,
                coset_lde: load_symbol(
                    &library,
                    "cmfd_proof_cuda_coset_lde",
                    b"cmfd_proof_cuda_coset_lde\0",
                )?,
                coefficients_to_coset_lde: load_symbol(
                    &library,
                    "cmfd_proof_cuda_coefficients_to_coset_lde",
                    b"cmfd_proof_cuda_coefficients_to_coset_lde\0",
                )?,
                destroy: load_symbol(
                    &library,
                    "cmfd_proof_cuda_destroy",
                    b"cmfd_proof_cuda_destroy\0",
                )?,
                _library: library,
            })
        }
    }
}

struct ProofStreamApi {
    create: ProofStreamCreateFn,
    next: ProofStreamNextFn,
    destroy: ProofStreamDestroyFn,
    // Tests install exact-signature fake functions without loading a dynamic
    // library. Production always stores the library here so its code remains
    // loaded through the final context destruction.
    _library: Option<Library>,
}

impl ProofStreamApi {
    fn load(path: &Path) -> Result<Self, ProofAccelError> {
        // SAFETY: every copied function pointer has the exact proof-stream v1
        // signature, and the loaded library is retained by the returned API.
        unsafe {
            let library = Library::new(path).map_err(|error| ProofAccelError::LoadLibrary {
                path: path.to_path_buf(),
                message: error.to_string(),
            })?;
            let api_version: ApiVersionFn = load_symbol(
                &library,
                "cmfd_proof_stream_api_version",
                b"cmfd_proof_stream_api_version\0",
            )?;
            let actual = api_version();
            if actual != CUDA_PROOF_STREAM_API_VERSION {
                return Err(ProofAccelError::ProofStreamAbiVersion {
                    expected: CUDA_PROOF_STREAM_API_VERSION,
                    actual,
                });
            }
            Ok(Self {
                create: load_symbol(
                    &library,
                    "cmfd_proof_stream_create",
                    b"cmfd_proof_stream_create\0",
                )?,
                next: load_symbol(
                    &library,
                    "cmfd_proof_stream_next",
                    b"cmfd_proof_stream_next\0",
                )?,
                destroy: load_symbol(
                    &library,
                    "cmfd_proof_stream_destroy",
                    b"cmfd_proof_stream_destroy\0",
                )?,
                _library: Some(library),
            })
        }
    }
}

unsafe fn load_symbol<T: Copy>(
    library: &Library,
    symbol_name: &'static str,
    symbol: &[u8],
) -> Result<T, ProofAccelError> {
    // SAFETY: the caller supplies an exact signature from a checked,
    // versioned proof CUDA ABI.
    unsafe {
        library
            .get::<T>(symbol)
            .map(|loaded| *loaded)
            .map_err(|error| ProofAccelError::MissingSymbol {
                symbol: symbol_name,
                message: error.to_string(),
            })
    }
}

/// Information reported for the explicitly selected CUDA proof device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CudaProofDevice {
    pub index: i32,
    pub name: String,
    pub compute_major: u32,
    pub compute_minor: u32,
    pub total_memory_bytes: u64,
}

/// One ordered coefficient matrix supplied to [`CudaProofStream`].
///
/// Rows must use the physical bit-reversed coefficient order expected by the
/// proof-stream ABI. The constructor preserves caller order; matrices are
/// concatenated in exactly the order of the slice passed to
/// [`CudaProofStream::load`].
#[derive(Clone, Copy)]
pub struct CudaProofStreamMatrix<'a> {
    coefficients: &'a RowMajorMatrix<Goldilocks>,
    coset_shift: Goldilocks,
}

impl<'a> CudaProofStreamMatrix<'a> {
    pub const fn new(
        coefficients: &'a RowMajorMatrix<Goldilocks>,
        coset_shift: Goldilocks,
    ) -> Self {
        Self {
            coefficients,
            coset_shift,
        }
    }

    pub const fn coefficients(&self) -> &'a RowMajorMatrix<Goldilocks> {
        self.coefficients
    }

    pub const fn coset_shift(&self) -> Goldilocks {
        self.coset_shift
    }
}

impl fmt::Debug for CudaProofStreamMatrix<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CudaProofStreamMatrix")
            .field(
                "height",
                &(self.coefficients.values.len() / self.coefficients.width.max(1)),
            )
            .field("width", &self.coefficients.width)
            .field("coset_shift", &self.coset_shift.as_canonical_u64())
            .finish()
    }
}

/// Immutable plain-data identity for one ordered proof-stream component.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CudaProofStreamComponent {
    ordinal: usize,
    width: usize,
    coset_shift: u64,
}

impl CudaProofStreamComponent {
    pub const fn ordinal(&self) -> usize {
        self.ordinal
    }

    pub const fn width(&self) -> usize {
        self.width
    }

    pub const fn coset_shift(&self) -> u64 {
        self.coset_shift
    }
}

/// One validated chunk returned by [`CudaProofStream::next_rows`].
#[derive(Debug, PartialEq, Eq)]
pub struct CudaProofStreamRows {
    /// First global physical LDE row represented by this chunk.
    global_physical_row: u64,
    /// Poseidon2 width-4 digests, one row per emitted LDE row.
    digests: RowMajorMatrix<Goldilocks>,
    /// Concatenated physical LDE rows when requested by the caller.
    lde: Option<RowMajorMatrix<Goldilocks>>,
    /// Width of each concatenated LDE row, including digest-only chunks.
    lde_width: usize,
}

impl CudaProofStreamRows {
    pub const fn global_physical_row(&self) -> u64 {
        self.global_physical_row
    }

    pub fn row_count(&self) -> usize {
        self.digests.values.len() / self.digests.width
    }

    pub const fn digest_width(&self) -> usize {
        self.digests.width
    }

    pub const fn lde_width(&self) -> usize {
        self.lde_width
    }

    pub const fn digests(&self) -> &RowMajorMatrix<Goldilocks> {
        &self.digests
    }

    pub fn lde(&self) -> Option<&RowMajorMatrix<Goldilocks>> {
        self.lde.as_ref()
    }

    /// Consume this chunk and expose its already-validated canonical limbs
    /// without allocating or copying the potentially large output buffers.
    pub fn into_canonical_values(self) -> CudaProofStreamCanonicalRows {
        let row_count = self.row_count();
        CudaProofStreamCanonicalRows {
            global_physical_row: self.global_physical_row,
            row_count,
            digest_width: self.digests.width,
            lde_width: self.lde_width,
            digests: goldilocks_vec_into_u64s(self.digests.values),
            lde: self
                .lde
                .map(|matrix| goldilocks_vec_into_u64s(matrix.values)),
        }
    }
}

/// Canonical host limbs from one consumed proof-stream chunk.
///
/// This transport type has no Plonky3 types in its fields, so a spill writer
/// can persist exact rows without a direct P3 dependency.
#[derive(Debug, PartialEq, Eq)]
pub struct CudaProofStreamCanonicalRows {
    pub global_physical_row: u64,
    pub row_count: usize,
    pub digest_width: usize,
    pub lde_width: usize,
    pub digests: Vec<u64>,
    pub lde: Option<Vec<u64>>,
}

/// Unique owner of one stateful CUDA proof stream.
///
/// This type is intentionally not `Clone`. Advancing requires `&mut self`, and
/// the wrapper supplies the ABI cursor itself, so safe callers cannot race or
/// replay chunks. Any backend or output-validation failure permanently
/// poisons the stream; there is no implicit CPU fallback.
pub struct CudaProofStream {
    api: Arc<ProofStreamApi>,
    context: Option<NonNull<c_void>>,
    library_path: Option<PathBuf>,
    source_height: u64,
    expanded_rows: u64,
    added_bits: usize,
    total_width: usize,
    components: Vec<CudaProofStreamComponent>,
    cursor: u64,
    poisoned: bool,
    _not_send_or_sync: PhantomData<Rc<()>>,
}

impl fmt::Debug for CudaProofStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CudaProofStream")
            .field("library_path", &self.library_path)
            .field("source_height", &self.source_height)
            .field("expanded_rows", &self.expanded_rows)
            .field("added_bits", &self.added_bits)
            .field("total_width", &self.total_width)
            .field("components", &self.components)
            .field("cursor", &self.cursor)
            .field("poisoned", &self.poisoned)
            .finish_non_exhaustive()
    }
}

impl CudaProofStream {
    /// Load an explicitly named proof library and synchronously copy an ordered
    /// collection of physical bit-reversed coefficient matrices into a new
    /// stateful stream.
    pub fn load(
        path: impl AsRef<Path>,
        device_index: i32,
        matrices: &[CudaProofStreamMatrix<'_>],
        added_bits: usize,
    ) -> Result<Self, ProofAccelError> {
        let path = path.as_ref();
        let api = Arc::new(ProofStreamApi::load(path)?);
        Self::create_with_api(
            api,
            Some(path.to_path_buf()),
            device_index,
            matrices,
            added_bits,
        )
    }

    fn create_with_api(
        api: Arc<ProofStreamApi>,
        library_path: Option<PathBuf>,
        device_index: i32,
        matrices: &[CudaProofStreamMatrix<'_>],
        added_bits: usize,
    ) -> Result<Self, ProofAccelError> {
        if device_index < 0 {
            return Err(ProofAccelError::InvalidDimensions(
                "proof CUDA stream device index must be nonnegative".to_owned(),
            ));
        }
        let plan = validate_proof_stream_matrices(matrices, added_bits)?;
        let encoded = matrices
            .iter()
            .enumerate()
            .map(|(index, matrix)| {
                proof_stream_canonical_storage(matrix.coefficients.values.as_slice(), index)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let raw_matrices = matrices
            .iter()
            .zip(&plan.shapes)
            .zip(&encoded)
            .map(|((matrix, shape), coefficients)| RawProofStreamMatrixV1 {
                physical_coefficients: coefficients.as_slice().as_ptr(),
                coefficients_len: coefficients.as_slice().len(),
                height: u32::try_from(shape.height)
                    .expect("validated proof-stream height fits u32"),
                width: u32::try_from(shape.width).expect("validated proof-stream width fits u32"),
                coset_shift: matrix.coset_shift.as_canonical_u64(),
            })
            .collect::<Vec<_>>();
        let components = matrices
            .iter()
            .zip(&plan.shapes)
            .enumerate()
            .map(|(ordinal, (matrix, shape))| CudaProofStreamComponent {
                ordinal,
                width: shape.width,
                coset_shift: matrix.coset_shift.as_canonical_u64(),
            })
            .collect();

        let mut raw_context = std::ptr::null_mut();
        let mut error = [0 as c_char; ERROR_BUFFER_BYTES];
        // SAFETY: descriptor pointers reference immutable canonical buffers
        // through this synchronous call. The ABI copies them before returning.
        let result = unsafe {
            (api.create)(
                device_index,
                raw_matrices.as_ptr(),
                raw_matrices.len(),
                u32::try_from(added_bits).expect("validated added_bits fits u32"),
                &mut raw_context,
                error.as_mut_ptr(),
                error.len(),
            )
        };
        if result != 0 {
            if !raw_context.is_null() {
                // SAFETY: a non-null failure result is still owned by this
                // call, and v1 permits destruction of any returned context.
                unsafe { (api.destroy)(raw_context) };
            }
            return Err(ProofAccelError::Backend {
                operation: "stream create",
                code: result,
                message: decode_c_chars(&error),
            });
        }
        let context = NonNull::new(raw_context).ok_or(ProofAccelError::NullContext)?;
        Ok(Self {
            api,
            context: Some(context),
            library_path,
            source_height: plan.source_height as u64,
            expanded_rows: plan.expanded_rows as u64,
            added_bits,
            total_width: plan.total_width,
            components,
            cursor: 0,
            poisoned: false,
            _not_send_or_sync: PhantomData,
        })
    }

    pub fn library_path(&self) -> Option<&Path> {
        self.library_path.as_deref()
    }

    pub const fn source_height(&self) -> u64 {
        self.source_height
    }

    pub const fn expanded_rows(&self) -> u64 {
        self.expanded_rows
    }

    pub const fn added_bits(&self) -> usize {
        self.added_bits
    }

    pub const fn total_width(&self) -> usize {
        self.total_width
    }

    pub fn components(&self) -> &[CudaProofStreamComponent] {
        &self.components
    }

    pub const fn cursor(&self) -> u64 {
        self.cursor
    }

    pub const fn is_finished(&self) -> bool {
        self.cursor == self.expanded_rows
    }

    /// Return the next globally ordered physical rows.
    ///
    /// `requested_rows` must be a nonzero power of two no larger than `2^16`,
    /// fit in the remaining stream, and remain within the current source-height
    /// coset block. Set `include_lde` to false to receive only the digest rows.
    pub fn next_rows(
        &mut self,
        requested_rows: usize,
        include_lde: bool,
    ) -> Result<CudaProofStreamRows, ProofAccelError> {
        if self.poisoned {
            return Err(ProofAccelError::ProofStreamPoisoned);
        }
        validate_proof_stream_request(
            self.cursor,
            self.source_height,
            self.expanded_rows,
            requested_rows,
        )?;
        let digest_len = requested_rows.checked_mul(4).ok_or_else(|| {
            ProofAccelError::InvalidDimensions(
                "proof CUDA stream digest output length overflow".to_owned(),
            )
        })?;
        let mut digests = try_zeroed_output(digest_len, "stream digest output")?;
        let mut lde = if include_lde {
            let lde_len = requested_rows
                .checked_mul(self.total_width)
                .ok_or_else(|| {
                    ProofAccelError::InvalidDimensions(
                        "proof CUDA stream LDE output length overflow".to_owned(),
                    )
                })?;
            Some(try_zeroed_output(lde_len, "stream LDE output")?)
        } else {
            None
        };
        let (lde_pointer, lde_len) = lde.as_mut().map_or((std::ptr::null_mut(), 0), |values| {
            (values.as_mut_ptr(), values.len())
        });
        let start = self.cursor;
        let mut error = [0 as c_char; ERROR_BUFFER_BYTES];
        let context = self
            .context
            .expect("live proof stream always retains its context");
        // SAFETY: all output pointers are either null with zero length or
        // writable exact-length buffers. Unique `&mut self` serializes cursor
        // advancement and context access.
        let result = unsafe {
            (self.api.next)(
                context.as_ptr(),
                start,
                u32::try_from(requested_rows).expect("validated chunk size fits u32"),
                lde_pointer,
                lde_len,
                digests.as_mut_ptr(),
                digests.len(),
                error.as_mut_ptr(),
                error.len(),
            )
        };
        if result != 0 {
            self.poisoned = true;
            return Err(ProofAccelError::Backend {
                operation: "stream next",
                code: result,
                message: decode_c_chars(&error),
            });
        }

        let decoded_digests = match decode_output_matrix(digests, 4) {
            Ok(output) => output,
            Err(error) => {
                self.poisoned = true;
                return Err(error);
            }
        };
        let decoded_lde = match lde {
            Some(values) => match decode_output_matrix(values, self.total_width) {
                Ok(output) => Some(output),
                Err(error) => {
                    self.poisoned = true;
                    return Err(error);
                }
            },
            None => None,
        };
        self.cursor = self
            .cursor
            .checked_add(requested_rows as u64)
            .expect("validated proof-stream cursor cannot overflow");
        Ok(CudaProofStreamRows {
            global_physical_row: start,
            digests: decoded_digests,
            lde: decoded_lde,
            lde_width: self.total_width,
        })
    }
}

impl Drop for CudaProofStream {
    fn drop(&mut self) {
        if let Some(context) = self.context.take() {
            // SAFETY: `CudaProofStream` uniquely owns the live context and the
            // backing library remains stored in `api` through this call.
            unsafe { (self.api.destroy)(context.as_ptr()) };
        }
    }
}

struct ContextHandle(NonNull<c_void>);

// SAFETY: all access to the opaque handle is serialized by `CudaContext`'s
// mutex. The ABI permits a context to move between host threads and its
// destructor cannot run while an `Arc<CudaContext>` call is in flight.
unsafe impl Send for ContextHandle {}

struct CudaContext {
    api: Arc<CudaApi>,
    handle: Mutex<ContextHandle>,
}

impl Drop for CudaContext {
    fn drop(&mut self) {
        let handle = match self.handle.get_mut() {
            Ok(handle) => handle.0,
            Err(poisoned) => poisoned.into_inner().0,
        };
        // SAFETY: this is the unique live context returned by `create`; the
        // backing library remains owned by `api` through this call.
        unsafe { (self.api.destroy)(handle.as_ptr()) };
    }
}

/// An explicitly loaded CUDA prover DFT. Clones share one serialized context.
#[derive(Clone)]
pub struct CudaProofDft {
    context: Arc<CudaContext>,
    device: CudaProofDevice,
    library_path: PathBuf,
}

impl fmt::Debug for CudaProofDft {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CudaProofDft")
            .field("device", &self.device)
            .field("library_path", &self.library_path)
            .finish_non_exhaustive()
    }
}

impl CudaProofDft {
    /// Load the exact caller-supplied library and create the selected device.
    ///
    /// This function never searches default paths or reads environment
    /// variables. Once selected, backend failures are returned to the caller
    /// and never converted into CPU fallback.
    pub fn load(path: impl AsRef<Path>, device_index: i32) -> Result<Self, ProofAccelError> {
        let path = path.as_ref();
        let api = Arc::new(CudaApi::load(path)?);
        let count = device_count(&api)?;
        if device_index < 0 || device_index >= count {
            return Err(ProofAccelError::DeviceOutOfRange {
                requested: device_index,
                count,
            });
        }
        let device = read_device(&api, device_index)?;
        let mut raw_context = std::ptr::null_mut();
        let mut error = [0 as c_char; ERROR_BUFFER_BYTES];
        // SAFETY: all pointers reference writable buffers of their declared
        // sizes. Ownership transfers only after a successful non-null return.
        let result = unsafe {
            (api.create)(
                device_index,
                &mut raw_context,
                error.as_mut_ptr(),
                error.len(),
            )
        };
        check_backend_result("create", result, &error)?;
        let handle = NonNull::new(raw_context).ok_or(ProofAccelError::NullContext)?;
        Ok(Self {
            context: Arc::new(CudaContext {
                api,
                handle: Mutex::new(ContextHandle(handle)),
            }),
            device,
            library_path: path.to_path_buf(),
        })
    }

    pub fn device(&self) -> &CudaProofDevice {
        &self.device
    }

    pub fn library_path(&self) -> &Path {
        &self.library_path
    }

    /// Execute one forward DFT with natural row-major input and a physically
    /// bit-reversed output compatible with `Radix2DitParallel`.
    pub fn try_dft_batch(
        &self,
        mat: RowMajorMatrix<Goldilocks>,
    ) -> Result<ProofEvaluations, ProofAccelError> {
        let output = self.try_dft_matrix(mat, false)?;
        Ok(BitReversalPerm::new_view(output))
    }

    fn try_inverse_dft_batch_physical(
        &self,
        mat: RowMajorMatrix<Goldilocks>,
    ) -> Result<RowMajorMatrix<Goldilocks>, ProofAccelError> {
        self.try_dft_matrix(mat, true)
    }

    fn try_dft_matrix(
        &self,
        mat: RowMajorMatrix<Goldilocks>,
        inverse: bool,
    ) -> Result<RowMajorMatrix<Goldilocks>, ProofAccelError> {
        let shape = validate_cuda_shape(&mat)?;
        let input = encode_canonical(&mat.values);
        drop(mat);
        let mut output = vec![0_u64; shape.elements];
        let mut error = [0 as c_char; ERROR_BUFFER_BYTES];
        let handle = self
            .context
            .handle
            .lock()
            .map_err(|_| ProofAccelError::ContextPoisoned)?;
        // SAFETY: the serialized context is live; every buffer remains valid
        // for the call and the element counts exactly match its allocation.
        let result = unsafe {
            (self.context.api.dft)(
                handle.0.as_ptr(),
                input.as_ptr(),
                input.len(),
                u32::try_from(shape.height).map_err(|_| {
                    ProofAccelError::InvalidDimensions(
                        "CUDA proof DFT height exceeds u32".to_owned(),
                    )
                })?,
                u32::try_from(shape.width).map_err(|_| {
                    ProofAccelError::InvalidDimensions(
                        "CUDA proof DFT width exceeds u32".to_owned(),
                    )
                })?,
                u32::from(inverse),
                ORDER_NATURAL,
                ORDER_PHYSICAL_BIT_REVERSED,
                output.as_mut_ptr(),
                output.len(),
                error.as_mut_ptr(),
                error.len(),
            )
        };
        check_backend_result("dft", result, &error)?;
        decode_output_matrix(output, shape.width)
    }

    /// Execute a coset low-degree extension with canonical shift and the same
    /// physical bit-reversed output layout used by Plonky3's parallel DFT.
    pub fn try_coset_lde_batch(
        &self,
        mat: RowMajorMatrix<Goldilocks>,
        added_bits: usize,
        shift: Goldilocks,
    ) -> Result<ProofEvaluations, ProofAccelError> {
        let input_shape = validate_cuda_shape(&mat)?;
        let output_shape = validate_cuda_lde_shape(input_shape, added_bits)?;
        let added_bits_u32 = u32::try_from(added_bits).map_err(|_| {
            ProofAccelError::InvalidDimensions("CUDA LDE added-bits value exceeds u32".to_owned())
        })?;
        let input = encode_canonical(&mat.values);
        drop(mat);
        let mut output = vec![0_u64; output_shape.elements];
        let mut error = [0 as c_char; ERROR_BUFFER_BYTES];
        let handle = self
            .context
            .handle
            .lock()
            .map_err(|_| ProofAccelError::ContextPoisoned)?;
        // SAFETY: the serialized context and all declared input/output buffers
        // remain valid for the duration of this exact v2 ABI call.
        let result = unsafe {
            (self.context.api.coset_lde)(
                handle.0.as_ptr(),
                input.as_ptr(),
                input.len(),
                u32::try_from(input_shape.height).map_err(|_| {
                    ProofAccelError::InvalidDimensions(
                        "CUDA proof DFT height exceeds u32".to_owned(),
                    )
                })?,
                u32::try_from(input_shape.width).map_err(|_| {
                    ProofAccelError::InvalidDimensions(
                        "CUDA proof DFT width exceeds u32".to_owned(),
                    )
                })?,
                added_bits_u32,
                shift.as_canonical_u64(),
                ORDER_NATURAL,
                ORDER_PHYSICAL_BIT_REVERSED,
                output.as_mut_ptr(),
                output.len(),
                error.as_mut_ptr(),
                error.len(),
            )
        };
        check_backend_result("coset LDE", result, &error)?;
        decode_bit_reversed_output(output, output_shape.width)
    }

    /// Expand transformed coefficients without materializing the expanded
    /// coefficient matrix on the host. Input rows and returned evaluation rows
    /// both use Plonky3's physical bit-reversed storage order.
    fn try_coefficients_to_coset_lde_batch(
        &self,
        coefficients: RowMajorMatrix<Goldilocks>,
        added_bits: usize,
        shift: Goldilocks,
    ) -> Result<ProofEvaluations, ProofAccelError> {
        let input_shape = validate_cuda_shape(&coefficients)?;
        let plan = coefficient_lde_plan(input_shape, added_bits)?;
        let input = encode_canonical(&coefficients.values);
        // The transformed field matrix is no longer needed after canonical
        // encoding. Drop it before allocating the much larger evaluation
        // output so peak host memory is one small input plus one final output.
        drop(coefficients);
        let mut output = try_zeroed_output(plan.output.elements, "coefficient LDE output")?;
        let mut error = [0 as c_char; ERROR_BUFFER_BYTES];
        let handle = self
            .context
            .handle
            .lock()
            .map_err(|_| ProofAccelError::ContextPoisoned)?;
        // SAFETY: the input is canonical PHYSICAL_BIT_REVERSED coefficient
        // storage, the output is sized for the validated expanded shape, and
        // the serialized context remains live for this exact v2 ABI call.
        let result = unsafe {
            (self.context.api.coefficients_to_coset_lde)(
                handle.0.as_ptr(),
                input.as_ptr(),
                input.len(),
                u32::try_from(plan.input.height).map_err(|_| {
                    ProofAccelError::InvalidDimensions(
                        "CUDA coefficient LDE height exceeds u32".to_owned(),
                    )
                })?,
                u32::try_from(plan.input.width).map_err(|_| {
                    ProofAccelError::InvalidDimensions(
                        "CUDA coefficient LDE width exceeds u32".to_owned(),
                    )
                })?,
                plan.added_bits,
                shift.as_canonical_u64(),
                output.as_mut_ptr(),
                output.len(),
                error.as_mut_ptr(),
                error.len(),
            )
        };
        check_backend_result("coefficient LDE", result, &error)?;
        decode_bit_reversed_output(output, plan.output.width)
    }
}

#[derive(Clone, Debug)]
enum ProofDftBackend {
    Cpu(Radix2DitParallel<Goldilocks>),
    Cuda(CudaProofDft),
}

/// Plonky3-compatible proof DFT with a CPU default and explicit CUDA opt-in.
///
/// The `try_*` methods preserve backend errors. The infallible Plonky3 trait
/// methods panic when an explicitly selected CUDA backend fails because the
/// upstream trait has no error return and silently changing algorithms would
/// hide a failed or compromised accelerator.
#[derive(Clone, Debug)]
pub struct ProofDft {
    backend: ProofDftBackend,
}

impl Default for ProofDft {
    fn default() -> Self {
        Self::cpu()
    }
}

impl ProofDft {
    pub fn cpu() -> Self {
        Self {
            backend: ProofDftBackend::Cpu(Radix2DitParallel::default()),
        }
    }

    pub fn cuda(cuda: CudaProofDft) -> Self {
        Self {
            backend: ProofDftBackend::Cuda(cuda),
        }
    }

    pub fn load_cuda(path: impl AsRef<Path>, device_index: i32) -> Result<Self, ProofAccelError> {
        CudaProofDft::load(path, device_index).map(Self::cuda)
    }

    pub fn is_cuda(&self) -> bool {
        matches!(self.backend, ProofDftBackend::Cuda(_))
    }

    pub fn try_dft_batch(
        &self,
        mat: RowMajorMatrix<Goldilocks>,
    ) -> Result<ProofEvaluations, ProofAccelError> {
        validate_goldilocks_shape(&mat)?;
        match &self.backend {
            ProofDftBackend::Cpu(cpu) => Ok(cpu.dft_batch(mat)),
            ProofDftBackend::Cuda(cuda) => cuda.try_dft_batch(mat),
        }
    }

    pub fn try_coset_lde_batch(
        &self,
        mat: RowMajorMatrix<Goldilocks>,
        added_bits: usize,
        shift: Goldilocks,
    ) -> Result<ProofEvaluations, ProofAccelError> {
        let shape = validate_goldilocks_shape(&mat)?;
        validate_goldilocks_lde_shape(shape, added_bits)?;
        match &self.backend {
            ProofDftBackend::Cpu(cpu) => Ok(cpu.coset_lde_batch(mat, added_bits, shift)),
            ProofDftBackend::Cuda(cuda) => cuda.try_coset_lde_batch(mat, added_bits, shift),
        }
    }

    fn panic_on_error<T>(result: Result<T, ProofAccelError>) -> T {
        result.unwrap_or_else(|error| panic!("explicit proof DFT backend failed: {error}"))
    }
}

impl TwoAdicSubgroupDft<Goldilocks> for ProofDft {
    type Evaluations = ProofEvaluations;

    fn dft_batch(&self, mat: RowMajorMatrix<Goldilocks>) -> Self::Evaluations {
        Self::panic_on_error(self.try_dft_batch(mat))
    }

    fn coset_lde_batch(
        &self,
        mat: RowMajorMatrix<Goldilocks>,
        added_bits: usize,
        shift: Goldilocks,
    ) -> Self::Evaluations {
        Self::panic_on_error(self.try_coset_lde_batch(mat, added_bits, shift))
    }

    fn coset_lde_batch_with_transform<T>(
        &self,
        mat: RowMajorMatrix<Goldilocks>,
        added_bits: usize,
        shift: Goldilocks,
        transform: T,
    ) -> Self::Evaluations
    where
        T: FnOnce(&mut RowMajorMatrixViewMut<'_, Goldilocks>, Layout),
    {
        match &self.backend {
            ProofDftBackend::Cpu(cpu) => {
                cpu.coset_lde_batch_with_transform(mat, added_bits, shift, transform)
            }
            ProofDftBackend::Cuda(cuda) => {
                Self::panic_on_error(
                    validate_cuda_shape(&mat)
                        .and_then(|input| validate_cuda_lde_shape(input, added_bits)),
                );
                let mut coefficients =
                    Self::panic_on_error(cuda.try_inverse_dft_batch_physical(mat));
                transform(&mut coefficients.as_view_mut(), Layout::BitReversed);
                Self::panic_on_error(cuda.try_coefficients_to_coset_lde_batch(
                    coefficients,
                    added_bits,
                    shift,
                ))
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MatrixShape {
    height: usize,
    width: usize,
    elements: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CoefficientLdePlan {
    input: MatrixShape,
    output: MatrixShape,
    added_bits: u32,
}

#[derive(Debug)]
struct ProofStreamPlan {
    shapes: Vec<MatrixShape>,
    source_height: usize,
    expanded_rows: usize,
    total_width: usize,
}

fn validate_proof_stream_matrices(
    matrices: &[CudaProofStreamMatrix<'_>],
    added_bits: usize,
) -> Result<ProofStreamPlan, ProofAccelError> {
    if matrices.is_empty() || matrices.len() > CUDA_PROOF_STREAM_MAX_MATRICES {
        return Err(ProofAccelError::InvalidDimensions(format!(
            "proof CUDA stream matrix count {} is outside 1..={CUDA_PROOF_STREAM_MAX_MATRICES}",
            matrices.len()
        )));
    }
    if added_bits > CUDA_PROOF_STREAM_MAX_ADDED_BITS {
        return Err(ProofAccelError::InvalidDimensions(format!(
            "proof CUDA stream added_bits {added_bits} exceeds {CUDA_PROOF_STREAM_MAX_ADDED_BITS}"
        )));
    }

    let mut shapes = Vec::new();
    shapes.try_reserve_exact(matrices.len()).map_err(|error| {
        ProofAccelError::InvalidDimensions(format!(
            "proof CUDA stream shape allocation failed: {error}"
        ))
    })?;
    let mut source_height = None;
    let mut total_width = 0_usize;
    let mut total_input_limbs = 0_usize;
    for (index, matrix) in matrices.iter().enumerate() {
        let shape = validate_goldilocks_shape(matrix.coefficients).map_err(|error| {
            ProofAccelError::InvalidDimensions(format!(
                "proof CUDA stream matrix {index} is invalid: {error}"
            ))
        })?;
        if shape.height > CUDA_PROOF_STREAM_MAX_SOURCE_HEIGHT {
            return Err(ProofAccelError::InvalidDimensions(format!(
                "proof CUDA stream matrix {index} height {} exceeds {CUDA_PROOF_STREAM_MAX_SOURCE_HEIGHT}",
                shape.height
            )));
        }
        if let Some(expected) = source_height {
            if shape.height != expected {
                return Err(ProofAccelError::InvalidDimensions(format!(
                    "proof CUDA stream matrix {index} height {} does not match first height {expected}",
                    shape.height
                )));
            }
        } else {
            source_height = Some(shape.height);
        }
        let shift = matrix.coset_shift.as_canonical_u64();
        if shift == 0 || shift >= Goldilocks::ORDER_U64 {
            return Err(ProofAccelError::InvalidDimensions(format!(
                "proof CUDA stream matrix {index} coset shift must be canonical and nonzero"
            )));
        }
        total_width = total_width.checked_add(shape.width).ok_or_else(|| {
            ProofAccelError::InvalidDimensions(
                "proof CUDA stream concatenated width overflow".to_owned(),
            )
        })?;
        if total_width > CUDA_PROOF_STREAM_MAX_TOTAL_WIDTH {
            return Err(ProofAccelError::InvalidDimensions(format!(
                "proof CUDA stream concatenated width {total_width} exceeds {CUDA_PROOF_STREAM_MAX_TOTAL_WIDTH}"
            )));
        }
        total_input_limbs = total_input_limbs
            .checked_add(shape.elements)
            .ok_or_else(|| {
                ProofAccelError::InvalidDimensions(
                    "proof CUDA stream input limb count overflow".to_owned(),
                )
            })?;
        if total_input_limbs > CUDA_PROOF_STREAM_MAX_INPUT_LIMBS {
            return Err(ProofAccelError::InvalidDimensions(format!(
                "proof CUDA stream input limb count {total_input_limbs} exceeds {CUDA_PROOF_STREAM_MAX_INPUT_LIMBS}"
            )));
        }
        shapes.push(shape);
    }

    let source_height = source_height.expect("nonempty matrix list has a height");
    let expanded_rows = source_height
        .checked_shl(added_bits as u32)
        .ok_or_else(|| {
            ProofAccelError::InvalidDimensions("proof CUDA stream row count overflow".to_owned())
        })?;
    if expanded_rows > CUDA_PROOF_STREAM_MAX_ROWS {
        return Err(ProofAccelError::InvalidDimensions(format!(
            "proof CUDA stream expanded row count {expanded_rows} exceeds {CUDA_PROOF_STREAM_MAX_ROWS}"
        )));
    }
    Ok(ProofStreamPlan {
        shapes,
        source_height,
        expanded_rows,
        total_width,
    })
}

fn validate_proof_stream_request(
    cursor: u64,
    source_height: u64,
    expanded_rows: u64,
    requested_rows: usize,
) -> Result<(), ProofAccelError> {
    if requested_rows == 0
        || !requested_rows.is_power_of_two()
        || requested_rows > CUDA_PROOF_STREAM_MAX_CHUNK_ROWS
    {
        return Err(ProofAccelError::InvalidDimensions(format!(
            "proof CUDA stream requested row count {requested_rows} must be a nonzero power of two no larger than {CUDA_PROOF_STREAM_MAX_CHUNK_ROWS}"
        )));
    }
    let requested_rows = requested_rows as u64;
    let end = cursor.checked_add(requested_rows).ok_or_else(|| {
        ProofAccelError::InvalidDimensions("proof CUDA stream cursor overflow".to_owned())
    })?;
    if cursor >= expanded_rows || end > expanded_rows {
        return Err(ProofAccelError::InvalidDimensions(format!(
            "proof CUDA stream rows {cursor}..{end} exceed expanded row count {expanded_rows}"
        )));
    }
    let block_offset = cursor % source_height;
    if requested_rows > source_height - block_offset {
        return Err(ProofAccelError::InvalidDimensions(format!(
            "proof CUDA stream rows {cursor}..{end} cross a source-height coset block boundary"
        )));
    }
    Ok(())
}

fn validate_goldilocks_shape(
    mat: &RowMajorMatrix<Goldilocks>,
) -> Result<MatrixShape, ProofAccelError> {
    validate_goldilocks_dimensions(mat.values.len(), mat.width)
}

fn validate_goldilocks_dimensions(
    values_len: usize,
    width: usize,
) -> Result<MatrixShape, ProofAccelError> {
    if width == 0 {
        return Err(ProofAccelError::InvalidDimensions(
            "proof DFT matrix width must be nonzero".to_owned(),
        ));
    }
    if !values_len.is_multiple_of(width) {
        return Err(ProofAccelError::InvalidDimensions(format!(
            "proof DFT input length {} is not divisible by width {}",
            values_len, width
        )));
    }
    let height = values_len / width;
    if height == 0 || !height.is_power_of_two() {
        return Err(ProofAccelError::InvalidDimensions(format!(
            "proof DFT height {height} must be a nonzero power of two"
        )));
    }
    let log_height = height.trailing_zeros() as usize;
    if log_height > Goldilocks::TWO_ADICITY {
        return Err(ProofAccelError::InvalidDimensions(format!(
            "proof DFT height 2^{log_height} exceeds Goldilocks two-adicity {}",
            Goldilocks::TWO_ADICITY
        )));
    }
    let elements = height.checked_mul(width).ok_or_else(|| {
        ProofAccelError::InvalidDimensions("proof DFT element count overflow".to_owned())
    })?;
    if elements != values_len {
        return Err(ProofAccelError::InvalidDimensions(
            "proof DFT dimensions do not match input length".to_owned(),
        ));
    }
    Ok(MatrixShape {
        height,
        width,
        elements,
    })
}

fn validate_cuda_shape(mat: &RowMajorMatrix<Goldilocks>) -> Result<MatrixShape, ProofAccelError> {
    let shape = validate_goldilocks_shape(mat)?;
    if shape.height > CUDA_MAX_HEIGHT {
        return Err(ProofAccelError::InvalidDimensions(format!(
            "CUDA proof DFT height {} exceeds {}",
            shape.height, CUDA_MAX_HEIGHT
        )));
    }
    if shape.width > CUDA_MAX_WIDTH {
        return Err(ProofAccelError::InvalidDimensions(format!(
            "CUDA proof DFT width {} exceeds {}",
            shape.width, CUDA_MAX_WIDTH
        )));
    }
    if shape.elements > CUDA_MAX_ELEMENTS {
        return Err(ProofAccelError::InvalidDimensions(format!(
            "CUDA proof DFT element count {} exceeds {}",
            shape.elements, CUDA_MAX_ELEMENTS
        )));
    }
    u32::try_from(shape.height).map_err(|_| {
        ProofAccelError::InvalidDimensions("CUDA proof DFT height exceeds u32".to_owned())
    })?;
    u32::try_from(shape.width).map_err(|_| {
        ProofAccelError::InvalidDimensions("CUDA proof DFT width exceeds u32".to_owned())
    })?;
    Ok(shape)
}

fn validate_goldilocks_lde_shape(
    input: MatrixShape,
    added_bits: usize,
) -> Result<MatrixShape, ProofAccelError> {
    let input_log_height = input.height.trailing_zeros() as usize;
    let log_height = input_log_height.checked_add(added_bits).ok_or_else(|| {
        ProofAccelError::InvalidDimensions("proof LDE height overflow".to_owned())
    })?;
    if log_height > Goldilocks::TWO_ADICITY {
        return Err(ProofAccelError::InvalidDimensions(format!(
            "proof LDE height exponent {log_height} exceeds Goldilocks two-adicity {}",
            Goldilocks::TWO_ADICITY
        )));
    }
    let height = 1_usize.checked_shl(log_height as u32).ok_or_else(|| {
        ProofAccelError::InvalidDimensions("proof LDE height overflow".to_owned())
    })?;
    let elements = height.checked_mul(input.width).ok_or_else(|| {
        ProofAccelError::InvalidDimensions("proof LDE element count overflow".to_owned())
    })?;
    Ok(MatrixShape {
        height,
        width: input.width,
        elements,
    })
}

fn validate_cuda_lde_shape(
    input: MatrixShape,
    added_bits: usize,
) -> Result<MatrixShape, ProofAccelError> {
    let output = validate_goldilocks_lde_shape(input, added_bits)?;
    if output.height > CUDA_MAX_HEIGHT {
        return Err(ProofAccelError::InvalidDimensions(format!(
            "CUDA proof LDE height {} exceeds {CUDA_MAX_HEIGHT}",
            output.height
        )));
    }
    if output.elements > CUDA_MAX_ELEMENTS {
        return Err(ProofAccelError::InvalidDimensions(format!(
            "CUDA proof LDE element count {} exceeds {CUDA_MAX_ELEMENTS}",
            output.elements
        )));
    }
    Ok(output)
}

fn coefficient_lde_plan(
    input: MatrixShape,
    added_bits: usize,
) -> Result<CoefficientLdePlan, ProofAccelError> {
    let output = validate_cuda_lde_shape(input, added_bits)?;
    let added_bits = u32::try_from(added_bits).map_err(|_| {
        ProofAccelError::InvalidDimensions(
            "CUDA coefficient LDE added-bits value exceeds u32".to_owned(),
        )
    })?;
    Ok(CoefficientLdePlan {
        input,
        output,
        added_bits,
    })
}

fn try_zeroed_output(elements: usize, label: &'static str) -> Result<Vec<u64>, ProofAccelError> {
    let mut output = Vec::new();
    output.try_reserve_exact(elements).map_err(|error| {
        ProofAccelError::InvalidDimensions(format!(
            "proof CUDA {label} allocation for {elements} elements failed: {error}"
        ))
    })?;
    output.resize(elements, 0);
    Ok(output)
}

fn encode_canonical(values: &[Goldilocks]) -> Vec<u64> {
    values.iter().map(PrimeField64::as_canonical_u64).collect()
}

enum ProofStreamCanonicalStorage<'a> {
    Borrowed(&'a [u64]),
    Owned(Vec<u64>),
}

impl ProofStreamCanonicalStorage<'_> {
    fn as_slice(&self) -> &[u64] {
        match self {
            Self::Borrowed(values) => values,
            Self::Owned(values) => values,
        }
    }
}

fn proof_stream_canonical_storage<'a>(
    values: &'a [Goldilocks],
    matrix_index: usize,
) -> Result<ProofStreamCanonicalStorage<'a>, ProofAccelError> {
    const {
        assert!(size_of::<Goldilocks>() == size_of::<u64>());
        assert!(align_of::<Goldilocks>() == align_of::<u64>());
    }
    // SAFETY: p3-goldilocks 0.6.3 pins Goldilocks as repr(transparent) over
    // u64. The immutable view is used only after every limb is checked.
    let raw = unsafe { std::slice::from_raw_parts(values.as_ptr().cast::<u64>(), values.len()) };
    if raw.iter().all(|&value| value < Goldilocks::ORDER_U64) {
        return Ok(ProofStreamCanonicalStorage::Borrowed(raw));
    }

    let mut encoded = Vec::new();
    encoded.try_reserve_exact(values.len()).map_err(|error| {
        ProofAccelError::InvalidDimensions(format!(
            "proof CUDA stream matrix {matrix_index} canonical input allocation for {} elements failed: {error}",
            values.len()
        ))
    })?;
    encoded.extend(values.iter().map(PrimeField64::as_canonical_u64));
    Ok(ProofStreamCanonicalStorage::Owned(encoded))
}

fn decode_bit_reversed_output(
    values: Vec<u64>,
    width: usize,
) -> Result<ProofEvaluations, ProofAccelError> {
    decode_output_matrix(values, width).map(BitReversalPerm::new_view)
}

fn decode_output_matrix(
    values: Vec<u64>,
    width: usize,
) -> Result<RowMajorMatrix<Goldilocks>, ProofAccelError> {
    if width == 0 || values.is_empty() || !values.len().is_multiple_of(width) {
        return Err(ProofAccelError::InvalidDimensions(
            "proof CUDA output dimensions do not match its length".to_owned(),
        ));
    }
    for (index, &value) in values.iter().enumerate() {
        if value >= Goldilocks::ORDER_U64 {
            return Err(ProofAccelError::NonCanonicalOutput { index, value });
        }
    }
    let decoded = canonical_u64s_into_goldilocks(values);
    Ok(RowMajorMatrix::new(decoded, width))
}

fn canonical_u64s_into_goldilocks(values: Vec<u64>) -> Vec<Goldilocks> {
    const {
        assert!(size_of::<Goldilocks>() == size_of::<u64>());
        assert!(align_of::<Goldilocks>() == align_of::<u64>());
    }
    let mut values = ManuallyDrop::new(values);
    let pointer = values.as_mut_ptr().cast::<Goldilocks>();
    let length = values.len();
    let capacity = values.capacity();
    // SAFETY: p3-goldilocks 0.6.3 pins `Goldilocks` as `repr(transparent)`
    // over u64 with identical size/alignment, and every u64 was checked above
    // to be canonical. Capacity is measured in equal-sized elements, so the
    // original allocation can be owned and freed by `Vec<Goldilocks>`.
    unsafe { Vec::from_raw_parts(pointer, length, capacity) }
}

fn goldilocks_vec_into_u64s(values: Vec<Goldilocks>) -> Vec<u64> {
    const {
        assert!(size_of::<Goldilocks>() == size_of::<u64>());
        assert!(align_of::<Goldilocks>() == align_of::<u64>());
    }
    let mut values = ManuallyDrop::new(values);
    let pointer = values.as_mut_ptr().cast::<u64>();
    let length = values.len();
    let capacity = values.capacity();
    // SAFETY: stream output was accepted only after every underlying u64 was
    // checked canonical, and the pinned transparent layouts have identical
    // size and alignment. Ownership of the same allocation transfers back to
    // `Vec<u64>` without copying.
    unsafe { Vec::from_raw_parts(pointer, length, capacity) }
}

fn device_count(api: &CudaApi) -> Result<i32, ProofAccelError> {
    let mut count = 0_i32;
    let mut error = [0 as c_char; ERROR_BUFFER_BYTES];
    // SAFETY: both output buffers are live and writable for the call.
    let result = unsafe { (api.device_count)(&mut count, error.as_mut_ptr(), error.len()) };
    check_backend_result("device count", result, &error)?;
    if count < 0 {
        return Err(ProofAccelError::InvalidDeviceCount(count));
    }
    Ok(count)
}

fn read_device(api: &CudaApi, device_index: i32) -> Result<CudaProofDevice, ProofAccelError> {
    let mut raw = RawDeviceInfo::default();
    let mut error = [0 as c_char; ERROR_BUFFER_BYTES];
    // SAFETY: `raw` and `error` are fixed-size writable C layouts.
    let result =
        unsafe { (api.device_info)(device_index, &mut raw, error.as_mut_ptr(), error.len()) };
    check_backend_result("device info", result, &error)?;
    if raw.api_version != CUDA_PROOF_API_VERSION {
        return Err(ProofAccelError::InvalidDeviceInfo(format!(
            "device response ABI {} does not match {}",
            raw.api_version, CUDA_PROOF_API_VERSION
        )));
    }
    if raw.device_index != device_index {
        return Err(ProofAccelError::InvalidDeviceInfo(format!(
            "requested device {device_index}, received {}",
            raw.device_index
        )));
    }
    let name = decode_c_chars(&raw.name);
    if name.is_empty() {
        return Err(ProofAccelError::InvalidDeviceInfo(
            "device name is empty or not NUL-terminated".to_owned(),
        ));
    }
    Ok(CudaProofDevice {
        index: raw.device_index,
        name,
        compute_major: raw.compute_major,
        compute_minor: raw.compute_minor,
        total_memory_bytes: raw.total_memory_bytes,
    })
}

fn check_backend_result(
    operation: &'static str,
    code: i32,
    error: &[c_char],
) -> Result<(), ProofAccelError> {
    if code == 0 {
        return Ok(());
    }
    Err(ProofAccelError::Backend {
        operation,
        code,
        message: decode_c_chars(error),
    })
}

fn decode_c_chars(chars: &[c_char]) -> String {
    let bytes: Vec<u8> = chars.iter().map(|character| *character as u8).collect();
    let Some(nul) = bytes.iter().position(|byte| *byte == 0) else {
        return String::new();
    };
    String::from_utf8_lossy(&bytes[..nul]).into_owned()
}

#[cfg(test)]
mod tests {
    use std::mem::{offset_of, size_of};
    use std::path::Path;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use p3_field::{Field, PrimeCharacteristicRing};
    use p3_matrix::Matrix;
    use p3_matrix::bitrev::BitReversibleMatrix;

    use super::*;

    fn matrix(height: usize, width: usize) -> RowMajorMatrix<Goldilocks> {
        RowMajorMatrix::new(
            (0..height * width)
                .map(|index| Goldilocks::from_u64((index * 17 + 5) as u64))
                .collect(),
            width,
        )
    }

    fn mutate_bit_reversed_coefficients(
        coefficients: &mut RowMajorMatrixViewMut<'_, Goldilocks>,
        layout: Layout,
    ) {
        assert_eq!(layout, Layout::BitReversed);
        let width = coefficients.width;
        for (physical_row, row) in coefficients.values.chunks_exact_mut(width).enumerate() {
            for (column, value) in row.iter_mut().enumerate() {
                let tweak = physical_row * width + column + 1;
                *value += Goldilocks::from_usize(tweak);
            }
        }
    }

    #[test]
    fn default_is_cpu_and_matches_parallel_dft_logically_and_physically() {
        let proof_dft = ProofDft::default();
        let reference = Radix2DitParallel::<Goldilocks>::default();
        assert!(!proof_dft.is_cuda());

        for (height, width) in [(1, 1), (2, 3), (8, 5), (32, 2)] {
            let input = matrix(height, width);
            let expected_logical = reference.dft_batch(input.clone()).to_row_major_matrix();
            let actual_logical = proof_dft.dft_batch(input.clone()).to_row_major_matrix();
            assert_eq!(actual_logical, expected_logical);

            let expected_physical = reference.dft_batch(input.clone()).bit_reverse_rows();
            let actual_physical = proof_dft.dft_batch(input).bit_reverse_rows();
            assert_eq!(actual_physical, expected_physical);
        }
    }

    #[test]
    fn cpu_coset_lde_matches_parallel_dft_logically_and_physically() {
        let proof_dft = ProofDft::cpu();
        let reference = Radix2DitParallel::<Goldilocks>::default();
        let input = matrix(16, 4);
        let shift = Goldilocks::GENERATOR;

        let expected_logical = reference
            .coset_lde_batch(input.clone(), 2, shift)
            .to_row_major_matrix();
        let actual_logical = proof_dft
            .coset_lde_batch(input.clone(), 2, shift)
            .to_row_major_matrix();
        assert_eq!(actual_logical, expected_logical);

        let expected_physical = reference
            .coset_lde_batch(input.clone(), 2, shift)
            .bit_reverse_rows();
        let actual_physical = proof_dft
            .coset_lde_batch(input, 2, shift)
            .bit_reverse_rows();
        assert_eq!(actual_physical, expected_physical);
    }

    #[test]
    fn malformed_matrices_and_lde_overflow_are_rejected() {
        assert!(validate_goldilocks_dimensions(1, 0).is_err());
        assert!(validate_goldilocks_dimensions(3, 2).is_err());
        assert!(validate_cuda_shape(&matrix(8, 9_168)).is_ok());
        assert!(validate_cuda_shape(&matrix(1, CUDA_MAX_WIDTH + 1)).is_err());

        let input = matrix(2, 1);
        assert!(
            ProofDft::cpu()
                .try_coset_lde_batch(input, usize::MAX, Goldilocks::ONE)
                .is_err()
        );
    }

    #[test]
    fn coefficient_lde_plan_keeps_expanded_coefficients_off_host() {
        let input = MatrixShape {
            height: 32_768,
            width: 291,
            elements: 32_768 * 291,
        };
        let plan = coefficient_lde_plan(input, 7).unwrap();
        assert_eq!(plan.input.elements, 9_535_488);
        assert_eq!(plan.output.height, 4_194_304);
        assert_eq!(plan.output.elements, 1_220_542_464);

        // The v2 path holds one canonical small coefficient input and one
        // final evaluation output. The old path held three expanded buffers.
        let v2_peak_elements = plan.input.elements + plan.output.elements;
        let old_peak_elements = plan.output.elements * 3;
        assert!(v2_peak_elements < old_peak_elements / 2);
        assert!(coefficient_lde_plan(input, 8).is_err());
    }

    #[test]
    fn noncanonical_cuda_output_is_rejected_without_reduction() {
        let error = decode_bit_reversed_output(vec![Goldilocks::ORDER_U64], 1).unwrap_err();
        assert!(matches!(
            error,
            ProofAccelError::NonCanonicalOutput {
                index: 0,
                value: Goldilocks::ORDER_U64
            }
        ));
    }

    #[test]
    fn decoded_output_retains_physical_bit_reversed_storage() {
        let physical = vec![0_u64, 4, 2, 6, 1, 5, 3, 7];
        let decoded = decode_bit_reversed_output(physical.clone(), 1).unwrap();
        let logical = decoded.to_row_major_matrix();
        assert_eq!(
            logical
                .values
                .iter()
                .map(PrimeField64::as_canonical_u64)
                .collect::<Vec<_>>(),
            (0_u64..8).collect::<Vec<_>>()
        );

        let decoded = decode_bit_reversed_output(physical.clone(), 1).unwrap();
        assert_eq!(
            decoded
                .bit_reverse_rows()
                .values
                .iter()
                .map(PrimeField64::as_canonical_u64)
                .collect::<Vec<_>>(),
            physical
        );
    }

    #[test]
    fn canonical_cuda_output_is_reused_without_a_second_large_allocation() {
        let raw = vec![0_u64, 1, Goldilocks::ORDER_U64 - 1];
        let pointer = raw.as_ptr().cast::<Goldilocks>();
        let capacity = raw.capacity();
        let decoded = canonical_u64s_into_goldilocks(raw);
        assert_eq!(decoded.as_ptr(), pointer);
        assert_eq!(decoded.capacity(), capacity);
        assert_eq!(
            decoded
                .iter()
                .map(PrimeField64::as_canonical_u64)
                .collect::<Vec<_>>(),
            vec![0, 1, Goldilocks::ORDER_U64 - 1]
        );
    }

    #[test]
    fn cuda_never_searches_for_a_missing_explicit_library() {
        let path = Path::new("cmfd-proof-accel-definitely-missing-library.dll");
        let error = CudaProofDft::load(path, 0).unwrap_err();
        assert!(matches!(error, ProofAccelError::LoadLibrary { .. }));
    }

    const FAKE_BACKEND_FAILURE: u64 = 0xBAD;
    const FAKE_NONCANONICAL_OUTPUT: u64 = 0xBAD0;
    static FAKE_DESTROY_CALLS: AtomicUsize = AtomicUsize::new(0);
    static FAKE_TEST_LOCK: Mutex<()> = Mutex::new(());

    struct FakeProofStream {
        cursor: u64,
        source_height: u64,
        expanded_rows: u64,
        total_width: usize,
        first_rows: Vec<u64>,
        fail_next: bool,
        noncanonical_output: bool,
    }

    unsafe extern "C" fn fake_stream_create(
        device_index: i32,
        matrices: *const RawProofStreamMatrixV1,
        matrix_count: usize,
        added_bits: u32,
        output_context: *mut *mut c_void,
        error: *mut c_char,
        error_len: usize,
    ) -> i32 {
        if device_index < 0 || matrices.is_null() || matrix_count == 0 || output_context.is_null() {
            unsafe { write_fake_error(error, error_len, b"bad create arguments") };
            return 1;
        }
        let matrices = unsafe { std::slice::from_raw_parts(matrices, matrix_count) };
        let source_height = matrices[0].height as u64;
        let mut total_width = 0_usize;
        let mut first_rows = Vec::new();
        for matrix in matrices {
            if matrix.height as u64 != source_height
                || matrix.width == 0
                || matrix.physical_coefficients.is_null()
                || matrix.coefficients_len != matrix.height as usize * matrix.width as usize
                || matrix.coset_shift == 0
                || matrix.coset_shift >= Goldilocks::ORDER_U64
            {
                unsafe { write_fake_error(error, error_len, b"bad matrix descriptor") };
                return 1;
            }
            let values = unsafe {
                std::slice::from_raw_parts(matrix.physical_coefficients, matrix.coefficients_len)
            };
            if values.iter().any(|&value| value >= Goldilocks::ORDER_U64) {
                unsafe { write_fake_error(error, error_len, b"noncanonical input") };
                return 1;
            }
            total_width += matrix.width as usize;
            first_rows.extend_from_slice(&values[..matrix.width as usize]);
        }
        let context = Box::new(FakeProofStream {
            cursor: 0,
            source_height,
            expanded_rows: source_height << added_bits,
            total_width,
            fail_next: first_rows[0] == FAKE_BACKEND_FAILURE,
            noncanonical_output: first_rows[0] == FAKE_NONCANONICAL_OUTPUT,
            first_rows,
        });
        unsafe { *output_context = Box::into_raw(context).cast() };
        0
    }

    unsafe extern "C" fn fake_stream_next(
        context: *mut c_void,
        expected_global_physical_row: u64,
        requested_rows: u32,
        optional_lde_output: *mut u64,
        lde_output_len: usize,
        digest_output: *mut u64,
        digest_output_len: usize,
        error: *mut c_char,
        error_len: usize,
    ) -> i32 {
        if context.is_null() || digest_output.is_null() {
            unsafe { write_fake_error(error, error_len, b"bad next pointers") };
            return 1;
        }
        let context = unsafe { &mut *context.cast::<FakeProofStream>() };
        let rows = requested_rows as usize;
        let end = expected_global_physical_row.saturating_add(requested_rows as u64);
        let lde_shape_ok = if optional_lde_output.is_null() {
            lde_output_len == 0
        } else {
            lde_output_len == rows * context.total_width
        };
        if expected_global_physical_row != context.cursor
            || requested_rows == 0
            || !requested_rows.is_power_of_two()
            || end > context.expanded_rows
            || rows as u64 > context.source_height - context.cursor % context.source_height
            || digest_output_len != rows * 4
            || !lde_shape_ok
        {
            unsafe { write_fake_error(error, error_len, b"bad next arguments") };
            return 1;
        }
        if context.fail_next {
            unsafe { write_fake_error(error, error_len, b"injected failure") };
            return 1;
        }

        if !optional_lde_output.is_null() {
            let output =
                unsafe { std::slice::from_raw_parts_mut(optional_lde_output, lde_output_len) };
            for row in 0..rows {
                for (column, &base) in context.first_rows.iter().enumerate() {
                    output[row * context.total_width + column] =
                        (base + expected_global_physical_row + row as u64) % Goldilocks::ORDER_U64;
                }
            }
        }
        let digests = unsafe { std::slice::from_raw_parts_mut(digest_output, digest_output_len) };
        for row in 0..rows {
            for column in 0..4 {
                digests[row * 4 + column] =
                    (expected_global_physical_row + row as u64) * 4 + column as u64;
            }
        }
        if context.noncanonical_output {
            digests[0] = Goldilocks::ORDER_U64;
        }
        context.cursor = end;
        0
    }

    unsafe extern "C" fn fake_stream_destroy(context: *mut c_void) {
        if !context.is_null() {
            unsafe { drop(Box::from_raw(context.cast::<FakeProofStream>())) };
            FAKE_DESTROY_CALLS.fetch_add(1, Ordering::SeqCst);
        }
    }

    unsafe fn write_fake_error(output: *mut c_char, output_len: usize, message: &[u8]) {
        if output.is_null() || output_len == 0 {
            return;
        }
        let copy_len = message.len().min(output_len - 1);
        unsafe {
            std::ptr::copy_nonoverlapping(message.as_ptr(), output.cast::<u8>(), copy_len);
            *output.add(copy_len) = 0;
        }
    }

    fn fake_stream_api() -> Arc<ProofStreamApi> {
        Arc::new(ProofStreamApi {
            create: fake_stream_create,
            next: fake_stream_next,
            destroy: fake_stream_destroy,
            _library: None,
        })
    }

    fn create_fake_stream(
        matrices: &[CudaProofStreamMatrix<'_>],
        added_bits: usize,
    ) -> Result<CudaProofStream, ProofAccelError> {
        CudaProofStream::create_with_api(fake_stream_api(), None, 0, matrices, added_bits)
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn proof_stream_descriptor_matches_abi_v1_layout() {
        assert_eq!(size_of::<RawProofStreamMatrixV1>(), 32);
        assert_eq!(offset_of!(RawProofStreamMatrixV1, physical_coefficients), 0);
        assert_eq!(offset_of!(RawProofStreamMatrixV1, coefficients_len), 8);
        assert_eq!(offset_of!(RawProofStreamMatrixV1, height), 16);
        assert_eq!(offset_of!(RawProofStreamMatrixV1, width), 20);
        assert_eq!(offset_of!(RawProofStreamMatrixV1, coset_shift), 24);
    }

    #[test]
    fn proof_stream_preserves_matrix_order_and_tracks_the_global_cursor() {
        let _guard = FAKE_TEST_LOCK.lock().unwrap();
        let first = RowMajorMatrix::new(
            [1_u64, 2, 3, 4, 5, 6, 7, 8]
                .map(Goldilocks::from_u64)
                .to_vec(),
            2,
        );
        let second = RowMajorMatrix::new([9_u64, 10, 11, 12].map(Goldilocks::from_u64).to_vec(), 1);
        let matrices = [
            CudaProofStreamMatrix::new(&first, Goldilocks::GENERATOR),
            CudaProofStreamMatrix::new(&second, Goldilocks::from_u64(7)),
        ];
        let mut stream = create_fake_stream(&matrices, 1).unwrap();
        assert_eq!(stream.source_height(), 4);
        assert_eq!(stream.expanded_rows(), 8);
        assert_eq!(stream.added_bits(), 1);
        assert_eq!(stream.total_width(), 3);
        assert_eq!(stream.cursor(), 0);

        let first_chunk = stream.next_rows(2, true).unwrap();
        assert_eq!(first_chunk.global_physical_row, 0);
        assert_eq!(first_chunk.row_count(), 2);
        assert_eq!(
            first_chunk
                .lde
                .unwrap()
                .values
                .iter()
                .map(PrimeField64::as_canonical_u64)
                .collect::<Vec<_>>(),
            vec![1, 2, 9, 2, 3, 10]
        );
        assert_eq!(stream.cursor(), 2);

        // Four rows would cross the current source-height block. This local
        // validation does not advance or poison the live context.
        assert!(stream.next_rows(4, true).is_err());
        assert_eq!(stream.cursor(), 2);
        stream.next_rows(2, false).unwrap();
        assert_eq!(stream.cursor(), 4);
        let final_chunk = stream.next_rows(4, false).unwrap();
        assert!(final_chunk.lde.is_none());
        assert!(stream.is_finished());
        assert!(stream.next_rows(1, false).is_err());
    }

    #[test]
    fn proof_stream_components_expose_canonical_ordered_identity() {
        let _guard = FAKE_TEST_LOCK.lock().unwrap();
        let narrow = matrix(4, 1);
        let wide = matrix(4, 2);
        let shift_three = Goldilocks::new(Goldilocks::ORDER_U64 + 3);
        let shift_five = Goldilocks::from_u64(5);
        let shift_seven = Goldilocks::from_u64(7);

        let ordered_matrices = [
            CudaProofStreamMatrix::new(&narrow, shift_three),
            CudaProofStreamMatrix::new(&wide, shift_five),
        ];
        let reversed_matrices = [
            CudaProofStreamMatrix::new(&wide, shift_five),
            CudaProofStreamMatrix::new(&narrow, shift_three),
        ];
        let shifted_matrices = [
            CudaProofStreamMatrix::new(&narrow, shift_seven),
            CudaProofStreamMatrix::new(&wide, shift_five),
        ];
        let ordered = create_fake_stream(&ordered_matrices, 0).unwrap();
        let reversed = create_fake_stream(&reversed_matrices, 0).unwrap();
        let shifted = create_fake_stream(&shifted_matrices, 0).unwrap();

        assert_eq!(ordered.components()[0].ordinal(), 0);
        assert_eq!(ordered.components()[0].width(), 1);
        assert_eq!(ordered.components()[0].coset_shift(), 3);
        assert_eq!(ordered.components()[1].ordinal(), 1);
        assert_eq!(ordered.components()[1].width(), 2);
        assert_eq!(ordered.components()[1].coset_shift(), 5);
        assert_ne!(ordered.components(), reversed.components());
        assert_ne!(ordered.components(), shifted.components());
    }

    #[test]
    fn proof_stream_validation_rejects_bad_shapes_shifts_and_chunks() {
        let _guard = FAKE_TEST_LOCK.lock().unwrap();
        assert!(create_fake_stream(&[], 0).is_err());

        let height_four = matrix(4, 2);
        let height_eight = matrix(8, 1);
        let unequal = [
            CudaProofStreamMatrix::new(&height_four, Goldilocks::ONE),
            CudaProofStreamMatrix::new(&height_eight, Goldilocks::ONE),
        ];
        assert!(create_fake_stream(&unequal, 0).is_err());

        let zero_shift = [CudaProofStreamMatrix::new(&height_four, Goldilocks::ZERO)];
        assert!(create_fake_stream(&zero_shift, 0).is_err());
        let valid = [CudaProofStreamMatrix::new(&height_four, Goldilocks::ONE)];
        assert!(create_fake_stream(&valid, 8).is_err());

        let mut stream = create_fake_stream(&valid, 1).unwrap();
        assert!(stream.next_rows(0, false).is_err());
        assert!(stream.next_rows(3, false).is_err());
        assert!(
            stream
                .next_rows(CUDA_PROOF_STREAM_MAX_CHUNK_ROWS + 1, false)
                .is_err()
        );
        assert_eq!(stream.cursor(), 0);
    }

    #[test]
    fn proof_stream_borrows_canonical_inputs_and_normalizes_noncanonical_storage() {
        let canonical = vec![Goldilocks::ZERO, Goldilocks::ONE];
        let storage = proof_stream_canonical_storage(&canonical, 0).unwrap();
        assert!(matches!(storage, ProofStreamCanonicalStorage::Borrowed(_)));
        assert_eq!(storage.as_slice().as_ptr(), canonical.as_ptr().cast());

        let noncanonical = vec![Goldilocks::new(Goldilocks::ORDER_U64)];
        let storage = proof_stream_canonical_storage(&noncanonical, 0).unwrap();
        assert!(matches!(storage, ProofStreamCanonicalStorage::Owned(_)));
        assert_eq!(storage.as_slice(), &[0]);
    }

    #[test]
    fn proof_stream_canonical_export_reuses_validated_output_allocations() {
        let _guard = FAKE_TEST_LOCK.lock().unwrap();
        let coefficients = matrix(4, 2);
        let matrices = [CudaProofStreamMatrix::new(&coefficients, Goldilocks::ONE)];
        let mut stream = create_fake_stream(&matrices, 0).unwrap();
        let chunk = stream.next_rows(2, true).unwrap();
        let digest_pointer = chunk.digests.values.as_ptr().cast::<u64>();
        let lde_pointer = chunk.lde.as_ref().unwrap().values.as_ptr().cast::<u64>();

        let canonical = chunk.into_canonical_values();
        assert_eq!(canonical.global_physical_row, 0);
        assert_eq!(canonical.row_count, 2);
        assert_eq!(canonical.digest_width, 4);
        assert_eq!(canonical.lde_width, 2);
        assert_eq!(canonical.digests.as_ptr(), digest_pointer);
        assert_eq!(canonical.lde.as_ref().unwrap().as_ptr(), lde_pointer);
        assert_eq!(canonical.digests.len(), 8);
        assert_eq!(canonical.lde.unwrap().len(), 4);
    }

    #[test]
    fn proof_stream_backend_and_output_failures_poison_without_replay() {
        let _guard = FAKE_TEST_LOCK.lock().unwrap();
        let backend_failure =
            RowMajorMatrix::new(vec![Goldilocks::from_u64(FAKE_BACKEND_FAILURE); 4], 1);
        let matrices = [CudaProofStreamMatrix::new(
            &backend_failure,
            Goldilocks::ONE,
        )];
        let mut stream = create_fake_stream(&matrices, 0).unwrap();
        let error = stream.next_rows(1, false).unwrap_err();
        assert!(matches!(error, ProofAccelError::Backend { .. }));
        assert_eq!(stream.cursor(), 0);
        assert!(matches!(
            stream.next_rows(1, false),
            Err(ProofAccelError::ProofStreamPoisoned)
        ));

        let noncanonical =
            RowMajorMatrix::new(vec![Goldilocks::from_u64(FAKE_NONCANONICAL_OUTPUT); 4], 1);
        let matrices = [CudaProofStreamMatrix::new(&noncanonical, Goldilocks::ONE)];
        let mut stream = create_fake_stream(&matrices, 0).unwrap();
        let error = stream.next_rows(1, true).unwrap_err();
        assert!(matches!(error, ProofAccelError::NonCanonicalOutput { .. }));
        assert!(matches!(
            stream.next_rows(1, true),
            Err(ProofAccelError::ProofStreamPoisoned)
        ));
    }

    #[test]
    fn proof_stream_drop_destroys_the_unique_context_once() {
        let _guard = FAKE_TEST_LOCK.lock().unwrap();
        let before = FAKE_DESTROY_CALLS.load(Ordering::SeqCst);
        let coefficients = matrix(4, 1);
        let matrices = [CudaProofStreamMatrix::new(&coefficients, Goldilocks::ONE)];
        let stream = create_fake_stream(&matrices, 0).unwrap();
        drop(stream);
        assert_eq!(FAKE_DESTROY_CALLS.load(Ordering::SeqCst), before + 1);
    }

    #[test]
    #[ignore = "requires an explicitly named real CUDA proof library"]
    fn real_cuda_matches_cpu_dft_and_coset_lde() {
        let path = std::env::var_os("CMFD_TEST_PROOF_CUDA_LIBRARY")
            .expect("set CMFD_TEST_PROOF_CUDA_LIBRARY to the built proof CUDA library");
        let device = std::env::var("CMFD_TEST_PROOF_CUDA_DEVICE")
            .ok()
            .map(|value| value.parse::<i32>().expect("device must be an i32"))
            .unwrap_or(0);
        let cuda = CudaProofDft::load(path, device).unwrap();
        let cpu = ProofDft::cpu();

        for (height, width) in [(1, 1), (2, 3), (8, 5), (64, 7), (1024, 4), (8, 9_168)] {
            let input = matrix(height, width);
            assert_eq!(
                cuda.try_dft_batch(input.clone())
                    .unwrap()
                    .to_row_major_matrix(),
                cpu.dft_batch(input.clone()).to_row_major_matrix()
            );
            assert_eq!(
                cuda.try_coset_lde_batch(input.clone(), 2, Goldilocks::GENERATOR)
                    .unwrap()
                    .to_row_major_matrix(),
                cpu.coset_lde_batch(input, 2, Goldilocks::GENERATOR)
                    .to_row_major_matrix()
            );
        }
    }

    #[test]
    #[ignore = "requires an explicitly named real CUDA proof library"]
    fn real_cuda_matches_transformed_lde_layout_and_output() {
        let path = std::env::var_os("CMFD_TEST_PROOF_CUDA_LIBRARY")
            .expect("set CMFD_TEST_PROOF_CUDA_LIBRARY to the built proof CUDA library");
        let device = std::env::var("CMFD_TEST_PROOF_CUDA_DEVICE")
            .ok()
            .map(|value| value.parse::<i32>().expect("device must be an i32"))
            .unwrap_or(0);
        let accelerated = ProofDft::cuda(CudaProofDft::load(path, device).unwrap());
        let reference = Radix2DitParallel::<Goldilocks>::default();
        let input = matrix(32, 3);
        let shift = Goldilocks::GENERATOR;

        let expected = reference.coset_lde_batch_with_transform(
            input.clone(),
            2,
            shift,
            mutate_bit_reversed_coefficients,
        );
        let actual = accelerated.coset_lde_batch_with_transform(
            input.clone(),
            2,
            shift,
            mutate_bit_reversed_coefficients,
        );
        assert_eq!(actual.to_row_major_matrix(), expected.to_row_major_matrix());

        let expected = reference.coset_lde_batch_with_transform(
            input.clone(),
            2,
            shift,
            mutate_bit_reversed_coefficients,
        );
        let actual = accelerated.coset_lde_batch_with_transform(
            input,
            2,
            shift,
            mutate_bit_reversed_coefficients,
        );
        assert_eq!(actual.bit_reverse_rows(), expected.bit_reverse_rows());
    }

    #[test]
    #[ignore = "requires an explicitly named real CUDA proof-stream v1 library"]
    fn real_cuda_stream_matches_cpu_lde_and_poseidon2_in_chunks() {
        use p3_goldilocks::{Poseidon2Goldilocks, default_goldilocks_poseidon2_8};
        use p3_symmetric::{CryptographicHasher, PaddingFreeSponge};

        type Poseidon2Hasher = PaddingFreeSponge<Poseidon2Goldilocks<8>, 8, 4, 4>;

        let path = std::env::var_os("CMFD_TEST_PROOF_CUDA_LIBRARY")
            .expect("set CMFD_TEST_PROOF_CUDA_LIBRARY to the built proof CUDA library");
        let device = std::env::var("CMFD_TEST_PROOF_CUDA_DEVICE")
            .ok()
            .map(|value| value.parse::<i32>().expect("device must be an i32"))
            .unwrap_or(0);
        let reference = Radix2DitParallel::<Goldilocks>::default();
        let first_input = matrix(8, 2);
        let second_input = RowMajorMatrix::new(
            (0..24)
                .map(|index| Goldilocks::from_u64((index * 29 + 101) as u64))
                .collect(),
            3,
        );
        let first_shift = Goldilocks::GENERATOR;
        let second_shift = Goldilocks::GENERATOR.square();
        let added_bits = 2;

        let first_coefficients = reference
            .idft_batch(first_input.clone())
            .bit_reverse_rows()
            .to_row_major_matrix();
        let second_coefficients = reference
            .idft_batch(second_input.clone())
            .bit_reverse_rows()
            .to_row_major_matrix();
        let first_expected = reference
            .coset_lde_batch(first_input, added_bits, first_shift)
            .bit_reverse_rows();
        let second_expected = reference
            .coset_lde_batch(second_input, added_bits, second_shift)
            .bit_reverse_rows();

        let expanded_rows = first_expected.height();
        let total_width = first_expected.width + second_expected.width;
        let mut expected_lde = Vec::with_capacity(expanded_rows * total_width);
        let mut expected_digests = Vec::with_capacity(expanded_rows * 4);
        let hasher = Poseidon2Hasher::new(default_goldilocks_poseidon2_8());
        for row in 0..expanded_rows {
            let first_start = row * first_expected.width;
            let second_start = row * second_expected.width;
            expected_lde.extend_from_slice(
                &first_expected.values[first_start..first_start + first_expected.width],
            );
            expected_lde.extend_from_slice(
                &second_expected.values[second_start..second_start + second_expected.width],
            );
            let combined_start = row * total_width;
            expected_digests.extend(
                hasher.hash_iter(
                    expected_lde[combined_start..combined_start + total_width]
                        .iter()
                        .copied(),
                ),
            );
        }

        let matrices = [
            CudaProofStreamMatrix::new(&first_coefficients, first_shift),
            CudaProofStreamMatrix::new(&second_coefficients, second_shift),
        ];
        let mut stream = CudaProofStream::load(path, device, &matrices, added_bits).unwrap();
        let mut actual_lde = Vec::new();
        let mut actual_digests = Vec::new();
        while !stream.is_finished() {
            let chunk = stream.next_rows(8, true).unwrap();
            actual_lde.extend(chunk.lde.unwrap().values);
            actual_digests.extend(chunk.digests.values);
        }
        assert_eq!(actual_lde, expected_lde);
        assert_eq!(actual_digests, expected_digests);
    }
}
