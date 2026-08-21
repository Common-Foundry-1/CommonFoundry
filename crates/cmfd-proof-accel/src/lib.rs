//! Optional, non-consensus acceleration for Common Foundry proof generation.
//!
//! [`ProofDft`] uses Plonky3's CPU DFT by default. A prover may explicitly
//! select [`CudaProofDft`] with a caller-supplied library path and device, but
//! proof verification must remain independent of this crate and its backend.

mod poseidon2;

pub use poseidon2::{
    CUDA_POSEIDON2_API_VERSION, CUDA_POSEIDON2_MAX_MATRICES, CUDA_POSEIDON2_MAX_ROW_WIDTH,
    CUDA_POSEIDON2_MAX_ROWS, CUDA_POSEIDON2_MAX_TOTAL_LIMBS, CudaProofPoseidon2,
    POSEIDON2_DIGEST_WIDTH,
};

use std::ffi::{c_char, c_void};
use std::fmt;
use std::mem::{ManuallyDrop, align_of, size_of};
use std::path::{Path, PathBuf};
use std::ptr::NonNull;
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
    use std::path::Path;

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
}
