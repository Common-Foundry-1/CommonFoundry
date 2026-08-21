use std::ffi::{c_char, c_void};
use std::fmt;
use std::mem::{align_of, size_of};
use std::path::{Path, PathBuf};
use std::ptr::NonNull;
use std::slice;
use std::sync::{Arc, Mutex};

use libloading::Library;
use p3_field::PrimeField64;
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::RowMajorMatrix;

use super::{
    ApiVersionFn, ERROR_BUFFER_BYTES, ProofAccelError, check_backend_result, decode_output_matrix,
    load_symbol, try_zeroed_output,
};

/// Version of the standalone first-digest Poseidon2 CUDA C ABI.
pub const CUDA_POSEIDON2_API_VERSION: u32 = 1;

/// Maximum number of row-major matrices accepted by Poseidon2 ABI v1.
pub const CUDA_POSEIDON2_MAX_MATRICES: usize = 64;

/// Maximum common matrix height accepted by Poseidon2 ABI v1.
pub const CUDA_POSEIDON2_MAX_ROWS: usize = 1 << 24;

/// Maximum sum of all matrix widths accepted by Poseidon2 ABI v1.
pub const CUDA_POSEIDON2_MAX_ROW_WIDTH: usize = 4096;

/// Maximum total input limbs accepted by Poseidon2 ABI v1.
pub const CUDA_POSEIDON2_MAX_TOTAL_LIMBS: usize = 1 << 31;

/// Number of Goldilocks limbs returned for each physical input row.
pub const POSEIDON2_DIGEST_WIDTH: usize = 4;

type Poseidon2CreateFn = unsafe extern "C" fn(i32, *mut *mut c_void, *mut c_char, usize) -> i32;
type Poseidon2FirstDigestLayerFn = unsafe extern "C" fn(
    *mut c_void,
    *const RawPoseidon2MatrixViewV1,
    usize,
    u32,
    *mut u64,
    usize,
    *mut c_char,
    usize,
) -> i32;
type Poseidon2DestroyFn = unsafe extern "C" fn(*mut c_void);

#[repr(C)]
struct RawPoseidon2MatrixViewV1 {
    values: *const u64,
    values_len: usize,
    rows: u32,
    columns: u32,
}

struct Poseidon2Api {
    create: Poseidon2CreateFn,
    first_digest_layer: Poseidon2FirstDigestLayerFn,
    destroy: Poseidon2DestroyFn,
    _library: Library,
}

impl Poseidon2Api {
    fn load(path: &Path) -> Result<Self, ProofAccelError> {
        // SAFETY: each copied function pointer has the exact C ABI v1
        // signature, and the returned API retains ownership of the library.
        unsafe {
            let library = Library::new(path).map_err(|error| ProofAccelError::LoadLibrary {
                path: path.to_path_buf(),
                message: error.to_string(),
            })?;
            let api_version: ApiVersionFn = load_symbol(
                &library,
                "cmfd_proof_poseidon2_api_version",
                b"cmfd_proof_poseidon2_api_version\0",
            )?;
            let actual = api_version();
            if actual != CUDA_POSEIDON2_API_VERSION {
                return Err(ProofAccelError::Poseidon2AbiVersion {
                    expected: CUDA_POSEIDON2_API_VERSION,
                    actual,
                });
            }
            Ok(Self {
                create: load_symbol(
                    &library,
                    "cmfd_proof_poseidon2_create",
                    b"cmfd_proof_poseidon2_create\0",
                )?,
                first_digest_layer: load_symbol(
                    &library,
                    "cmfd_proof_poseidon2_first_digest_layer",
                    b"cmfd_proof_poseidon2_first_digest_layer\0",
                )?,
                destroy: load_symbol(
                    &library,
                    "cmfd_proof_poseidon2_destroy",
                    b"cmfd_proof_poseidon2_destroy\0",
                )?,
                _library: library,
            })
        }
    }
}

struct Poseidon2ContextHandle(NonNull<c_void>);

// SAFETY: the opaque handle is accessed only while holding the context mutex.
// ABI v1 permits moving a live context between host threads, and Arc prevents
// destruction while a cloned wrapper has an operation in flight.
unsafe impl Send for Poseidon2ContextHandle {}

struct Poseidon2Context {
    api: Arc<Poseidon2Api>,
    handle: Mutex<Poseidon2ContextHandle>,
}

impl Drop for Poseidon2Context {
    fn drop(&mut self) {
        let handle = match self.handle.get_mut() {
            Ok(handle) => handle.0,
            Err(poisoned) => poisoned.into_inner().0,
        };
        // SAFETY: this is the unique live context returned by `create`, and
        // the API retains the backing library until this destructor returns.
        unsafe { (self.api.destroy)(handle.as_ptr()) };
    }
}

/// Explicit CUDA accelerator for Plonky3's first Poseidon2 digest layer.
///
/// Loading requires an exact caller-supplied library path and device. Clones
/// share one serialized context. Errors never select a CPU fallback.
#[derive(Clone)]
pub struct CudaProofPoseidon2 {
    context: Arc<Poseidon2Context>,
    device_index: i32,
    library_path: PathBuf,
}

impl fmt::Debug for CudaProofPoseidon2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CudaProofPoseidon2")
            .field("device_index", &self.device_index)
            .field("library_path", &self.library_path)
            .finish_non_exhaustive()
    }
}

impl CudaProofPoseidon2 {
    /// Load Poseidon2 ABI v1 from the exact path and create the selected device.
    ///
    /// This function does not inspect environment variables or search default
    /// locations. An absent symbol, version mismatch, or backend failure is
    /// returned directly to the caller.
    pub fn load(path: impl AsRef<Path>, device_index: i32) -> Result<Self, ProofAccelError> {
        let path = path.as_ref();
        let api = Arc::new(Poseidon2Api::load(path)?);
        let mut raw_context = std::ptr::null_mut();
        let mut error = [0 as c_char; ERROR_BUFFER_BYTES];
        // SAFETY: both output buffers are writable for their declared sizes.
        // Ownership transfers only after a successful non-null return.
        let result = unsafe {
            (api.create)(
                device_index,
                &mut raw_context,
                error.as_mut_ptr(),
                error.len(),
            )
        };
        check_backend_result("Poseidon2 create", result, &error)?;
        let handle = NonNull::new(raw_context).ok_or(ProofAccelError::NullContext)?;
        Ok(Self {
            context: Arc::new(Poseidon2Context {
                api,
                handle: Mutex::new(Poseidon2ContextHandle(handle)),
            }),
            device_index,
            library_path: path.to_path_buf(),
        })
    }

    pub fn device_index(&self) -> i32 {
        self.device_index
    }

    pub fn library_path(&self) -> &Path {
        &self.library_path
    }

    /// Hash the ordered concatenation of equal-height physical matrix rows.
    ///
    /// The returned matrix has the same physical row order and exactly four
    /// canonical Goldilocks columns. Inputs are encoded canonically before the
    /// C boundary because Plonky3 permits noncanonical internal field limbs.
    pub fn try_first_digest_layer(
        &self,
        matrices: &[RowMajorMatrix<Goldilocks>],
    ) -> Result<RowMajorMatrix<Goldilocks>, ProofAccelError> {
        let matrices = matrices.iter().collect::<Vec<_>>();
        self.try_first_digest_layer_refs(&matrices)
    }

    /// Hash borrowed row-major matrices without cloning their value buffers.
    ///
    /// Matrix order is significant: each physical output row hashes the
    /// ordered concatenation of the corresponding rows from `matrices`.
    /// Canonical Goldilocks buffers cross the C boundary by reference;
    /// noncanonical buffers still receive the required canonical copy.
    pub fn try_first_digest_layer_refs(
        &self,
        matrices: &[&RowMajorMatrix<Goldilocks>],
    ) -> Result<RowMajorMatrix<Goldilocks>, ProofAccelError> {
        let shape = validate_poseidon2_matrix_refs(matrices)?;
        let encoded = matrices
            .iter()
            .enumerate()
            .map(|(index, matrix)| canonical_limb_storage(&matrix.values, index))
            .collect::<Result<Vec<_>, _>>()?;
        let views = poseidon2_raw_views(&encoded, matrices, shape.rows);
        let mut output = try_zeroed_output(shape.output_limbs, "Poseidon2 digest output")?;
        let mut error = [0 as c_char; ERROR_BUFFER_BYTES];
        let handle = self
            .context
            .handle
            .lock()
            .map_err(|_| ProofAccelError::ContextPoisoned)?;
        // SAFETY: validation fixes every row count and buffer length; encoded
        // inputs, views, output, and the serialized context all remain live
        // and immovable for this exact ABI v1 call.
        let result = unsafe {
            (self.context.api.first_digest_layer)(
                handle.0.as_ptr(),
                views.as_ptr(),
                views.len(),
                shape.rows,
                output.as_mut_ptr(),
                output.len(),
                error.as_mut_ptr(),
                error.len(),
            )
        };
        check_backend_result("Poseidon2 first digest layer", result, &error)?;
        decode_output_matrix(output, POSEIDON2_DIGEST_WIDTH)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Poseidon2Shape {
    rows: u32,
    total_width: usize,
    total_limbs: usize,
    output_limbs: usize,
}

fn validate_poseidon2_matrix_refs(
    matrices: &[&RowMajorMatrix<Goldilocks>],
) -> Result<Poseidon2Shape, ProofAccelError> {
    validate_poseidon2_matrix_count(matrices.len())?;
    let dimensions = matrices
        .iter()
        .map(|matrix| (matrix.values.len(), matrix.width))
        .collect::<Vec<_>>();
    validate_poseidon2_dimensions(&dimensions)
}

fn poseidon2_raw_views(
    encoded: &[CanonicalLimbStorage<'_>],
    matrices: &[&RowMajorMatrix<Goldilocks>],
    rows: u32,
) -> Vec<RawPoseidon2MatrixViewV1> {
    encoded
        .iter()
        .zip(matrices)
        .map(|(storage, matrix)| {
            let values = storage.as_slice();
            RawPoseidon2MatrixViewV1 {
                values: values.as_ptr(),
                values_len: values.len(),
                rows,
                columns: u32::try_from(matrix.width)
                    .expect("validated Poseidon2 width always fits u32"),
            }
        })
        .collect()
}

fn validate_poseidon2_matrix_count(count: usize) -> Result<(), ProofAccelError> {
    if count == 0 || count > CUDA_POSEIDON2_MAX_MATRICES {
        return Err(ProofAccelError::InvalidDimensions(format!(
            "CUDA Poseidon2 matrix count {count} is outside 1..={CUDA_POSEIDON2_MAX_MATRICES}"
        )));
    }
    Ok(())
}

fn validate_poseidon2_dimensions(
    matrices: &[(usize, usize)],
) -> Result<Poseidon2Shape, ProofAccelError> {
    validate_poseidon2_matrix_count(matrices.len())?;

    let mut common_rows = None;
    let mut total_width = 0_usize;
    for (index, &(values_len, width)) in matrices.iter().enumerate() {
        if width == 0 {
            return Err(ProofAccelError::InvalidDimensions(format!(
                "CUDA Poseidon2 matrix {index} width must be nonzero"
            )));
        }
        if !values_len.is_multiple_of(width) {
            return Err(ProofAccelError::InvalidDimensions(format!(
                "CUDA Poseidon2 matrix {index} length {values_len} is not divisible by width {width}"
            )));
        }
        let rows = values_len / width;
        if rows == 0 {
            return Err(ProofAccelError::InvalidDimensions(format!(
                "CUDA Poseidon2 matrix {index} height must be nonzero"
            )));
        }
        if rows > CUDA_POSEIDON2_MAX_ROWS {
            return Err(ProofAccelError::InvalidDimensions(format!(
                "CUDA Poseidon2 row count {rows} exceeds {CUDA_POSEIDON2_MAX_ROWS}"
            )));
        }
        if let Some(expected) = common_rows {
            if rows != expected {
                return Err(ProofAccelError::InvalidDimensions(format!(
                    "CUDA Poseidon2 matrix {index} height {rows} does not match {expected}"
                )));
            }
        } else {
            common_rows = Some(rows);
        }
        total_width = total_width.checked_add(width).ok_or_else(|| {
            ProofAccelError::InvalidDimensions(
                "CUDA Poseidon2 concatenated row width overflow".to_owned(),
            )
        })?;
        if total_width > CUDA_POSEIDON2_MAX_ROW_WIDTH {
            return Err(ProofAccelError::InvalidDimensions(format!(
                "CUDA Poseidon2 concatenated row width {total_width} exceeds {CUDA_POSEIDON2_MAX_ROW_WIDTH}"
            )));
        }
    }

    let rows = common_rows.expect("nonempty matrices establish a row count");
    let total_limbs = rows.checked_mul(total_width).ok_or_else(|| {
        ProofAccelError::InvalidDimensions("CUDA Poseidon2 total limb count overflow".to_owned())
    })?;
    if total_limbs > CUDA_POSEIDON2_MAX_TOTAL_LIMBS {
        return Err(ProofAccelError::InvalidDimensions(format!(
            "CUDA Poseidon2 total limb count {total_limbs} exceeds {CUDA_POSEIDON2_MAX_TOTAL_LIMBS}"
        )));
    }
    let output_limbs = rows.checked_mul(POSEIDON2_DIGEST_WIDTH).ok_or_else(|| {
        ProofAccelError::InvalidDimensions("CUDA Poseidon2 output limb count overflow".to_owned())
    })?;
    Ok(Poseidon2Shape {
        rows: u32::try_from(rows).expect("validated Poseidon2 rows always fit u32"),
        total_width,
        total_limbs,
        output_limbs,
    })
}

enum CanonicalLimbStorage<'a> {
    Borrowed(&'a [u64]),
    Owned(Vec<u64>),
}

impl CanonicalLimbStorage<'_> {
    fn as_slice(&self) -> &[u64] {
        match self {
            Self::Borrowed(values) => values,
            Self::Owned(values) => values,
        }
    }
}

fn canonical_limb_storage<'a>(
    values: &'a [Goldilocks],
    matrix_index: usize,
) -> Result<CanonicalLimbStorage<'a>, ProofAccelError> {
    const {
        assert!(size_of::<Goldilocks>() == size_of::<u64>());
        assert!(align_of::<Goldilocks>() == align_of::<u64>());
    }
    // SAFETY: p3-goldilocks 0.6.3 pins Goldilocks as repr(transparent) over
    // u64. This immutable view reads only the valid underlying bit patterns;
    // it neither assumes nor changes their canonical field representation.
    let raw = unsafe { slice::from_raw_parts(values.as_ptr().cast::<u64>(), values.len()) };
    if raw.iter().all(|&value| value < Goldilocks::ORDER_U64) {
        return Ok(CanonicalLimbStorage::Borrowed(raw));
    }

    let mut encoded = Vec::new();
    encoded.try_reserve_exact(values.len()).map_err(|error| {
        ProofAccelError::InvalidDimensions(format!(
            "CUDA Poseidon2 matrix {matrix_index} allocation for {} limbs failed: {error}",
            values.len()
        ))
    })?;
    encoded.extend(values.iter().map(PrimeField64::as_canonical_u64));
    Ok(CanonicalLimbStorage::Owned(encoded))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use p3_field::{PrimeCharacteristicRing, PrimeField64};
    use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks, default_goldilocks_poseidon2_8};
    use p3_symmetric::{CryptographicHasher, PaddingFreeSponge};

    use super::*;

    type Poseidon2Hasher = PaddingFreeSponge<Poseidon2Goldilocks<8>, 8, 4, 4>;

    fn matrix(rows: usize, width: usize, salt: u64) -> RowMajorMatrix<Goldilocks> {
        RowMajorMatrix::new(
            (0..rows * width)
                .map(|index| {
                    Goldilocks::from_u64(
                        (index as u64)
                            .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                            .wrapping_add(salt),
                    )
                })
                .collect(),
            width,
        )
    }

    fn cpu_first_digest_layer(
        matrices: &[RowMajorMatrix<Goldilocks>],
    ) -> RowMajorMatrix<Goldilocks> {
        let matrices = matrices.iter().collect::<Vec<_>>();
        cpu_first_digest_layer_refs(&matrices)
    }

    fn cpu_first_digest_layer_refs(
        matrices: &[&RowMajorMatrix<Goldilocks>],
    ) -> RowMajorMatrix<Goldilocks> {
        let shape = validate_poseidon2_matrix_refs(matrices).unwrap();
        let hasher = Poseidon2Hasher::new(default_goldilocks_poseidon2_8());
        let mut output = Vec::with_capacity(shape.output_limbs);
        for row in 0..shape.rows as usize {
            output.extend(hasher.hash_iter(matrices.iter().flat_map(|matrix| {
                let start = row * matrix.width;
                matrix.values[start..start + matrix.width].iter().copied()
            })));
        }
        RowMajorMatrix::new(output, POSEIDON2_DIGEST_WIDTH)
    }

    fn fixture_value(index: usize, salt: u64) -> u64 {
        let mut value = (index as u64).wrapping_add(salt);
        value ^= value >> 12;
        value ^= value << 25;
        value ^= value >> 27;
        value = value.wrapping_mul(0x2545_f491_4f6c_dd1d);
        if value >= Goldilocks::ORDER_U64 {
            value - Goldilocks::ORDER_U64
        } else {
            value
        }
    }

    #[test]
    fn cpu_reference_matches_pinned_plonky3_vectors() {
        const SALT: u64 = 0x1234_5678_9abc_def0;
        const FIXTURES: &[(usize, [u64; 4])] = &[
            (
                1,
                [
                    7668073106091160635,
                    8186641118638216760,
                    6457284654664772022,
                    5770619367258960679,
                ],
            ),
            (
                4,
                [
                    11126648771938909578,
                    13035621986393488367,
                    4678693851439491810,
                    875937718037293451,
                ],
            ),
            (
                8,
                [
                    17634486255809933696,
                    15766679345631357503,
                    16584936375404369965,
                    18186598152891123503,
                ],
            ),
            (
                87,
                [
                    10725271548208625869,
                    17474902801359862501,
                    2635340078653449537,
                    7180112465085594324,
                ],
            ),
            (
                291,
                [
                    13843296229019507427,
                    1099202951096753247,
                    12685862824277584409,
                    2349131546407372023,
                ],
            ),
        ];

        for &(width, expected) in FIXTURES {
            let input = RowMajorMatrix::new(
                (0..width)
                    .map(|index| Goldilocks::from_u64(fixture_value(index, SALT)))
                    .collect(),
                width,
            );
            let actual = cpu_first_digest_layer(&[input]);
            assert_eq!(
                actual
                    .values
                    .iter()
                    .map(PrimeField64::as_canonical_u64)
                    .collect::<Vec<_>>(),
                expected
            );
        }
    }

    #[test]
    fn poseidon2_dimensions_enforce_all_abi_v1_caps() {
        assert!(validate_poseidon2_dimensions(&[]).is_err());
        assert!(validate_poseidon2_dimensions(&vec![(1, 1); 65]).is_err());
        assert!(validate_poseidon2_dimensions(&[(1, 0)]).is_err());
        assert!(validate_poseidon2_dimensions(&[(3, 2)]).is_err());
        assert!(validate_poseidon2_dimensions(&[(2, 1), (3, 1)]).is_err());
        assert!(validate_poseidon2_dimensions(&[(CUDA_POSEIDON2_MAX_ROWS + 1, 1)]).is_err());
        assert!(
            validate_poseidon2_dimensions(&[(
                CUDA_POSEIDON2_MAX_ROW_WIDTH + 1,
                CUDA_POSEIDON2_MAX_ROW_WIDTH + 1
            )])
            .is_err()
        );
        assert!(validate_poseidon2_dimensions(&[(CUDA_POSEIDON2_MAX_ROWS * 129, 129,)]).is_err());

        let valid = validate_poseidon2_dimensions(&[(24, 3), (40, 5)]).unwrap();
        assert_eq!(valid.rows, 8);
        assert_eq!(valid.total_width, 8);
        assert_eq!(valid.total_limbs, 64);
        assert_eq!(valid.output_limbs, 32);
    }

    #[test]
    fn poseidon2_never_searches_for_a_missing_explicit_library() {
        let path = Path::new("cmfd-proof-accel-definitely-missing-poseidon2-library.dll");
        let error = CudaProofPoseidon2::load(path, 0).unwrap_err();
        assert!(matches!(error, ProofAccelError::LoadLibrary { .. }));
    }

    #[test]
    fn canonical_poseidon2_input_borrows_existing_storage() {
        let values = [Goldilocks::from_u64(0), Goldilocks::from_u64(17)];
        let storage = canonical_limb_storage(&values, 0).unwrap();
        let CanonicalLimbStorage::Borrowed(raw) = storage else {
            panic!("canonical Goldilocks storage was copied");
        };
        assert_eq!(raw, [0, 17]);
        assert_eq!(raw.as_ptr(), values.as_ptr().cast::<u64>());
    }

    #[test]
    fn poseidon2_reference_views_preserve_pointers_and_matrix_order() {
        let first = matrix(4, 3, 0x101);
        let second = matrix(4, 5, 0x202);
        let matrices = [&second, &first];
        let shape = validate_poseidon2_matrix_refs(&matrices).unwrap();
        let encoded = matrices
            .iter()
            .enumerate()
            .map(|(index, matrix)| canonical_limb_storage(&matrix.values, index))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(
            encoded
                .iter()
                .all(|storage| matches!(storage, CanonicalLimbStorage::Borrowed(_)))
        );

        let views = poseidon2_raw_views(&encoded, &matrices, shape.rows);
        assert_eq!(views.len(), 2);
        assert_eq!(views[0].values, second.values.as_ptr().cast::<u64>());
        assert_eq!(views[0].values_len, second.values.len());
        assert_eq!(views[0].columns, 5);
        assert_eq!(views[1].values, first.values.as_ptr().cast::<u64>());
        assert_eq!(views[1].values_len, first.values.len());
        assert_eq!(views[1].columns, 3);
        assert!(views.iter().all(|view| view.rows == 4));

        assert_ne!(
            cpu_first_digest_layer_refs(&matrices),
            cpu_first_digest_layer_refs(&[&first, &second])
        );
    }

    #[test]
    fn noncanonical_poseidon2_input_gets_an_owned_canonical_copy() {
        let values = [
            Goldilocks::new(Goldilocks::ORDER_U64),
            Goldilocks::new(u64::MAX),
        ];
        let storage = canonical_limb_storage(&values, 0).unwrap();
        let CanonicalLimbStorage::Owned(encoded) = storage else {
            panic!("noncanonical Goldilocks storage was borrowed");
        };
        assert_eq!(
            encoded,
            values
                .iter()
                .map(PrimeField64::as_canonical_u64)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn poseidon2_wrapper_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<CudaProofPoseidon2>();
    }

    #[test]
    #[ignore = "requires an explicitly named real CUDA proof library"]
    fn real_cuda_poseidon2_matches_cpu_for_all_production_widths_and_multiple_matrices() {
        let path = std::env::var_os("CMFD_TEST_PROOF_CUDA_LIBRARY")
            .expect("set CMFD_TEST_PROOF_CUDA_LIBRARY to the built proof CUDA library");
        let device = std::env::var("CMFD_TEST_PROOF_CUDA_DEVICE")
            .ok()
            .map(|value| value.parse::<i32>().expect("device must be an i32"))
            .unwrap_or(0);
        let cuda = CudaProofPoseidon2::load(path, device).unwrap();
        const WIDTHS: [usize; 5] = [1, 4, 8, 87, 291];

        for (index, width) in WIDTHS.into_iter().enumerate() {
            let matrices = [matrix(16, width, 0x1000 + index as u64)];
            assert_eq!(
                cuda.try_first_digest_layer(&matrices).unwrap(),
                cpu_first_digest_layer(&matrices)
            );
        }

        let matrices = WIDTHS
            .into_iter()
            .enumerate()
            .map(|(index, width)| matrix(16, width, 0x2000 + index as u64))
            .collect::<Vec<_>>();
        let references = matrices.iter().rev().collect::<Vec<_>>();
        assert_eq!(
            cuda.try_first_digest_layer(&matrices).unwrap(),
            cpu_first_digest_layer(&matrices)
        );
        assert_eq!(
            cuda.try_first_digest_layer_refs(&references).unwrap(),
            cpu_first_digest_layer_refs(&references)
        );
    }
}
