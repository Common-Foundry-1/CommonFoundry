//! CPU re-execution of ProductionV4 work.
//!
//! Nodes independently re-execute each block's work: from the block's
//! challenge digest and the authenticated model bank, this module runs the
//! forward pass described by `FORGEMATRIX_V4_EXECUTION_SEMANTICS` and returns
//! the final activation, its digest and the resulting work digest.
//!
//! - model byte `x` maps to `x - 125`;
//! - `a_0[r][c] = (base[r][c] - 125 + mask(challenge, u32::MAX)(r, c))^3`;
//! - `a_{l+1}[r][c] = (sum_k a_l[r][k] * (W_l[k][c] - 125) + mask(challenge, l)(r, c))^3`;
//! - all arithmetic is canonical KoalaBear (`p = 2^31 - 2^24 + 1`).
//!
//! The matrix products run as a float64 GEMM over the raw model bytes, and
//! `125 * sum_k a_l[r][k]` is subtracted afterwards in `i64`. This is exact:
//! activations are below `p < 2^31`, raw model bytes are at most 250 and a
//! row has at most 4096 terms, so every partial sum is a non-negative integer
//! below `4096 * 250 * p < 2^53`. The result is therefore independent of
//! summation order, blocking and thread count.
//!
//! Model layers are read one at a time from a [`ForgeMatrixV4LayerSource`],
//! one layer ahead of the computation. The file-backed source streams them
//! from the bank and can check each layer against the root captured while the
//! whole bank was authenticated; the resident source holds every layer in
//! memory, each checked against its root once when it is loaded.

use std::fs::File;
use std::io;
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;

use thiserror::Error;

use crate::{
    FORGEMATRIX_V4_FIELD_MODULUS, FORGEMATRIX_V4_FINAL_ACTIVATION_DIGEST_DOMAIN,
    FORGEMATRIX_V4_PUBLIC_FINAL_ACTIVATION_BYTES, MAX_MODEL_BYTE, MODEL_BANK_HEADER_BYTES,
    ModelBankManifest, PRODUCTION_V2_BATCH, PRODUCTION_V2_DIMENSION, PRODUCTION_V2_LAYERS,
    PRODUCTION_V4_MODEL_MANIFEST_DIGEST,
    forgematrix_v2::{V2_MODEL_VALUE_CENTER, mask_coefficients},
    forgematrix_v4_work_digest,
};

/// Coefficients in one ProductionV4 mask: a constant, one per row bit and
/// one per column bit.
pub const FORGEMATRIX_V4_MASK_COEFFICIENTS: usize =
    1 + PRODUCTION_V2_BATCH.ilog2() as usize + PRODUCTION_V2_DIMENSION.ilog2() as usize;
/// Mask coefficients for one ProductionV4 forward pass: the initial-activation
/// set (`u32::MAX`), then one set per layer.
pub const FORGEMATRIX_V4_REPLAY_COEFFICIENT_BYTES: usize =
    (PRODUCTION_V2_LAYERS as usize + 1) * FORGEMATRIX_V4_MASK_COEFFICIENTS;

/// Largest inner dimension for which the float64 accumulation stays exact.
const MAX_EXACT_DIMENSION: usize = 4096;
/// Output columns per work item, and the inner-dimension block per GEMM call.
const PANEL: usize = 256;
const MODULUS: u64 = FORGEMATRIX_V4_FIELD_MODULUS as u64;
const CENTER: i64 = V2_MODEL_VALUE_CENTER as i64;

// Every partial sum of activation (< p) times raw model byte (<= 250) over at
// most MAX_EXACT_DIMENSION terms must be an exactly representable f64 integer.
const _: () = assert!(
    (MAX_EXACT_DIMENSION as u128) * (MAX_MODEL_BYTE as u128) * ((MODULUS - 1) as u128)
        < (1_u128 << f64::MANTISSA_DIGITS)
);
const _: () = assert!(PRODUCTION_V2_DIMENSION as usize <= MAX_EXACT_DIMENSION);
const _: () = assert!(FORGEMATRIX_V4_REPLAY_COEFFICIENT_BYTES == 7_700);

/// A failure to re-execute work.
///
/// Every variant is a fault of the local engine, its inputs or its model
/// bank. None of them says anything about the block being checked: callers
/// must report them as a retryable "work check unavailable" and must never
/// treat one as evidence that a block is invalid.
#[derive(Debug, Error)]
pub enum ForgeMatrixV4ExecutionError {
    #[error("work execution shape is not supported")]
    Shape,
    #[error("work execution input has the wrong length")]
    InputLength,
    #[error("work execution needs at least one thread")]
    ThreadCount,
    #[error("could not start a work execution thread: {0}")]
    ThreadSpawn(#[source] io::Error),
    #[error("a work execution thread panicked")]
    ThreadPanicked,
    #[error("model bank file has {actual} bytes; expected {expected}")]
    BankLength { actual: u64, expected: u64 },
    #[error("could not read the model bank: {0}")]
    BankIo(#[source] io::Error),
    #[error("could not read model layer {layer}: {source}")]
    LayerRead {
        layer: usize,
        #[source]
        source: io::Error,
    },
    #[error("model layer {layer} does not match its authenticated root")]
    LayerAuthentication { layer: usize },
    #[error("could not allocate {bytes} bytes to hold the model bank in memory")]
    ResidentAllocation { bytes: usize },
    #[error("ProductionV4 final activation has the wrong byte length")]
    FinalActivationLength,
    #[error("ProductionV4 final activation contains a noncanonical field value")]
    NonCanonicalFinalActivation,
}

/// Geometry of one forward pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForgeMatrixV4ExecutionShape {
    pub batch: usize,
    pub dimension: usize,
    pub layers: usize,
}

impl ForgeMatrixV4ExecutionShape {
    pub const PRODUCTION: Self = Self {
        batch: PRODUCTION_V2_BATCH as usize,
        dimension: PRODUCTION_V2_DIMENSION as usize,
        layers: PRODUCTION_V2_LAYERS as usize,
    };

    /// The shape of the bank described by `manifest`.
    pub fn from_manifest(
        manifest: &ModelBankManifest,
    ) -> Result<Self, ForgeMatrixV4ExecutionError> {
        let shape = Self {
            batch: usize::try_from(manifest.batch)
                .map_err(|_| ForgeMatrixV4ExecutionError::Shape)?,
            dimension: usize::try_from(manifest.dimension)
                .map_err(|_| ForgeMatrixV4ExecutionError::Shape)?,
            layers: usize::try_from(manifest.layers)
                .map_err(|_| ForgeMatrixV4ExecutionError::Shape)?,
        };
        shape.validate()?;
        if manifest.base_input_bytes != shape.cells() as u64
            || manifest.bytes_per_layer != shape.layer_bytes() as u64
            || Some(manifest.payload_bytes)
                != (shape.layers as u64)
                    .checked_mul(manifest.bytes_per_layer)
                    .and_then(|layers| layers.checked_add(manifest.base_input_bytes))
        {
            return Err(ForgeMatrixV4ExecutionError::Shape);
        }
        Ok(shape)
    }

    /// Cells in one activation matrix (`batch * dimension`).
    pub const fn cells(self) -> usize {
        self.batch * self.dimension
    }

    /// Bytes in one model layer (`dimension * dimension`).
    pub const fn layer_bytes(self) -> usize {
        self.dimension * self.dimension
    }

    /// Coefficients in one mask.
    pub const fn mask_coefficients(self) -> usize {
        1 + self.row_bits() + self.column_bits()
    }

    /// Mask coefficient bytes for one forward pass: `layers + 1` sets.
    pub const fn coefficient_bytes(self) -> usize {
        (self.layers + 1) * self.mask_coefficients()
    }

    const fn row_bits(self) -> usize {
        self.batch.ilog2() as usize
    }

    const fn column_bits(self) -> usize {
        self.dimension.ilog2() as usize
    }

    const fn panel(self) -> usize {
        if self.dimension < PANEL {
            self.dimension
        } else {
            PANEL
        }
    }

    fn validate(self) -> Result<(), ForgeMatrixV4ExecutionError> {
        if !self.batch.is_power_of_two()
            || !self.dimension.is_power_of_two()
            || self.dimension > MAX_EXACT_DIMENSION
            || self.layers == 0
        {
            return Err(ForgeMatrixV4ExecutionError::Shape);
        }
        Ok(())
    }
}

/// Where the executor reads the model from.
pub trait ForgeMatrixV4LayerSource: Send + Sync {
    /// The shape of the model this source holds.
    fn shape(&self) -> ForgeMatrixV4ExecutionShape;

    /// The authenticated base input, `batch * dimension` bytes.
    fn base_input(&self) -> &[u8];

    /// Fills `out` (exactly `dimension * dimension` bytes) with layer
    /// `layer`. With `authenticate`, the bytes read must also hash to the
    /// layer's authenticated root.
    fn read_layer(
        &self,
        layer: usize,
        out: &mut [u8],
        authenticate: bool,
    ) -> Result<(), ForgeMatrixV4ExecutionError>;

    /// Called first on every thread the executor starts to read or compute
    /// for this source, before it does any work. It cannot change the
    /// result; a node uses it to set the thread's scheduling priority. Does
    /// nothing by default.
    fn on_thread_start(&self) {}
}

/// Reads layers from a model bank file whose base input and per-layer roots
/// were captured when the whole bank was authenticated (see
/// `verify_model_bank_and_retain_base_input_and_layer_roots`).
pub struct ForgeMatrixV4FileLayerSource {
    file: File,
    shape: ForgeMatrixV4ExecutionShape,
    base_input: Arc<[u8]>,
    layer_roots: Arc<[[u8; 32]]>,
    first_layer_offset: u64,
    bytes_per_layer: u64,
}

impl ForgeMatrixV4FileLayerSource {
    /// `file` must be the bank that was authenticated against `manifest` and
    /// produced `base_input` and `layer_roots`.
    pub fn new(
        file: File,
        manifest: &ModelBankManifest,
        base_input: Arc<[u8]>,
        layer_roots: Arc<[[u8; 32]]>,
    ) -> Result<Self, ForgeMatrixV4ExecutionError> {
        let shape = ForgeMatrixV4ExecutionShape::from_manifest(manifest)?;
        if base_input.len() != shape.cells() || layer_roots.len() != shape.layers {
            return Err(ForgeMatrixV4ExecutionError::InputLength);
        }
        let expected = (MODEL_BANK_HEADER_BYTES as u64)
            .checked_add(manifest.payload_bytes)
            .ok_or(ForgeMatrixV4ExecutionError::Shape)?;
        let actual = file
            .metadata()
            .map_err(ForgeMatrixV4ExecutionError::BankIo)?
            .len();
        if actual != expected {
            return Err(ForgeMatrixV4ExecutionError::BankLength { actual, expected });
        }
        Ok(Self {
            file,
            shape,
            base_input,
            layer_roots,
            first_layer_offset: MODEL_BANK_HEADER_BYTES as u64 + manifest.base_input_bytes,
            bytes_per_layer: manifest.bytes_per_layer,
        })
    }
}

impl ForgeMatrixV4LayerSource for ForgeMatrixV4FileLayerSource {
    fn shape(&self) -> ForgeMatrixV4ExecutionShape {
        self.shape
    }

    fn base_input(&self) -> &[u8] {
        &self.base_input
    }

    fn read_layer(
        &self,
        layer: usize,
        out: &mut [u8],
        authenticate: bool,
    ) -> Result<(), ForgeMatrixV4ExecutionError> {
        if layer >= self.shape.layers || out.len() != self.shape.layer_bytes() {
            return Err(ForgeMatrixV4ExecutionError::InputLength);
        }
        let offset = (layer as u64)
            .checked_mul(self.bytes_per_layer)
            .and_then(|start| start.checked_add(self.first_layer_offset))
            .ok_or(ForgeMatrixV4ExecutionError::Shape)?;
        read_exact_at(&self.file, out, offset)
            .map_err(|source| ForgeMatrixV4ExecutionError::LayerRead { layer, source })?;
        if authenticate && blake3::hash(out).as_bytes() != &self.layer_roots[layer] {
            return Err(ForgeMatrixV4ExecutionError::LayerAuthentication { layer });
        }
        Ok(())
    }
}

/// Holds every layer of a model bank in memory, so a forward pass reads no
/// disk. Each layer is checked against the root captured while the whole
/// bank was authenticated as it is loaded, so the bytes held are the bytes
/// that pass authenticated, whatever happens to the file later.
pub struct ForgeMatrixV4ResidentLayerSource {
    shape: ForgeMatrixV4ExecutionShape,
    base_input: Arc<[u8]>,
    layer_roots: Arc<[[u8; 32]]>,
    layers: Vec<u8>,
}

impl ForgeMatrixV4ResidentLayerSource {
    /// Reads every layer of `file` into memory and checks each against its
    /// root. The arguments are those of [`ForgeMatrixV4FileLayerSource::new`].
    /// Fails with [`ForgeMatrixV4ExecutionError::ResidentAllocation`] if the
    /// layers do not fit in memory.
    pub fn load(
        file: File,
        manifest: &ModelBankManifest,
        base_input: Arc<[u8]>,
        layer_roots: Arc<[[u8; 32]]>,
    ) -> Result<Self, ForgeMatrixV4ExecutionError> {
        let streamed = ForgeMatrixV4FileLayerSource::new(file, manifest, base_input, layer_roots)?;
        let shape = streamed.shape;
        let bytes = shape
            .layers
            .checked_mul(shape.layer_bytes())
            .ok_or(ForgeMatrixV4ExecutionError::Shape)?;
        let mut layers = Vec::new();
        layers
            .try_reserve_exact(bytes)
            .map_err(|_| ForgeMatrixV4ExecutionError::ResidentAllocation { bytes })?;
        layers.resize(bytes, 0);
        for (layer, out) in layers.chunks_exact_mut(shape.layer_bytes()).enumerate() {
            streamed.read_layer(layer, out, true)?;
        }
        Ok(Self {
            shape,
            base_input: streamed.base_input,
            layer_roots: streamed.layer_roots,
            layers,
        })
    }
}

impl ForgeMatrixV4LayerSource for ForgeMatrixV4ResidentLayerSource {
    fn shape(&self) -> ForgeMatrixV4ExecutionShape {
        self.shape
    }

    fn base_input(&self) -> &[u8] {
        &self.base_input
    }

    fn read_layer(
        &self,
        layer: usize,
        out: &mut [u8],
        authenticate: bool,
    ) -> Result<(), ForgeMatrixV4ExecutionError> {
        let bytes = self.shape.layer_bytes();
        if layer >= self.shape.layers || out.len() != bytes {
            return Err(ForgeMatrixV4ExecutionError::InputLength);
        }
        out.copy_from_slice(&self.layers[layer * bytes..(layer + 1) * bytes]);
        if authenticate && blake3::hash(out).as_bytes() != &self.layer_roots[layer] {
            return Err(ForgeMatrixV4ExecutionError::LayerAuthentication { layer });
        }
        Ok(())
    }
}

#[cfg(unix)]
fn read_exact_at(file: &File, out: &mut [u8], offset: u64) -> io::Result<()> {
    std::os::unix::fs::FileExt::read_exact_at(file, out, offset)
}

#[cfg(windows)]
fn read_exact_at(file: &File, mut out: &mut [u8], mut offset: u64) -> io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !out.is_empty() {
        match file.seek_read(out, offset) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(read) => {
                out = &mut out[read..];
                offset += read as u64;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// The mask coefficients for one ProductionV4 forward pass: the
/// initial-activation set (`u32::MAX`) first, then one set per layer. This is
/// the exact input the replay worker takes.
pub fn forgematrix_v4_replay_coefficients(
    challenge_digest: [u8; 32],
) -> [u8; FORGEMATRIX_V4_REPLAY_COEFFICIENT_BYTES] {
    let mut coefficients = [0_u8; FORGEMATRIX_V4_REPLAY_COEFFICIENT_BYTES];
    for (slot, set) in coefficients
        .chunks_exact_mut(FORGEMATRIX_V4_MASK_COEFFICIENTS)
        .enumerate()
    {
        let layer = if slot == 0 { u32::MAX } else { slot as u32 - 1 };
        set.copy_from_slice(&mask_coefficients(
            &challenge_digest,
            layer,
            PRODUCTION_V2_BATCH as usize,
            PRODUCTION_V2_DIMENSION as usize,
        ));
    }
    coefficients
}

/// The final-activation digest of a ProductionV4 final activation given as
/// canonical little-endian `u32` values, row-major. Rejects a wrong length or
/// any value that is not a canonical field element.
pub fn forgematrix_v4_final_activation_digest_from_le_bytes(
    challenge_digest: [u8; 32],
    final_activation: &[u8],
) -> Result<[u8; 32], ForgeMatrixV4ExecutionError> {
    if final_activation.len() != FORGEMATRIX_V4_PUBLIC_FINAL_ACTIVATION_BYTES {
        return Err(ForgeMatrixV4ExecutionError::FinalActivationLength);
    }
    if final_activation
        .chunks_exact(size_of::<u32>())
        .any(|encoded| {
            u32::from_le_bytes(encoded.try_into().expect("four-byte chunk"))
                >= FORGEMATRIX_V4_FIELD_MODULUS
        })
    {
        return Err(ForgeMatrixV4ExecutionError::NonCanonicalFinalActivation);
    }
    let mut hasher = blake3::Hasher::new_derive_key(FORGEMATRIX_V4_FINAL_ACTIVATION_DIGEST_DOMAIN);
    hasher.update(&challenge_digest);
    hasher.update(&((final_activation.len() / size_of::<u32>()) as u64).to_le_bytes());
    hasher.update(final_activation);
    Ok(*hasher.finalize().as_bytes())
}

/// Digests produced by re-executing one ProductionV4 challenge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForgeMatrixV4Execution {
    pub challenge_digest: [u8; 32],
    pub final_activation_digest: [u8; 32],
    pub work_digest: [u8; 32],
}

/// Re-executes the ProductionV4 work for `challenge_digest` and returns its
/// digests. The caller compares them with a block's own claim.
///
/// This blocks for the whole forward pass (seconds); run it off any async
/// runtime.
pub fn forgematrix_v4_execute_challenge(
    challenge_digest: [u8; 32],
    source: &dyn ForgeMatrixV4LayerSource,
    threads: usize,
    authenticate: bool,
) -> Result<ForgeMatrixV4Execution, ForgeMatrixV4ExecutionError> {
    let final_activation = forgematrix_v4_execute(
        ForgeMatrixV4ExecutionShape::PRODUCTION,
        source,
        &forgematrix_v4_replay_coefficients(challenge_digest),
        threads,
        authenticate,
    )?;
    let encoded = final_activation
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect::<Vec<_>>();
    let final_activation_digest =
        forgematrix_v4_final_activation_digest_from_le_bytes(challenge_digest, &encoded)?;
    Ok(ForgeMatrixV4Execution {
        challenge_digest,
        final_activation_digest,
        work_digest: forgematrix_v4_work_digest(
            PRODUCTION_V4_MODEL_MANIFEST_DIGEST,
            challenge_digest,
            final_activation_digest,
        ),
    })
}

/// Runs the forward pass for one set of mask `coefficients` (`layers + 1`
/// sets, the initial-activation set first) and returns the final activation
/// as canonical field values, row-major.
///
/// `threads` compute workers are used, capped at the machine's available
/// parallelism, plus one reader that fetches layer `l + 1` while layer `l`
/// is computed. The result does not depend on the thread count. This blocks
/// for the whole forward pass.
pub fn forgematrix_v4_execute(
    shape: ForgeMatrixV4ExecutionShape,
    source: &dyn ForgeMatrixV4LayerSource,
    coefficients: &[u8],
    threads: usize,
    authenticate: bool,
) -> Result<Vec<u32>, ForgeMatrixV4ExecutionError> {
    shape.validate()?;
    if source.shape() != shape {
        return Err(ForgeMatrixV4ExecutionError::Shape);
    }
    if coefficients.len() != shape.coefficient_bytes() || source.base_input().len() != shape.cells()
    {
        return Err(ForgeMatrixV4ExecutionError::InputLength);
    }
    if threads == 0 {
        return Err(ForgeMatrixV4ExecutionError::ThreadCount);
    }
    let available = thread::available_parallelism().map_or(1, usize::from);
    let (initial, layers) = coefficients.split_at(shape.mask_coefficients());
    let activation = initial_activation(shape, source.base_input(), initial);
    forward(
        shape,
        &activation,
        layers,
        |layer, out| source.read_layer(layer, out, authenticate),
        &|| source.on_thread_start(),
        threads.min(available),
    )
}

/// Coordinate mask split into its row and column parts:
/// `mask(r, c) = row[r] + column[c]`, with the constant term folded into `row`.
struct Mask {
    row: Vec<i64>,
    column: Vec<i64>,
}

impl Mask {
    fn new(shape: ForgeMatrixV4ExecutionShape, coefficients: &[u8]) -> Self {
        let bit_sum = |index: usize, terms: &[u8]| -> i64 {
            terms
                .iter()
                .enumerate()
                .filter(|(bit, _)| (index >> bit) & 1 == 1)
                .map(|(_, &coefficient)| i64::from(coefficient))
                .sum()
        };
        let (constant, terms) = coefficients.split_first().expect("mask has a constant");
        let (row_terms, column_terms) = terms.split_at(shape.row_bits());
        Self {
            row: (0..shape.batch)
                .map(|row| i64::from(*constant) + bit_sum(row, row_terms))
                .collect(),
            column: (0..shape.dimension)
                .map(|column| bit_sum(column, column_terms))
                .collect(),
        }
    }
}

fn cube(value: i64) -> u32 {
    let x = value.rem_euclid(MODULUS as i64) as u64;
    (((x * x) % MODULUS) * x % MODULUS) as u32
}

fn initial_activation(
    shape: ForgeMatrixV4ExecutionShape,
    base: &[u8],
    coefficients: &[u8],
) -> Vec<u32> {
    let mask = Mask::new(shape, coefficients);
    base.chunks_exact(shape.dimension)
        .zip(&mask.row)
        .flat_map(|(input, row)| {
            input
                .iter()
                .zip(&mask.column)
                .map(move |(&byte, column)| cube(i64::from(byte) - CENTER + row + column))
        })
        .collect()
}

/// `c = a * b` (or `c += a * b` with `accumulate`) for row-major, contiguous
/// `a` (m x k), `b` (k x n) and `c` (m x n).
fn gemm(m: usize, k: usize, n: usize, a: &[f64], b: &[f64], c: &mut [f64], accumulate: bool) {
    assert_eq!(a.len(), m * k);
    assert_eq!(b.len(), k * n);
    assert_eq!(c.len(), m * n);
    // SAFETY: the asserts above bound every element dgemm reads or writes for
    // contiguous row-major operands of these sizes (row strides k, n and n,
    // unit column strides), and `c` is a unique borrow, so it aliases neither
    // `a` nor `b`.
    unsafe {
        matrixmultiply::dgemm(
            m,
            k,
            n,
            1.0,
            a.as_ptr(),
            k as isize,
            1,
            b.as_ptr(),
            n as isize,
            1,
            if accumulate { 1.0 } else { 0.0 },
            c.as_mut_ptr(),
            n as isize,
            1,
        );
    }
}

/// Per-thread buffers: one widened weight tile and one panel of products.
struct ThreadScratch {
    tile: Vec<f64>,
    products: Vec<f64>,
}

/// Runs every layer from `initial` (row-major canonical values).
///
/// Activations are kept as f64 in panel-blocked order: panel `p` (columns
/// `p * panel ..`) is one contiguous `batch x panel` row-major block. A panel
/// of output columns is then exactly one inner-dimension block of the next
/// layer's input, so each GEMM reads a contiguous block and no reshuffle is
/// needed between layers. Every thread it starts calls `on_thread_start`
/// first.
fn forward(
    shape: ForgeMatrixV4ExecutionShape,
    initial: &[u32],
    layer_coefficients: &[u8],
    read_layer: impl Fn(usize, &mut [u8]) -> Result<(), ForgeMatrixV4ExecutionError> + Sync,
    on_thread_start: &(dyn Fn() + Sync),
    threads: usize,
) -> Result<Vec<u32>, ForgeMatrixV4ExecutionError> {
    let ForgeMatrixV4ExecutionShape {
        batch, dimension, ..
    } = shape;
    let panel = shape.panel();
    let panels = dimension / panel;
    let block = batch * panel;
    let terms = shape.mask_coefficients();
    let blocked =
        |row: usize, column: usize| (column / panel) * block + row * panel + column % panel;

    let mut current = vec![0.0_f64; shape.cells()];
    // row_partials[p * batch + r]: sum of row r's activations within panel p.
    let mut row_partials = vec![0_i64; panels * batch];
    for (index, &value) in initial.iter().enumerate() {
        let (row, column) = (index / dimension, index % dimension);
        current[blocked(row, column)] = f64::from(value);
        row_partials[(column / panel) * batch + row] += i64::from(value);
    }
    let mut next = vec![0.0_f64; shape.cells()];
    let mut weights = vec![0_u8; shape.layer_bytes()];
    let mut prefetched = vec![0_u8; shape.layer_bytes()];
    read_layer(0, &mut weights)?;
    let mut scratch = (0..threads.clamp(1, panels))
        .map(|_| ThreadScratch {
            tile: vec![0.0; panel * panel],
            products: vec![0.0; block],
        })
        .collect::<Vec<_>>();

    for layer in 0..shape.layers {
        let mask = Mask::new(
            shape,
            &layer_coefficients[layer * terms..(layer + 1) * terms],
        );
        let row_offsets = (0..batch)
            .map(|row| {
                let sum: i64 = (0..panels).map(|p| row_partials[p * batch + row]).sum();
                mask.row[row] - CENTER * sum
            })
            .collect::<Vec<_>>();
        let work = Mutex::new(
            next.chunks_exact_mut(block)
                .zip(row_partials.chunks_exact_mut(batch))
                .enumerate(),
        );
        thread::scope(|scope| {
            let (current, weights, mask, row_offsets, work) =
                (&current, &weights, &mask, &row_offsets, &work);
            let (read_layer, prefetched) = (&read_layer, &mut prefetched);
            let mut spawn_error = None;
            // One reader fetches (and, if asked, authenticates) the next
            // layer while the workers compute this one.
            let reader = if layer + 1 < shape.layers {
                match thread::Builder::new().spawn_scoped(scope, move || {
                    on_thread_start();
                    read_layer(layer + 1, prefetched)
                }) {
                    Ok(reader) => Some(reader),
                    Err(error) => {
                        spawn_error = Some(error);
                        None
                    }
                }
            } else {
                None
            };
            let mut workers = Vec::with_capacity(scratch.len());
            for scratch in scratch.iter_mut() {
                if spawn_error.is_some() {
                    break;
                }
                let spawned = thread::Builder::new().spawn_scoped(scope, move || {
                    on_thread_start();
                    loop {
                        let Some((output_panel, (out, partials))) =
                            work.lock().unwrap_or_else(PoisonError::into_inner).next()
                        else {
                            break;
                        };
                        let first_column = output_panel * panel;
                        for inner_panel in 0..panels {
                            for (tile_row, wide) in scratch.tile.chunks_exact_mut(panel).enumerate()
                            {
                                let start =
                                    (inner_panel * panel + tile_row) * dimension + first_column;
                                for (wide, &byte) in wide.iter_mut().zip(&weights[start..]) {
                                    *wide = f64::from(byte);
                                }
                            }
                            gemm(
                                batch,
                                panel,
                                panel,
                                &current[inner_panel * block..(inner_panel + 1) * block],
                                &scratch.tile,
                                &mut scratch.products,
                                inner_panel > 0,
                            );
                        }
                        for (row, ((out, products), partial)) in out
                            .chunks_exact_mut(panel)
                            .zip(scratch.products.chunks_exact(panel))
                            .zip(partials.iter_mut())
                            .enumerate()
                        {
                            *partial = 0;
                            let row_offset = row_offsets[row];
                            for ((out, &product), column) in out
                                .iter_mut()
                                .zip(products)
                                .zip(&mask.column[first_column..])
                            {
                                // Exact: a non-negative integer below 2^53.
                                let value = cube(product as i64 + row_offset + column);
                                *out = f64::from(value);
                                *partial += i64::from(value);
                            }
                        }
                    }
                });
                match spawned {
                    Ok(worker) => workers.push(worker),
                    Err(error) => {
                        spawn_error = Some(error);
                        break;
                    }
                }
            }
            // Join every thread that started before looking at the results.
            let mut panicked = workers
                .into_iter()
                .map(|worker| worker.join().is_err())
                .collect::<Vec<_>>()
                .contains(&true);
            let read = match reader.map(|reader| reader.join()) {
                None => Ok(()),
                Some(Ok(read)) => read,
                Some(Err(_)) => {
                    panicked = true;
                    Ok(())
                }
            };
            match spawn_error {
                Some(error) => Err(ForgeMatrixV4ExecutionError::ThreadSpawn(error)),
                None if panicked => Err(ForgeMatrixV4ExecutionError::ThreadPanicked),
                None => read,
            }
        })?;
        std::mem::swap(&mut current, &mut next);
        std::mem::swap(&mut weights, &mut prefetched);
    }

    let mut out = vec![0_u32; shape.cells()];
    for (index, out) in out.iter_mut().enumerate() {
        // Exact: canonical field values are stored as integral f64.
        *out = current[blocked(index / dimension, index % dimension)] as u32;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::io::{Seek, SeekFrom, Write};
    use std::path::PathBuf;

    use super::*;
    use crate::{
        BlockChallenge, SmallModelBankFixture, build_small_model_bank,
        forgematrix_v4_challenge_digest, verify_model_bank_and_retain_base_input_and_layer_roots,
    };

    const P: u32 = FORGEMATRIX_V4_FIELD_MODULUS;

    fn shape(batch: usize, dimension: usize, layers: usize) -> ForgeMatrixV4ExecutionShape {
        ForgeMatrixV4ExecutionShape {
            batch,
            dimension,
            layers,
        }
    }

    fn test_bytes(seed: &str, len: usize) -> Vec<u8> {
        let mut reader = blake3::Hasher::new_derive_key(seed).finalize_xof();
        let mut out = Vec::with_capacity(len);
        let mut buffer = [0_u8; 64];
        while out.len() < len {
            reader.fill(&mut buffer);
            out.extend(
                buffer
                    .iter()
                    .copied()
                    .filter(|byte| *byte <= MAX_MODEL_BYTE),
            );
        }
        out.truncate(len);
        out
    }

    fn test_coefficients(shape: ForgeMatrixV4ExecutionShape, challenge: [u8; 32]) -> Vec<u8> {
        let mut out = mask_coefficients(&challenge, u32::MAX, shape.batch, shape.dimension);
        for layer in 0..shape.layers as u32 {
            out.extend(mask_coefficients(
                &challenge,
                layer,
                shape.batch,
                shape.dimension,
            ));
        }
        out
    }

    /// The model held in memory. Test only.
    struct MemorySource {
        shape: ForgeMatrixV4ExecutionShape,
        base: Vec<u8>,
        layers: Vec<u8>,
    }

    impl ForgeMatrixV4LayerSource for MemorySource {
        fn shape(&self) -> ForgeMatrixV4ExecutionShape {
            self.shape
        }

        fn base_input(&self) -> &[u8] {
            &self.base
        }

        fn read_layer(
            &self,
            layer: usize,
            out: &mut [u8],
            _authenticate: bool,
        ) -> Result<(), ForgeMatrixV4ExecutionError> {
            let bytes = self.shape.layer_bytes();
            out.copy_from_slice(&self.layers[layer * bytes..(layer + 1) * bytes]);
            Ok(())
        }
    }

    /// Straightforward scalar reference: i128, no floating point, no
    /// blocking, mask evaluated bit by bit.
    fn reference_forward(
        shape: ForgeMatrixV4ExecutionShape,
        base: &[u8],
        layers: &[u8],
        coefficients: &[u8],
    ) -> Vec<u32> {
        let p = i128::from(P);
        let terms = shape.mask_coefficients();
        let row_bits = shape.row_bits();
        let mask = |set: &[u8], row: usize, column: usize| -> i128 {
            let mut value = i128::from(set[0]);
            for bit in 0..row_bits {
                if (row >> bit) & 1 == 1 {
                    value += i128::from(set[1 + bit]);
                }
            }
            for bit in 0..shape.column_bits() {
                if (column >> bit) & 1 == 1 {
                    value += i128::from(set[1 + row_bits + bit]);
                }
            }
            value
        };
        let cube = |value: i128| -> i128 { value.rem_euclid(p).pow(3).rem_euclid(p) };
        let (rows, dim) = (shape.batch, shape.dimension);
        let mut activation = (0..rows * dim)
            .map(|index| {
                cube(
                    i128::from(base[index]) - 125
                        + mask(&coefficients[..terms], index / dim, index % dim),
                )
            })
            .collect::<Vec<_>>();
        for layer in 0..shape.layers {
            let set = &coefficients[(layer + 1) * terms..(layer + 2) * terms];
            let weights = &layers[layer * dim * dim..];
            let mut next = vec![0_i128; rows * dim];
            for row in 0..rows {
                for column in 0..dim {
                    let mut sum = 0_i128;
                    for common in 0..dim {
                        sum += activation[row * dim + common]
                            * (i128::from(weights[common * dim + column]) - 125);
                    }
                    next[row * dim + column] = cube(sum + mask(set, row, column));
                }
            }
            activation = next;
        }
        activation.into_iter().map(|value| value as u32).collect()
    }

    fn check_against_reference(
        source: &MemorySource,
        coefficients: &[u8],
        thread_counts: &[usize],
        label: &str,
    ) {
        let expected = reference_forward(source.shape, &source.base, &source.layers, coefficients);
        for &threads in thread_counts {
            let reads = Mutex::new(Vec::new());
            let actual = forward(
                source.shape,
                &initial_activation(
                    source.shape,
                    &source.base,
                    &coefficients[..source.shape.mask_coefficients()],
                ),
                &coefficients[source.shape.mask_coefficients()..],
                |layer, out| {
                    reads.lock().unwrap().push(layer);
                    source.read_layer(layer, out, false)
                },
                &|| {},
                threads,
            )
            .unwrap();
            assert_eq!(actual, expected, "{label} threads {threads}");
            // Each layer is read exactly once, in order, one ahead.
            assert_eq!(
                reads.into_inner().unwrap(),
                (0..source.shape.layers).collect::<Vec<_>>(),
                "{label} reads threads {threads}"
            );
            assert_eq!(
                forgematrix_v4_execute(source.shape, source, coefficients, threads, false).unwrap(),
                expected,
                "{label} public threads {threads}"
            );
        }
    }

    #[test]
    fn forgematrix_v4_execution_matches_the_scalar_reference_at_any_thread_count() {
        // (4, 8, 3) is a single panel; the wider shapes run several panels
        // and several inner-dimension blocks per GEMM.
        for (batch, dimension, layers) in [(4, 8, 3), (1, 1, 2), (2, 512, 2), (2, 2048, 1)] {
            let shape = shape(batch, dimension, layers);
            let source = MemorySource {
                shape,
                base: test_bytes("cmfd execution test base", shape.cells()),
                layers: test_bytes(
                    "cmfd execution test weights",
                    shape.layers * shape.layer_bytes(),
                ),
            };
            check_against_reference(
                &source,
                &test_coefficients(shape, [7; 32]),
                &[1, 2, 3, 7],
                &format!("{shape:?}"),
            );
        }
    }

    #[test]
    fn forgematrix_v4_execution_matches_the_scalar_reference_on_extreme_inputs() {
        let shape = shape(4, 8, 3);
        let terms = shape.mask_coefficients();
        // Distinct powers of two make every (row, column) bit pattern give a
        // distinct mask value.
        let bit_weights = (0..terms).map(|bit| 1_u8 << (bit % 8)).collect::<Vec<_>>();
        let bytes = |name: &str, len: usize| -> Vec<u8> {
            match name {
                "zero" => vec![0; len],
                "max" => vec![MAX_MODEL_BYTE; len],
                _ => test_bytes(name, len),
            }
        };
        for base in ["zero", "max", "cmfd execution extreme base"] {
            for weights in ["zero", "max", "cmfd execution extreme weights"] {
                for coefficients in ["zero", "max", "bits", "random"] {
                    let coefficients = match coefficients {
                        "zero" => vec![0; shape.coefficient_bytes()],
                        "max" => vec![MAX_MODEL_BYTE; shape.coefficient_bytes()],
                        "bits" => bit_weights.repeat(shape.layers + 1),
                        _ => test_coefficients(shape, [0xc3; 32]),
                    };
                    let source = MemorySource {
                        shape,
                        base: bytes(base, shape.cells()),
                        layers: bytes(weights, shape.layers * shape.layer_bytes()),
                    };
                    check_against_reference(
                        &source,
                        &coefficients,
                        &[2],
                        &format!("base {base} weights {weights}"),
                    );
                }
            }
        }
    }

    #[test]
    fn forgematrix_v4_execution_layer_is_exact_at_the_largest_partial_sums() {
        // Every activation p - 1 at the full 4096 inner dimension, with every
        // model byte 250 (all terms +125) or 0 (all terms -125), gives the
        // largest raw products and the largest centered sums the kernel sees.
        let shape = shape(1, MAX_EXACT_DIMENSION, 1);
        let p = i128::from(P);
        for (byte, centered) in [(MAX_MODEL_BYTE, 125_i128), (0, -125)] {
            let weights = vec![byte; shape.layer_bytes()];
            let out = forward(
                shape,
                &vec![P - 1; shape.cells()],
                &vec![0; shape.mask_coefficients()],
                |_, out| {
                    out.copy_from_slice(&weights);
                    Ok(())
                },
                &|| {},
                3,
            )
            .unwrap();
            let sum = (4096 * (p - 1) * centered).rem_euclid(p);
            let expected = (sum.pow(3) % p) as u32;
            assert!(out.iter().all(|value| *value == expected), "byte {byte}");
        }
    }

    #[test]
    fn every_executor_thread_calls_the_source_hook_before_it_works() {
        use std::collections::HashSet;
        use std::thread::ThreadId;

        /// Records the threads that called the hook, and fails a layer read
        /// on a thread that had not.
        struct Hooked {
            inner: MemorySource,
            started: Mutex<Vec<ThreadId>>,
        }

        impl ForgeMatrixV4LayerSource for Hooked {
            fn shape(&self) -> ForgeMatrixV4ExecutionShape {
                self.inner.shape()
            }

            fn base_input(&self) -> &[u8] {
                self.inner.base_input()
            }

            fn read_layer(
                &self,
                layer: usize,
                out: &mut [u8],
                authenticate: bool,
            ) -> Result<(), ForgeMatrixV4ExecutionError> {
                let current = thread::current().id();
                if layer > 0 && !self.started.lock().unwrap().contains(&current) {
                    return Err(ForgeMatrixV4ExecutionError::ThreadCount);
                }
                self.inner.read_layer(layer, out, authenticate)
            }

            fn on_thread_start(&self) {
                self.started.lock().unwrap().push(thread::current().id());
            }
        }

        // Two panels, so up to two workers per layer, and a reader for every
        // layer after the first.
        let shape = shape(2, 512, 3);
        let plain = MemorySource {
            shape,
            base: test_bytes("cmfd execution hook base", shape.cells()),
            layers: test_bytes(
                "cmfd execution hook weights",
                shape.layers * shape.layer_bytes(),
            ),
        };
        let coefficients = test_coefficients(shape, [3; 32]);
        let expected = forgematrix_v4_execute(shape, &plain, &coefficients, 2, false).unwrap();
        let hooked = Hooked {
            inner: plain,
            started: Mutex::new(Vec::new()),
        };
        assert_eq!(
            forgematrix_v4_execute(shape, &hooked, &coefficients, 2, false).unwrap(),
            expected
        );
        let started = hooked.started.into_inner().unwrap();
        let workers = 2.min(thread::available_parallelism().map_or(1, usize::from));
        assert_eq!(started.len(), shape.layers * workers + shape.layers - 1);
        // Each call came from a thread of its own, never the caller's.
        let distinct = started.iter().collect::<HashSet<_>>();
        assert_eq!(distinct.len(), started.len());
        assert!(!distinct.contains(&thread::current().id()));
    }

    #[test]
    fn forgematrix_v4_execution_rejects_bad_shapes_and_inputs() {
        let shape = shape(2, 4, 1);
        let source = MemorySource {
            shape,
            base: vec![0; shape.cells()],
            layers: vec![0; shape.layer_bytes()],
        };
        let coefficients = vec![0; shape.coefficient_bytes()];
        assert!(forgematrix_v4_execute(shape, &source, &coefficients, 1, false).is_ok());
        assert!(matches!(
            forgematrix_v4_execute(shape, &source, &coefficients, 0, false),
            Err(ForgeMatrixV4ExecutionError::ThreadCount)
        ));
        assert!(matches!(
            forgematrix_v4_execute(shape, &source, &coefficients[1..], 1, false),
            Err(ForgeMatrixV4ExecutionError::InputLength)
        ));
        let short_base = MemorySource {
            base: vec![0; shape.cells() - 1],
            layers: source.layers.clone(),
            ..source
        };
        assert!(matches!(
            forgematrix_v4_execute(shape, &short_base, &coefficients, 1, false),
            Err(ForgeMatrixV4ExecutionError::InputLength)
        ));
        let deeper = ForgeMatrixV4ExecutionShape { layers: 2, ..shape };
        assert!(matches!(
            forgematrix_v4_execute(deeper, &source, &coefficients, 1, false),
            Err(ForgeMatrixV4ExecutionError::Shape)
        ));
        for bad in [
            ForgeMatrixV4ExecutionShape { batch: 3, ..shape },
            ForgeMatrixV4ExecutionShape {
                dimension: 2 * MAX_EXACT_DIMENSION,
                ..shape
            },
            ForgeMatrixV4ExecutionShape { layers: 0, ..shape },
        ] {
            assert!(matches!(
                bad.validate(),
                Err(ForgeMatrixV4ExecutionError::Shape)
            ));
        }
        assert!(ForgeMatrixV4ExecutionShape::PRODUCTION.validate().is_ok());
        assert_eq!(
            ForgeMatrixV4ExecutionShape::PRODUCTION.mask_coefficients(),
            FORGEMATRIX_V4_MASK_COEFFICIENTS
        );
        assert_eq!(
            ForgeMatrixV4ExecutionShape::PRODUCTION.coefficient_bytes(),
            FORGEMATRIX_V4_REPLAY_COEFFICIENT_BYTES
        );
    }

    #[test]
    fn forgematrix_v4_replay_coefficients_have_the_exact_production_layout() {
        let challenge = [7; 32];
        let coefficients = forgematrix_v4_replay_coefficients(challenge);
        assert_eq!(coefficients.len(), 7_700);
        assert_eq!(coefficients, forgematrix_v4_replay_coefficients(challenge));
        let set = |layer| mask_coefficients(&challenge, layer, 128, 4096);
        assert_eq!(&coefficients[..20], set(u32::MAX));
        assert_eq!(&coefficients[20..40], set(0));
        assert_eq!(&coefficients[7_680..], set(383));
        assert!(coefficients.iter().all(|value| *value <= MAX_MODEL_BYTE));
        #[cfg(feature = "forgematrix-v4-verifier")]
        for (slot, layer) in [(0, u32::MAX), (1, 0), (384, 383)] {
            assert_eq!(
                coefficients[slot * 20..(slot + 1) * 20],
                crate::forgematrix_v4_proof::forgematrix_v4_mask_coefficients(challenge, layer)
            );
        }
    }

    #[test]
    fn forgematrix_v4_final_activation_digest_rejects_noncanonical_fields() {
        let challenge_digest = [0x6b; 32];
        let mut values = (0..FORGEMATRIX_V4_PUBLIC_FINAL_ACTIVATION_BYTES / size_of::<u32>())
            .map(|index| ((index as u64 * 1_000_003 + 97) % MODULUS) as u32)
            .collect::<Vec<_>>();
        values[..3].copy_from_slice(&[0, 1, P - 1]);
        let mut encoded = values
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect::<Vec<_>>();
        let digest =
            forgematrix_v4_final_activation_digest_from_le_bytes(challenge_digest, &encoded)
                .unwrap();
        #[cfg(feature = "forgematrix-v4-verifier")]
        {
            use slop_algebra::AbstractField;
            let fields = values
                .iter()
                .map(|value| slop_koala_bear::KoalaBear::from_canonical_u32(*value))
                .collect::<Vec<_>>();
            assert_eq!(
                digest,
                crate::forgematrix_v4_proof::forgematrix_v4_final_activation_digest(
                    challenge_digest,
                    &fields
                )
            );
        }
        assert_ne!(
            digest,
            forgematrix_v4_final_activation_digest_from_le_bytes([0x6c; 32], &encoded).unwrap()
        );
        for index in [0, values.len() - 1] {
            let offset = index * size_of::<u32>();
            encoded[offset..offset + size_of::<u32>()].copy_from_slice(&P.to_le_bytes());
            assert!(matches!(
                forgematrix_v4_final_activation_digest_from_le_bytes(challenge_digest, &encoded),
                Err(ForgeMatrixV4ExecutionError::NonCanonicalFinalActivation)
            ));
            encoded[offset..offset + size_of::<u32>()]
                .copy_from_slice(&values[index].to_le_bytes());
        }
        assert!(matches!(
            forgematrix_v4_final_activation_digest_from_le_bytes(challenge_digest, &encoded[4..]),
            Err(ForgeMatrixV4ExecutionError::FinalActivationLength)
        ));
    }

    struct TempBank(PathBuf);

    impl Drop for TempBank {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[test]
    fn forgematrix_v4_file_layer_source_detects_a_changed_layer_only_when_authenticating() {
        let shape = shape(4, 8, 3);
        let base = test_bytes("cmfd execution file base", shape.cells());
        let layers = test_bytes(
            "cmfd execution file weights",
            shape.layers * shape.layer_bytes(),
        );
        let layer_slices = layers.chunks_exact(shape.layer_bytes()).collect::<Vec<_>>();
        let built = build_small_model_bank(SmallModelBankFixture {
            model_version: 2,
            dimension: shape.dimension as u32,
            batch: shape.batch as u32,
            base_input: &base,
            layers: &layer_slices,
            pcs_parameter_digest: [0x51; 32],
            pcs_commitment_root: [0xa7; 32],
        })
        .unwrap();
        let path = TempBank(std::env::temp_dir().join(format!(
            "cmfd-execution-file-source-{}-{:?}.bank",
            std::process::id(),
            thread::current().id()
        )));
        std::fs::write(&path.0, &built.bytes).unwrap();
        let (retained_base, roots) = verify_model_bank_and_retain_base_input_and_layer_roots(
            File::open(&path.0).unwrap(),
            &built.manifest,
        )
        .unwrap();
        let open = || {
            ForgeMatrixV4FileLayerSource::new(
                File::open(&path.0).unwrap(),
                &built.manifest,
                Arc::from(retained_base.clone()),
                Arc::from(roots.clone()),
            )
            .unwrap()
        };
        let coefficients = test_coefficients(shape, [0x2d; 32]);
        let expected = reference_forward(shape, &base, &layers, &coefficients);
        for authenticate in [false, true] {
            assert_eq!(
                forgematrix_v4_execute(shape, &open(), &coefficients, 2, authenticate).unwrap(),
                expected
            );
        }

        let first_layer = MODEL_BANK_HEADER_BYTES + shape.cells();
        for layer in 0..shape.layers {
            let offset = first_layer + layer * shape.layer_bytes() + 5;
            let flip = |file: &mut File| {
                file.seek(SeekFrom::Start(offset as u64)).unwrap();
                file.write_all(&[built.bytes[offset] ^ 1]).unwrap();
            };
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .open(&path.0)
                .unwrap();
            flip(&mut file);
            let source = open();
            assert!(matches!(
                forgematrix_v4_execute(shape, &source, &coefficients, 2, true),
                Err(ForgeMatrixV4ExecutionError::LayerAuthentication { layer: failed }) if failed == layer
            ));
            assert_ne!(
                forgematrix_v4_execute(shape, &source, &coefficients, 2, false).unwrap(),
                expected
            );
            file.seek(SeekFrom::Start(offset as u64)).unwrap();
            file.write_all(&[built.bytes[offset]]).unwrap();
        }
        assert_eq!(
            forgematrix_v4_execute(shape, &open(), &coefficients, 2, true).unwrap(),
            expected
        );

        let truncated = built.bytes.len() as u64 - 1;
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path.0)
            .unwrap()
            .set_len(truncated)
            .unwrap();
        assert!(matches!(
            ForgeMatrixV4FileLayerSource::new(
                File::open(&path.0).unwrap(),
                &built.manifest,
                Arc::from(retained_base.clone()),
                Arc::from(roots.clone()),
            ),
            Err(ForgeMatrixV4ExecutionError::BankLength { actual, .. }) if actual == truncated
        ));
    }

    #[test]
    fn forgematrix_v4_resident_layer_source_checks_every_layer_once_when_it_loads() {
        let shape = shape(4, 8, 3);
        let base = test_bytes("cmfd execution resident base", shape.cells());
        let layers = test_bytes(
            "cmfd execution resident weights",
            shape.layers * shape.layer_bytes(),
        );
        let layer_slices = layers.chunks_exact(shape.layer_bytes()).collect::<Vec<_>>();
        let built = build_small_model_bank(SmallModelBankFixture {
            model_version: 2,
            dimension: shape.dimension as u32,
            batch: shape.batch as u32,
            base_input: &base,
            layers: &layer_slices,
            pcs_parameter_digest: [0x51; 32],
            pcs_commitment_root: [0xa7; 32],
        })
        .unwrap();
        let path = TempBank(std::env::temp_dir().join(format!(
            "cmfd-execution-resident-source-{}-{:?}.bank",
            std::process::id(),
            thread::current().id()
        )));
        std::fs::write(&path.0, &built.bytes).unwrap();
        let (retained_base, roots) = verify_model_bank_and_retain_base_input_and_layer_roots(
            File::open(&path.0).unwrap(),
            &built.manifest,
        )
        .unwrap();
        let load = || {
            ForgeMatrixV4ResidentLayerSource::load(
                File::open(&path.0).unwrap(),
                &built.manifest,
                Arc::from(retained_base.clone()),
                Arc::from(roots.clone()),
            )
        };
        let coefficients = test_coefficients(shape, [0x3e; 32]);
        let expected = reference_forward(shape, &base, &layers, &coefficients);
        let resident = load().unwrap();
        for threads in [1, 3] {
            for authenticate in [false, true] {
                assert_eq!(
                    forgematrix_v4_execute(shape, &resident, &coefficients, threads, authenticate)
                        .unwrap(),
                    expected
                );
            }
        }

        // A change to the file after the load does not reach the held layers.
        let first_layer = MODEL_BANK_HEADER_BYTES + shape.cells();
        let flip = |offset: usize, value: u8| {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .open(&path.0)
                .unwrap();
            file.seek(SeekFrom::Start(offset as u64)).unwrap();
            file.write_all(&[value]).unwrap();
        };
        let offset = first_layer + 7;
        flip(offset, built.bytes[offset] ^ 1);
        assert_eq!(
            forgematrix_v4_execute(shape, &resident, &coefficients, 2, false).unwrap(),
            expected
        );
        flip(offset, built.bytes[offset]);

        // A layer that no longer matches its root is refused at load time.
        for layer in 0..shape.layers {
            let offset = first_layer + layer * shape.layer_bytes() + 5;
            flip(offset, built.bytes[offset] ^ 1);
            assert!(matches!(
                load(),
                Err(ForgeMatrixV4ExecutionError::LayerAuthentication { layer: failed }) if failed == layer
            ));
            flip(offset, built.bytes[offset]);
        }
        assert_eq!(
            forgematrix_v4_execute(shape, &load().unwrap(), &coefficients, 2, true).unwrap(),
            expected
        );

        let truncated = built.bytes.len() as u64 - 1;
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path.0)
            .unwrap()
            .set_len(truncated)
            .unwrap();
        assert!(matches!(
            load(),
            Err(ForgeMatrixV4ExecutionError::BankLength { actual, .. }) if actual == truncated
        ));
    }

    struct Vector {
        height: u64,
        block: BlockChallenge,
        nonce: u64,
        challenge_digest: [u8; 32],
        final_activation_digest: [u8; 32],
        work_digest: [u8; 32],
    }

    fn hex32(value: &serde_json::Value) -> [u8; 32] {
        hex::decode(value.as_str().expect("hex field"))
            .expect("valid hex")
            .try_into()
            .expect("32 bytes")
    }

    fn vector(value: &serde_json::Value) -> Vector {
        Vector {
            height: value["height"].as_u64().unwrap(),
            block: BlockChallenge {
                network_id: hex32(&value["network_id"]),
                previous_block: hex32(&value["previous_block"]),
                transaction_root: hex32(&value["transaction_root"]),
                height: value["height"].as_u64().unwrap(),
                timestamp: value["timestamp"].as_u64().unwrap(),
                target: hex32(&value["target"]),
            },
            nonce: value["nonce"].as_str().unwrap().parse().unwrap(),
            challenge_digest: hex32(&value["challenge_digest"]),
            final_activation_digest: hex32(&value["final_activation_digest"]),
            work_digest: hex32(&value["work_digest"]),
        }
    }

    /// The committed published vectors, then the synthetic changes of
    /// published blocks with their independently computed results.
    fn vectors() -> (Vec<Vector>, Vec<Vector>) {
        let document: serde_json::Value = serde_json::from_str(include_str!(
            "../data/forgematrix_v4_execution_vectors_v1.json"
        ))
        .unwrap();
        assert_eq!(
            document["schema"],
            "CommonFoundry/ForgeMatrix/V4/ExecutionVectors/v1"
        );
        assert_eq!(
            hex32(&document["model_manifest_digest"]),
            PRODUCTION_V4_MODEL_MANIFEST_DIGEST
        );
        let published = document["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .map(vector)
            .collect::<Vec<_>>();
        let changed = document["changed_vectors"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| {
                let base = published
                    .iter()
                    .find(|vector| vector.height == value["height"].as_u64().unwrap())
                    .expect("changed vector names a published height");
                let (block, nonce) = match value["change"].as_str().unwrap() {
                    "nonce+1" => (base.block, base.nonce + 1),
                    "timestamp+1" => (
                        BlockChallenge {
                            timestamp: base.block.timestamp + 1,
                            ..base.block
                        },
                        base.nonce,
                    ),
                    other => panic!("unknown change {other}"),
                };
                Vector {
                    height: base.height,
                    block,
                    nonce,
                    challenge_digest: hex32(&value["challenge_digest"]),
                    final_activation_digest: hex32(&value["final_activation_digest"]),
                    work_digest: hex32(&value["work_digest"]),
                }
            })
            .collect();
        (published, changed)
    }

    #[test]
    fn forgematrix_v4_execution_vectors_bind_header_nonce_and_work() {
        let (published, changed) = vectors();
        assert_eq!(published.len(), 6);
        assert_eq!(changed.len(), 2);
        for vector in published.iter().chain(&changed) {
            let challenge = forgematrix_v4_challenge_digest(
                &vector.block,
                vector.nonce,
                PRODUCTION_V4_MODEL_MANIFEST_DIGEST,
            );
            assert_eq!(
                challenge, vector.challenge_digest,
                "height {}",
                vector.height
            );
            assert_eq!(
                forgematrix_v4_work_digest(
                    PRODUCTION_V4_MODEL_MANIFEST_DIGEST,
                    challenge,
                    vector.final_activation_digest
                ),
                vector.work_digest,
                "height {}",
                vector.height
            );
        }
        for vector in &published {
            assert!(vector.work_digest <= vector.block.target);
        }
        for vector in &changed {
            let original = published
                .iter()
                .find(|published| published.height == vector.height)
                .unwrap();
            assert_ne!(vector.work_digest, original.work_digest);
            assert_ne!(
                vector.final_activation_digest,
                original.final_activation_digest
            );
            assert!(vector.work_digest > vector.block.target);
        }
    }

    /// Re-executes real blocks on the production model bank, reading layers
    /// from the bank file with authentication. It needs the bank (about
    /// 6.4 GB on disk) and an optimized build; run it alone:
    ///
    /// ```text
    /// CMFD_HW_MODEL_BANK=/path/MODEL-V2.bank \
    /// CMFD_HW_FIXED_RECORD=/path/FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json \
    /// CMFD_WORK_THREADS=6 \
    /// cargo test --release -p cmfd-consensus --lib \
    ///     --features forgematrix-v4-executor,forgematrix-v4-verifier \
    ///     forgematrix_v4_execution_reproduces_known_answers -- --ignored --test-threads=1 --nocapture
    /// ```
    ///
    /// It runs the newest published vector and the two changed vectors;
    /// `CMFD_WORK_VECTORS=all` also runs every other published vector.
    #[cfg(feature = "forgematrix-v4-verifier")]
    #[test]
    #[ignore = "needs the production model bank; see the doc comment"]
    fn forgematrix_v4_execution_reproduces_known_answers_with_the_model_bank() {
        let bank_path = std::env::var_os("CMFD_HW_MODEL_BANK").expect("CMFD_HW_MODEL_BANK");
        let record_path = std::env::var_os("CMFD_HW_FIXED_RECORD").expect("CMFD_HW_FIXED_RECORD");
        let threads = std::env::var("CMFD_WORK_THREADS")
            .map(|value| value.parse().expect("CMFD_WORK_THREADS is a number"))
            .unwrap_or(6);
        let record: crate::ForgeMatrixV4FixedArtifactRecordV1 =
            serde_json::from_slice(&std::fs::read(record_path).unwrap()).unwrap();
        let (published, changed) = vectors();
        let newest = published.iter().max_by_key(|vector| vector.height).unwrap();

        let started = std::time::Instant::now();
        let (_, identity) = crate::ConsensusPowVerifier::v4_candidate_for_network_with_layer_roots(
            newest.block.network_id,
            record,
            std::io::BufReader::with_capacity(1024 * 1024, File::open(&bank_path).unwrap()),
        )
        .unwrap();
        eprintln!(
            "bank authenticated in {:.1}s",
            started.elapsed().as_secs_f64()
        );
        let source = ForgeMatrixV4FileLayerSource::new(
            File::open(&bank_path).unwrap(),
            &identity.manifest,
            identity.base_input,
            identity.layer_roots,
        )
        .unwrap();

        let all = std::env::var("CMFD_WORK_VECTORS").is_ok_and(|value| value == "all");
        let mut run = vec![newest];
        run.extend(&changed);
        if all {
            run.extend(
                published
                    .iter()
                    .filter(|vector| vector.height != newest.height),
            );
        }
        for vector in run {
            let started = std::time::Instant::now();
            let execution =
                forgematrix_v4_execute_challenge(vector.challenge_digest, &source, threads, true)
                    .unwrap();
            eprintln!(
                "height {} nonce {}: {:.2}s on {threads} threads",
                vector.height,
                vector.nonce,
                started.elapsed().as_secs_f64()
            );
            assert_eq!(
                execution,
                ForgeMatrixV4Execution {
                    challenge_digest: vector.challenge_digest,
                    final_activation_digest: vector.final_activation_digest,
                    work_digest: vector.work_digest,
                },
                "height {} nonce {}",
                vector.height,
                vector.nonce
            );
        }
    }
}
