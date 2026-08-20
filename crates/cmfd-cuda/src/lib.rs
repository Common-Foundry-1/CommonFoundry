use std::env;
use std::ffi::{CStr, c_char, c_void};
use std::path::{Path, PathBuf};
use std::ptr::NonNull;
use std::sync::Arc;

use cmfd_consensus::{ForgeMatrixV2AcceleratorBatch, ForgeMatrixV2AcceleratorModel};
use libloading::Library;

const CUDA_API_VERSION: u32 = 1;
const ERROR_BUFFER_BYTES: usize = 512;

type ApiVersionFn = unsafe extern "C" fn() -> u32;
type DeviceCountFn = unsafe extern "C" fn(*mut i32, *mut c_char, usize) -> i32;
type DeviceInfoFn = unsafe extern "C" fn(i32, *mut RawDeviceInfo, *mut c_char, usize) -> i32;
type CreateFn = unsafe extern "C" fn(
    i32,
    u32,
    u32,
    u32,
    u32,
    *const u8,
    usize,
    *const u8,
    usize,
    *mut *mut c_void,
    *mut c_char,
    usize,
) -> i32;
type EvaluateFn = unsafe extern "C" fn(
    *mut c_void,
    *const u8,
    usize,
    u32,
    *mut u8,
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
            device_index: 0,
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
    evaluate: EvaluateFn,
    destroy: DestroyFn,
    _library: Library,
}

impl CudaApi {
    fn load(path: &Path) -> Result<Self, String> {
        // SAFETY: symbols are copied while `library` is alive and the library
        // is retained in the returned API for at least as long as every pointer.
        unsafe {
            let library = Library::new(path)
                .map_err(|error| format!("could not load {}: {error}", path.display()))?;
            let api_version: ApiVersionFn = load_symbol(&library, b"cmfd_cuda_api_version\0")?;
            let api = Self {
                device_count: load_symbol(&library, b"cmfd_cuda_device_count\0")?,
                device_info: load_symbol(&library, b"cmfd_cuda_device_info\0")?,
                create: load_symbol(&library, b"cmfd_cuda_create\0")?,
                evaluate: load_symbol(&library, b"cmfd_cuda_evaluate\0")?,
                destroy: load_symbol(&library, b"cmfd_cuda_destroy\0")?,
                _library: library,
            };
            let version = api_version();
            if version != CUDA_API_VERSION {
                return Err(format!(
                    "CUDA backend API version {version} does not match miner API {CUDA_API_VERSION}"
                ));
            }
            Ok(api)
        }
    }
}

unsafe fn load_symbol<T: Copy>(library: &Library, symbol: &[u8]) -> Result<T, String> {
    // SAFETY: the caller supplies the exact C ABI type for a versioned backend
    // symbol and retains the library for the lifetime of the copied pointer.
    unsafe {
        library
            .get::<T>(symbol)
            .map(|loaded| *loaded)
            .map_err(|error| {
                format!(
                    "CUDA backend is missing {}: {error}",
                    String::from_utf8_lossy(&symbol[..symbol.len().saturating_sub(1)])
                )
            })
    }
}

/// Which vendor runtime a loaded backend library drives. Both expose the same
/// versioned C ABI; only device naming and the support floor differ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuBackend {
    Cuda,
    OpenCl,
}

impl GpuBackend {
    pub fn name(self) -> &'static str {
        match self {
            Self::Cuda => "CUDA",
            Self::OpenCl => "OpenCL",
        }
    }

    fn library_stem(self) -> &'static str {
        match self {
            Self::Cuda => "cmfd-forgematrix-v2-miner",
            Self::OpenCl => "cmfd-forgematrix-v2-opencl",
        }
    }

    fn library_environment(self) -> &'static str {
        match self {
            Self::Cuda => "CMFD_CUDA_MINER_LIBRARY",
            Self::OpenCl => "CMFD_OPENCL_MINER_LIBRARY",
        }
    }

    /// The oldest capability pair the backend accepts: CUDA compute capability
    /// 7.0 for the INT8 dot-product path, OpenCL 1.2 for the portable kernel.
    fn minimum_version(self) -> (u32, u32) {
        match self {
            Self::Cuda => (7, 0),
            Self::OpenCl => (1, 2),
        }
    }

    fn from_library_path(path: &Path) -> Self {
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        if name.contains("opencl") {
            Self::OpenCl
        } else {
            Self::Cuda
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CudaDevice {
    pub backend: GpuBackend,
    pub index: i32,
    pub name: String,
    pub compute_major: u32,
    pub compute_minor: u32,
    pub total_memory_bytes: u64,
}

impl CudaDevice {
    pub fn label(&self) -> String {
        format!(
            "{} ({} {}.{})",
            self.name,
            self.backend.name(),
            self.compute_major,
            self.compute_minor
        )
    }

    pub fn is_supported(&self) -> bool {
        (self.compute_major, self.compute_minor) >= self.backend.minimum_version()
    }

    /// Human-readable reason a device is rejected, used by device listings.
    pub fn requirement(&self) -> String {
        let (major, minor) = self.backend.minimum_version();
        match self.backend {
            GpuBackend::Cuda => {
                format!("requires CUDA compute capability {major}.{minor}+")
            }
            GpuBackend::OpenCl => format!("requires OpenCL {major}.{minor}+"),
        }
    }
}

#[derive(Clone)]
pub struct CudaLibrary {
    api: Arc<CudaApi>,
    path: PathBuf,
    backend: GpuBackend,
}

impl CudaLibrary {
    /// Loads a GPU backend. `CMFD_GPU_BACKEND` may pin `cuda` or `opencl`;
    /// otherwise CUDA is preferred and the OpenCL library, which covers Intel
    /// Arc, is used when no CUDA library is present. Absence of every default
    /// candidate returns `Ok(None)`.
    pub fn load(explicit: Option<&Path>) -> Result<Option<Self>, String> {
        for backend in requested_backends()? {
            if let Some(library) = Self::load_backend(backend, explicit)? {
                return Ok(Some(library));
            }
        }
        Ok(None)
    }

    /// Loads one named backend, ignoring the `CMFD_GPU_BACKEND` preference.
    pub fn load_backend(
        backend: GpuBackend,
        explicit: Option<&Path>,
    ) -> Result<Option<Self>, String> {
        let environment = env::var_os(backend.library_environment()).map(PathBuf::from);
        let requested = explicit.map(Path::to_path_buf).or(environment);
        let backend = requested
            .as_deref()
            .map(GpuBackend::from_library_path)
            .unwrap_or(backend);
        let candidates = library_candidates(backend, requested.as_deref());
        let path = candidates.iter().find(|candidate| candidate.is_file());
        let Some(path) = path else {
            if let Some(path) = requested {
                return Err(format!(
                    "{} miner library does not name a file: {}",
                    backend.name(),
                    path.display()
                ));
            }
            return Ok(None);
        };
        Ok(Some(Self {
            api: Arc::new(CudaApi::load(path)?),
            path: path.clone(),
            backend,
        }))
    }

    pub fn backend(&self) -> GpuBackend {
        self.backend
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn devices(&self) -> Result<Vec<CudaDevice>, String> {
        let count = device_count(&self.api)?;
        (0..count)
            .map(|device_index| read_device(&self.api, self.backend, device_index))
            .collect()
    }

    pub fn create(
        &self,
        model: &ForgeMatrixV2AcceleratorModel,
        device_index: i32,
    ) -> Result<CudaMiner, String> {
        let device = read_device(&self.api, self.backend, device_index)?;
        if !device.is_supported() {
            let (major, minor) = self.backend.minimum_version();
            return Err(format!(
                "{} reports {} {}.{}, but ForgeMatrix requires {major}.{minor} or newer",
                device.name,
                self.backend.name(),
                device.compute_major,
                device.compute_minor
            ));
        }
        let mut context = std::ptr::null_mut();
        let mut error = [0 as c_char; ERROR_BUFFER_BYTES];
        // SAFETY: all buffers remain valid for the duration of the call and
        // lengths exactly describe their allocations. The returned context is
        // owned by the miner and destroyed before unloading the library.
        let result = unsafe {
            (self.api.create)(
                device_index,
                model.rows(),
                model.width(),
                model.layers(),
                model.coefficient_count(),
                model.base_input().as_ptr(),
                model.base_input().len(),
                model.weights().as_ptr(),
                model.weights().len(),
                &mut context,
                error.as_mut_ptr(),
                error.len(),
            )
        };
        check_result(result, &error)?;
        let context = NonNull::new(context)
            .ok_or_else(|| "CUDA backend returned a null context".to_owned())?;
        Ok(CudaMiner {
            context,
            api: Arc::clone(&self.api),
            device,
        })
    }
}

pub struct CudaMiner {
    context: NonNull<c_void>,
    api: Arc<CudaApi>,
    device: CudaDevice,
}

impl CudaMiner {
    /// Compatibility helper used by the desktop wallet. It selects the device
    /// from `CMFD_CUDA_DEVICE`, defaulting to device zero.
    pub fn load(model: &ForgeMatrixV2AcceleratorModel) -> Result<Option<Self>, String> {
        let Some(library) = CudaLibrary::load(None)? else {
            return Ok(None);
        };
        let device_index = selected_device()?;
        Ok(Some(library.create(model, device_index)?))
    }

    pub fn device(&self) -> &CudaDevice {
        &self.device
    }

    pub fn evaluate(&mut self, batch: &ForgeMatrixV2AcceleratorBatch) -> Result<Vec<u8>, String> {
        let output_len = (batch.count() as usize)
            .checked_mul(batch.activation_len())
            .ok_or_else(|| "CUDA output length overflow".to_owned())?;
        let mut outputs = vec![0_u8; output_len];
        let mut error = [0 as c_char; ERROR_BUFFER_BYTES];
        // SAFETY: the context belongs to this backend; input and output buffers
        // remain live and are sized from the private authoritative batch.
        let result = unsafe {
            (self.api.evaluate)(
                self.context.as_ptr(),
                batch.coefficients().as_ptr(),
                batch.coefficients().len(),
                batch.count(),
                outputs.as_mut_ptr(),
                outputs.len(),
                error.as_mut_ptr(),
                error.len(),
            )
        };
        check_result(result, &error)?;
        Ok(outputs)
    }
}

impl Drop for CudaMiner {
    fn drop(&mut self) {
        // SAFETY: this is the unique context returned by `create`; destroy is
        // called exactly once while the backing library remains loaded.
        unsafe { (self.api.destroy)(self.context.as_ptr()) };
    }
}

fn device_count(api: &CudaApi) -> Result<i32, String> {
    let mut count = 0_i32;
    let mut error = [0 as c_char; ERROR_BUFFER_BYTES];
    // SAFETY: pointers reference writable fixed-size values for the call.
    let result = unsafe { (api.device_count)(&mut count, error.as_mut_ptr(), error.len()) };
    check_result(result, &error)?;
    Ok(count)
}

fn read_device(
    api: &CudaApi,
    backend: GpuBackend,
    device_index: i32,
) -> Result<CudaDevice, String> {
    let count = device_count(api)?;
    if device_index < 0 || device_index >= count {
        return Err(format!(
            "CUDA device index {device_index} is outside the available range 0..{count}"
        ));
    }

    let mut raw = RawDeviceInfo::default();
    let mut error = [0 as c_char; ERROR_BUFFER_BYTES];
    // SAFETY: `raw` and the error buffer are valid writable C layouts.
    let result =
        unsafe { (api.device_info)(device_index, &mut raw, error.as_mut_ptr(), error.len()) };
    check_result(result, &error)?;
    if raw.api_version != CUDA_API_VERSION {
        return Err(format!(
            "{} device response has the wrong API version",
            backend.name()
        ));
    }
    // SAFETY: the backend promises a zero-filled, nul-terminated name buffer.
    let name = unsafe { CStr::from_ptr(raw.name.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    Ok(CudaDevice {
        backend,
        index: raw.device_index,
        name,
        compute_major: raw.compute_major,
        compute_minor: raw.compute_minor,
        total_memory_bytes: raw.total_memory_bytes,
    })
}

fn selected_device() -> Result<i32, String> {
    match env::var("CMFD_CUDA_DEVICE") {
        Ok(value) => value
            .parse::<i32>()
            .map_err(|_| "CMFD_CUDA_DEVICE must be a nonnegative decimal device index".to_owned()),
        Err(env::VarError::NotPresent) => Ok(0),
        Err(env::VarError::NotUnicode(_)) => {
            Err("CMFD_CUDA_DEVICE is not valid Unicode".to_owned())
        }
    }
}

/// Backends to try, in order. `CMFD_GPU_BACKEND` pins one of them.
fn requested_backends() -> Result<Vec<GpuBackend>, String> {
    match env::var("CMFD_GPU_BACKEND") {
        Ok(value) => match value.trim().to_ascii_lowercase().as_str() {
            "cuda" | "nvidia" => Ok(vec![GpuBackend::Cuda]),
            "opencl" | "intel" | "arc" => Ok(vec![GpuBackend::OpenCl]),
            "auto" | "" => Ok(vec![GpuBackend::Cuda, GpuBackend::OpenCl]),
            _ => Err("CMFD_GPU_BACKEND must be cuda, opencl, or auto".to_owned()),
        },
        Err(env::VarError::NotPresent) => Ok(vec![GpuBackend::Cuda, GpuBackend::OpenCl]),
        Err(env::VarError::NotUnicode(_)) => {
            Err("CMFD_GPU_BACKEND is not valid Unicode".to_owned())
        }
    }
}

fn library_candidates(backend: GpuBackend, explicit: Option<&Path>) -> Vec<PathBuf> {
    if let Some(explicit) = explicit {
        return vec![explicit.to_path_buf()];
    }

    let name = if cfg!(target_os = "windows") {
        format!("{}.dll", backend.library_stem())
    } else {
        format!("{}.so", backend.library_stem())
    };
    let name = name.as_str();
    let mut paths = Vec::new();
    if let Ok(executable) = env::current_exe()
        && let Some(parent) = executable.parent()
    {
        paths.push(parent.join(name));
    }
    if cfg!(debug_assertions) {
        paths.push(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/gpu-miner-build")
                .join(name),
        );
    }
    paths
}

fn check_result(result: i32, error: &[c_char]) -> Result<(), String> {
    if result == 0 {
        return Ok(());
    }
    // SAFETY: every backend call zero-initializes this fixed buffer and writes
    // at most its declared capacity, always retaining a trailing nul byte.
    let message = unsafe { CStr::from_ptr(error.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    Err(if message.is_empty() {
        format!("CUDA backend failed with code {result}")
    } else {
        message
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_library_path_is_the_only_candidate() {
        let path = Path::new("custom-cuda-backend.dll");
        assert_eq!(library_candidates(GpuBackend::Cuda, Some(path)), vec![path]);
    }

    #[test]
    fn default_candidates_are_named_per_backend() {
        let named = |backend| {
            library_candidates(backend, None)
                .iter()
                .all(|path: &PathBuf| {
                    path.file_name()
                        .unwrap()
                        .to_string_lossy()
                        .starts_with(GpuBackend::library_stem(backend))
                })
        };
        assert!(named(GpuBackend::Cuda));
        assert!(named(GpuBackend::OpenCl));
    }

    #[test]
    fn backend_is_inferred_from_an_explicit_library_name() {
        assert_eq!(
            GpuBackend::from_library_path(Path::new("cmfd-forgematrix-v2-opencl.dll")),
            GpuBackend::OpenCl
        );
        assert_eq!(
            GpuBackend::from_library_path(Path::new("cmfd-forgematrix-v2-miner.dll")),
            GpuBackend::Cuda
        );
    }

    #[test]
    fn opencl_devices_are_supported_from_version_one_point_two() {
        let device = CudaDevice {
            backend: GpuBackend::OpenCl,
            index: 0,
            name: "Intel(R) Arc(TM) A770 Graphics".to_owned(),
            compute_major: 3,
            compute_minor: 0,
            total_memory_bytes: 1,
        };
        assert_eq!(
            device.label(),
            "Intel(R) Arc(TM) A770 Graphics (OpenCL 3.0)"
        );
        assert!(device.is_supported());
        assert_eq!(device.requirement(), "requires OpenCL 1.2+");

        let legacy = CudaDevice {
            compute_major: 1,
            compute_minor: 1,
            ..device
        };
        assert!(!legacy.is_supported());
    }

    #[test]
    fn device_label_and_support_cover_volta_through_blackwell() {
        let mut device = CudaDevice {
            backend: GpuBackend::Cuda,
            index: 0,
            name: "NVIDIA Tesla V100".to_owned(),
            compute_major: 7,
            compute_minor: 0,
            total_memory_bytes: 1,
        };
        assert_eq!(device.label(), "NVIDIA Tesla V100 (CUDA 7.0)");
        assert!(device.is_supported());

        device.compute_major = 6;
        device.compute_minor = 1;
        assert!(!device.is_supported());

        device.compute_major = 12;
        device.compute_minor = 0;
        assert!(device.is_supported());
    }
}
