//! Private pool-to-prover transport for the CPU replay witness on Windows.
use std::{
    io,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr, slice,
};
use windows_sys::Win32::{
    Foundation::{ERROR_ALREADY_EXISTS, GetLastError, INVALID_HANDLE_VALUE},
    System::Memory::{
        CreateFileMappingW, FILE_MAP_READ, FILE_MAP_WRITE, MEMORY_MAPPED_VIEW_ADDRESS,
        MapViewOfFile, OpenFileMappingW, PAGE_READWRITE, UnmapViewOfFile,
    },
};

pub const COLUMN_WORDS: usize = 384 * 128 * 4096;
const BYTES: usize = COLUMN_WORDS * 2 * size_of::<u32>();
const PREFIX: &str = "Local\\CommonFoundry.CpuTrace.";

fn wide(name: &str) -> io::Result<Vec<u16>> {
    if !name
        .strip_prefix(PREFIX)
        .is_some_and(|id| id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid CPU trace section name",
        ));
    }
    Ok(name.encode_utf16().chain(Some(0)).collect())
}

struct View {
    address: MEMORY_MAPPED_VIEW_ADDRESS,
    _handle: OwnedHandle,
}
impl View {
    fn map(handle: OwnedHandle, access: u32) -> io::Result<Self> {
        let address = unsafe { MapViewOfFile(handle.as_raw_handle(), access, 0, 0, BYTES) };
        if address.Value.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            address,
            _handle: handle,
        })
    }
}
impl Drop for View {
    fn drop(&mut self) {
        unsafe {
            UnmapViewOfFile(self.address);
        }
    }
}

pub struct Writer {
    name: String,
    view: View,
}
// SAFETY: moving a section view between threads does not change its address.
// Writable access requires exclusive ownership and completion of any reader.
unsafe impl Send for Writer {}
impl std::fmt::Debug for Writer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CpuTraceWriter")
    }
}
impl Writer {
    pub fn create(id: [u8; 16]) -> io::Result<Self> {
        let name = format!("{PREFIX}{}", hex::encode(id));
        let wide = wide(&name)?;
        let raw = unsafe {
            CreateFileMappingW(
                INVALID_HANDLE_VALUE,
                ptr::null(),
                PAGE_READWRITE,
                0,
                BYTES as u32,
                wide.as_ptr(),
            )
        };
        if raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        let existed = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
        let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
        if existed {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "CPU trace section already exists",
            ));
        }
        Ok(Self {
            name,
            view: View::map(handle, FILE_MAP_WRITE)?,
        })
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    /// # Safety
    /// The pool must hold the exclusive slot until the reader completes or exits.
    pub unsafe fn columns_mut(&mut self) -> (&mut [u32], &mut [u32]) {
        unsafe {
            slice::from_raw_parts_mut(self.view.address.Value.cast::<u32>(), COLUMN_WORDS * 2)
        }
        .split_at_mut(COLUMN_WORDS)
    }
}
pub struct Reader(View);
impl Reader {
    pub fn open(name: &str) -> io::Result<Self> {
        let wide = wide(name)?;
        let raw = unsafe { OpenFileMappingW(FILE_MAP_READ, 0, wide.as_ptr()) };
        if raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(View::map(
            unsafe { OwnedHandle::from_raw_handle(raw) },
            FILE_MAP_READ,
        )?))
    }
    /// # Safety
    /// The owning pool must keep the selected slot immutable for this request.
    pub unsafe fn columns(&self) -> (&[u32], &[u32]) {
        unsafe { slice::from_raw_parts(self.0.address.Value.cast::<u32>(), COLUMN_WORDS * 2) }
            .split_at(COLUMN_WORDS)
    }
}
