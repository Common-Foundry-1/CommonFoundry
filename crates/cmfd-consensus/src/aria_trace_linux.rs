//! Linux pool-to-worker witness transport. Only the writable mapping exists in the
//! pool. The matched worker inherits read-only descriptors for two sealed memfds.
use std::{
    ffi::CString,
    fs::File,
    io,
    os::fd::{AsRawFd, FromRawFd, RawFd},
    os::unix::process::CommandExt,
    process::Command,
    ptr::NonNull,
    slice,
};

const WORDS: usize = 384 * 128 * 4096;
const BYTES: usize = 2 * WORDS * size_of::<u32>();
const SEALS: i32 =
    libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_FUTURE_WRITE;

struct View(NonNull<u32>);
impl View {
    fn map(file: &File, access: i32) -> io::Result<Self> {
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                BYTES,
                access,
                libc::MAP_SHARED,
                file.as_raw_fd(),
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(
            NonNull::new(ptr.cast()).expect("nonzero mmap address"),
        ))
    }
}
impl Drop for View {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.0.as_ptr().cast(), BYTES);
        }
    }
}

fn descriptor(name: &str) -> io::Result<RawFd> {
    name.parse::<RawFd>()
        .ok()
        .filter(|&fd| fd >= 3)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid CPU trace descriptor"))
}

fn valid_reader(fd: RawFd) -> io::Result<File> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    let seals = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
    if flags < 0 || seals < 0 {
        return Err(io::Error::last_os_error());
    }
    if flags & libc::O_ACCMODE != libc::O_RDONLY || seals & SEALS != SEALS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected a read-only sealed replay section",
        ));
    }
    let file = File::open(format!("/proc/self/fd/{fd}"))?;
    if file.metadata()?.len() != BYTES as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected CPU trace length",
        ));
    }
    Ok(file)
}

/// The pool retains the descriptors across worker startup and restart. Clear
/// CLOEXEC in this particular child after fork, leaving the parent and every
/// unrelated child untouched. fcntl is async-signal-safe.
pub fn inherit_readers(command: &mut Command, names: &str) -> io::Result<()> {
    let (first, second) = names
        .split_once(',')
        .ok_or_else(|| io::Error::other("expected two CPU trace descriptors"))?;
    let fds = [descriptor(first)?, descriptor(second)?];
    if fds[0] == fds[1] {
        return Err(io::Error::other("duplicate CPU trace descriptor"));
    }
    for fd in fds {
        valid_reader(fd)?;
    }
    unsafe {
        command.pre_exec(move || {
            for fd in fds {
                if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    Ok(())
}

pub struct Writer {
    view: View,
    _reader: File,
    name: String,
}
// SAFETY: exclusive leases transfer ownership across threads. A published slot
// stays immutable until the worker acknowledges the request or is reaped.
unsafe impl Send for Writer {}
impl std::fmt::Debug for Writer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CpuTraceWriter")
    }
}
impl Writer {
    pub fn create(id: [u8; 16]) -> io::Result<Self> {
        let label = CString::new(format!("cmfd-cpu-trace-{}", hex::encode(id))).unwrap();
        let fd = unsafe {
            libc::memfd_create(label.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING)
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        file.set_len(BYTES as u64)?;
        let view = View::map(&file, libc::PROT_READ | libc::PROT_WRITE)?;
        if unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, SEALS) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let reader = File::open(format!("/proc/self/fd/{fd}"))?;
        let name = reader.as_raw_fd().to_string();
        Ok(Self {
            view,
            _reader: reader,
            name,
        })
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    /// # Safety
    /// The caller must retain the exclusive slot until the proof worker finishes.
    pub unsafe fn columns_mut(&mut self) -> (&mut [u32], &mut [u32]) {
        unsafe { slice::from_raw_parts_mut(self.view.0.as_ptr(), 2 * WORDS) }.split_at_mut(WORDS)
    }
}

pub struct Reader(View);
impl Reader {
    pub fn open(name: &str) -> io::Result<Self> {
        let fd = descriptor(name)?;
        let file = valid_reader(fd)?;
        // The exec launcher has handed the descriptor to its final worker.
        // Any children of the worker should no longer inherit it.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(View::map(&file, libc::PROT_READ)?))
    }
    /// # Safety
    /// The producing pool must hold the selected trace immutable for this request.
    pub unsafe fn columns(&self) -> (&[u32], &[u32]) {
        unsafe { slice::from_raw_parts(self.0.0.as_ptr(), 2 * WORDS) }.split_at(WORDS)
    }
}
