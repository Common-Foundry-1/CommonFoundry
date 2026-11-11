//! The direct pool CLI enforces the same RAM-directory contract as launch.py.
use std::path::{Path, PathBuf};

pub fn validate(path: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    #[cfg(target_os = "linux")]
    {
        use std::ffi::CString;
        use std::mem::MaybeUninit;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::MetadataExt;

        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err("RAM witnesses require an existing Linux tmpfs mount".into());
        }
        let path = path.canonicalize()?;
        let metadata = path.metadata()?;
        // SAFETY: geteuid has no pointer arguments or mutable process state.
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
            return Err("RAM witness mount must be owned by this user with mode 0700".into());
        }
        let parent = path
            .parent()
            .ok_or("RAM witness directory needs a parent")?;
        if parent.metadata()?.dev() == metadata.dev() {
            return Err("RAM witness directory must be a dedicated bounded tmpfs mount".into());
        }
        let native = CString::new(path.as_os_str().as_bytes())?;
        let mut filesystem = MaybeUninit::<libc::statfs>::uninit();
        let mut capacity = MaybeUninit::<libc::statvfs>::uninit();
        // SAFETY: both buffers have the native struct size, and the C path is
        // terminated and remains alive until the calls return.
        unsafe {
            if libc::statfs(native.as_ptr(), filesystem.as_mut_ptr()) != 0
                || libc::statvfs(native.as_ptr(), capacity.as_mut_ptr()) != 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            let filesystem = filesystem.assume_init();
            let capacity = capacity.assume_init();
            if filesystem.f_type != libc::TMPFS_MAGIC {
                return Err("RAM witness directory must use tmpfs".into());
            }
            if u128::from(capacity.f_blocks) * u128::from(capacity.f_frsize) > 2 * 1024_u128.pow(3)
            {
                return Err("RAM witness tmpfs capacity must be capped at 2 GiB".into());
            }
            if u128::from(capacity.f_bavail) * u128::from(capacity.f_frsize) < 1_650_000_000 {
                return Err("RAM witness tmpfs needs at least 1.65 GB free".into());
            }
        }
        let meminfo = std::fs::read_to_string("/proc/meminfo")?;
        let available = meminfo
            .lines()
            .find_map(|line| {
                line.strip_prefix("MemAvailable:")?
                    .split_whitespace()
                    .next()?
                    .parse::<u64>()
                    .ok()
            })
            .unwrap_or(0);
        if available < 8 * 1024 * 1024 {
            return Err(
                "RAM witnesses need at least 8 GiB available host RAM before startup".into(),
            );
        }
        Ok(path)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        Err("RAM witnesses require an existing private Linux tmpfs mount".into())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_regular_directory_cannot_silently_become_ram_witness_storage() {
        assert!(super::validate(&std::env::temp_dir()).is_err());
    }

    #[test]
    #[cfg(target_os = "linux")]
    #[ignore = "requires CMFD_RAM_WITNESS_TEST_DIR naming a private dedicated 2 GiB tmpfs"]
    fn accepts_a_private_bounded_tmpfs_mount() {
        let path = std::env::var_os("CMFD_RAM_WITNESS_TEST_DIR").expect("test tmpfs path");
        assert_eq!(
            super::validate(std::path::Path::new(&path)).unwrap(),
            std::path::Path::new(&path).canonicalize().unwrap()
        );
    }
}
