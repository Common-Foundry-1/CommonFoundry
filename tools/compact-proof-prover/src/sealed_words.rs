//! Freeze replay traces in kernel-sealed inodes before checking their words.
//! Pool replay writes regular files, so the prover takes an immutable snapshot.

use memmap2::{Mmap, MmapOptions};
use rayon::prelude::*;
use std::{
    ffi::CString,
    fs::{self, File},
    io::{Read, Write},
    os::fd::{AsRawFd, FromRawFd},
    path::Path,
};

const REQUIRED_SEALS: i32 =
    libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;

pub struct SealedWords {
    map: Mmap,
    modulus: u32,
}

impl SealedWords {
    pub fn open(path: &Path, expected_bytes: usize, modulus: u32) -> Result<Self, String> {
        if modulus < 2 || expected_bytes == 0 || expected_bytes % 4 != 0 {
            return Err("invalid trusted shape".into());
        }
        let mut file = File::open(path).map_err(|e| format!("open trace: {e}"))?;
        if file.metadata().map_err(|e| e.to_string())?.len() != expected_bytes as u64 {
            return Err("wrong trace length".into());
        }

        let seals = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) };
        // Ordinary tmpfs inodes report F_SEAL_SEAL alone: they cannot acquire
        // write/grow/shrink seals. Treat them as mutable replay files, exactly
        // like disk files, and validate only an owned, fully sealed snapshot.
        if seals < 0 || seals == libc::F_SEAL_SEAL {
            // A regular file has no F_SEAL_WRITE. Copy exact bytes to an owned
            // memfd, seal it, then validate and prove from that snapshot.
            if fs::symlink_metadata(path)
                .map_err(|e| e.to_string())?
                .file_type()
                .is_symlink()
            {
                return Err("trace path is a symlink".into());
            }
            if !file.metadata().map_err(|e| e.to_string())?.is_file() {
                return Err("trace is not a regular file".into());
            }
            let name = CString::new("cmfd-direct-replay-trace").expect("static name");
            let fd = unsafe {
                libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING)
            };
            if fd < 0 {
                return Err(format!(
                    "create snapshot memfd: {}",
                    std::io::Error::last_os_error()
                ));
            }
            let mut snapshot = unsafe { File::from_raw_fd(fd) };
            let mut remaining = expected_bytes;
            let mut buffer = vec![0_u8; 4 * 1024 * 1024];
            while remaining > 0 {
                let chunk = remaining.min(buffer.len());
                file.read_exact(&mut buffer[..chunk])
                    .map_err(|e| format!("read trace: {e}"))?;
                snapshot
                    .write_all(&buffer[..chunk])
                    .map_err(|e| format!("write snapshot: {e}"))?;
                remaining -= chunk;
            }
            let mut trailing = [0_u8; 1];
            if file.read(&mut trailing).map_err(|e| e.to_string())? != 0 {
                return Err("trace grew during snapshot".into());
            }
            if unsafe { libc::fcntl(snapshot.as_raw_fd(), libc::F_ADD_SEALS, REQUIRED_SEALS) } != 0
            {
                return Err(format!(
                    "seal snapshot: {}",
                    std::io::Error::last_os_error()
                ));
            }
            // A writable fd cannot create a new shared mmap after F_SEAL_WRITE.
            // Reopen the same sealed inode read-only through procfs.
            file = File::open(format!("/proc/self/fd/{}", snapshot.as_raw_fd()))
                .map_err(|e| format!("reopen sealed snapshot: {e}"))?;
        } else if seals & REQUIRED_SEALS != REQUIRED_SEALS {
            return Err("trace lacks immutable kernel seals".into());
        }

        let final_seals = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) };
        if final_seals < 0 || final_seals & REQUIRED_SEALS != REQUIRED_SEALS {
            return Err("trace lacks immutable kernel seals".into());
        }
        let map = unsafe {
            MmapOptions::new()
                .map(&file)
                .map_err(|e| format!("map snapshot: {e}"))?
        };
        if map.as_ptr().align_offset(std::mem::align_of::<u32>()) != 0 {
            return Err("unaligned sealed trace".into());
        }
        let words =
            unsafe { std::slice::from_raw_parts(map.as_ptr().cast::<u32>(), map.len() / 4) };
        if !words.par_iter().all(|x| *x < modulus) {
            return Err("noncanonical sealed trace word".into());
        }
        Ok(Self { map, modulus })
    }

    pub fn words(&self) -> &[u32] {
        unsafe { std::slice::from_raw_parts(self.map.as_ptr().cast::<u32>(), self.map.len() / 4) }
    }

    pub fn modulus(&self) -> u32 {
        self.modulus
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Seek, SeekFrom},
        os::fd::RawFd,
    };
    const P: u32 = 2_130_706_433;

    fn file(words: &[u32], seals: i32) -> File {
        let name = CString::new("cmfd-sealed-words-test").unwrap();
        let fd = unsafe {
            libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING)
        };
        assert!(fd >= 0);
        let mut f = unsafe { File::from_raw_fd(fd) };
        for word in words {
            f.write_all(&word.to_le_bytes()).unwrap();
        }
        if seals != 0 {
            assert_eq!(unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) }, 0);
        }
        f
    }

    fn path(fd: RawFd) -> std::path::PathBuf {
        format!("/proc/self/fd/{fd}").into()
    }

    #[test]
    fn canonical_mapping_remains_immutable() {
        let f = file(&[0, 1, P - 1, 7], REQUIRED_SEALS);
        let t = SealedWords::open(&path(f.as_raw_fd()), 16, P).unwrap();
        assert_eq!(t.words(), &[0, 1, P - 1, 7]);
        assert_eq!(
            unsafe { libc::pwrite(f.as_raw_fd(), b"bad".as_ptr().cast(), 3, 0) },
            -1
        );
        assert_eq!(unsafe { libc::ftruncate(f.as_raw_fd(), 4) }, -1);
        assert_eq!(t.words(), &[0, 1, P - 1, 7]);
    }

    #[test]
    fn regular_replay_file_is_snapshotted_before_use() {
        let path = std::env::temp_dir().join(format!("cmfd-trace-snapshot-{}", std::process::id()));
        let mut source = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        for word in [0, 1, P - 1, 7] {
            source.write_all(&word.to_le_bytes()).unwrap();
        }
        source.flush().unwrap();
        let snapshot = SealedWords::open(&path, 16, P).unwrap();
        source.seek(SeekFrom::Start(0)).unwrap();
        source.write_all(&0_u32.to_le_bytes()).unwrap();
        assert_eq!(snapshot.words(), &[0, 1, P - 1, 7]);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn ordinary_tmpfs_replay_file_is_snapshotted_and_checked() {
        let path = std::path::PathBuf::from("/dev/shm").join(format!(
            "cmfd-tmpfs-snapshot-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut source = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        for word in [0, 1, P - 1, 7] {
            source.write_all(&word.to_le_bytes()).unwrap();
        }
        source.flush().unwrap();
        assert_eq!(
            unsafe { libc::fcntl(source.as_raw_fd(), libc::F_GET_SEALS) },
            libc::F_SEAL_SEAL
        );
        let snapshot = SealedWords::open(&path, 16, P).unwrap();
        source.seek(SeekFrom::Start(0)).unwrap();
        source.write_all(&P.to_le_bytes()).unwrap();
        source.flush().unwrap();
        assert_eq!(snapshot.words(), &[0, 1, P - 1, 7]);
        assert!(
            SealedWords::open(&path, 16, P).is_err(),
            "noncanonical tmpfs words must still fail"
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn missing_write_seal_is_rejected() {
        let f = file(&[0, 1, 2, 3], libc::F_SEAL_SHRINK | libc::F_SEAL_GROW);
        assert!(SealedWords::open(&path(f.as_raw_fd()), 16, P).is_err());
    }

    #[test]
    fn wrong_lengths_and_noncanonical_words_are_rejected() {
        for words in [vec![P, 1, 2, 3], vec![1, 2, 3, u32::MAX]] {
            let f = file(&words, REQUIRED_SEALS);
            assert!(SealedWords::open(&path(f.as_raw_fd()), 16, P).is_err());
        }
        let f = file(&[1, 2, 3, 4], REQUIRED_SEALS);
        assert!(SealedWords::open(&path(f.as_raw_fd()), 12, P).is_err());
        assert!(SealedWords::open(&path(f.as_raw_fd()), 0, P).is_err());
    }
}
