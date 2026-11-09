//! Per-user GPU ownership for pools that retain a replay model between shares.
//! Uses the existing miner lock namespace for other CMFD processes of this user.
use fs2::FileExt;
use std::{
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
};

#[derive(Debug)]
pub struct PoolGpuLease {
    _files: Vec<File>,
}

fn valid_uuid(value: &str) -> bool {
    value.len() == 40
        && value.starts_with("GPU-")
        && value[4..].bytes().enumerate().all(|(i, c)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                c == b'-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
}

/// Check all visible compute processes, including those outside this user's
/// lock namespace. This never stops a workload; an occupied card is refused.
pub fn validate_idle_devices(devices: &[String], processes: &str) -> Result<(), String> {
    if devices.is_empty() || devices.iter().any(|d| !valid_uuid(d)) {
        return Err("GPU idle check requires complete physical UUIDs".into());
    }
    for line in processes.lines().filter(|line| !line.trim().is_empty()) {
        let mut fields = line.split(',').map(str::trim);
        let uuid = fields.next().unwrap_or_default();
        if !valid_uuid(uuid) || fields.next().is_none() {
            return Err("cannot interpret NVIDIA compute-process inventory".into());
        }
        if devices.iter().any(|d| d.eq_ignore_ascii_case(uuid)) {
            return Err(format!(
                "GPU {uuid} already has a compute workload; dedicated pool replay requires an idle assigned card"
            ));
        }
    }
    Ok(())
}

impl PoolGpuLease {
    pub fn acquire(devices: &[String]) -> Result<Self, String> {
        let root = if cfg!(windows) {
            std::env::var_os("LOCALAPPDATA").map(PathBuf::from)
        } else {
            std::env::var_os("HOME").map(|p| PathBuf::from(p).join(".local/state"))
        }
        .ok_or("user-state directory is required for a dedicated pool GPU")?;
        Self::acquire_at(devices, &root.join("CommonFoundry/gpu-locks"))
    }

    pub fn acquire_at(devices: &[String], directory: &Path) -> Result<Self, String> {
        if devices.is_empty() || !directory.is_absolute() || devices.iter().any(|d| !valid_uuid(d))
        {
            return Err("dedicated pool GPUs require complete physical UUIDs and an absolute lock directory".into());
        }
        let mut devices = devices
            .iter()
            .map(|d| d.to_ascii_lowercase())
            .collect::<Vec<_>>();
        devices.sort();
        devices.dedup();
        fs::create_dir_all(directory).map_err(|e| e.to_string())?;
        if fs::symlink_metadata(directory)
            .map_err(|e| e.to_string())?
            .file_type()
            .is_symlink()
        {
            return Err("GPU lock directory must not be a symlink".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            if fs::metadata(directory).map_err(|e| e.to_string())?.uid()
                != unsafe { libc::geteuid() }
            {
                return Err("GPU lock directory has another owner".into());
            }
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
                .map_err(|e| e.to_string())?;
        }
        let directory = fs::canonicalize(directory).map_err(|e| e.to_string())?;
        let mut files = Vec::new();
        for device in devices {
            let path = directory.join(format!(".pool-miner-{device}.lock"));
            let mut options = OpenOptions::new();
            options.create(true).truncate(false).read(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .mode(0o600);
            }
            let file = options
                .open(&path)
                .map_err(|e| format!("open GPU ownership lock: {e}"))?;
            let metadata = file.metadata().map_err(|e| e.to_string())?;
            if !metadata.is_file() {
                return Err("GPU ownership lock must be a regular file".into());
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if metadata.uid() != unsafe { libc::geteuid() } {
                    return Err("GPU ownership lock has another owner".into());
                }
            }
            file.try_lock_exclusive().map_err(|_| {
                format!("GPU {device} is already owned by a local CMFD miner or pool")
            })?;
            files.push(file);
        }
        Ok(Self { _files: files })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dedicated_idle_check_refuses_selected_workloads_and_unknown_inventory() {
        let gpu = "GPU-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa".to_owned();
        assert!(validate_idle_devices(&[gpu.clone()], "").is_ok());
        assert!(
            validate_idle_devices(
                &[gpu.clone()],
                "GPU-bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb, 12, other"
            )
            .is_ok()
        );
        assert!(validate_idle_devices(&[gpu.clone()], &format!("{gpu}, 13, miner")).is_err());
        assert!(validate_idle_devices(&[gpu], "unknown inventory").is_err());
    }
    #[test]
    fn dedicated_pool_uses_the_miners_lock_and_releases_it_on_drop() {
        let mut id = [0u8; 16];
        getrandom::fill(&mut id).unwrap();
        let directory = std::env::temp_dir().join(format!("cmfd-pool-lease-{}", hex::encode(id)));
        fs::create_dir(&directory).unwrap();
        let uuid = "GPU-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa".to_owned();
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(directory.join(format!(".pool-miner-{}.lock", uuid.to_ascii_lowercase())))
            .unwrap();
        lock.try_lock_exclusive().unwrap();
        assert!(PoolGpuLease::acquire_at(&[uuid.clone()], &directory).is_err());
        FileExt::unlock(&lock).unwrap();
        let pool = PoolGpuLease::acquire_at(
            &[
                uuid.clone(),
                uuid.to_ascii_lowercase().replace("gpu-", "GPU-"),
            ],
            &directory,
        )
        .unwrap();
        assert!(lock.try_lock_exclusive().is_err());
        assert!(PoolGpuLease::acquire_at(&["GPU-../bad".into()], &directory).is_err());
        drop(pool);
        lock.try_lock_exclusive().unwrap();
        drop(lock);
        assert_eq!(
            directory.canonicalize().unwrap().parent(),
            Some(std::env::temp_dir().canonicalize().unwrap().as_path())
        );
        fs::remove_dir_all(directory).unwrap();
    }
}
