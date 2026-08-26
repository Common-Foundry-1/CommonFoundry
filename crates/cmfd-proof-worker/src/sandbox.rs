use std::ffi::OsStr;
use std::path::Path;
#[cfg(target_os = "linux")]
use std::path::PathBuf;

const LINUX_SANDBOX_DIAGNOSTIC_MODE: &str = "--cmfd-internal-linux-sandbox-diagnostic";

/// Runtime isolation established before a verifier reads/loads production
/// artifact contents or reads an untrusted block frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum VerifierSandboxStatus {
    Unconfined = 0,
    LinuxLandlockSeccompV1 = 1,
    WindowsAppContainerV1 = 2,
}

impl VerifierSandboxStatus {
    pub(crate) fn from_wire(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Unconfined),
            1 => Some(Self::LinuxLandlockSeccompV1),
            2 => Some(Self::WindowsAppContainerV1),
            _ => None,
        }
    }
}

pub(crate) fn diagnostic_mode_requested() -> bool {
    cfg!(target_os = "linux")
        && std::env::args_os().nth(1).as_deref() == Some(OsStr::new(LINUX_SANDBOX_DIAGNOSTIC_MODE))
}

pub(crate) fn diagnostic_main() -> i32 {
    #[cfg(target_os = "linux")]
    {
        let artifacts = std::env::args_os()
            .skip(2)
            .map(PathBuf::from)
            .collect::<Vec<_>>();
        if artifacts.len() != 1 {
            eprintln!("the Linux sandbox diagnostic requires exactly one Record V2 path");
            return 2;
        }
        match install_production(&[&artifacts[0]]) {
            Ok(VerifierSandboxStatus::LinuxLandlockSeccompV1) => 0,
            Ok(_) => 1,
            Err(error) => {
                eprintln!("{error}");
                1
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        1
    }
}

pub(crate) fn required_production_status() -> Result<VerifierSandboxStatus, &'static str> {
    #[cfg(target_os = "linux")]
    {
        Ok(VerifierSandboxStatus::LinuxLandlockSeccompV1)
    }
    #[cfg(windows)]
    {
        Ok(VerifierSandboxStatus::WindowsAppContainerV1)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        Err("ProductionV3 verifier sandboxing is unsupported on this operating system")
    }
}

/// Installs the production verifier sandbox in the child itself. The caller
/// invokes this after parsing trusted process arguments, but before
/// reading/loading artifact contents or any untrusted IPC bytes.
pub(crate) fn install_production(artifacts: &[&Path]) -> Result<VerifierSandboxStatus, String> {
    #[cfg(target_os = "linux")]
    {
        linux::install(artifacts)?;
        Ok(VerifierSandboxStatus::LinuxLandlockSeccompV1)
    }
    #[cfg(windows)]
    {
        let _ = artifacts;
        crate::windows_launcher::validate_current_process_sandbox()?;
        Ok(VerifierSandboxStatus::WindowsAppContainerV1)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = artifacts;
        Err("ProductionV3 verifier sandboxing is unsupported on this operating system".to_owned())
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::{VerifierSandboxStatus, install_production, required_production_status};

    #[test]
    fn production_verifier_requires_the_appcontainer_launch_context() {
        assert_eq!(
            required_production_status(),
            Ok(VerifierSandboxStatus::WindowsAppContainerV1)
        );
        assert!(install_production(&[]).is_err());
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs::File;
    use std::io;
    use std::os::fd::AsRawFd;
    use std::path::Path;

    const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
    const LANDLOCK_RULE_PATH_BENEATH: i32 = 1;

    const ACCESS_FS_EXECUTE: u64 = 1 << 0;
    const ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
    const ACCESS_FS_READ_FILE: u64 = 1 << 2;
    const ACCESS_FS_READ_DIR: u64 = 1 << 3;
    const ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
    const ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
    const ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
    const ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
    const ACCESS_FS_MAKE_REG: u64 = 1 << 8;
    const ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
    const ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
    const ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
    const ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
    const ACCESS_FS_REFER: u64 = 1 << 13;
    const ACCESS_FS_TRUNCATE: u64 = 1 << 14;
    const HANDLED_FS: u64 = ACCESS_FS_EXECUTE
        | ACCESS_FS_WRITE_FILE
        | ACCESS_FS_READ_FILE
        | ACCESS_FS_READ_DIR
        | ACCESS_FS_REMOVE_DIR
        | ACCESS_FS_REMOVE_FILE
        | ACCESS_FS_MAKE_CHAR
        | ACCESS_FS_MAKE_DIR
        | ACCESS_FS_MAKE_REG
        | ACCESS_FS_MAKE_SOCK
        | ACCESS_FS_MAKE_FIFO
        | ACCESS_FS_MAKE_BLOCK
        | ACCESS_FS_MAKE_SYM
        | ACCESS_FS_REFER
        | ACCESS_FS_TRUNCATE;
    const ACCESS_NET_BIND_TCP: u64 = 1 << 0;
    const ACCESS_NET_CONNECT_TCP: u64 = 1 << 1;
    const HANDLED_NET: u64 = ACCESS_NET_BIND_TCP | ACCESS_NET_CONNECT_TCP;

    const PR_SET_DUMPABLE: libc::c_int = 4;
    const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;
    const PR_SET_SECCOMP: libc::c_int = 22;
    const SECCOMP_MODE_FILTER: libc::c_ulong = 2;
    const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
    const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;

    const BPF_LD: u16 = 0x00;
    const BPF_W: u16 = 0x00;
    const BPF_ABS: u16 = 0x20;
    const BPF_JMP: u16 = 0x05;
    const BPF_JEQ: u16 = 0x10;
    const BPF_K: u16 = 0x00;
    const BPF_RET: u16 = 0x06;

    const SECCOMP_DATA_NR_OFFSET: u32 = 0;
    const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;
    const SECCOMP_DATA_ARG0_OFFSET: u32 = 16;
    const SECCOMP_DATA_ARG0_HIGH_OFFSET: u32 = 20;
    const SECCOMP_DATA_ARG1_OFFSET: u32 = 24;
    const SECCOMP_DATA_ARG1_HIGH_OFFSET: u32 = 28;
    const SECCOMP_DATA_ARG2_OFFSET: u32 = 32;
    const SECCOMP_DATA_ARG2_HIGH_OFFSET: u32 = 36;
    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
    const SANDBOX_MAX_OPEN_FILES: libc::rlim_t = 64;
    const SANDBOX_MAX_USER_TASKS: libc::rlim_t = 512;
    #[cfg(target_env = "musl")]
    type RlimitResource = libc::c_int;
    #[cfg(not(target_env = "musl"))]
    type RlimitResource = libc::__rlimit_resource_t;
    #[cfg(test)]
    const F_SETSIG_LINUX: libc::c_int = 10;
    const ALLOWED_THREAD_CLONE_FLAGS: u32 = (libc::CLONE_VM
        | libc::CLONE_FS
        | libc::CLONE_FILES
        | libc::CLONE_SIGHAND
        | libc::CLONE_THREAD
        | libc::CLONE_SYSVSEM
        | libc::CLONE_SETTLS
        | libc::CLONE_PARENT_SETTID
        | libc::CLONE_CHILD_CLEARTID) as u32;

    #[repr(C)]
    struct LandlockRulesetAttr {
        handled_access_fs: u64,
        handled_access_net: u64,
    }

    #[repr(C)]
    struct LandlockPathBeneathAttr {
        allowed_access: u64,
        parent_fd: i32,
        reserved: u32,
    }

    #[repr(C)]
    struct CapUserHeader {
        version: u32,
        pid: i32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CapUserData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct SockFilter {
        code: u16,
        jt: u8,
        jf: u8,
        k: u32,
    }

    #[repr(C)]
    struct SockFprog {
        len: u16,
        filter: *mut SockFilter,
    }

    struct OwnedFd(i32);

    impl Drop for OwnedFd {
        fn drop(&mut self) {
            // SAFETY: this wrapper is created only from a successful syscall
            // returning a new descriptor, and owns that descriptor exactly once.
            unsafe {
                libc::close(self.0);
            }
        }
    }

    pub(super) fn install(artifacts: &[&Path]) -> Result<(), String> {
        install_inner(artifacts, true)
    }

    #[cfg(test)]
    fn install_policy_for_multithreaded_test(artifacts: &[&Path]) -> Result<(), String> {
        install_inner(artifacts, false)
    }

    fn install_inner(artifacts: &[&Path], require_single_task: bool) -> Result<(), String> {
        if artifacts.len() != 1 {
            return Err(
                "the ProductionV3 verifier sandbox requires exactly one Record V2 artifact"
                    .to_owned(),
            );
        }
        #[cfg(not(target_arch = "x86_64"))]
        return Err("the ProductionV3 Linux sandbox is qualified only for x86_64".to_owned());

        #[cfg(target_arch = "x86_64")]
        {
            let artifact_files = open_canonical_artifacts(artifacts)?;
            let parent_directories = open_canonical_parent_directories(artifacts)?;
            require_unprivileged_identity()?;
            if require_single_task {
                require_single_threaded_process()?;
            }
            set_resource_limits()?;
            set_no_new_privileges()?;
            install_landlock(&artifact_files, &parent_directories)?;
            install_seccomp()?;
            Ok(())
        }
    }

    fn open_canonical_artifacts(artifacts: &[&Path]) -> Result<Vec<File>, String> {
        artifacts
            .iter()
            .map(|path| {
                let canonical = std::fs::canonicalize(path)
                    .map_err(|error| format!("could not canonicalize sandbox artifact: {error}"))?;
                if canonical != *path {
                    return Err("ProductionV3 sandbox artifact path is not canonical".to_owned());
                }
                File::open(path)
                    .map_err(|error| format!("could not open sandbox artifact read-only: {error}"))
            })
            .collect()
    }

    fn open_canonical_parent_directories(artifacts: &[&Path]) -> Result<Vec<File>, String> {
        let mut parents = Vec::new();
        for path in artifacts {
            let parent = path
                .parent()
                .ok_or_else(|| "ProductionV3 sandbox artifact has no parent".to_owned())?;
            if parents
                .iter()
                .any(|existing: &File| same_file(existing, parent))
            {
                continue;
            }
            parents.push(File::open(parent).map_err(|error| {
                format!("could not open sandbox artifact parent read-only: {error}")
            })?);
        }
        Ok(parents)
    }

    fn same_file(existing: &File, candidate: &Path) -> bool {
        use std::os::unix::fs::MetadataExt;

        let Ok(existing_metadata) = existing.metadata() else {
            return false;
        };
        let Ok(candidate_metadata) = candidate.metadata() else {
            return false;
        };
        existing_metadata.dev() == candidate_metadata.dev()
            && existing_metadata.ino() == candidate_metadata.ino()
    }

    fn set_no_new_privileges() -> Result<(), String> {
        // SAFETY: prctl receives no pointers and only narrows this process.
        if unsafe { libc::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
            return Err(format!(
                "could not disable verifier core dumps: {}",
                io::Error::last_os_error()
            ));
        }
        // SAFETY: prctl receives no pointers and permanently narrows this process.
        if unsafe { libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            return Err(format!(
                "could not set verifier no_new_privs: {}",
                io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    fn require_unprivileged_identity() -> Result<(), String> {
        let (mut uid, mut euid, mut saved_uid) = (0, 0, 0);
        let (mut gid, mut egid, mut saved_gid) = (0, 0, 0);
        // SAFETY: all six output pointers are valid for the credential queries.
        if unsafe { libc::getresuid(&mut uid, &mut euid, &mut saved_uid) } != 0
            || unsafe { libc::getresgid(&mut gid, &mut egid, &mut saved_gid) } != 0
        {
            return Err(format!(
                "could not inspect verifier credentials: {}",
                io::Error::last_os_error()
            ));
        }
        if uid == 0
            || euid == 0
            || saved_uid == 0
            || gid == 0
            || egid == 0
            || saved_gid == 0
            || uid != euid
            || uid != saved_uid
            || gid != egid
            || gid != saved_gid
        {
            return Err(
                "ProductionV3 requires non-root matching real/effective/saved credentials"
                    .to_owned(),
            );
        }
        // SAFETY: a null list asks only for the number of supplementary
        // groups and has no side effects.
        let group_count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
        if group_count < 0 {
            return Err(format!(
                "could not inspect verifier supplementary groups: {}",
                io::Error::last_os_error()
            ));
        }
        let mut supplementary_groups: Vec<libc::gid_t> = vec![0; group_count as usize];
        if group_count > 0 {
            // SAFETY: the vector has exactly group_count writable entries.
            let read = unsafe { libc::getgroups(group_count, supplementary_groups.as_mut_ptr()) };
            if read != group_count {
                return Err(format!(
                    "could not read verifier supplementary groups: {}",
                    io::Error::last_os_error()
                ));
            }
        }
        if supplementary_groups.contains(&0) {
            return Err(
                "ProductionV3 verifier must not inherit the root supplementary group".to_owned(),
            );
        }

        let header = CapUserHeader {
            version: LINUX_CAPABILITY_VERSION_3,
            pid: 0,
        };
        let mut data = [CapUserData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        }; 2];
        // SAFETY: header and both capability words have the kernel ABI layout
        // and remain live for the read-only capability query.
        if unsafe {
            libc::syscall(
                libc::SYS_capget,
                std::ptr::from_ref(&header),
                data.as_mut_ptr(),
            )
        } != 0
        {
            return Err(format!(
                "could not inspect verifier Linux capabilities: {}",
                io::Error::last_os_error()
            ));
        }
        if data
            .iter()
            .any(|word| word.effective != 0 || word.permitted != 0 || word.inheritable != 0)
        {
            return Err("ProductionV3 verifier must not inherit Linux capabilities".to_owned());
        }
        Ok(())
    }

    fn require_single_threaded_process() -> Result<(), String> {
        let tasks = std::fs::read_dir("/proc/self/task")
            .map_err(|error| format!("could not inspect verifier task count: {error}"))?
            .try_fold(0_usize, |count, entry| {
                entry.map(|_| count.saturating_add(1))
            })
            .map_err(|error| format!("could not enumerate verifier task count: {error}"))?;
        validate_single_task_count(tasks)
    }

    fn validate_single_task_count(tasks: usize) -> Result<(), String> {
        if tasks != 1 {
            return Err(format!(
                "ProductionV3 sandbox installation requires exactly one process task, found {tasks}"
            ));
        }
        Ok(())
    }

    fn set_resource_limits() -> Result<(), String> {
        narrow_resource_limit(libc::RLIMIT_NOFILE, SANDBOX_MAX_OPEN_FILES, "open files")?;
        narrow_resource_limit(libc::RLIMIT_NPROC, SANDBOX_MAX_USER_TASKS, "per-user tasks")?;
        Ok(())
    }

    fn narrow_resource_limit(
        resource: RlimitResource,
        maximum: libc::rlim_t,
        name: &str,
    ) -> Result<(), String> {
        let mut inherited = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: inherited is a live writable kernel ABI structure.
        if unsafe { libc::getrlimit(resource, &mut inherited) } != 0 {
            return Err(format!(
                "could not inspect verifier {name} limit: {}",
                io::Error::last_os_error()
            ));
        }
        // Pin the hard limit to the lowest inherited authority. This never
        // raises a lower soft limit and prevents a later soft-limit increase.
        let narrowed = inherited.rlim_cur.min(inherited.rlim_max).min(maximum);
        let limit = libc::rlimit {
            rlim_cur: narrowed,
            rlim_max: narrowed,
        };
        // SAFETY: the limit is a live kernel ABI structure and can only narrow
        // the current process before any untrusted input is read.
        if unsafe { libc::setrlimit(resource, &limit) } != 0 {
            return Err(format!(
                "could not bound verifier {name}: {}",
                io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    fn install_landlock(artifacts: &[File], parent_directories: &[File]) -> Result<(), String> {
        // SAFETY: the version query uses the kernel-defined null attribute form.
        let abi = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                std::ptr::null::<LandlockRulesetAttr>(),
                0_usize,
                LANDLOCK_CREATE_RULESET_VERSION,
            )
        };
        if abi < 3 {
            return Err(format!(
                "ProductionV3 requires Linux Landlock ABI 3 or newer (kernel reported {abi})"
            ));
        }
        let attr = LandlockRulesetAttr {
            handled_access_fs: HANDLED_FS,
            // ABI 3 has the complete filesystem rights used here. TCP access
            // is still denied by seccomp below; ABI 4+ additionally asks
            // Landlock to enforce the same network boundary independently.
            handled_access_net: if abi >= 4 { HANDLED_NET } else { 0 },
        };
        let attr_size = if abi >= 4 {
            size_of::<LandlockRulesetAttr>()
        } else {
            size_of::<u64>()
        };
        // SAFETY: attr is a live, correctly sized kernel ABI structure.
        let ruleset = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                std::ptr::from_ref(&attr),
                attr_size,
                0_u32,
            )
        };
        if ruleset < 0 {
            return Err(format!(
                "could not create ProductionV3 Landlock ruleset: {}",
                io::Error::last_os_error()
            ));
        }
        let ruleset = i32::try_from(ruleset).map(OwnedFd).map_err(|_| {
            format!("ProductionV3 Landlock ruleset descriptor does not fit i32: {ruleset}")
        })?;

        for artifact in artifacts {
            add_path_rule(ruleset.0, artifact, ACCESS_FS_READ_FILE)?;
        }
        for parent in parent_directories {
            add_path_rule(ruleset.0, parent, ACCESS_FS_READ_DIR)?;
        }

        // SAFETY: ruleset is a live Landlock ruleset fd; flags must be zero.
        if unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset.0, 0_u32) } != 0 {
            return Err(format!(
                "could not enforce ProductionV3 Landlock ruleset: {}",
                io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    fn add_path_rule(ruleset: i32, path: &File, allowed_access: u64) -> Result<(), String> {
        let attr = LandlockPathBeneathAttr {
            allowed_access,
            parent_fd: path.as_raw_fd(),
            reserved: 0,
        };
        // SAFETY: both descriptors and attr remain live for the call.
        if unsafe {
            libc::syscall(
                libc::SYS_landlock_add_rule,
                ruleset,
                LANDLOCK_RULE_PATH_BENEATH,
                std::ptr::from_ref(&attr),
                0_u32,
            )
        } != 0
        {
            return Err(format!(
                "could not add ProductionV3 Landlock path rule: {}",
                io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    fn statement(code: u16, k: u32) -> SockFilter {
        SockFilter {
            code,
            jt: 0,
            jf: 0,
            k,
        }
    }

    fn jump(code: u16, k: u32, jt: u8, jf: u8) -> SockFilter {
        SockFilter { code, jt, jf, k }
    }

    fn allow_syscall(program: &mut Vec<SockFilter>, syscall: libc::c_long) {
        program.push(jump(BPF_JMP | BPF_JEQ | BPF_K, syscall as u32, 0, 1));
        program.push(statement(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    }

    #[cfg(target_arch = "x86_64")]
    fn install_seccomp() -> Result<(), String> {
        let mut program = vec![
            statement(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARCH_OFFSET),
            jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
            statement(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
            statement(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET),
        ];

        // Default-deny: this is the audited syscall surface needed by Rust's
        // allocator, panic/runtime machinery, retained read-only artifact
        // validation, framed stdio, clocks, and Rayon worker threads. Any new
        // runtime dependency fails closed until deliberately added and tested.
        for syscall in [
            libc::SYS_read,
            libc::SYS_write,
            libc::SYS_readv,
            libc::SYS_writev,
            libc::SYS_pread64,
            libc::SYS_preadv,
            libc::SYS_preadv2,
            libc::SYS_close,
            libc::SYS_lseek,
            libc::SYS_dup,
            libc::SYS_dup2,
            libc::SYS_dup3,
            libc::SYS_open,
            libc::SYS_openat,
            libc::SYS_openat2,
            libc::SYS_stat,
            libc::SYS_lstat,
            libc::SYS_fstat,
            libc::SYS_newfstatat,
            libc::SYS_statx,
            libc::SYS_mmap,
            libc::SYS_mprotect,
            libc::SYS_munmap,
            libc::SYS_mremap,
            libc::SYS_madvise,
            libc::SYS_mincore,
            libc::SYS_brk,
            libc::SYS_rt_sigaction,
            libc::SYS_rt_sigprocmask,
            libc::SYS_rt_sigreturn,
            libc::SYS_sigaltstack,
            libc::SYS_futex,
            libc::SYS_set_tid_address,
            libc::SYS_set_robust_list,
            libc::SYS_rseq,
            libc::SYS_arch_prctl,
            libc::SYS_sched_yield,
            libc::SYS_nanosleep,
            libc::SYS_clock_nanosleep,
            libc::SYS_clock_gettime,
            libc::SYS_clock_getres,
            libc::SYS_gettimeofday,
            libc::SYS_time,
            libc::SYS_getpid,
            libc::SYS_getppid,
            libc::SYS_gettid,
            libc::SYS_getuid,
            libc::SYS_geteuid,
            libc::SYS_getgid,
            libc::SYS_getegid,
            libc::SYS_getgroups,
            libc::SYS_getrusage,
            libc::SYS_times,
            libc::SYS_uname,
            libc::SYS_sysinfo,
            libc::SYS_getcpu,
            libc::SYS_getrandom,
            libc::SYS_poll,
            libc::SYS_ppoll,
            libc::SYS_select,
            libc::SYS_pselect6,
            libc::SYS_epoll_create1,
            libc::SYS_epoll_ctl,
            libc::SYS_epoll_wait,
            libc::SYS_epoll_pwait,
            libc::SYS_eventfd2,
            libc::SYS_restart_syscall,
            libc::SYS_exit,
            libc::SYS_exit_group,
        ] {
            allow_syscall(&mut program, syscall);
        }

        // fcntl can redirect asynchronous I/O signals to another same-user
        // process through F_SETOWN/F_SETSIG/F_SETFL(O_ASYNC). Retain only the
        // two read-only descriptor queries needed by runtime diagnostics.
        program.push(jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            libc::SYS_fcntl as u32,
            0,
            7,
        ));
        program.push(statement(
            BPF_LD | BPF_W | BPF_ABS,
            SECCOMP_DATA_ARG1_HIGH_OFFSET,
        ));
        program.push(jump(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 4));
        program.push(statement(
            BPF_LD | BPF_W | BPF_ABS,
            SECCOMP_DATA_ARG1_OFFSET,
        ));
        program.push(jump(BPF_JMP | BPF_JEQ | BPF_K, libc::F_GETFD as u32, 1, 0));
        program.push(jump(BPF_JMP | BPF_JEQ | BPF_K, libc::F_GETFL as u32, 0, 1));
        program.push(statement(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
        program.push(statement(
            BPF_RET | BPF_K,
            SECCOMP_RET_ERRNO | (libc::EPERM as u32),
        ));

        // Runtime CPU discovery needs only the calling process. Arbitrary-pid
        // affinity inspection would expose same-user process state.
        program.push(jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            libc::SYS_sched_getaffinity as u32,
            0,
            6,
        ));
        program.push(statement(
            BPF_LD | BPF_W | BPF_ABS,
            SECCOMP_DATA_ARG0_HIGH_OFFSET,
        ));
        program.push(jump(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 3));
        program.push(statement(
            BPF_LD | BPF_W | BPF_ABS,
            SECCOMP_DATA_ARG0_OFFSET,
        ));
        program.push(jump(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1));
        program.push(statement(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
        program.push(statement(
            BPF_RET | BPF_K,
            SECCOMP_RET_ERRNO | (libc::EPERM as u32),
        ));

        // Returning ENOSYS makes libc thread creation fall back to legacy
        // clone, whose exact kernel-valid pthread flags are checked below.
        program.push(jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            libc::SYS_clone3 as u32,
            0,
            1,
        ));
        program.push(statement(
            BPF_RET | BPF_K,
            SECCOMP_RET_ERRNO | (libc::ENOSYS as u32),
        ));

        // libc implements getrlimit through prlimit64. Permit only a pid=0
        // query with a null new-limit pointer; mutation and cross-process
        // inspection remain denied.
        program.push(jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            libc::SYS_prlimit64 as u32,
            0,
            10,
        ));
        program.push(statement(
            BPF_LD | BPF_W | BPF_ABS,
            SECCOMP_DATA_ARG0_HIGH_OFFSET,
        ));
        program.push(jump(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 7));
        program.push(statement(
            BPF_LD | BPF_W | BPF_ABS,
            SECCOMP_DATA_ARG0_OFFSET,
        ));
        program.push(jump(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 5));
        program.push(statement(
            BPF_LD | BPF_W | BPF_ABS,
            SECCOMP_DATA_ARG2_HIGH_OFFSET,
        ));
        program.push(jump(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 3));
        program.push(statement(
            BPF_LD | BPF_W | BPF_ABS,
            SECCOMP_DATA_ARG2_OFFSET,
        ));
        program.push(jump(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1));
        program.push(statement(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
        program.push(statement(
            BPF_RET | BPF_K,
            SECCOMP_RET_ERRNO | (libc::EPERM as u32),
        ));

        // Thread names are the only post-sandbox prctl operations needed by
        // Rust/Rayon. No dumpability, ptracer, seccomp, or privilege controls
        // are exposed to hostile verifier code.
        program.push(jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            libc::SYS_prctl as u32,
            0,
            5,
        ));
        program.push(statement(
            BPF_LD | BPF_W | BPF_ABS,
            SECCOMP_DATA_ARG0_OFFSET,
        ));
        program.push(jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            libc::PR_SET_NAME as u32,
            1,
            0,
        ));
        program.push(jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            libc::PR_GET_NAME as u32,
            0,
            1,
        ));
        program.push(statement(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
        program.push(statement(
            BPF_RET | BPF_K,
            SECCOMP_RET_ERRNO | (libc::EPERM as u32),
        ));

        // Permit only the exact legacy flags emitted by pthread creation. A
        // merely CLONE_THREAD-containing mask is too broad: namespace,
        // tracing, or non-shared descriptor flags must not pass the filter.
        program.push(jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            libc::SYS_clone as u32,
            0,
            6,
        ));
        program.push(statement(
            BPF_LD | BPF_W | BPF_ABS,
            SECCOMP_DATA_ARG0_HIGH_OFFSET,
        ));
        program.push(jump(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 3));
        program.push(statement(
            BPF_LD | BPF_W | BPF_ABS,
            SECCOMP_DATA_ARG0_OFFSET,
        ));
        program.push(jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            ALLOWED_THREAD_CLONE_FLAGS,
            0,
            1,
        ));
        program.push(statement(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
        program.push(statement(
            BPF_RET | BPF_K,
            SECCOMP_RET_ERRNO | (libc::EPERM as u32),
        ));

        // Every syscall not named above is denied. This includes network,
        // process/exec, filesystem or metadata mutation, ptrace, namespaces,
        // mounts, IPC, io_uring, keyrings, signals, and future syscalls.
        program.push(statement(
            BPF_RET | BPF_K,
            SECCOMP_RET_ERRNO | (libc::EPERM as u32),
        ));

        let len = u16::try_from(program.len())
            .map_err(|_| "ProductionV3 seccomp program is too large".to_owned())?;
        let mut filter = SockFprog {
            len,
            filter: program.as_mut_ptr(),
        };
        // SAFETY: filter and its backing program remain live during prctl.
        if unsafe {
            libc::prctl(
                PR_SET_SECCOMP,
                SECCOMP_MODE_FILTER,
                std::ptr::from_mut(&mut filter),
            )
        } != 0
        {
            return Err(format!(
                "could not enforce ProductionV3 seccomp filter: {}",
                io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use std::ffi::CString;
        use std::fs::{self, OpenOptions, Permissions};
        use std::io::Read;
        use std::net::{SocketAddr, TcpListener, TcpStream};
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::process::CommandExt;
        use std::path::PathBuf;
        use std::process::{Child, Command, Stdio};
        use std::sync::atomic::{AtomicU64, Ordering};

        use super::{
            ALLOWED_THREAD_CLONE_FLAGS, F_SETSIG_LINUX, SANDBOX_MAX_OPEN_FILES,
            SANDBOX_MAX_USER_TASKS, install_policy_for_multithreaded_test,
        };

        const PROBE_ENV: &str = "CMFD_VERIFIER_SANDBOX_PROBE";
        const ARTIFACT_ENV_PREFIX: &str = "CMFD_VERIFIER_SANDBOX_ARTIFACT_";
        const OUTSIDE_ENV: &str = "CMFD_VERIFIER_SANDBOX_OUTSIDE";
        const SOCKET_ENV: &str = "CMFD_VERIFIER_SANDBOX_SOCKET";
        const TARGET_PID_ENV: &str = "CMFD_VERIFIER_SANDBOX_TARGET_PID";
        static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

        fn temporary_directory() -> PathBuf {
            std::env::temp_dir().join(format!(
                "cmfd-verifier-sandbox-{}-{}",
                std::process::id(),
                NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
            ))
        }

        #[test]
        fn production_sandbox_probe_child() {
            if std::env::var_os(PROBE_ENV).is_none() {
                return;
            }
            let artifact = PathBuf::from(
                std::env::var_os(format!("{ARTIFACT_ENV_PREFIX}0"))
                    .expect("sandbox probe Record V2 path"),
            );
            let outside =
                PathBuf::from(std::env::var_os(OUTSIDE_ENV).expect("sandbox probe outside path"));
            let socket = std::env::var(SOCKET_ENV)
                .expect("sandbox probe socket")
                .parse::<SocketAddr>()
                .expect("sandbox probe socket address");
            let target_pid = std::env::var(TARGET_PID_ENV)
                .expect("sandbox probe same-user target PID")
                .parse::<libc::pid_t>()
                .expect("sandbox probe target PID");

            // Prove that each escape sentinel is accessible to this exact
            // unprivileged identity before installing the policy. Otherwise a
            // root-owned CI fixture could turn a DAC denial into a false
            // sandbox pass.
            OpenOptions::new()
                .write(true)
                .open(&artifact)
                .expect("Record V2 is writable before sandbox installation");
            assert_eq!(fs::read(&outside).unwrap(), b"secret");
            let created = outside.with_extension("control");
            fs::write(&created, b"control").expect("create control file before sandbox");
            fs::remove_file(created).expect("remove control file before sandbox");
            fs::set_permissions(&outside, Permissions::from_mode(0o600))
                .expect("chmod control before sandbox");
            let outside_c = CString::new(outside.as_os_str().as_bytes()).unwrap();
            assert_eq!(
                unsafe { libc::utimensat(libc::AT_FDCWD, outside_c.as_ptr(), std::ptr::null(), 0) },
                0,
                "timestamp control must succeed before sandbox"
            );
            let xattr_name = c"user.cmfd-sandbox-escape";
            let xattr_value = b"escape";
            assert_eq!(
                unsafe {
                    libc::setxattr(
                        outside_c.as_ptr(),
                        xattr_name.as_ptr(),
                        xattr_value.as_ptr().cast(),
                        xattr_value.len(),
                        0,
                    )
                },
                0,
                "xattr control must succeed before sandbox"
            );
            assert_eq!(
                unsafe { libc::removexattr(outside_c.as_ptr(), xattr_name.as_ptr()) },
                0,
                "xattr cleanup must succeed before sandbox"
            );
            let mut target_limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            assert_eq!(
                unsafe {
                    libc::syscall(
                        libc::SYS_prlimit64,
                        target_pid,
                        libc::RLIMIT_NOFILE,
                        std::ptr::null::<libc::rlimit>(),
                        std::ptr::from_mut(&mut target_limit),
                    )
                },
                0,
                "same-user prlimit control must succeed before sandbox"
            );
            let mut target_affinity: libc::cpu_set_t = unsafe { std::mem::zeroed() };
            assert_eq!(
                unsafe {
                    libc::sched_getaffinity(
                        target_pid,
                        size_of::<libc::cpu_set_t>(),
                        std::ptr::from_mut(&mut target_affinity),
                    )
                },
                0,
                "same-user affinity control must succeed before sandbox"
            );
            TcpStream::connect(socket).expect("network control must connect before sandbox");
            assert!(
                Command::new("/bin/true").status().unwrap().success(),
                "exec control must succeed before sandbox"
            );

            fn lower_soft_limit(
                resource: super::RlimitResource,
                desired: libc::rlim_t,
            ) -> libc::rlim_t {
                let mut inherited = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                assert_eq!(unsafe { libc::getrlimit(resource, &mut inherited) }, 0);
                let lowered = inherited.rlim_cur.min(inherited.rlim_max).min(desired);
                let narrowed_soft = libc::rlimit {
                    rlim_cur: lowered,
                    rlim_max: inherited.rlim_max,
                };
                assert_eq!(unsafe { libc::setrlimit(resource, &narrowed_soft) }, 0);
                lowered
            }
            let expected_open_files = lower_soft_limit(libc::RLIMIT_NOFILE, 48);
            let expected_user_tasks = lower_soft_limit(libc::RLIMIT_NPROC, 384);

            install_policy_for_multithreaded_test(&[&artifact])
                .expect("install Linux production verifier sandbox");

            let mut limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            // SAFETY: the writable limit structure remains live for each
            // read-only resource-limit query.
            assert_eq!(
                unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) },
                0
            );
            assert_eq!(limit.rlim_cur, expected_open_files);
            assert_eq!(limit.rlim_max, expected_open_files);
            assert_eq!(
                unsafe { libc::getrlimit(libc::RLIMIT_NPROC, &mut limit) },
                0
            );
            assert_eq!(limit.rlim_cur, expected_user_tasks);
            assert_eq!(limit.rlim_max, expected_user_tasks);
            assert!(expected_open_files <= SANDBOX_MAX_OPEN_FILES);
            assert!(expected_user_tasks <= SANDBOX_MAX_USER_TASKS);

            let mut bytes = Vec::new();
            fs::File::open(&artifact)
                .expect("sandbox keeps exact Record V2 readable")
                .read_to_end(&mut bytes)
                .expect("read exact sandbox Record V2");
            assert_eq!(bytes, b"artifact");
            assert!(
                OpenOptions::new().write(true).open(&artifact).is_err(),
                "sandbox Record V2 unexpectedly remained writable"
            );
            assert!(
                fs::File::open(&outside).is_err(),
                "sandbox read an unlisted sentinel"
            );
            assert!(
                fs::write(outside.with_extension("created"), b"escape").is_err(),
                "sandbox created an unlisted file"
            );
            assert!(
                fs::set_permissions(&outside, Permissions::from_mode(0o600)).is_err(),
                "sandbox changed unlisted file permissions"
            );
            // SAFETY: the C string is NUL-terminated and remains live for each
            // syscall. All three operations are expected to be denied before
            // they can mutate the sentinel.
            assert_eq!(
                unsafe { libc::utimensat(libc::AT_FDCWD, outside_c.as_ptr(), std::ptr::null(), 0) },
                -1,
                "sandbox changed unlisted file timestamps"
            );
            assert_eq!(
                unsafe {
                    libc::setxattr(
                        outside_c.as_ptr(),
                        xattr_name.as_ptr(),
                        xattr_value.as_ptr().cast(),
                        xattr_value.len(),
                        0,
                    )
                },
                -1,
                "sandbox set metadata on an unlisted file"
            );
            let mut separate_limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            // SAFETY: the old-limit pointer is writable and no new limit is
            // supplied, so even an unexpected success would be read-only.
            assert_eq!(
                unsafe {
                    libc::syscall(
                        libc::SYS_prlimit64,
                        target_pid,
                        libc::RLIMIT_NOFILE,
                        std::ptr::null::<libc::rlimit>(),
                        std::ptr::from_mut(&mut separate_limit),
                    )
                },
                -1,
                "sandbox inspected a separate process resource limit"
            );
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EPERM)
            );
            let mut own_affinity: libc::cpu_set_t = unsafe { std::mem::zeroed() };
            assert_eq!(
                unsafe {
                    libc::sched_getaffinity(
                        0,
                        size_of::<libc::cpu_set_t>(),
                        std::ptr::from_mut(&mut own_affinity),
                    )
                },
                0,
                "sandbox denied its own affinity query"
            );
            assert_eq!(
                unsafe {
                    libc::sched_getaffinity(
                        target_pid,
                        size_of::<libc::cpu_set_t>(),
                        std::ptr::from_mut(&mut own_affinity),
                    )
                },
                -1,
                "sandbox inspected a separate process affinity"
            );
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EPERM)
            );
            const MEMBARRIER_CMD_GLOBAL: libc::c_int = 1;
            assert_eq!(
                unsafe { libc::syscall(libc::SYS_membarrier, MEMBARRIER_CMD_GLOBAL, 0_u32,) },
                -1,
                "sandbox admitted a process-global memory barrier"
            );
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EPERM)
            );
            // SAFETY: no arguments are pointers and the filter must reject the
            // descriptor creation before it can observe host filesystem state.
            assert_eq!(
                unsafe { libc::syscall(libc::SYS_inotify_init1, libc::IN_CLOEXEC) },
                -1,
                "sandbox created a filesystem observation descriptor"
            );
            assert!(
                TcpStream::connect(socket).is_err(),
                "sandbox opened an outbound TCP connection"
            );
            assert!(
                TcpListener::bind("127.0.0.1:0").is_err(),
                "sandbox bound a TCP listener"
            );
            assert!(
                Command::new("/bin/true").status().is_err(),
                "sandbox spawned or executed a process"
            );
            // SAFETY: the sandbox is expected to reject fork before creating a
            // child. A zero result would be an escape and exits immediately.
            let fork_result = unsafe { libc::fork() };
            if fork_result == 0 {
                unsafe { libc::_exit(101) };
            }
            assert_eq!(fork_result, -1, "sandbox forked a child process");

            // A hostile verifier must not be able to redirect asynchronous
            // pipe notifications to its same-user parent. If this sequence
            // were admitted, the parent test process is the sacrificial
            // signal target; every mutating fcntl command must fail first.
            let stdout_flags = unsafe { libc::fcntl(libc::STDOUT_FILENO, libc::F_GETFL) };
            assert!(
                stdout_flags >= 0,
                "read-only fcntl query was unexpectedly denied"
            );
            // SAFETY: this only reads the caller's process ID.
            for (command, argument) in [
                (libc::F_SETOWN, target_pid),
                (F_SETSIG_LINUX, libc::SIGIO),
                (libc::F_SETFL, stdout_flags | libc::O_ASYNC),
            ] {
                // SAFETY: all arguments are scalar. The seccomp filter must
                // reject the command before the descriptor can be mutated.
                assert_eq!(
                    unsafe { libc::fcntl(libc::STDOUT_FILENO, command, argument) },
                    -1,
                    "sandbox admitted an asynchronous-signal fcntl command"
                );
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::EPERM)
                );
            }

            let broadened_thread_flags =
                u64::from(ALLOWED_THREAD_CLONE_FLAGS | libc::CLONE_UNTRACED as u32);
            // SAFETY: the policy must reject the non-exact flag mask before
            // the kernel observes the deliberately null clone arguments.
            assert_eq!(
                unsafe {
                    libc::syscall(
                        libc::SYS_clone,
                        broadened_thread_flags,
                        std::ptr::null_mut::<libc::c_void>(),
                        std::ptr::null_mut::<libc::c_void>(),
                        std::ptr::null_mut::<libc::c_void>(),
                        0_usize,
                    )
                },
                -1,
                "sandbox accepted a broadened CLONE_THREAD flag mask"
            );
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EPERM)
            );

            // SAFETY: this intentionally unassigned syscall number has no
            // arguments. EPERM, rather than the kernel's ENOSYS, proves the
            // seccomp program is default-deny.
            assert_eq!(unsafe { libc::syscall(0x7fff_ffff_i64) }, -1);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EPERM),
                "an unlisted syscall did not hit the default-deny rule"
            );

            std::thread::spawn(|| 7_u8)
                .join()
                .expect("sandbox must still permit in-process worker threads");
        }

        fn configure_unprivileged_child(command: &mut Command) {
            if unsafe { libc::geteuid() } != 0 {
                return;
            }
            // SAFETY: these credential syscalls are async-signal-safe between
            // fork and exec. Failure aborts the child launch.
            unsafe {
                command.pre_exec(|| {
                    if libc::syscall(
                        libc::SYS_setgroups,
                        0_usize,
                        std::ptr::null::<libc::gid_t>(),
                    ) != 0
                        || libc::syscall(libc::SYS_setresgid, 65_534_u32, 65_534_u32, 65_534_u32)
                            != 0
                        || libc::syscall(libc::SYS_setresuid, 65_534_u32, 65_534_u32, 65_534_u32)
                            != 0
                    {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }

        fn chown_to_probe_identity(path: &std::path::Path) {
            if unsafe { libc::geteuid() } != 0 {
                return;
            }
            let path = CString::new(path.as_os_str().as_bytes()).unwrap();
            assert_eq!(
                unsafe { libc::chown(path.as_ptr(), 65_534_u32, 65_534_u32) },
                0,
                "chown sandbox fixture"
            );
        }

        fn spawn_same_identity_victim() -> Child {
            let mut command = Command::new("/bin/sleep");
            command
                .arg("30")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            configure_unprivileged_child(&mut command);
            command.spawn().expect("spawn same-user sandbox victim")
        }

        #[test]
        fn production_sandbox_denies_file_network_and_process_escape() {
            let root = temporary_directory();
            let artifact_directory = root.join("artifacts");
            let outside_directory = root.join("outside");
            fs::create_dir_all(&artifact_directory).unwrap();
            fs::create_dir_all(&outside_directory).unwrap();
            fs::set_permissions(&root, Permissions::from_mode(0o700)).unwrap();
            fs::set_permissions(&artifact_directory, Permissions::from_mode(0o700)).unwrap();
            fs::set_permissions(&outside_directory, Permissions::from_mode(0o700)).unwrap();
            let record = artifact_directory.join("record-v2.json");
            fs::write(&record, b"artifact").unwrap();
            fs::set_permissions(&record, Permissions::from_mode(0o600)).unwrap();
            let record = record.canonicalize().unwrap();
            let outside = outside_directory.join("sentinel");
            fs::write(&outside, b"secret").unwrap();
            fs::set_permissions(&outside, Permissions::from_mode(0o600)).unwrap();
            let outside = outside.canonicalize().unwrap();
            for path in [
                record.as_path(),
                outside.as_path(),
                artifact_directory.as_path(),
                outside_directory.as_path(),
                root.as_path(),
            ] {
                chown_to_probe_identity(path);
            }
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let socket = listener.local_addr().unwrap();
            let mut victim = spawn_same_identity_victim();

            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .arg("--exact")
                .arg("sandbox::linux::tests::production_sandbox_probe_child")
                .arg("--nocapture")
                .env(PROBE_ENV, "1")
                .env(OUTSIDE_ENV, &outside)
                .env(SOCKET_ENV, socket.to_string())
                .env(TARGET_PID_ENV, victim.id().to_string());
            configure_unprivileged_child(&mut command);
            command.env(format!("{ARTIFACT_ENV_PREFIX}0"), &record);
            let status = command.status().expect("launch sandbox probe child");
            let _ = victim.kill();
            let _ = victim.wait();
            assert!(status.success(), "sandbox escape probe failed: {status}");

            drop(listener);
            fs::remove_dir_all(root).unwrap();
        }

        #[test]
        fn production_sandbox_requires_exactly_one_task() {
            assert!(super::validate_single_task_count(1).is_ok());
            assert!(super::validate_single_task_count(0).is_err());
            assert!(super::validate_single_task_count(2).is_err());
        }
    }
}
