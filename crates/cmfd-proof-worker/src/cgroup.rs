//! Delegated cgroup-v2 containment for the Linux ProductionV3 verifier.
//!
//! The node must start in a writable delegated cgroup. Initialization moves
//! the whole node process into a supervisor child before enabling controllers
//! on the now-empty delegated root. Every worker generation then receives a
//! unique sibling leaf with exact, read-back resource limits.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::path::{Component, Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

const REQUIRED_CONTROLLERS: [&str; 3] = ["cpu", "memory", "pids"];
const FREEZE_TIMEOUT: Duration = Duration::from_secs(2);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LinuxCgroupLimits {
    pub(crate) cpu_quota_micros: u64,
    pub(crate) cpu_period_micros: u64,
    pub(crate) memory_bytes: u64,
    pub(crate) pids: u64,
}

impl LinuxCgroupLimits {
    pub(crate) fn validate(self) -> io::Result<Self> {
        if self.cpu_quota_micros < 1_000 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ProductionV3 cgroup CPU quota must be at least 1000 microseconds",
            ));
        }
        if !(1_000..=1_000_000).contains(&self.cpu_period_micros) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ProductionV3 cgroup CPU period must be between 1000 and 1000000 microseconds",
            ));
        }
        if self.memory_bytes == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ProductionV3 cgroup memory limit must be nonzero",
            ));
        }
        if self.pids == 0 || self.pids > i64::MAX as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ProductionV3 cgroup PID limit must be a nonzero signed 64-bit integer",
            ));
        }
        Ok(self)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct LinuxCgroupManager {
    delegated_root: PathBuf,
    delegated_cgroup_path: PathBuf,
}

impl LinuxCgroupManager {
    pub(crate) fn initialize() -> io::Result<Self> {
        let membership = fs::read_to_string("/proc/self/cgroup")?;
        let cgroup_path = parse_unified_membership(&membership)?;
        let mountinfo = fs::read_to_string("/proc/self/mountinfo")?;
        let mount = find_cgroup2_mount(&mountinfo, &cgroup_path)?;
        let relative = relative_to_mount_root(&cgroup_path, &mount.root)?;
        let delegated_root = mount.mount_point.join(relative);
        let filesystem_root = delegated_root == mount.mount_point;
        initialize_delegated_root(&delegated_root, &cgroup_path, filesystem_root)?;
        Ok(Self {
            delegated_root,
            delegated_cgroup_path: cgroup_path,
        })
    }

    pub(crate) fn create_worker(
        &self,
        name: &str,
        limits: LinuxCgroupLimits,
    ) -> io::Result<LinuxWorkerCgroup> {
        validate_leaf_name(name)?;
        let limits = limits.validate()?;
        let path = self.delegated_root.join(name);
        fs::create_dir(&path)?;
        let result = (|| {
            require_controllers(&self.delegated_root.join("cgroup.subtree_control"))?;
            require_exact_control(&path.join("cgroup.type"), "domain")?;
            configure_exact(
                &path,
                "cpu.max",
                &format!("{} {}", limits.cpu_quota_micros, limits.cpu_period_micros),
            )?;
            configure_exact(&path, "memory.max", &limits.memory_bytes.to_string())?;
            configure_exact(&path, "memory.swap.max", "0")?;
            configure_exact(&path, "pids.max", &limits.pids.to_string())?;
            configure_exact(&path, "memory.oom.group", "1")?;
            configure_exact(&path, "cgroup.max.depth", "0")?;
            configure_exact(&path, "cgroup.max.descendants", "0")?;
            require_writable_control(&path.join("cgroup.freeze"))?;
            require_regular_control(&path.join("cgroup.events"))?;
            require_writable_control(&path.join("cgroup.kill"))?;
            let procs = OpenOptions::new()
                .write(true)
                .open(path.join("cgroup.procs"))?;
            let expected_membership = join_cgroup_path(&self.delegated_cgroup_path, name)?;
            let worker = LinuxWorkerCgroup {
                path: path.clone(),
                expected_membership,
                procs: Some(procs),
            };
            // Exercise every action-only containment control while the leaf is
            // empty. Production must fail before exec if the delegated root
            // merely exposes these files without permitting the operations.
            worker.freeze()?;
            worker.thaw()?;
            worker.kill()?;
            Ok(worker)
        })();
        if result.is_err() {
            let _ = fs::remove_dir(&path);
        }
        result
    }
}

#[derive(Debug)]
pub(crate) struct LinuxWorkerCgroup {
    path: PathBuf,
    expected_membership: PathBuf,
    procs: Option<File>,
}

impl LinuxWorkerCgroup {
    /// Descriptor inherited across fork and used before exec. The descriptor
    /// remains owned by this object in the parent and is marked CLOEXEC by the
    /// existing production launch boundary after the child writes itself.
    pub(crate) fn procs_fd(&self) -> RawFd {
        self.procs
            .as_ref()
            .expect("worker cgroup descriptor remains open until spawn returns")
            .as_raw_fd()
    }

    pub(crate) fn finish_spawn(&mut self, pid: u32) -> io::Result<()> {
        self.procs.take();
        let membership = fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
        let actual = parse_unified_membership(&membership)?;
        if actual != self.expected_membership {
            return Err(io::Error::other(format!(
                "worker joined {}, expected {}",
                actual.display(),
                self.expected_membership.display()
            )));
        }
        let direct = parse_pid_list(&fs::read_to_string(self.path.join("cgroup.procs"))?)?;
        if !direct.contains(&pid) {
            return Err(io::Error::other(
                "worker PID is absent from its exact cgroup leaf",
            ));
        }
        Ok(())
    }

    pub(crate) fn freeze(&self) -> io::Result<()> {
        self.set_frozen(true)
    }

    pub(crate) fn thaw(&self) -> io::Result<()> {
        self.set_frozen(false)
    }

    fn set_frozen(&self, frozen: bool) -> io::Result<()> {
        write_control(
            &self.path.join("cgroup.freeze"),
            if frozen { "1" } else { "0" },
        )?;
        let expected = if frozen { 1 } else { 0 };
        let started = Instant::now();
        loop {
            let events = fs::read_to_string(self.path.join("cgroup.events"))?;
            if parse_keyed_u64(&events, "frozen")? == expected {
                return Ok(());
            }
            if started.elapsed() >= FREEZE_TIMEOUT {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    if frozen {
                        "worker cgroup did not freeze"
                    } else {
                        "worker cgroup did not thaw"
                    },
                ));
            }
            thread::sleep(Duration::from_millis(1));
        }
    }

    /// `cgroup.kill` is the authoritative descendant-safe termination path.
    pub(crate) fn kill(&self) -> io::Result<()> {
        write_control(&self.path.join("cgroup.kill"), "1")
    }

    pub(crate) fn cleanup(&mut self) -> io::Result<()> {
        self.procs.take();
        let started = Instant::now();
        loop {
            match fs::remove_dir(&self.path) {
                Ok(()) => return Ok(()),
                Err(source)
                    if matches!(
                        source.kind(),
                        io::ErrorKind::DirectoryNotEmpty | io::ErrorKind::PermissionDenied
                    ) && started.elapsed() < CLEANUP_TIMEOUT =>
                {
                    thread::sleep(Duration::from_millis(1));
                }
                Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(source) => return Err(source),
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Cgroup2Mount {
    root: PathBuf,
    mount_point: PathBuf,
}

fn initialize_delegated_root(
    root: &Path,
    original_cgroup_path: &Path,
    filesystem_root: bool,
) -> io::Result<()> {
    let root_type = root.join("cgroup.type");
    if root_type.exists() {
        require_exact_control(&root_type, "domain")?;
    } else if !filesystem_root {
        return Err(io::Error::other(
            "delegated non-root cgroup has no cgroup.type control",
        ));
    }
    require_controllers(&root.join("cgroup.controllers"))?;
    let initial_processes = parse_pid_list(&fs::read_to_string(root.join("cgroup.procs"))?)?;
    if initial_processes.as_slice() != [std::process::id()] {
        return Err(io::Error::other(
            "delegated cgroup root must initially contain only the node process",
        ));
    }
    let supervisor_name = format!("cmfd-supervisor-{}", std::process::id());
    validate_leaf_name(&supervisor_name)?;
    let supervisor = root.join(&supervisor_name);
    fs::create_dir(&supervisor)?;

    let result = (|| {
        require_exact_control(&supervisor.join("cgroup.type"), "domain")?;
        write_control(
            &supervisor.join("cgroup.procs"),
            &std::process::id().to_string(),
        )?;
        let moved = parse_unified_membership(&fs::read_to_string("/proc/self/cgroup")?)?;
        let expected = join_cgroup_path(original_cgroup_path, &supervisor_name)?;
        if moved != expected {
            return Err(io::Error::other(format!(
                "node joined {}, expected supervisor cgroup {}",
                moved.display(),
                expected.display()
            )));
        }
        if !parse_pid_list(&fs::read_to_string(root.join("cgroup.procs"))?)?.is_empty() {
            return Err(io::Error::other(
                "delegated cgroup root still contains processes after moving the node",
            ));
        }
        write_control(&root.join("cgroup.subtree_control"), "+cpu +memory +pids")?;
        require_controllers(&root.join("cgroup.subtree_control"))?;
        Ok(())
    })();

    // The node may already have moved into the supervisor child. There is no
    // safe generic rollback through a possibly non-delegated parent; fail
    // closed and leave the explicit child visible to the operator.
    result?;
    Ok(())
}

fn require_controllers(path: &Path) -> io::Result<()> {
    let contents = fs::read_to_string(path)?;
    let present: std::collections::BTreeSet<_> = contents.split_whitespace().collect();
    for controller in REQUIRED_CONTROLLERS {
        if !present.contains(controller) {
            return Err(io::Error::other(format!(
                "delegated cgroup is missing required {controller} controller"
            )));
        }
    }
    Ok(())
}

fn configure_exact(directory: &Path, name: &str, expected: &str) -> io::Result<()> {
    let path = directory.join(name);
    write_control(&path, expected)?;
    let actual = fs::read_to_string(&path)?;
    if actual.trim() != expected {
        return Err(io::Error::other(format!(
            "{name} read back as {:?}, expected {:?}",
            actual.trim(),
            expected
        )));
    }
    Ok(())
}

fn require_exact_control(path: &Path, expected: &str) -> io::Result<()> {
    let actual = fs::read_to_string(path)?;
    if actual.trim() != expected {
        return Err(io::Error::other(format!(
            "{} read back as {:?}, expected {:?}",
            path.display(),
            actual.trim(),
            expected
        )));
    }
    Ok(())
}

fn write_control(path: &Path, value: &str) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).open(path)?;
    let mut command = Vec::with_capacity(value.len() + 1);
    command.extend_from_slice(value.as_bytes());
    command.push(b'\n');
    // cgroupfs parses one command per write. Splitting the newline into a
    // second write is an empty command and returns EINVAL on real cgroupfs.
    file.write_all(&command)?;
    file.flush()
}

fn require_regular_control(path: &Path) -> io::Result<()> {
    let metadata = fs::metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(io::Error::other(format!(
            "{} is not a cgroup control file",
            path.display()
        )));
    }
    Ok(())
}

fn require_writable_control(path: &Path) -> io::Result<()> {
    require_regular_control(path)?;
    OpenOptions::new().write(true).open(path).map(drop)
}

fn parse_unified_membership(contents: &str) -> io::Result<PathBuf> {
    let mut unified = None;
    for line in contents.lines() {
        if line.is_empty() {
            continue;
        }
        let mut fields = line.splitn(3, ':');
        let hierarchy = fields.next().unwrap_or_default();
        let controllers = fields.next().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "malformed /proc cgroup entry")
        })?;
        let path = fields.next().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "malformed /proc cgroup entry")
        })?;
        if hierarchy == "0" && controllers.is_empty() {
            if unified.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "multiple unified cgroup memberships",
                ));
            }
            unified = Some(parse_absolute_cgroup_path(path)?);
        } else {
            return Err(io::Error::other(
                "hybrid or legacy cgroup membership is not accepted for ProductionV3",
            ));
        }
    }
    unified.ok_or_else(|| io::Error::other("unified cgroup-v2 membership is absent"))
}

fn parse_absolute_cgroup_path(value: &str) -> io::Result<PathBuf> {
    let path = PathBuf::from(value);
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "cgroup path is not canonical and absolute",
        ));
    }
    Ok(path)
}

fn find_cgroup2_mount(contents: &str, cgroup_path: &Path) -> io::Result<Cgroup2Mount> {
    let mut selected: Option<Cgroup2Mount> = None;
    for line in contents.lines() {
        let Some((before, after)) = line.split_once(" - ") else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed /proc mountinfo entry",
            ));
        };
        let mut after_fields = after.split_whitespace();
        if after_fields.next() != Some("cgroup2") {
            continue;
        }
        let fields: Vec<_> = before.split_whitespace().collect();
        if fields.len() < 6 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated cgroup2 mountinfo entry",
            ));
        }
        let root = parse_absolute_cgroup_path(&decode_mountinfo_field(fields[3])?)?;
        let mount_point = parse_absolute_cgroup_path(&decode_mountinfo_field(fields[4])?)?;
        if relative_to_mount_root(cgroup_path, &root).is_ok()
            && selected
                .as_ref()
                .is_none_or(|current| root.components().count() > current.root.components().count())
        {
            selected = Some(Cgroup2Mount { root, mount_point });
        }
    }
    selected.ok_or_else(|| io::Error::other("unified cgroup-v2 control mount was not found"))
}

fn decode_mountinfo_field(value: &str) -> io::Result<String> {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut cursor = 0;
    while cursor < bytes.len() {
        if bytes[cursor] != b'\\' {
            output.push(bytes[cursor]);
            cursor += 1;
            continue;
        }
        if cursor + 3 >= bytes.len()
            || !bytes[cursor + 1..=cursor + 3]
                .iter()
                .all(u8::is_ascii_digit)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid mountinfo escape",
            ));
        }
        let octal = &bytes[cursor + 1..=cursor + 3];
        if octal.iter().any(|digit| *digit > b'7') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid mountinfo octal escape",
            ));
        }
        output.push((octal[0] - b'0') * 64 + (octal[1] - b'0') * 8 + (octal[2] - b'0'));
        cursor += 4;
    }
    String::from_utf8(output)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "mountinfo path is not UTF-8"))
}

fn relative_to_mount_root<'a>(path: &'a Path, root: &Path) -> io::Result<&'a Path> {
    path.strip_prefix(root)
        .map_err(|_| io::Error::other("cgroup membership is outside the cgroup2 mount root"))
}

fn join_cgroup_path(parent: &Path, leaf: &str) -> io::Result<PathBuf> {
    validate_leaf_name(leaf)?;
    Ok(parent.join(leaf))
}

fn validate_leaf_name(name: &str) -> io::Result<()> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.as_bytes().contains(&b'/')
        || name.as_bytes().contains(&0)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid cgroup leaf name",
        ));
    }
    Ok(())
}

fn parse_pid_list(contents: &str) -> io::Result<Vec<u32>> {
    contents
        .split_whitespace()
        .map(|value| {
            value
                .parse::<u32>()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid cgroup PID entry"))
        })
        .collect()
}

fn parse_keyed_u64(contents: &str, key: &str) -> io::Result<u64> {
    let mut found = None;
    for line in contents.lines() {
        let mut fields = line.split_whitespace();
        let Some(candidate) = fields.next() else {
            continue;
        };
        if candidate != key {
            continue;
        }
        if found.is_some() || fields.clone().count() != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed duplicate cgroup event",
            ));
        }
        found = Some(
            fields
                .next()
                .expect("one value was counted above")
                .parse::<u64>()
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid cgroup event value")
                })?,
        );
    }
    found.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "cgroup event is absent"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);
    const DELEGATED_HELPER_ENV: &str = "CMFD_CGROUP_DELEGATED_HELPER";

    fn temp_dir(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "cmfd-cgroup-{label}-{}-{}",
            std::process::id(),
            TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn unified_membership_rejects_hybrid_and_noncanonical_paths() {
        assert_eq!(
            parse_unified_membership("0::/user.slice/cmfd.service\n").unwrap(),
            PathBuf::from("/user.slice/cmfd.service")
        );
        assert!(parse_unified_membership("0::/ok\n4:cpu:/legacy\n").is_err());
        assert!(parse_unified_membership("0::relative\n").is_err());
        assert!(parse_unified_membership("0::/a/../b\n").is_err());
    }

    #[test]
    fn cgroup2_mount_parser_selects_the_most_specific_covering_mount() {
        let mountinfo = concat!(
            "29 23 0:26 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n",
            "30 29 0:26 /user.slice /delegated\\040root rw - cgroup2 cgroup rw\n"
        );
        assert_eq!(
            find_cgroup2_mount(mountinfo, Path::new("/user.slice/cmfd.service")).unwrap(),
            Cgroup2Mount {
                root: PathBuf::from("/user.slice"),
                mount_point: PathBuf::from("/delegated root"),
            }
        );
    }

    #[test]
    fn exact_readback_detects_kernel_or_hierarchy_rewrite() {
        let root = temp_dir("readback");
        let control = root.join("cpu.max");
        fs::write(&control, b"0\n").unwrap();
        configure_exact(&root, "cpu.max", "25000 100000").unwrap();
        assert_eq!(fs::read_to_string(&control).unwrap(), "25000 100000\n");
        assert!(configure_exact(&root, "missing", "1").is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn required_controller_readback_is_fail_closed() {
        let root = temp_dir("controllers");
        let control = root.join("controllers");
        fs::write(&control, b"cpu memory pids io\n").unwrap();
        require_controllers(&control).unwrap();
        fs::write(&control, b"cpu memory\n").unwrap();
        assert!(require_controllers(&control).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cgroup_limits_reject_zero_and_kernel_invalid_ranges() {
        let valid = LinuxCgroupLimits {
            cpu_quota_micros: 25_000,
            cpu_period_micros: 100_000,
            memory_bytes: 1024,
            pids: 1,
        };
        assert_eq!(valid.validate().unwrap(), valid);
        assert!(
            LinuxCgroupLimits {
                cpu_quota_micros: 0,
                ..valid
            }
            .validate()
            .is_err()
        );
        assert!(
            LinuxCgroupLimits {
                cpu_period_micros: 999,
                ..valid
            }
            .validate()
            .is_err()
        );
        assert!(
            LinuxCgroupLimits {
                memory_bytes: 0,
                ..valid
            }
            .validate()
            .is_err()
        );
        assert!(LinuxCgroupLimits { pids: 0, ..valid }.validate().is_err());
    }

    #[test]
    fn event_and_pid_parsers_are_exact() {
        assert_eq!(
            parse_keyed_u64("populated 1\nfrozen 0\n", "frozen").unwrap(),
            0
        );
        assert!(parse_keyed_u64("frozen 0 1\n", "frozen").is_err());
        assert!(parse_keyed_u64("populated 0\n", "frozen").is_err());
        assert_eq!(parse_pid_list("12\n34\n").unwrap(), vec![12, 34]);
        assert!(parse_pid_list("not-a-pid\n").is_err());
    }

    #[test]
    fn unwritable_or_wrong_type_controls_fail_closed() {
        let root = temp_dir("unwritable");
        let wrong_type = root.join("cgroup.kill");
        fs::create_dir(&wrong_type).unwrap();
        assert!(require_writable_control(&wrong_type).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn delegated_cgroup_runtime_helper() {
        if std::env::var_os(DELEGATED_HELPER_ENV).is_none() {
            return;
        }
        let mut command = std::process::Command::new("/bin/sleep");
        command
            .arg("30")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        let mut child = crate::spawn_contained_production(
            command,
            Some(256 * 1024 * 1024),
            LinuxCgroupLimits {
                cpu_quota_micros: 100_000,
                cpu_period_micros: 100_000,
                memory_bytes: 256 * 1024 * 1024,
                pids: 16,
            },
        )
        .expect("delegated ProductionV3 cgroup launch");
        child
            .freeze_after_response()
            .expect("freeze and confirm worker leaf");
        child
            .thaw_for_request()
            .expect("thaw and confirm worker leaf");
        child.terminate_and_reap();
        assert!(child.direct_child_reaped, "cgroup.kill did not reap worker");
        assert!(child.cgroup.is_none(), "worker cgroup leaf was not removed");
    }

    #[test]
    fn delegated_cgroup_v2_launch_freeze_kill_and_cleanup() {
        use std::os::unix::process::CommandExt;

        let membership = match fs::read_to_string("/proc/self/cgroup")
            .and_then(|contents| parse_unified_membership(&contents))
        {
            Ok(path) => path,
            Err(error) => {
                eprintln!("skipping delegated cgroup integration test: {error}");
                return;
            }
        };
        let mount = match fs::read_to_string("/proc/self/mountinfo")
            .and_then(|contents| find_cgroup2_mount(&contents, &membership))
        {
            Ok(mount) => mount,
            Err(error) => {
                eprintln!("skipping delegated cgroup integration test: {error}");
                return;
            }
        };
        let relative = relative_to_mount_root(&membership, &mount.root).unwrap();
        let current = mount.mount_point.join(relative);
        if require_controllers(&current.join("cgroup.subtree_control")).is_err() {
            eprintln!("skipping delegated cgroup integration test: controllers are not delegated");
            return;
        }

        let name = format!(
            "cmfd-integration-{}-{}",
            std::process::id(),
            TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        let delegated = current.join(&name);
        if let Err(error) = fs::create_dir(&delegated) {
            eprintln!("skipping delegated cgroup integration test: {error}");
            return;
        }
        let procs = match OpenOptions::new()
            .write(true)
            .open(delegated.join("cgroup.procs"))
        {
            Ok(procs) => procs,
            Err(error) => {
                let _ = fs::remove_dir(&delegated);
                eprintln!("skipping delegated cgroup integration test: {error}");
                return;
            }
        };
        let procs_fd = procs.as_raw_fd();
        let mut helper = std::process::Command::new(std::env::current_exe().unwrap());
        helper
            .arg("--exact")
            .arg("cgroup::tests::delegated_cgroup_runtime_helper")
            .arg("--nocapture")
            .env(DELEGATED_HELPER_ENV, "1")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::inherit());
        // SAFETY: only async-signal-safe write is used between fork and exec;
        // the owned descriptor remains live in the parent through spawn.
        unsafe {
            helper.pre_exec(move || {
                const SELF_PID: &[u8] = b"0\n";
                let written = libc::write(procs_fd, SELF_PID.as_ptr().cast(), SELF_PID.len());
                if written == SELF_PID.len() as libc::ssize_t {
                    Ok(())
                } else {
                    Err(io::Error::last_os_error())
                }
            });
        }
        let status = helper.status().expect("launch delegated cgroup helper");
        drop(procs);

        if let Ok(entries) = fs::read_dir(&delegated) {
            for entry in entries.flatten() {
                if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                    let _ = fs::remove_dir(entry.path());
                }
            }
        }
        let cleanup = fs::remove_dir(&delegated);
        assert!(status.success(), "delegated cgroup helper failed: {status}");
        cleanup.expect("remove empty delegated integration cgroup");
    }
}
