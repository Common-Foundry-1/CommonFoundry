//! Delegated cgroup-v2 containment for the Linux ProductionV3 verifier.
//!
//! The node must start in a writable delegated cgroup. Initialization moves
//! the whole node process into a supervisor child before enabling controllers
//! on the now-empty delegated root. Every worker generation then receives a
//! unique sibling leaf with exact, read-back resource limits.

#[cfg(test)]
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const REQUIRED_CONTROLLERS: [&str; 3] = ["cpu", "memory", "pids"];
const FREEZE_TIMEOUT: Duration = Duration::from_secs(2);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);

#[cfg(test)]
#[derive(Debug)]
pub(crate) struct DelegationUnavailable(String);

#[cfg(test)]
impl fmt::Display for DelegationUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[cfg(test)]
pub(crate) fn delegation_precheck() -> Result<(), DelegationUnavailable> {
    delegation_precheck_inner(true).map_err(|source| DelegationUnavailable(source.to_string()))
}

#[cfg(test)]
fn integration_delegation_precheck() -> Result<(), DelegationUnavailable> {
    delegation_precheck_inner(false).map_err(|source| DelegationUnavailable(source.to_string()))
}

#[cfg(test)]
fn delegation_precheck_inner(require_exclusive_process_layout: bool) -> io::Result<()> {
    let membership = fs::read_to_string("/proc/self/cgroup")?;
    let cgroup_path = parse_unified_membership(&membership)?;
    let mountinfo = fs::read_to_string("/proc/self/mountinfo")?;
    let mount = find_cgroup2_mount(&mountinfo, &cgroup_path)?;
    let relative = relative_to_mount_root(&cgroup_path, &mount.root)?;
    let current = mount.mount_point.join(relative);
    let root = test_delegated_root(&current)?;
    let root_type = root.join("cgroup.type");
    if root_type.exists() {
        require_exact_control(&root_type, "domain")?;
    } else if root != mount.mount_point {
        return Err(io::Error::other(
            "delegated non-root cgroup has no cgroup.type control",
        ));
    }
    require_controllers(&root.join("cgroup.controllers"))?;
    require_controllers(&root.join("cgroup.subtree_control"))?;
    if require_exclusive_process_layout {
        let root_processes = parse_pid_list(&fs::read_to_string(root.join("cgroup.procs"))?)?;
        let current_processes = parse_pid_list(&fs::read_to_string(current.join("cgroup.procs"))?)?;
        let process_layout_is_valid = if root == current {
            root_processes.as_slice() == [std::process::id()]
        } else {
            root_processes.is_empty() && current_processes.as_slice() == [std::process::id()]
        };
        if !process_layout_is_valid {
            return Err(io::Error::other(
                "delegated cgroup root/supervisor does not exclusively contain this test process",
            ));
        }
    }
    let mut random = [0_u8; 8];
    getrandom::fill(&mut random).map_err(|source| io::Error::other(source.to_string()))?;
    let probe = root.join(format!(
        "cmfd-delegation-probe-{}-{}",
        std::process::id(),
        hex::encode(random)
    ));
    fs::create_dir(&probe)?;
    let result = require_exact_control(&probe.join("cgroup.type"), "domain")
        .and_then(|()| require_writable_control(&probe.join("cgroup.procs")));
    let cleanup = fs::remove_dir(&probe);
    result?;
    cleanup
}

#[cfg(test)]
fn test_delegated_root(current: &Path) -> io::Result<PathBuf> {
    let supervisor_name = format!("cmfd-supervisor-{}", std::process::id());
    if current.file_name().and_then(|name| name.to_str()) == Some(supervisor_name.as_str()) {
        return current
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| io::Error::other("test supervisor cgroup has no delegated parent"));
    }
    Ok(current.to_path_buf())
}

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
    health: Arc<ContainmentHealth>,
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
            health: Arc::new(ContainmentHealth::default()),
        })
    }

    pub(crate) fn create_worker(
        &self,
        name: &str,
        limits: LinuxCgroupLimits,
    ) -> io::Result<LinuxWorkerCgroup> {
        self.health.ensure_healthy()?;
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
                health: Arc::clone(&self.health),
                #[cfg(test)]
                cleanup_busy_failures: 0,
            };
            // Exercise every action-only containment control while the leaf is
            // empty. Production must fail before exec if the delegated root
            // merely exposes these files without permitting the operations.
            worker.freeze()?;
            worker.thaw()?;
            worker.kill()?;
            Ok(worker)
        })();
        match result {
            Ok(worker) => Ok(worker),
            Err(source) => {
                if let Err(cleanup) = cleanup_leaf_path(&path, CLEANUP_TIMEOUT, None) {
                    self.health.poison(
                        &path,
                        "cleaning a failed ProductionV3 cgroup setup",
                        &cleanup,
                    );
                    return Err(io::Error::other(format!(
                        "worker cgroup setup failed: {source}; setup cleanup failed: {cleanup}"
                    )));
                }
                Err(source)
            }
        }
    }
}

#[derive(Debug, Default)]
struct ContainmentHealth {
    failure: Mutex<Option<String>>,
}

impl ContainmentHealth {
    fn ensure_healthy(&self) -> io::Result<()> {
        let failure = match self.failure.lock() {
            Ok(failure) => failure,
            Err(poisoned) => poisoned.into_inner(),
        };
        match failure.as_deref() {
            Some(failure) => Err(io::Error::other(format!(
                "ProductionV3 cgroup containment is poisoned: {failure}"
            ))),
            None => Ok(()),
        }
    }

    fn poison(&self, path: &Path, operation: &str, source: &io::Error) {
        let mut failure = match self.failure.lock() {
            Ok(failure) => failure,
            Err(poisoned) => poisoned.into_inner(),
        };
        if failure.is_none() {
            *failure = Some(format!(
                "{operation} for {} failed: {source}",
                path.display()
            ));
        }
    }
}

#[derive(Debug)]
pub(crate) struct LinuxWorkerCgroup {
    path: PathBuf,
    expected_membership: PathBuf,
    procs: Option<File>,
    health: Arc<ContainmentHealth>,
    #[cfg(test)]
    cleanup_busy_failures: usize,
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
        let result = (|| {
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
            if direct.as_slice() != [pid] {
                return Err(io::Error::other(format!(
                    "worker cgroup must contain only PID {pid}, found {direct:?}"
                )));
            }
            Ok(())
        })();
        if let Err(source) = &result {
            self.health.poison(
                &self.path,
                "confirming exact ProductionV3 worker membership",
                source,
            );
        }
        result
    }

    pub(crate) fn freeze(&self) -> io::Result<()> {
        self.set_frozen(true)
    }

    pub(crate) fn thaw(&self) -> io::Result<()> {
        self.set_frozen(false)
    }

    fn set_frozen(&self, frozen: bool) -> io::Result<()> {
        let result = (|| {
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
        })();
        if let Err(source) = &result {
            self.health.poison(
                &self.path,
                if frozen {
                    "freezing the ProductionV3 worker cgroup"
                } else {
                    "thawing the ProductionV3 worker cgroup"
                },
                source,
            );
        }
        result
    }

    /// `cgroup.kill` is the authoritative descendant-safe termination path.
    pub(crate) fn kill(&self) -> io::Result<()> {
        let result = write_control(&self.path.join("cgroup.kill"), "1");
        if let Err(source) = &result {
            self.health
                .poison(&self.path, "killing the ProductionV3 worker cgroup", source);
        }
        result
    }

    pub(crate) fn cleanup(&mut self) -> io::Result<()> {
        self.cleanup_for(CLEANUP_TIMEOUT)
    }

    fn cleanup_for(&mut self, timeout: Duration) -> io::Result<()> {
        self.procs.take();
        #[cfg(test)]
        let injected_busy = Some(&mut self.cleanup_busy_failures);
        #[cfg(not(test))]
        let injected_busy = None;
        let result = cleanup_leaf_path(&self.path, timeout, injected_busy);
        if let Err(source) = &result {
            self.health.poison(
                &self.path,
                "removing the empty ProductionV3 worker cgroup",
                source,
            );
        }
        result
    }

    pub(crate) fn ensure_healthy(&self) -> io::Result<()> {
        self.health.ensure_healthy()
    }

    pub(crate) fn poison(&self, operation: &str, source: &io::Error) {
        self.health.poison(&self.path, operation, source);
    }

    #[cfg(test)]
    fn set_cleanup_busy_failures(&mut self, failures: usize) {
        self.cleanup_busy_failures = failures;
    }
}

fn cleanup_leaf_path(
    path: &Path,
    timeout: Duration,
    mut injected_busy: Option<&mut usize>,
) -> io::Result<()> {
    let started = Instant::now();
    loop {
        let events = match fs::read_to_string(path.join("cgroup.events")) {
            Ok(events) => events,
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                match fs::symlink_metadata(path) {
                    Err(missing) if missing.kind() == io::ErrorKind::NotFound => return Ok(()),
                    Ok(_) => return Err(source),
                    Err(metadata) => return Err(metadata),
                }
            }
            Err(source) => return Err(source),
        };
        let populated = parse_keyed_u64(&events, "populated")?;
        let result = if populated != 0 {
            Err(io::Error::from_raw_os_error(libc::EBUSY))
        } else if injected_busy
            .as_deref()
            .is_some_and(|remaining| *remaining > 0)
        {
            if let Some(remaining) = injected_busy.as_deref_mut() {
                *remaining = remaining.saturating_sub(1);
            }
            Err(io::Error::from_raw_os_error(libc::EBUSY))
        } else {
            fs::remove_dir(path)
        };
        match result {
            Ok(()) => return Ok(()),
            Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(source) if is_resource_busy(&source) && started.elapsed() < timeout => {
                thread::sleep(Duration::from_millis(1));
            }
            Err(source) => return Err(source),
        }
    }
}

fn is_resource_busy(source: &io::Error) -> bool {
    source.kind() == io::ErrorKind::ResourceBusy || source.raw_os_error() == Some(libc::EBUSY)
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
    const HELPER_POSITIVE: &str = "positive";
    const HELPER_EXTRA_PROCESS: &str = "extra-process";
    const HELPER_WAIT_ERROR: &str = "wait-error";
    const HELPER_WAIT_TIMEOUT: &str = "wait-timeout";
    const HELPER_CLEANUP_BUSY: &str = "cleanup-busy";
    const HELPER_SUCCESSIVE_EXCHANGE: &str = "successive-exchange";

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
    fn cleanup_does_not_confuse_a_missing_events_control_with_a_removed_leaf() {
        let existing = temp_dir("missing-events");
        assert!(cleanup_leaf_path(&existing, Duration::ZERO, None).is_err());
        fs::remove_dir(&existing).unwrap();
        cleanup_leaf_path(&existing, Duration::ZERO, None).unwrap();
    }

    #[test]
    fn unwritable_or_wrong_type_controls_fail_closed() {
        let root = temp_dir("unwritable");
        let wrong_type = root.join("cgroup.kill");
        fs::create_dir(&wrong_type).unwrap();
        assert!(require_writable_control(&wrong_type).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    fn test_limits() -> LinuxCgroupLimits {
        LinuxCgroupLimits {
            cpu_quota_micros: 100_000,
            cpu_period_micros: 100_000,
            memory_bytes: 256 * 1024 * 1024,
            pids: 16,
        }
    }

    fn sleep_command() -> std::process::Command {
        let mut command = std::process::Command::new("/bin/sleep");
        command
            .arg("30")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        command
    }

    fn worker_leaf_names(root: &Path) -> Vec<String> {
        let mut leaves: Vec<_> = fs::read_dir(root)
            .expect("read delegated test root")
            .map(|entry| entry.expect("read delegated child").file_name())
            .filter_map(|name| name.into_string().ok())
            .filter(|name| name.starts_with("cmfd-worker-"))
            .collect();
        leaves.sort();
        leaves
    }

    fn assert_no_worker_leaves(root: &Path) {
        assert_eq!(worker_leaf_names(root), Vec::<String>::new());
    }

    fn direct_worker(manager: &LinuxCgroupManager, label: &str) -> crate::ContainedChild {
        let name = format!(
            "cmfd-worker-{label}-{}-{}",
            std::process::id(),
            TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        let worker = manager
            .create_worker(&name, test_limits())
            .expect("create direct test worker leaf");
        let mut command = sleep_command();
        crate::spawn_contained_unix(
            &mut command,
            Some(test_limits().memory_bytes),
            true,
            Some(worker),
        )
        .expect("launch direct contained test worker")
    }

    fn current_worker_parent() -> PathBuf {
        let membership = parse_unified_membership(
            &fs::read_to_string("/proc/self/cgroup").expect("read helper cgroup membership"),
        )
        .expect("parse helper cgroup membership");
        let mount = find_cgroup2_mount(
            &fs::read_to_string("/proc/self/mountinfo").expect("read helper mountinfo"),
            &membership,
        )
        .expect("find helper cgroup2 mount");
        let current = mount
            .mount_point
            .join(relative_to_mount_root(&membership, &mount.root).expect("map helper cgroup"));
        if current
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("cmfd-supervisor-"))
        {
            current
                .parent()
                .expect("supervisor cgroup has a delegated parent")
                .to_path_buf()
        } else {
            current
        }
    }

    fn positive_helper() {
        let mut child = crate::spawn_contained_production(
            sleep_command(),
            Some(test_limits().memory_bytes),
            test_limits(),
        )
        .expect("delegated ProductionV3 cgroup launch");
        child
            .freeze_after_response()
            .expect("freeze and confirm worker leaf");
        child
            .thaw_for_request()
            .expect("thaw and confirm worker leaf");
        child.terminate_and_reap().expect("kill and reap worker");
        assert!(child.direct_child_reaped, "cgroup.kill did not reap worker");
        assert!(child.cgroup.is_none(), "worker cgroup leaf was not removed");
        assert_no_worker_leaves(&current_worker_parent());
    }

    fn extra_process_helper() {
        use std::os::unix::process::CommandExt;

        let manager = LinuxCgroupManager::initialize().expect("initialize delegated manager");
        let name = format!(
            "cmfd-worker-extra-{}-{}",
            std::process::id(),
            TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        let worker = manager
            .create_worker(&name, test_limits())
            .expect("create extra-process worker leaf");
        let procs_fd = worker.procs_fd();
        let mut extra_command = sleep_command();
        // SAFETY: only an async-signal-safe write is used before exec and the
        // worker object retains the already-open cgroup.procs descriptor.
        unsafe {
            extra_command.pre_exec(move || {
                const SELF_PID: &[u8] = b"0\n";
                let written = libc::write(procs_fd, SELF_PID.as_ptr().cast(), SELF_PID.len());
                if written == SELF_PID.len() as libc::ssize_t {
                    Ok(())
                } else {
                    Err(io::Error::last_os_error())
                }
            });
        }
        let mut extra = extra_command
            .spawn()
            .expect("launch injected extra process");
        let mut target = sleep_command();
        let launch = crate::spawn_contained_unix(
            &mut target,
            Some(test_limits().memory_bytes),
            true,
            Some(worker),
        );
        assert!(
            matches!(launch, Err(crate::ProofWorkerError::Containment { .. })),
            "extra direct process must reject the launch"
        );
        let extra_status = extra.wait().expect("reap injected extra process");
        assert!(
            !extra_status.success(),
            "cgroup.kill did not kill extra process"
        );
        assert_no_worker_leaves(&manager.delegated_root);
        assert!(
            manager
                .create_worker("cmfd-worker-after-membership-poison", test_limits())
                .is_err(),
            "membership violation did not poison future generations"
        );
    }

    fn wait_error_helper() {
        let manager = LinuxCgroupManager::initialize().expect("initialize delegated manager");
        let mut transient = direct_worker(&manager, "transient-wait-error");
        transient.set_reap_fault(crate::TestReapFault::ErrorsRemaining(3));
        transient
            .terminate_and_reap_for(Duration::from_millis(250))
            .expect("bounded reap retried transient wait errors");
        assert!(transient.direct_child_reaped);
        assert!(transient.cgroup.is_none());
        assert_no_worker_leaves(&manager.delegated_root);

        let mut persistent = direct_worker(&manager, "persistent-wait-error");
        persistent.set_reap_fault(crate::TestReapFault::AlwaysError);
        assert!(
            persistent
                .terminate_and_reap_for(Duration::from_millis(10))
                .is_err()
        );
        assert!(!persistent.direct_child_reaped);
        assert!(persistent.cgroup.is_some());
        persistent.set_reap_fault(crate::TestReapFault::None);
        assert!(
            persistent
                .terminate_and_reap_for(Duration::from_millis(250))
                .is_err(),
            "poisoned containment health must remain actionable after cleanup"
        );
        assert!(persistent.direct_child_reaped);
        assert!(persistent.cgroup.is_none());
        assert_no_worker_leaves(&manager.delegated_root);
        assert!(
            manager
                .create_worker("cmfd-worker-after-wait-error", test_limits())
                .is_err()
        );
    }

    fn wait_timeout_helper() {
        let manager = LinuxCgroupManager::initialize().expect("initialize delegated manager");
        let mut child = direct_worker(&manager, "wait-timeout");
        child.set_reap_fault(crate::TestReapFault::AlwaysPending);
        assert!(
            child
                .terminate_and_reap_for(Duration::from_millis(10))
                .is_err()
        );
        assert!(!child.direct_child_reaped);
        assert!(child.cgroup.is_some());
        child.set_reap_fault(crate::TestReapFault::None);
        assert!(
            child
                .terminate_and_reap_for(Duration::from_millis(250))
                .is_err()
        );
        assert!(child.direct_child_reaped);
        assert!(child.cgroup.is_none());
        assert_no_worker_leaves(&manager.delegated_root);
        assert!(
            manager
                .create_worker("cmfd-worker-after-wait-timeout", test_limits())
                .is_err()
        );
    }

    fn cleanup_busy_helper() {
        let manager = LinuxCgroupManager::initialize().expect("initialize delegated manager");
        let mut transient = manager
            .create_worker("cmfd-worker-transient-ebusy", test_limits())
            .expect("create transient EBUSY leaf");
        transient.set_cleanup_busy_failures(3);
        transient
            .cleanup_for(Duration::from_millis(250))
            .expect("cleanup retried repeated EBUSY");
        assert_no_worker_leaves(&manager.delegated_root);

        let mut persistent = manager
            .create_worker("cmfd-worker-persistent-ebusy", test_limits())
            .expect("create persistent EBUSY leaf");
        persistent.set_cleanup_busy_failures(usize::MAX);
        assert!(persistent.cleanup_for(Duration::from_millis(10)).is_err());
        assert!(
            manager
                .create_worker("cmfd-worker-after-cleanup-poison", test_limits())
                .is_err(),
            "failed cleanup did not poison future generations"
        );
        persistent.set_cleanup_busy_failures(0);
        persistent
            .cleanup_for(Duration::from_millis(250))
            .expect("explicit retry removed poisoned empty leaf");
        assert_no_worker_leaves(&manager.delegated_root);
    }

    fn cat_command() -> std::process::Command {
        let mut command = std::process::Command::new("/bin/cat");
        command
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        command
    }

    fn successive_exchange_helper() {
        for request in [b"first generation\n".as_slice(), b"second generation\n"] {
            let child = crate::spawn_contained_production(
                cat_command(),
                Some(test_limits().memory_bytes),
                test_limits(),
            )
            .expect("launch delegated one-shot worker generation");
            let response =
                crate::exchange_with_child(child, request.to_vec(), Duration::from_secs(2), 1024)
                    .expect("complete delegated one-shot worker exchange");
            assert_eq!(response, request);
            assert_no_worker_leaves(&current_worker_parent());
        }
    }

    #[test]
    fn delegated_cgroup_runtime_helper() {
        match std::env::var(DELEGATED_HELPER_ENV).as_deref() {
            Err(_) => {}
            Ok(HELPER_POSITIVE) => positive_helper(),
            Ok(HELPER_EXTRA_PROCESS) => extra_process_helper(),
            Ok(HELPER_WAIT_ERROR) => wait_error_helper(),
            Ok(HELPER_WAIT_TIMEOUT) => wait_timeout_helper(),
            Ok(HELPER_CLEANUP_BUSY) => cleanup_busy_helper(),
            Ok(HELPER_SUCCESSIVE_EXCHANGE) => successive_exchange_helper(),
            Ok(mode) => panic!("unknown delegated helper mode {mode:?}"),
        }
    }

    fn prepare_delegated_helper_root() -> io::Result<(PathBuf, File)> {
        let membership = parse_unified_membership(&fs::read_to_string("/proc/self/cgroup")?)?;
        let mount = find_cgroup2_mount(&fs::read_to_string("/proc/self/mountinfo")?, &membership)?;
        let relative = relative_to_mount_root(&membership, &mount.root)?;
        let current = mount.mount_point.join(relative);
        let delegated_root = test_delegated_root(&current)?;
        require_controllers(&delegated_root.join("cgroup.subtree_control"))?;
        let name = format!(
            "cmfd-integration-{}-{}",
            std::process::id(),
            TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        let delegated = delegated_root.join(name);
        fs::create_dir(&delegated)?;
        let procs = OpenOptions::new()
            .write(true)
            .open(delegated.join("cgroup.procs"))?;
        Ok((delegated, procs))
    }

    fn run_delegated_helper(mode: &str) {
        use std::os::unix::process::CommandExt;

        if let Err(unavailable) = integration_delegation_precheck() {
            eprintln!("skipping delegated cgroup integration test: {unavailable}");
            return;
        }
        let (delegated, procs) =
            prepare_delegated_helper_root().expect("prepare isolated delegated helper root");
        let procs_fd = procs.as_raw_fd();
        let mut helper = std::process::Command::new(std::env::current_exe().unwrap());
        helper
            .arg("--exact")
            .arg("cgroup::tests::delegated_cgroup_runtime_helper")
            .arg("--nocapture")
            .env(DELEGATED_HELPER_ENV, mode)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::inherit());
        // SAFETY: only an async-signal-safe write is used between fork and
        // exec; the owned descriptor remains live in the parent through spawn.
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

        let entries: Vec<_> = fs::read_dir(&delegated)
            .expect("read delegated helper root")
            .map(|entry| entry.expect("read helper child cgroup"))
            .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
            .collect();
        let worker_leaves: Vec<_> = entries
            .iter()
            .filter_map(|entry| entry.file_name().into_string().ok())
            .filter(|name| name.starts_with("cmfd-worker-"))
            .collect();
        for entry in entries {
            let path = entry.path();
            let _ = write_control(&path.join("cgroup.kill"), "1");
            cleanup_leaf_path(&path, CLEANUP_TIMEOUT, None)
                .expect("remove empty helper child cgroup");
        }
        fs::remove_dir(&delegated).expect("remove delegated integration cgroup");
        assert!(status.success(), "delegated cgroup helper failed: {status}");
        assert!(
            worker_leaves.is_empty(),
            "delegated helper leaked worker leaves: {worker_leaves:?}"
        );
    }

    #[test]
    fn delegated_cgroup_v2_launch_freeze_kill_and_cleanup() {
        run_delegated_helper(HELPER_POSITIVE);
    }

    #[test]
    fn delegated_cgroup_rejects_extra_direct_process_and_cleans_leaf() {
        run_delegated_helper(HELPER_EXTRA_PROCESS);
    }

    #[test]
    fn delegated_cgroup_retries_wait_errors_then_poison_fails_closed() {
        run_delegated_helper(HELPER_WAIT_ERROR);
    }

    #[test]
    fn delegated_cgroup_wait_timeout_retains_then_cleans_poisoned_leaf() {
        run_delegated_helper(HELPER_WAIT_TIMEOUT);
    }

    #[test]
    fn delegated_cgroup_retries_ebusy_and_preserves_cleanup_poison() {
        run_delegated_helper(HELPER_CLEANUP_BUSY);
    }

    #[test]
    fn delegated_cgroup_successful_exchange_allows_a_second_generation() {
        run_delegated_helper(HELPER_SUCCESSIVE_EXCHANGE);
    }
}
