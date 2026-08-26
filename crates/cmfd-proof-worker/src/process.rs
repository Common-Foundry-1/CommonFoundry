use std::io::{self, Read, Write};
use std::process::{Child, ExitStatus};

/// Owned blocking byte stream read from a verifier child.
pub(crate) type BlockingPipeReader = Box<dyn Read + Send + 'static>;
/// Owned blocking byte stream written to a verifier child.
pub(crate) type BlockingPipeWriter = Box<dyn Write + Send + 'static>;

/// Process lifecycle and standard-pipe ownership shared by ordinary and
/// security-token-specific Windows launches.
pub(crate) enum ManagedProcess {
    Std(Child),
    #[cfg(windows)]
    #[allow(dead_code)] // Constructed by the AppContainer launcher tranche.
    Win32(Box<Win32Child>),
}

impl ManagedProcess {
    pub(crate) fn from_std(child: Child) -> Self {
        Self::Std(child)
    }

    #[cfg(windows)]
    #[allow(dead_code)] // Constructed by the AppContainer launcher tranche.
    pub(crate) fn from_win32(child: Win32Child) -> Self {
        Self::Win32(Box::new(child))
    }

    pub(crate) fn id(&self) -> u32 {
        match self {
            Self::Std(child) => child.id(),
            #[cfg(windows)]
            Self::Win32(child) => child.id(),
        }
    }

    pub(crate) fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        match self {
            Self::Std(child) => child.try_wait(),
            #[cfg(windows)]
            Self::Win32(child) => child.try_wait(),
        }
    }

    pub(crate) fn kill(&mut self) -> io::Result<()> {
        match self {
            Self::Std(child) => child.kill(),
            #[cfg(windows)]
            Self::Win32(child) => child.kill(),
        }
    }

    pub(crate) fn take_stdin(&mut self) -> Option<BlockingPipeWriter> {
        match self {
            Self::Std(child) => child
                .stdin
                .take()
                .map(|pipe| Box::new(pipe) as BlockingPipeWriter),
            #[cfg(windows)]
            Self::Win32(child) => child.take_stdin(),
        }
    }

    pub(crate) fn take_stdout(&mut self) -> Option<BlockingPipeReader> {
        match self {
            Self::Std(child) => child
                .stdout
                .take()
                .map(|pipe| Box::new(pipe) as BlockingPipeReader),
            #[cfg(windows)]
            Self::Win32(child) => child.take_stdout(),
        }
    }

    pub(crate) fn take_stderr(&mut self) -> Option<BlockingPipeReader> {
        match self {
            Self::Std(child) => child
                .stderr
                .take()
                .map(|pipe| Box::new(pipe) as BlockingPipeReader),
            #[cfg(windows)]
            Self::Win32(child) => child.take_stderr(),
        }
    }
}

/// Owned process and pipe handles returned by a direct Win32 launch.
///
/// The AppContainer launcher will construct this type without converting the
/// process handle into `std::process::Child`. Keeping that ownership native is
/// required because Rust does not expose a sound raw-handle constructor for
/// `Child`.
#[cfg(windows)]
pub(crate) struct Win32Child {
    process: std::os::windows::io::OwnedHandle,
    process_id: u32,
    exit_status: Option<ExitStatus>,
    appcontainer_profile: Option<WindowsAppContainerProfile>,
    private_runtime: Option<WindowsPrivateRuntime>,
    stdin: Option<BlockingPipeWriter>,
    stdout: Option<BlockingPipeReader>,
    stderr: Option<BlockingPipeReader>,
}

/// Exact per-launch executable objects retained until the contained process
/// exits. Holding all three handles without write/delete sharing prevents the
/// configured source, verified destination, or destination directory from
/// being replaced during CreateProcess image resolution or process lifetime.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WindowsFileIdentity {
    pub(crate) volume_serial: u64,
    pub(crate) file_id: [u8; 16],
}

#[cfg(windows)]
pub(crate) struct WindowsPrivateRuntime {
    source: Option<std::fs::File>,
    directory_handle: Option<std::fs::File>,
    executable_handle: Option<std::fs::File>,
    directory: std::path::PathBuf,
    executable: std::path::PathBuf,
    directory_identity: WindowsFileIdentity,
    executable_identity: WindowsFileIdentity,
    directory_deleted: bool,
    executable_deleted: bool,
    cleaned: bool,
}

#[cfg(windows)]
impl WindowsPrivateRuntime {
    pub(crate) fn new(
        source: std::fs::File,
        directory_handle: std::fs::File,
        executable_handle: std::fs::File,
        directory: std::path::PathBuf,
        executable: std::path::PathBuf,
        directory_identity: WindowsFileIdentity,
        executable_identity: WindowsFileIdentity,
    ) -> Self {
        Self {
            source: Some(source),
            directory_handle: Some(directory_handle),
            executable_handle: Some(executable_handle),
            directory,
            executable,
            directory_identity,
            executable_identity,
            directory_deleted: false,
            executable_deleted: false,
            cleaned: false,
        }
    }

    pub(crate) fn cleanup(&mut self) -> io::Result<()> {
        if self.cleaned {
            return Ok(());
        }
        // Mark each exact retained object delete-pending before releasing its
        // handle. Cleanup never closes a pin and reopens a pathname.
        if !self.executable_deleted {
            let executable_handle = self.executable_handle.as_ref().ok_or_else(|| {
                io::Error::other("private runtime executable cleanup handle is unavailable")
            })?;
            delete_exact_runtime_handle(executable_handle, false, self.executable_identity)
                .map_err(|error| {
                    io::Error::new(
                        error.kind(),
                        format!(
                            "cleaning private Windows verifier executable {} failed: {error}",
                            self.executable.display()
                        ),
                    )
                })?;
            self.executable_handle.take();
            self.executable_deleted = true;
        }
        if !self.directory_deleted {
            let directory_handle = self.directory_handle.as_ref().ok_or_else(|| {
                io::Error::other("private runtime directory cleanup handle is unavailable")
            })?;
            delete_exact_runtime_handle(directory_handle, true, self.directory_identity).map_err(
                |error| {
                    io::Error::new(
                        error.kind(),
                        format!(
                            "cleaning private Windows verifier directory {} failed: {error}",
                            self.directory.display()
                        ),
                    )
                },
            )?;
            self.directory_handle.take();
            self.directory_deleted = true;
        }
        self.source.take();
        self.cleaned = true;
        Ok(())
    }
}

#[cfg(windows)]
pub(crate) fn windows_file_identity(object: &std::fs::File) -> io::Result<WindowsFileIdentity> {
    use std::mem::MaybeUninit;
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ID_INFO, FileIdInfo, GetFileInformationByHandleEx,
    };

    let mut identity = MaybeUninit::<FILE_ID_INFO>::zeroed();
    // SAFETY: `object` is live and the output points to the exact documented
    // FILE_ID_INFO layout. Failure is propagated; there is deliberately no
    // fallback to the narrower legacy file index.
    if unsafe {
        GetFileInformationByHandleEx(
            object.as_raw_handle(),
            FileIdInfo,
            identity.as_mut_ptr().cast(),
            std::mem::size_of::<FILE_ID_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::new(
            io::Error::last_os_error().kind(),
            format!(
                "querying the 128-bit FILE_ID_INFO identity failed: {}",
                io::Error::last_os_error()
            ),
        ));
    }
    // SAFETY: the successful API call initialized the complete structure.
    let identity = unsafe { identity.assume_init() };
    Ok(WindowsFileIdentity {
        volume_serial: identity.VolumeSerialNumber,
        file_id: identity.FileId.Identifier,
    })
}

#[cfg(windows)]
pub(crate) fn delete_exact_runtime_handle(
    object: &std::fs::File,
    directory: bool,
    expected_identity: WindowsFileIdentity,
) -> io::Result<()> {
    delete_exact_runtime_handle_with_hook(object, directory, expected_identity, || Ok(()))
}

#[cfg(windows)]
fn delete_exact_runtime_handle_with_hook(
    object: &std::fs::File,
    directory: bool,
    expected_identity: WindowsFileIdentity,
    before_disposition: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    use std::mem::MaybeUninit;
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_DISPOSITION_INFO, FileDispositionInfo, GetFileInformationByHandle,
        SetFileInformationByHandle,
    };
    if windows_file_identity(object)? != expected_identity {
        return Err(io::Error::other(
            "private runtime cleanup handle identity changed",
        ));
    }
    let mut information = MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::zeroed();
    // SAFETY: `object` is live and `information` is writable for the exact API
    // structure size.
    if unsafe { GetFileInformationByHandle(object.as_raw_handle(), information.as_mut_ptr()) } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the successful call initialized the complete structure.
    let information = unsafe { information.assume_init() };
    let observed_directory = information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
    if observed_directory != directory
        || information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || information.nNumberOfLinks != 1
    {
        return Err(io::Error::other(
            "private runtime cleanup handle is not the exact regular single-link object",
        ));
    }
    before_disposition()?;
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: `object` has DELETE access and the disposition structure has the
    // exact documented layout. The operation targets the already-verified
    // handle, not a second pathname lookup.
    if unsafe {
        SetFileInformationByHandle(
            object.as_raw_handle(),
            FileDispositionInfo,
            (&raw const disposition).cast(),
            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // Re-query through the same delete-pending handle. A hard link inserted
    // between the first validation and disposition is detected and causes the
    // disposition to be cleared before cleanup reports failure. Once the
    // single-link object is delete-pending, a new alias cannot be created.
    let post_identity = windows_file_identity(object);
    let mut post_information = MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::zeroed();
    let post_information_result = if unsafe {
        GetFileInformationByHandle(object.as_raw_handle(), post_information.as_mut_ptr())
    } == 0
    {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: the successful call initialized the complete structure.
        Ok(unsafe { post_information.assume_init() })
    };
    let post_valid = post_identity
        .as_ref()
        .is_ok_and(|identity| *identity == expected_identity)
        && post_information_result.as_ref().is_ok_and(|information| {
            information.nNumberOfLinks == 0
                && (information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) == directory
                && information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
        });
    if !post_valid {
        let clear = FILE_DISPOSITION_INFO { DeleteFile: false };
        let cleared = unsafe {
            SetFileInformationByHandle(
                object.as_raw_handle(),
                FileDispositionInfo,
                (&raw const clear).cast(),
                std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
            )
        };
        let identity_status = match post_identity {
            Ok(identity) if identity == expected_identity => "matched",
            Ok(_) => "mismatched",
            Err(_) => "query-failed",
        };
        let information_status = post_information_result
            .as_ref()
            .map(|information| information.nNumberOfLinks.to_string())
            .unwrap_or_else(|_| "query-failed".to_owned());
        return Err(io::Error::other(format!(
            "private runtime object changed during retained-handle deletion; disposition_clear={}; identity={identity_status}; links={information_status}",
            cleared != 0
        )));
    }
    Ok(())
}

#[cfg(windows)]
impl Drop for WindowsPrivateRuntime {
    fn drop(&mut self) {
        if self.cleanup().is_err() {
            APPCONTAINER_CLEANUP_UNHEALTHY.store(true, std::sync::atomic::Ordering::Release);
        }
    }
}

/// One uniquely created per-user AppContainer profile retained until its
/// process has exited. The launcher never adopts an existing profile, so this
/// guard can delete only storage that this launch created.
#[cfg(windows)]
pub(crate) struct WindowsAppContainerProfile {
    name: Vec<u16>,
    ledger_entry: Option<ProfileLedgerEntry>,
    active_registration: bool,
    deleted: bool,
    #[cfg(test)]
    forced_delete_failures: Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>,
}

#[cfg(windows)]
struct ProfileLedgerEntry {
    path: std::path::PathBuf,
    file: Option<std::fs::File>,
    identity: WindowsFileIdentity,
    removed: bool,
    #[cfg(test)]
    forced_remove_failures: Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>,
}

#[cfg(windows)]
impl ProfileLedgerEntry {
    fn remove(&mut self) -> io::Result<()> {
        if self.removed {
            return Ok(());
        }
        #[cfg(test)]
        if let Some(failures) = &self.forced_remove_failures
            && failures
                .fetch_update(
                    std::sync::atomic::Ordering::AcqRel,
                    std::sync::atomic::Ordering::Acquire,
                    |remaining| {
                        if remaining == 0 {
                            None
                        } else {
                            Some(remaining - 1)
                        }
                    },
                )
                .is_ok()
        {
            return Err(io::Error::other(
                "forced exact profile-marker deletion failure",
            ));
        }
        let file = self
            .file
            .as_ref()
            .ok_or_else(|| io::Error::other("profile ledger cleanup handle is unavailable"))?;
        delete_exact_runtime_handle(file, false, self.identity).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "removing exact profile ledger marker {} failed: {error}",
                    self.path.display()
                ),
            )
        })?;
        self.file.take();
        self.removed = true;
        Ok(())
    }

    fn quarantine(mut self) {
        if let Some(file) = self.file.take() {
            quarantine_profile_ledger_handle(file);
        }
        self.removed = true;
    }
}

#[cfg(windows)]
impl Drop for ProfileLedgerEntry {
    fn drop(&mut self) {
        if self.remove().is_err() {
            if let Some(file) = self.file.take() {
                // Preserve the exact marker pin after uncertain cleanup. The
                // health latch blocks further launches in this process and a
                // later process treats the marker only as quarantine state.
                quarantine_profile_ledger_handle(file);
            }
            APPCONTAINER_CLEANUP_UNHEALTHY.store(true, std::sync::atomic::Ordering::Release);
        }
    }
}

#[cfg(windows)]
pub(crate) struct WindowsAppContainerProfileIntent {
    name: Vec<u16>,
    ledger_entry: Option<ProfileLedgerEntry>,
    active_registration: bool,
    completed: bool,
}

#[cfg(windows)]
static APPCONTAINER_CLEANUP_UNHEALTHY: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(windows)]
static PROFILE_LEDGER_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(windows)]
static ACTIVE_APPCONTAINER_PROFILES: std::sync::LazyLock<
    std::sync::Mutex<std::collections::BTreeSet<Vec<u16>>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::BTreeSet::new()));

#[cfg(windows)]
struct ProfileLedgerSession {
    directory: std::path::PathBuf,
    directory_handle: Option<std::fs::File>,
    directory_identity: WindowsFileIdentity,
    lock_handle: Option<std::fs::File>,
    lock_identity: WindowsFileIdentity,
    removed: bool,
}

#[cfg(windows)]
impl ProfileLedgerSession {
    fn remove_exact(&mut self) -> io::Result<()> {
        self.remove_exact_with_hook(|| Ok(()))
    }

    fn remove_exact_with_hook(
        &mut self,
        after_lock_disposition: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<()> {
        if self.removed {
            return Ok(());
        }
        let lock = self.lock_handle.as_ref().ok_or_else(|| {
            io::Error::other("cleanup ledger lock deletion handle is unavailable")
        })?;
        delete_exact_runtime_handle(lock, false, self.lock_identity)?;
        self.lock_handle.take();
        after_lock_disposition()?;
        let directory = self.directory_handle.as_ref().ok_or_else(|| {
            io::Error::other("cleanup ledger directory deletion handle is unavailable")
        })?;
        delete_exact_runtime_handle(directory, true, self.directory_identity)?;
        self.directory_handle.take();
        self.removed = true;
        Ok(())
    }

    fn quarantine(&mut self) {
        if let Some(lock) = self.lock_handle.take() {
            quarantine_profile_ledger_handle(lock);
        }
        if let Some(directory) = self.directory_handle.take() {
            quarantine_profile_ledger_handle(directory);
        }
        self.removed = true;
    }

    #[cfg(test)]
    fn release_without_deletion_for_test(&mut self) {
        self.lock_handle.take();
        self.directory_handle.take();
        self.removed = true;
    }
}

#[cfg(windows)]
impl Drop for ProfileLedgerSession {
    fn drop(&mut self) {
        if !self.removed {
            self.quarantine();
            APPCONTAINER_CLEANUP_UNHEALTHY.store(true, std::sync::atomic::Ordering::Release);
        }
    }
}

#[cfg(windows)]
static PROFILE_LEDGER_SESSION: std::sync::LazyLock<std::sync::Mutex<Option<ProfileLedgerSession>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(None));

#[cfg(windows)]
static QUARANTINED_PROFILE_LEDGER_HANDLES: std::sync::LazyLock<
    std::sync::Mutex<Vec<std::fs::File>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(Vec::new()));

#[cfg(windows)]
fn quarantine_profile_ledger_handle(file: std::fs::File) {
    match QUARANTINED_PROFILE_LEDGER_HANDLES.lock() {
        Ok(mut handles) => handles.push(file),
        Err(_) => std::mem::forget(file),
    }
}

#[cfg(windows)]
const PROFILE_LEDGER_DIRECTORY: &str = "AppContainerProfileCleanupV1";

#[cfg(windows)]
const PROFILE_NAME_PREFIX: &str = "CMFD.Verifier.";

#[cfg(windows)]
fn validate_profile_name(name: &[u16]) -> io::Result<()> {
    if name.len() < 2 || name.last() != Some(&0) || name[..name.len() - 1].contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "AppContainer profile name must contain one trailing NUL",
        ));
    }
    let decoded = String::from_utf16(&name[..name.len() - 1]).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "AppContainer profile name is not valid UTF-16",
        )
    })?;
    if !decoded.starts_with(PROFILE_NAME_PREFIX)
        || !decoded
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "AppContainer profile name is outside the owned CMFD namespace",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn production_profile_ledger_root() -> io::Result<std::path::PathBuf> {
    let local = std::env::var_os("LOCALAPPDATA")
        .map(std::path::PathBuf::from)
        .ok_or_else(|| io::Error::other("LOCALAPPDATA is unavailable for cleanup ledger"))?;
    Ok(local.join("CommonFoundry").join(PROFILE_LEDGER_DIRECTORY))
}

#[cfg(all(windows, not(test)))]
fn profile_ledger_root() -> io::Result<std::path::PathBuf> {
    production_profile_ledger_root()
}

#[cfg(all(windows, test))]
static TEST_PROFILE_LEDGER_ROOT: std::sync::LazyLock<std::path::PathBuf> =
    std::sync::LazyLock::new(|| {
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).expect("choose an isolated test cleanup-ledger root");
        std::env::temp_dir().join(format!(
            "cmfd-appcontainer-ledger-test-{}-{}",
            std::process::id(),
            hex::encode(random)
        ))
    });

#[cfg(all(windows, test))]
static TEST_PROFILE_LEDGER_OVERRIDE: std::sync::LazyLock<
    std::sync::Mutex<Option<std::path::PathBuf>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(None));

#[cfg(all(windows, test))]
static TEST_PROFILE_LEDGER_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(all(windows, test))]
pub(crate) struct CrossProcessAppContainerTestLock {
    handle: std::os::windows::io::OwnedHandle,
    owned: bool,
}

#[cfg(all(windows, test))]
impl CrossProcessAppContainerTestLock {
    pub(crate) fn acquire() -> Self {
        use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _};
        use windows_sys::Win32::{
            Foundation::{WAIT_ABANDONED, WAIT_OBJECT_0},
            System::Threading::{CreateMutexW, INFINITE, WaitForSingleObject},
        };

        let name = "Local\\CMFD.ProofWorker.AppContainer.Tests.V1\0"
            .encode_utf16()
            .collect::<Vec<_>>();
        // SAFETY: the security attributes are absent and the name is a live,
        // singly NUL-terminated UTF-16 string.
        let handle = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
        assert!(
            !handle.is_null(),
            "create the cross-process AppContainer test mutex: {}",
            io::Error::last_os_error()
        );
        // SAFETY: CreateMutexW returned one fresh owned handle.
        let handle = unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(handle.cast()) };
        // SAFETY: the mutex handle remains live for the entire wait.
        let wait = unsafe { WaitForSingleObject(handle.as_raw_handle().cast(), INFINITE) };
        assert!(
            matches!(wait, WAIT_OBJECT_0 | WAIT_ABANDONED),
            "acquire the cross-process AppContainer test mutex: wait={wait}"
        );
        Self {
            handle,
            owned: true,
        }
    }
}

#[cfg(all(windows, test))]
impl Drop for CrossProcessAppContainerTestLock {
    fn drop(&mut self) {
        if self.owned {
            use std::os::windows::io::AsRawHandle as _;
            use windows_sys::Win32::System::Threading::ReleaseMutex;

            // SAFETY: this thread owns the live mutex exactly once.
            if unsafe { ReleaseMutex(self.handle.as_raw_handle().cast()) } == 0 {
                APPCONTAINER_CLEANUP_UNHEALTHY.store(true, std::sync::atomic::Ordering::Release);
            }
            self.owned = false;
        }
    }
}

#[cfg(all(windows, test))]
fn profile_ledger_root() -> io::Result<std::path::PathBuf> {
    Ok(TEST_PROFILE_LEDGER_OVERRIDE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
        .unwrap_or_else(|| TEST_PROFILE_LEDGER_ROOT.clone()))
}

#[cfg(all(windows, test))]
pub(crate) struct IsolatedAppContainerLedgerTest {
    root: std::path::PathBuf,
    _serial: std::sync::MutexGuard<'static, ()>,
    _cross_process: CrossProcessAppContainerTestLock,
}

#[cfg(all(windows, test))]
pub(crate) fn isolated_appcontainer_ledger_test() -> IsolatedAppContainerLedgerTest {
    let cross_process = CrossProcessAppContainerTestLock::acquire();
    let serial = TEST_PROFILE_LEDGER_SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    reset_isolated_appcontainer_ledger_test_state();
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).expect("choose a per-test cleanup-ledger root");
    let root = std::env::temp_dir().join(format!(
        "cmfd-appcontainer-ledger-case-{}-{}",
        std::process::id(),
        hex::encode(random)
    ));
    *TEST_PROFILE_LEDGER_OVERRIDE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(root.clone());
    IsolatedAppContainerLedgerTest {
        root,
        _serial: serial,
        _cross_process: cross_process,
    }
}

#[cfg(all(windows, test))]
fn reset_isolated_appcontainer_ledger_test_state() {
    use windows_sys::Win32::Security::Isolation::DeleteAppContainerProfile;

    let _ledger = PROFILE_LEDGER_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(mut session) = PROFILE_LEDGER_SESSION
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take()
    {
        session.quarantine();
    }
    let names = ACTIVE_APPCONTAINER_PROFILES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    for name in names {
        unsafe { DeleteAppContainerProfile(name.as_ptr()) };
    }
    ACTIVE_APPCONTAINER_PROFILES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clear();
    QUARANTINED_PROFILE_LEDGER_HANDLES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clear();
    APPCONTAINER_CLEANUP_UNHEALTHY.store(false, std::sync::atomic::Ordering::Release);
}

#[cfg(all(windows, test))]
impl Drop for IsolatedAppContainerLedgerTest {
    fn drop(&mut self) {
        reset_isolated_appcontainer_ledger_test_state();
        if self.root.starts_with(std::env::temp_dir()) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
        *TEST_PROFILE_LEDGER_OVERRIDE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }
}

#[cfg(windows)]
fn ensure_profile_ledger_root() -> io::Result<std::path::PathBuf> {
    let root = profile_ledger_root()?;
    std::fs::create_dir_all(&root)?;
    crate::windows_launcher::secure_owner_only_path(&root, true)?;
    Ok(root)
}

#[cfg(windows)]
fn ensure_profile_ledger_session(root: &std::path::Path) -> io::Result<std::path::PathBuf> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows_sys::Win32::{
        Foundation::{GENERIC_READ, GENERIC_WRITE},
        Storage::FileSystem::{
            DELETE, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ, READ_CONTROL, SYNCHRONIZE, WRITE_DAC,
        },
    };

    let mut session = PROFILE_LEDGER_SESSION
        .lock()
        .map_err(|_| io::Error::other("cleanup ledger session lock is poisoned"))?;
    if let Some(session) = session.as_ref() {
        return Ok(session.directory.clone());
    }
    for attempt in 0..32_u32 {
        let mut random = [0_u8; 12];
        getrandom::fill(&mut random).map_err(|error| io::Error::other(error.to_string()))?;
        let directory = root.join(format!(
            "session-{}-{}-{attempt}",
            std::process::id(),
            hex::encode(random)
        ));
        match std::fs::create_dir(&directory) {
            Ok(()) => {
                let directory_handle = std::fs::OpenOptions::new()
                    .access_mode(
                        DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE | READ_CONTROL | WRITE_DAC,
                    )
                    .share_mode(FILE_SHARE_READ)
                    .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                    .open(&directory)
                    .inspect_err(|_| {
                        APPCONTAINER_CLEANUP_UNHEALTHY
                            .store(true, std::sync::atomic::Ordering::Release);
                    })?;
                let directory_identity = match windows_file_identity(&directory_handle) {
                    Ok(identity) => identity,
                    Err(error) => {
                        APPCONTAINER_CLEANUP_UNHEALTHY
                            .store(true, std::sync::atomic::Ordering::Release);
                        quarantine_profile_ledger_handle(directory_handle);
                        return Err(error);
                    }
                };
                if let Err(error) =
                    crate::windows_launcher::secure_owner_only_handle(&directory_handle)
                {
                    APPCONTAINER_CLEANUP_UNHEALTHY
                        .store(true, std::sync::atomic::Ordering::Release);
                    quarantine_profile_ledger_handle(directory_handle);
                    return Err(error);
                }
                let lock_path = directory.join(".lock");
                let lock = match std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .access_mode(
                        GENERIC_READ
                            | GENERIC_WRITE
                            | DELETE
                            | FILE_READ_ATTRIBUTES
                            | SYNCHRONIZE
                            | READ_CONTROL
                            | WRITE_DAC,
                    )
                    .create_new(true)
                    .share_mode(0)
                    .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                    .open(&lock_path)
                {
                    Ok(lock) => lock,
                    Err(error) => {
                        APPCONTAINER_CLEANUP_UNHEALTHY
                            .store(true, std::sync::atomic::Ordering::Release);
                        quarantine_profile_ledger_handle(directory_handle);
                        return Err(error);
                    }
                };
                let lock_identity = match windows_file_identity(&lock) {
                    Ok(identity) => identity,
                    Err(error) => {
                        APPCONTAINER_CLEANUP_UNHEALTHY
                            .store(true, std::sync::atomic::Ordering::Release);
                        quarantine_profile_ledger_handle(lock);
                        quarantine_profile_ledger_handle(directory_handle);
                        return Err(error);
                    }
                };
                let mut new_session = ProfileLedgerSession {
                    directory: directory.clone(),
                    directory_handle: Some(directory_handle),
                    directory_identity,
                    lock_handle: Some(lock),
                    lock_identity,
                    removed: false,
                };
                let initialize = new_session
                    .lock_handle
                    .as_ref()
                    .expect("new cleanup ledger lock handle is retained")
                    .sync_all()
                    .and_then(|()| {
                        crate::windows_launcher::secure_owner_only_handle(
                            new_session
                                .lock_handle
                                .as_ref()
                                .expect("new cleanup ledger lock handle is retained"),
                        )
                    });
                if let Err(error) = initialize {
                    APPCONTAINER_CLEANUP_UNHEALTHY
                        .store(true, std::sync::atomic::Ordering::Release);
                    new_session.quarantine();
                    return Err(error);
                }
                *session = Some(new_session);
                return Ok(directory);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "cleanup ledger session allocation attempts were exhausted",
    ))
}

#[cfg(windows)]
fn profile_ledger_filename(name: &[u16]) -> String {
    let bytes = name[..name.len() - 1]
        .iter()
        .flat_map(|unit| unit.to_le_bytes())
        .collect::<Vec<_>>();
    format!("p-{}", hex::encode(bytes))
}

#[cfg(windows)]
fn profile_name_from_ledger_filename(filename: &std::ffi::OsStr) -> io::Result<Vec<u16>> {
    let filename = filename
        .to_str()
        .ok_or_else(|| io::Error::other("cleanup ledger filename is not Unicode"))?;
    let encoded = filename
        .strip_prefix("p-")
        .ok_or_else(|| io::Error::other("cleanup ledger contains an unknown entry"))?;
    let bytes = hex::decode(encoded)
        .map_err(|_| io::Error::other("cleanup ledger filename is not canonical hex"))?;
    if bytes.is_empty() || bytes.len() % 2 != 0 {
        return Err(io::Error::other(
            "cleanup ledger filename has an invalid UTF-16 length",
        ));
    }
    let mut name = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect::<Vec<_>>();
    name.push(0);
    validate_profile_name(&name)?;
    if profile_ledger_filename(&name) != filename {
        return Err(io::Error::other("cleanup ledger filename is not canonical"));
    }
    Ok(name)
}

#[cfg(windows)]
#[cfg(windows)]
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProfileIntentFailpoint {
    BeforeMarkerCreate,
    AfterMarkerCreate,
    BeforeDacl,
    BeforeWrite,
    BeforeSync,
}

#[cfg(windows)]
fn record_profile_intent_inner(
    name: &[u16],
    #[cfg_attr(not(test), allow(unused_variables))] failpoint: Option<ProfileIntentFailpoint>,
) -> io::Result<ProfileLedgerEntry> {
    use std::io::Write as _;
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows_sys::Win32::{
        Foundation::{GENERIC_READ, GENERIC_WRITE},
        Storage::FileSystem::{
            DELETE, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, READ_CONTROL, SYNCHRONIZE,
            WRITE_DAC,
        },
    };

    let root = ensure_profile_ledger_root()?;
    let session = ensure_profile_ledger_session(&root)?;
    let entry = session.join(profile_ledger_filename(name));
    #[cfg(test)]
    if failpoint == Some(ProfileIntentFailpoint::BeforeMarkerCreate) {
        return Err(io::Error::other(
            "forced failure before creating the profile ownership marker",
        ));
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .access_mode(
            DELETE
                | GENERIC_READ
                | GENERIC_WRITE
                | READ_CONTROL
                | WRITE_DAC
                | FILE_READ_ATTRIBUTES
                | SYNCHRONIZE,
        )
        .share_mode(0)
        .create_new(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&entry)?;
    #[cfg(test)]
    if failpoint == Some(ProfileIntentFailpoint::AfterMarkerCreate) {
        quarantine_profile_ledger_handle(file);
        return Err(io::Error::other(
            "forced failure after creating the profile ownership marker",
        ));
    }
    let identity = match windows_file_identity(&file) {
        Ok(identity) => identity,
        Err(error) => {
            APPCONTAINER_CLEANUP_UNHEALTHY.store(true, std::sync::atomic::Ordering::Release);
            quarantine_profile_ledger_handle(file);
            return Err(io::Error::new(
                error.kind(),
                format!(
                    "identity-binding newly created profile ledger marker failed; manual cleanup of {} is required: {error}",
                    entry.display()
                ),
            ));
        }
    };
    let mut ledger = ProfileLedgerEntry {
        path: entry,
        file: Some(file),
        identity,
        removed: false,
        #[cfg(test)]
        forced_remove_failures: None,
    };
    let initialize = (|| {
        #[cfg(test)]
        if failpoint == Some(ProfileIntentFailpoint::BeforeDacl) {
            return Err(io::Error::other(
                "forced failure before securing the profile ownership marker",
            ));
        }
        crate::windows_launcher::secure_owner_only_handle(
            ledger
                .file
                .as_ref()
                .expect("new profile marker handle is retained"),
        )?;
        let file = ledger
            .file
            .as_mut()
            .expect("new profile marker handle is retained");
        // The name is encoded in the atomically created filename. The marker
        // records an ownership intent before CreateAppContainerProfile runs.
        #[cfg(test)]
        if failpoint == Some(ProfileIntentFailpoint::BeforeWrite) {
            return Err(io::Error::other(
                "forced failure before writing the profile ownership marker",
            ));
        }
        file.write_all(b"CMFD-APPCONTAINER-PROFILE-INTENT-V2\n")?;
        #[cfg(test)]
        if failpoint == Some(ProfileIntentFailpoint::BeforeSync) {
            return Err(io::Error::other(
                "forced failure before syncing the profile ownership marker",
            ));
        }
        file.sync_all()
    })();
    if let Err(primary) = initialize {
        APPCONTAINER_CLEANUP_UNHEALTHY.store(true, std::sync::atomic::Ordering::Release);
        ledger.quarantine();
        return Err(io::Error::new(
            primary.kind(),
            format!(
                "durably initializing the profile ownership marker failed and the exact marker was quarantined for manual remediation: {primary}"
            ),
        ));
    }
    Ok(ledger)
}

#[cfg(windows)]
impl WindowsAppContainerProfileIntent {
    pub(crate) fn begin(name: Vec<u16>) -> io::Result<Self> {
        Self::begin_inner(name, None)
    }

    fn begin_inner(
        name: Vec<u16>,
        #[cfg_attr(not(test), allow(unused_variables))] failpoint: Option<ProfileIntentFailpoint>,
    ) -> io::Result<Self> {
        let _lock = PROFILE_LEDGER_LOCK
            .lock()
            .map_err(|_| io::Error::other("cleanup ledger lock is poisoned"))?;
        validate_profile_name(&name)?;
        let ledger_entry = record_profile_intent_inner(&name, failpoint).inspect_err(|_| {
            APPCONTAINER_CLEANUP_UNHEALTHY.store(true, std::sync::atomic::Ordering::Release);
        })?;
        let registration = ACTIVE_APPCONTAINER_PROFILES
            .lock()
            .map_err(|_| io::Error::other("active AppContainer profile registry is poisoned"))?
            .insert(name.clone());
        if !registration {
            let mut ledger_entry = ledger_entry;
            let removal = ledger_entry.remove();
            return Err(io::Error::other(format!(
                "new AppContainer profile name was already active; exact ledger rollback={removal:?}"
            )));
        }
        Ok(Self {
            name,
            ledger_entry: Some(ledger_entry),
            active_registration: true,
            completed: false,
        })
    }

    #[cfg(test)]
    fn begin_with_failpoint(name: Vec<u16>, failpoint: ProfileIntentFailpoint) -> io::Result<Self> {
        Self::begin_inner(name, Some(failpoint))
    }

    pub(crate) fn commit(mut self) -> WindowsAppContainerProfile {
        self.completed = true;
        WindowsAppContainerProfile {
            name: std::mem::take(&mut self.name),
            ledger_entry: self.ledger_entry.take(),
            active_registration: std::mem::replace(&mut self.active_registration, false),
            deleted: false,
            #[cfg(test)]
            forced_delete_failures: None,
        }
    }

    pub(crate) fn cancel(&mut self) -> io::Result<()> {
        let _lock = PROFILE_LEDGER_LOCK
            .lock()
            .map_err(|_| io::Error::other("cleanup ledger lock is poisoned"))?;
        let ledger_cleanup = match self.ledger_entry.as_mut() {
            Some(entry) => entry.remove(),
            None => Ok(()),
        };
        if ledger_cleanup.is_ok() {
            self.ledger_entry = None;
        }
        let unregister = if self.active_registration {
            unregister_active_appcontainer_profile(&self.name)
        } else {
            Ok(())
        };
        if unregister.is_ok() {
            self.active_registration = false;
        }
        let result = combine_profile_cleanup_results(ledger_cleanup, unregister)
            .and_then(|()| shutdown_appcontainer_profile_cleanup_locked());
        if result.is_err() {
            APPCONTAINER_CLEANUP_UNHEALTHY.store(true, std::sync::atomic::Ordering::Release);
        }
        result
    }
}

#[cfg(windows)]
impl Drop for WindowsAppContainerProfileIntent {
    fn drop(&mut self) {
        if !self.completed && self.cancel().is_err() {
            APPCONTAINER_CLEANUP_UNHEALTHY.store(true, std::sync::atomic::Ordering::Release);
        }
    }
}

#[cfg(windows)]
fn appcontainer_profile_is_active(name: &[u16]) -> io::Result<bool> {
    Ok(ACTIVE_APPCONTAINER_PROFILES
        .lock()
        .map_err(|_| io::Error::other("active AppContainer profile registry is poisoned"))?
        .contains(name))
}

#[cfg(windows)]
fn unregister_active_appcontainer_profile(name: &[u16]) -> io::Result<()> {
    ACTIVE_APPCONTAINER_PROFILES
        .lock()
        .map_err(|_| io::Error::other("active AppContainer profile registry is poisoned"))?
        .remove(name);
    Ok(())
}

#[cfg(windows)]
fn combine_profile_cleanup_results(
    first: io::Result<()>,
    second: io::Result<()>,
) -> io::Result<()> {
    match (first, second) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(first), Err(second)) => Err(io::Error::other(format!(
            "{first}; additional profile cleanup failure: {second}"
        ))),
    }
}

#[cfg(windows)]
pub(crate) fn retry_pending_appcontainer_profile_cleanup() -> io::Result<()> {
    let result = retry_pending_appcontainer_profile_cleanup_inner();
    if result.is_err() {
        APPCONTAINER_CLEANUP_UNHEALTHY.store(true, std::sync::atomic::Ordering::Release);
    }
    result
}

#[cfg(windows)]
fn retry_pending_appcontainer_profile_cleanup_inner() -> io::Result<()> {
    use std::io::Read as _;
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Foundation::ERROR_SHARING_VIOLATION;

    let _lock = PROFILE_LEDGER_LOCK
        .lock()
        .map_err(|_| io::Error::other("cleanup ledger lock is poisoned"))?;
    let root = ensure_profile_ledger_root()?;
    let current_session = PROFILE_LEDGER_SESSION
        .lock()
        .map_err(|_| io::Error::other("cleanup ledger session lock is poisoned"))?
        .as_ref()
        .map(|session| session.directory.clone());
    let mut sessions = std::fs::read_dir(&root)?.collect::<Result<Vec<_>, _>>()?;
    sessions.sort_by_key(std::fs::DirEntry::file_name);
    for session in sessions {
        if !session.file_type()?.is_dir() {
            return Err(io::Error::other(
                "cleanup ledger contains a non-session entry",
            ));
        }
        let is_current = current_session.as_deref() == Some(session.path().as_path());
        let lock_path = session.path().join(".lock");
        if is_current {
            let mut entries = std::fs::read_dir(session.path())?.collect::<Result<Vec<_>, _>>()?;
            entries.sort_by_key(std::fs::DirEntry::file_name);
            for entry in entries {
                if entry.file_name() == ".lock" {
                    continue;
                }
                if !entry.file_type()?.is_file() {
                    return Err(io::Error::other(
                        "current cleanup ledger session contains a non-file entry",
                    ));
                }
                let name = profile_name_from_ledger_filename(&entry.file_name())?;
                if !appcontainer_profile_is_active(&name)? {
                    return Err(io::Error::other(format!(
                        "current-session AppContainer ownership marker {} has no live owner guard; launches are quarantined for manual remediation",
                        entry.path().display()
                    )));
                }
            }
            continue;
        }
        let _stale_lock = match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(0)
            .open(&lock_path)
        {
            Ok(lock) => lock,
            Err(error) if error.raw_os_error() == Some(ERROR_SHARING_VIOLATION as i32) => {
                continue;
            }
            Err(error) => return Err(error),
        };
        let mut entries = std::fs::read_dir(session.path())?.collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            if entry.file_name() == ".lock" {
                continue;
            }
            if !entry.file_type()?.is_file() {
                return Err(io::Error::other(
                    "cleanup ledger session contains a non-file entry",
                ));
            }
            let name = profile_name_from_ledger_filename(&entry.file_name())?;
            let mut marker = Vec::new();
            std::fs::File::open(entry.path())?.read_to_end(&mut marker)?;
            if marker != b"CMFD-APPCONTAINER-PROFILE-INTENT-V2\n" {
                return Err(io::Error::other("cleanup ledger entry marker is invalid"));
            }
            return Err(io::Error::other(format!(
                "stale AppContainer ownership marker {} for {} is quarantined; profile deletion by persisted name is forbidden and manual remediation is required",
                entry.path().display(),
                String::from_utf16_lossy(&name[..name.len() - 1])
            )));
        }
        return Err(io::Error::other(format!(
            "stale AppContainer cleanup session {} is quarantined; generation identity is unavailable, persisted names never authorize profile deletion, and manual remediation is required",
            session.path().display()
        )));
    }
    Ok(())
}

#[cfg(windows)]
pub(crate) fn shutdown_appcontainer_profile_cleanup() -> io::Result<()> {
    let _lock = PROFILE_LEDGER_LOCK
        .lock()
        .map_err(|_| io::Error::other("cleanup ledger lock is poisoned"))?;
    shutdown_appcontainer_profile_cleanup_locked()
}

#[cfg(windows)]
fn shutdown_appcontainer_profile_cleanup_locked() -> io::Result<()> {
    let mut session_slot = PROFILE_LEDGER_SESSION
        .lock()
        .map_err(|_| io::Error::other("cleanup ledger session lock is poisoned"))?;
    let Some(session) = session_slot.as_ref() else {
        #[cfg(test)]
        remove_empty_test_profile_ledger_root()?;
        return Ok(());
    };
    if !appcontainer_cleanup_healthy() {
        return Err(io::Error::other(
            "AppContainer cleanup health is latched; retaining the exact current-session ledger and lock for manual remediation",
        ));
    }
    let directory = session.directory.clone();
    let mut entries = std::fs::read_dir(&directory)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        if entry.file_name() == ".lock" {
            continue;
        }
        if !entry.file_type()?.is_file() {
            return Err(io::Error::other(
                "current cleanup ledger session contains a non-file entry",
            ));
        }
        let name = profile_name_from_ledger_filename(&entry.file_name())?;
        if appcontainer_profile_is_active(&name)? {
            continue;
        }
        return Err(io::Error::other(format!(
            "current-session AppContainer ownership marker {} has no live owner guard; shutdown cleanup will not delete a profile by persisted name",
            entry.path().display()
        )));
    }
    if std::fs::read_dir(&directory)?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .any(|entry| entry.file_name() != ".lock")
    {
        // Another worker in this process still owns a live profile. Keep the
        // session lock and ledger intact; its own teardown will remove that
        // exact entry before a later shutdown retry removes the empty session.
        return Ok(());
    }
    let mut session = session_slot
        .take()
        .expect("the process-local cleanup ledger session is still present");
    drop(session_slot);
    if let Err(error) = session.remove_exact() {
        session.quarantine();
        APPCONTAINER_CLEANUP_UNHEALTHY.store(true, std::sync::atomic::Ordering::Release);
        return Err(io::Error::new(
            error.kind(),
            format!(
                "removing exact cleanup ledger session {} through retained handles failed: {error}",
                directory.display()
            ),
        ));
    }
    #[cfg(test)]
    remove_empty_test_profile_ledger_root()?;
    Ok(())
}

#[cfg(all(windows, test))]
fn remove_empty_test_profile_ledger_root() -> io::Result<()> {
    let root = profile_ledger_root()?;
    let entries = match std::fs::read_dir(&root) {
        Ok(entries) => entries.collect::<Result<Vec<_>, _>>()?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if entries.is_empty() {
        std::fs::remove_dir(root)?;
    }
    Ok(())
}

#[cfg(windows)]
pub(crate) fn appcontainer_cleanup_healthy() -> bool {
    !APPCONTAINER_CLEANUP_UNHEALTHY.load(std::sync::atomic::Ordering::Acquire)
}

#[cfg(windows)]
pub(crate) fn mark_appcontainer_cleanup_unhealthy() {
    APPCONTAINER_CLEANUP_UNHEALTHY.store(true, std::sync::atomic::Ordering::Release);
}

#[cfg(windows)]
const PROFILE_DELETE_BACKOFF_MILLIS: [u64; 8] = [0, 10, 20, 40, 80, 160, 320, 500];

#[cfg(windows)]
impl WindowsAppContainerProfile {
    #[cfg(test)]
    fn new_untracked(name: Vec<u16>) -> io::Result<Self> {
        Self::new_without_ledger(name)
    }

    #[cfg(test)]
    pub(crate) fn own_raw_created_for_test(name: Vec<u16>) -> Self {
        // The test-only caller constructs this guard as the first operation
        // after a successful CreateAppContainerProfile. Do not add fallible
        // validation here: an unwind before this value exists would leave the
        // successful registration unowned.
        Self {
            name,
            ledger_entry: None,
            active_registration: false,
            deleted: false,
            forced_delete_failures: None,
        }
    }

    #[cfg(test)]
    fn new_without_ledger(name: Vec<u16>) -> io::Result<Self> {
        validate_profile_name(&name)?;
        Ok(Self {
            name,
            ledger_entry: None,
            active_registration: false,
            deleted: false,
            #[cfg(test)]
            forced_delete_failures: None,
        })
    }

    pub(crate) fn delete(&mut self) -> io::Result<()> {
        use windows_sys::Win32::Security::Isolation::DeleteAppContainerProfile;

        #[cfg(test)]
        if let Some(failures) = &self.forced_delete_failures
            && failures
                .fetch_update(
                    std::sync::atomic::Ordering::AcqRel,
                    std::sync::atomic::Ordering::Acquire,
                    |remaining| {
                        if remaining == 0 {
                            None
                        } else {
                            Some(remaining - 1)
                        }
                    },
                )
                .is_ok()
        {
            return Err(io::Error::other("forced AppContainer cleanup failure"));
        }

        self.delete_with(
            |name| {
                // SAFETY: `name` is a live, singly NUL-terminated UTF-16
                // string. This guard exists only after this process created
                // that exact unique profile registration.
                unsafe { DeleteAppContainerProfile(name) }
            },
            std::thread::sleep,
        )
    }

    #[cfg(test)]
    pub(crate) fn force_delete_failures(
        &mut self,
        failures: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) {
        self.forced_delete_failures = Some(failures);
    }

    fn delete_with(
        &mut self,
        mut delete: impl FnMut(*const u16) -> i32,
        mut sleep: impl FnMut(std::time::Duration),
    ) -> io::Result<()> {
        use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_NOT_FOUND};

        let owned_registration = self.ledger_entry.is_some() || self.active_registration;
        let _ledger_lock = if owned_registration {
            Some(
                PROFILE_LEDGER_LOCK
                    .lock()
                    .map_err(|_| io::Error::other("cleanup ledger lock is poisoned"))?,
            )
        } else {
            None
        };
        if !self.deleted {
            let mut final_status = 0_i32;
            for (attempt, delay_millis) in PROFILE_DELETE_BACKOFF_MILLIS.iter().copied().enumerate()
            {
                if delay_millis != 0 {
                    sleep(std::time::Duration::from_millis(delay_millis));
                }
                let status = delete(self.name.as_ptr());
                if status >= 0
                    || hresult_win32_code(status)
                        .is_some_and(|code| code == ERROR_FILE_NOT_FOUND || code == ERROR_NOT_FOUND)
                {
                    self.deleted = true;
                    break;
                }
                final_status = status;
                if attempt + 1 == PROFILE_DELETE_BACKOFF_MILLIS.len() {
                    break;
                }
            }
            if !self.deleted {
                // `deleted` deliberately remains false. Win32Child retains
                // this guard and a later cleanup attempt retries the same
                // registration instead of adopting a persisted name.
                return Err(io::Error::new(
                    hresult_error(final_status, "deleting the AppContainer profile").kind(),
                    format!(
                        "deleting the AppContainer profile failed after {} bounded attempts: {}",
                        PROFILE_DELETE_BACKOFF_MILLIS.len(),
                        hresult_error(final_status, "final profile deletion")
                    ),
                ));
            }
        }
        if let Some(entry) = &mut self.ledger_entry {
            entry.remove()?;
            self.ledger_entry = None;
        }
        if self.active_registration {
            unregister_active_appcontainer_profile(&self.name)?;
            self.active_registration = false;
        }
        if owned_registration {
            shutdown_appcontainer_profile_cleanup_locked()?;
        }
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for WindowsAppContainerProfile {
    fn drop(&mut self) {
        let cleanup = self.delete();
        if cleanup.is_err()
            && let Some(entry) = self.ledger_entry.take()
        {
            entry.quarantine();
        }
        let unregister = if self.active_registration {
            unregister_active_appcontainer_profile(&self.name)
        } else {
            Ok(())
        };
        self.active_registration = false;
        if cleanup.is_err() || unregister.is_err() {
            APPCONTAINER_CLEANUP_UNHEALTHY.store(true, std::sync::atomic::Ordering::Release);
        }
    }
}

#[cfg(windows)]
fn hresult_error(status: i32, operation: &'static str) -> io::Error {
    let raw = status as u32;
    if raw & 0xffff_0000 == 0x8007_0000 {
        io::Error::new(
            io::Error::from_raw_os_error((raw & 0xffff) as i32).kind(),
            format!(
                "{operation}: {}",
                io::Error::from_raw_os_error((raw & 0xffff) as i32)
            ),
        )
    } else {
        io::Error::other(format!("{operation} failed with HRESULT 0x{raw:08x}"))
    }
}

#[cfg(windows)]
fn hresult_win32_code(status: i32) -> Option<u32> {
    let raw = status as u32;
    (raw & 0xffff_0000 == 0x8007_0000).then_some(raw & 0xffff)
}

#[cfg(windows)]
impl Win32Child {
    #[allow(dead_code)] // Constructed by the AppContainer launcher tranche.
    pub(crate) fn new(
        process: std::os::windows::io::OwnedHandle,
        process_id: u32,
        appcontainer_profile: Option<WindowsAppContainerProfile>,
        private_runtime: Option<WindowsPrivateRuntime>,
        stdin: Option<BlockingPipeWriter>,
        stdout: Option<BlockingPipeReader>,
        stderr: Option<BlockingPipeReader>,
    ) -> io::Result<Self> {
        if process_id == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Win32 child process ID must be nonzero",
            ));
        }
        Ok(Self {
            process,
            process_id,
            exit_status: None,
            appcontainer_profile,
            private_runtime,
            stdin,
            stdout,
            stderr,
        })
    }

    fn id(&self) -> u32 {
        self.process_id
    }

    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        use std::os::windows::io::AsRawHandle;
        use std::os::windows::process::ExitStatusExt;
        use windows_sys::Win32::Foundation::{WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT};
        use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};

        if let Some(status) = self.exit_status {
            return Ok(Some(status));
        }
        // SAFETY: `process` is an owned, live process handle and the zero
        // timeout makes this a nonblocking state query.
        match unsafe { WaitForSingleObject(self.process.as_raw_handle().cast(), 0) } {
            WAIT_TIMEOUT => Ok(None),
            WAIT_OBJECT_0 => {
                let mut code = 0_u32;
                // SAFETY: the process handle is live and `code` is writable
                // for the duration of the call.
                if unsafe { GetExitCodeProcess(self.process.as_raw_handle().cast(), &mut code) }
                    == 0
                {
                    return Err(io::Error::last_os_error());
                }
                if let Some(profile) = &mut self.appcontainer_profile {
                    if let Err(error) = profile.delete() {
                        APPCONTAINER_CLEANUP_UNHEALTHY
                            .store(true, std::sync::atomic::Ordering::Release);
                        return Err(error);
                    }
                    self.appcontainer_profile = None;
                }
                if let Some(runtime) = &mut self.private_runtime {
                    if let Err(error) = runtime.cleanup() {
                        APPCONTAINER_CLEANUP_UNHEALTHY
                            .store(true, std::sync::atomic::Ordering::Release);
                        return Err(error);
                    }
                    self.private_runtime = None;
                }
                let status = ExitStatus::from_raw(code);
                self.exit_status = Some(status);
                Ok(Some(status))
            }
            WAIT_FAILED => Err(io::Error::last_os_error()),
            wait_status => Err(io::Error::other(format!(
                "unexpected Win32 process wait status {wait_status}"
            ))),
        }
    }

    fn kill(&mut self) -> io::Result<()> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::Threading::TerminateProcess;

        if self.try_wait()?.is_some() {
            return Ok(());
        }
        // SAFETY: `process` is an owned, live process handle. The exit code is
        // diagnostic only; consensus never observes it.
        if unsafe { TerminateProcess(self.process.as_raw_handle().cast(), 1) } == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn take_stdin(&mut self) -> Option<BlockingPipeWriter> {
        self.stdin.take()
    }

    fn take_stdout(&mut self) -> Option<BlockingPipeReader> {
        self.stdout.take()
    }

    fn take_stderr(&mut self) -> Option<BlockingPipeReader> {
        self.stderr.take()
    }
}

#[cfg(all(test, windows))]
mod tests {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::process::{Command, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};

    use windows_sys::Win32::Foundation::{DUPLICATE_SAME_ACCESS, DuplicateHandle};
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    use crate::windows_launcher::{
        try_create_owned_test_profile, try_create_untracked_test_profile,
    };

    use super::{
        BlockingPipeReader, BlockingPipeWriter, ManagedProcess, ProfileIntentFailpoint, Win32Child,
        WindowsAppContainerProfile, WindowsAppContainerProfileIntent, WindowsFileIdentity,
        delete_exact_runtime_handle, delete_exact_runtime_handle_with_hook,
        ensure_profile_ledger_root, ensure_profile_ledger_session,
        isolated_appcontainer_ledger_test, production_profile_ledger_root, profile_ledger_filename,
        retry_pending_appcontainer_profile_cleanup, shutdown_appcontainer_profile_cleanup,
        windows_file_identity,
    };

    const CHILD_ENV: &str = "CMFD_MANAGED_PROCESS_CHILD";
    const PROFILE_HOLDER_ENV: &str = "CMFD_PROFILE_HOLDER_NAME";

    fn test_profile() -> WindowsAppContainerProfile {
        WindowsAppContainerProfile::new_untracked(
            "CMFD.Verifier.profile-delete-test\0"
                .encode_utf16()
                .collect(),
        )
        .unwrap()
    }

    fn failed_win32(code: u32) -> i32 {
        (0x8007_0000_u32 | code) as i32
    }

    fn open_cleanup_handle(
        path: &std::path::Path,
        directory: bool,
    ) -> (std::fs::File, WindowsFileIdentity) {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::{
            DELETE, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ, SYNCHRONIZE,
        };

        let flags = FILE_FLAG_OPEN_REPARSE_POINT
            | if directory {
                FILE_FLAG_BACKUP_SEMANTICS
            } else {
                0
            };
        let file = std::fs::OpenOptions::new()
            .access_mode(DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(flags)
            .open(path)
            .unwrap();
        let identity = windows_file_identity(&file).unwrap();
        (file, identity)
    }

    #[test]
    fn retained_runtime_cleanup_blocks_path_replacement_and_deletes_exact_objects() {
        let mut random = [0_u8; 12];
        getrandom::fill(&mut random).unwrap();
        let root = std::env::temp_dir().join(format!(
            "cmfd-runtime-cleanup-test-{}-{}",
            std::process::id(),
            hex::encode(random)
        ));
        std::fs::create_dir(&root).unwrap();

        let executable = root.join("runtime.exe");
        std::fs::write(&executable, b"owned executable").unwrap();
        let (executable_handle, executable_identity) = open_cleanup_handle(&executable, false);
        let moved_executable = root.join("owned-runtime.exe");
        assert!(std::fs::rename(&executable, &moved_executable).is_err());
        assert!(std::fs::write(&executable, b"unrelated replacement").is_err());
        delete_exact_runtime_handle(&executable_handle, false, executable_identity).unwrap();
        drop(executable_handle);
        assert!(!executable.exists());

        let directory = root.join("runtime-directory");
        std::fs::create_dir(&directory).unwrap();
        let (directory_handle, directory_identity) = open_cleanup_handle(&directory, true);
        let moved_directory = root.join("owned-runtime-directory");
        assert!(std::fs::rename(&directory, &moved_directory).is_err());
        delete_exact_runtime_handle(&directory_handle, true, directory_identity).unwrap();
        drop(directory_handle);
        assert!(!directory.exists());
        std::fs::remove_dir(root).unwrap();
    }

    #[test]
    fn retained_runtime_cleanup_rejects_128_bit_collision_and_hardlink_race() {
        let mut random = [0_u8; 12];
        getrandom::fill(&mut random).unwrap();
        let root = std::env::temp_dir().join(format!(
            "cmfd-runtime-identity-test-{}-{}",
            std::process::id(),
            hex::encode(random)
        ));
        std::fs::create_dir(&root).unwrap();

        let collision = root.join("collision.exe");
        std::fs::write(&collision, b"collision sentinel").unwrap();
        let (collision_handle, identity) = open_cleanup_handle(&collision, false);
        let mut forged = identity;
        forged.file_id[15] ^= 0x80;
        assert_eq!(&forged.file_id[..8], &identity.file_id[..8]);
        assert!(delete_exact_runtime_handle(&collision_handle, false, forged).is_err());
        drop(collision_handle);
        assert_eq!(std::fs::read(&collision).unwrap(), b"collision sentinel");

        let raced = root.join("raced.exe");
        let alias = root.join("raced-alias.exe");
        std::fs::write(&raced, b"hardlink sentinel").unwrap();
        let (raced_handle, raced_identity) = open_cleanup_handle(&raced, false);
        let error =
            delete_exact_runtime_handle_with_hook(&raced_handle, false, raced_identity, || {
                std::fs::hard_link(&raced, &alias)
            })
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("changed during retained-handle deletion")
        );
        drop(raced_handle);
        assert_eq!(std::fs::read(&raced).unwrap(), b"hardlink sentinel");
        assert_eq!(std::fs::read(&alias).unwrap(), b"hardlink sentinel");

        std::fs::remove_file(collision).unwrap();
        std::fs::remove_file(alias).unwrap();
        std::fs::remove_file(raced).unwrap();
        std::fs::remove_dir(root).unwrap();
    }

    #[test]
    fn retained_runtime_cleanup_uses_128_bit_identity_on_refs_when_available() {
        use windows_sys::Win32::{
            Storage::FileSystem::{GetDriveTypeW, GetVolumeInformationW},
            System::WindowsProgramming::DRIVE_FIXED,
        };

        let refs_root = ('A'..='Z').find_map(|drive| {
            let root = format!("{drive}:\\");
            let wide = root
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect::<Vec<_>>();
            if unsafe { GetDriveTypeW(wide.as_ptr()) } != DRIVE_FIXED {
                return None;
            }
            let mut filesystem = [0_u16; 32];
            if unsafe {
                GetVolumeInformationW(
                    wide.as_ptr(),
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    filesystem.as_mut_ptr(),
                    filesystem.len() as u32,
                )
            } == 0
            {
                return None;
            }
            let length = filesystem
                .iter()
                .position(|unit| *unit == 0)
                .unwrap_or(filesystem.len());
            (String::from_utf16_lossy(&filesystem[..length]) == "ReFS")
                .then_some(std::path::PathBuf::from(root))
        });
        let Some(refs_root) = refs_root else {
            eprintln!("ReFS cleanup regression skipped: no fixed ReFS volume is available");
            return;
        };
        let mut random = [0_u8; 12];
        getrandom::fill(&mut random).unwrap();
        let root = refs_root.join(format!(
            "cmfd-runtime-refs-test-{}-{}",
            std::process::id(),
            hex::encode(random)
        ));
        if let Err(error) = std::fs::create_dir(&root) {
            eprintln!(
                "ReFS cleanup regression skipped: fixed ReFS volume is not writable: {error}"
            );
            return;
        }
        let executable = root.join("runtime.exe");
        std::fs::write(&executable, b"ReFS 128-bit identity sentinel").unwrap();
        let (handle, identity) = open_cleanup_handle(&executable, false);
        delete_exact_runtime_handle(&handle, false, identity).unwrap();
        drop(handle);
        assert!(!executable.exists());
        std::fs::remove_dir(root).unwrap();
    }

    #[test]
    fn appcontainer_profile_delete_retries_and_retains_failed_cleanup() {
        use windows_sys::Win32::Foundation::ERROR_BUSY;

        let mut profile = test_profile();
        let mut attempts = 0;
        let mut delays = Vec::new();
        profile
            .delete_with(
                |_| {
                    attempts += 1;
                    if attempts < 3 {
                        failed_win32(ERROR_BUSY)
                    } else {
                        0
                    }
                },
                |delay| delays.push(delay),
            )
            .unwrap();
        assert_eq!(attempts, 3);
        assert_eq!(
            delays,
            [Duration::from_millis(10), Duration::from_millis(20)]
        );

        let mut exhausted = test_profile();
        let error = exhausted
            .delete_with(|_| failed_win32(ERROR_BUSY), |_| {})
            .unwrap_err();
        assert!(error.to_string().contains("8 bounded attempts"));
        assert!(!exhausted.deleted, "failed cleanup must remain retryable");
        exhausted.delete_with(|_| 0, |_| {}).unwrap();
        assert!(exhausted.deleted);
    }

    #[test]
    fn already_absent_appcontainer_profile_is_successful_stale_cleanup() {
        use windows_sys::Win32::Foundation::ERROR_NOT_FOUND;

        let mut profile = test_profile();
        let mut attempts = 0;
        profile
            .delete_with(
                |_| {
                    attempts += 1;
                    failed_win32(ERROR_NOT_FOUND)
                },
                |_| panic!("stale profile cleanup must not back off"),
            )
            .unwrap();
        assert_eq!(attempts, 1);
        assert!(profile.deleted);
    }

    fn unique_profile_name(label: &str) -> Vec<u16> {
        let mut random = [0_u8; 8];
        getrandom::fill(&mut random).unwrap();
        format!(
            "CMFD.Verifier.{label}.{}.{}\0",
            std::process::id(),
            hex::encode(random)
        )
        .encode_utf16()
        .collect()
    }

    fn reset_profile_cleanup_test_state() {
        super::QUARANTINED_PROFILE_LEDGER_HANDLES
            .lock()
            .unwrap()
            .clear();
        super::APPCONTAINER_CLEANUP_UNHEALTHY.store(false, std::sync::atomic::Ordering::Release);
    }

    fn directory_contains_path(path: &std::path::Path) -> bool {
        let Some(name) = path.file_name() else {
            return false;
        };
        std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .any(|entry| entry.unwrap().file_name() == name)
    }

    #[derive(Debug, PartialEq, Eq)]
    struct LedgerTreeEntry {
        relative: std::path::PathBuf,
        directory: bool,
        identity: WindowsFileIdentity,
        bytes: Vec<u8>,
        modified: Option<std::time::SystemTime>,
    }

    fn snapshot_ledger_tree(root: &std::path::Path) -> Option<Vec<LedgerTreeEntry>> {
        if !root.exists() {
            return None;
        }
        fn visit(
            root: &std::path::Path,
            path: &std::path::Path,
            entries: &mut Vec<LedgerTreeEntry>,
        ) {
            use std::os::windows::fs::OpenOptionsExt as _;
            use windows_sys::Win32::Storage::FileSystem::{
                FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
                FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
            };

            let metadata = std::fs::symlink_metadata(path).unwrap();
            let directory = metadata.is_dir();
            let handle = std::fs::OpenOptions::new()
                .access_mode(FILE_READ_ATTRIBUTES)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                .custom_flags(
                    FILE_FLAG_OPEN_REPARSE_POINT
                        | if directory {
                            FILE_FLAG_BACKUP_SEMANTICS
                        } else {
                            0
                        },
                )
                .open(path)
                .unwrap();
            entries.push(LedgerTreeEntry {
                relative: path.strip_prefix(root).unwrap().to_owned(),
                directory,
                identity: windows_file_identity(&handle).unwrap(),
                bytes: if directory {
                    Vec::new()
                } else {
                    std::fs::read(path).unwrap()
                },
                modified: metadata.modified().ok(),
            });
            if directory {
                let mut children = std::fs::read_dir(path)
                    .unwrap()
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap();
                children.sort_by_key(std::fs::DirEntry::file_name);
                for child in children {
                    visit(root, &child.path(), entries);
                }
            }
        }

        let mut entries = Vec::new();
        visit(root, root, &mut entries);
        Some(entries)
    }

    #[test]
    fn unit_ledger_activity_never_mutates_the_real_localappdata_ledger() {
        let production = production_profile_ledger_root().unwrap();
        let before = snapshot_ledger_tree(&production);
        {
            let _ledger = isolated_appcontainer_ledger_test();
            let isolated = ensure_profile_ledger_root().unwrap();
            assert_ne!(isolated, production);
            let mut intent =
                WindowsAppContainerProfileIntent::begin(unique_profile_name("isolated")).unwrap();
            intent.cancel().unwrap();
            shutdown_appcontainer_profile_cleanup().unwrap();
        }
        assert_eq!(snapshot_ledger_tree(&production), before);
    }

    #[test]
    fn session_cleanup_retains_identity_and_preserves_a_lock_path_replacement() {
        let _ledger = isolated_appcontainer_ledger_test();
        let root = ensure_profile_ledger_root().unwrap();
        let directory = ensure_profile_ledger_session(&root).unwrap();
        let moved = root.join("moved-session");
        assert!(
            std::fs::rename(&directory, &moved).is_err(),
            "the retained directory handle allowed a rename before cleanup"
        );
        let replacement_directory = root.join("replacement-session");
        std::fs::create_dir(&replacement_directory).unwrap();
        assert!(
            std::fs::rename(&replacement_directory, &directory).is_err(),
            "a replacement directory displaced the retained session"
        );

        let mut session = super::PROFILE_LEDGER_SESSION
            .lock()
            .unwrap()
            .take()
            .expect("test session is retained");
        let replacement_lock = directory.join(".lock");
        let error = session
            .remove_exact_with_hook(|| std::fs::write(&replacement_lock, b"replacement lock"))
            .unwrap_err();
        assert_eq!(
            std::fs::read(&replacement_lock).unwrap(),
            b"replacement lock"
        );
        assert!(
            error.kind() == std::io::ErrorKind::DirectoryNotEmpty || error.raw_os_error().is_some(),
            "unexpected exact-session cleanup failure: {error}"
        );
        session.release_without_deletion_for_test();
        drop(session);
        assert_eq!(
            std::fs::read(&replacement_lock).unwrap(),
            b"replacement lock",
            "session cleanup deleted a replacement through the released lock pathname"
        );

        std::fs::remove_file(replacement_lock).unwrap();
        std::fs::remove_dir(directory).unwrap();
        std::fs::remove_dir(replacement_directory).unwrap();
        shutdown_appcontainer_profile_cleanup().unwrap();
    }

    #[test]
    fn profile_marker_partial_failures_are_durable_and_latch_health() {
        let _ledger = isolated_appcontainer_ledger_test();
        for (index, failpoint) in [
            ProfileIntentFailpoint::BeforeMarkerCreate,
            ProfileIntentFailpoint::AfterMarkerCreate,
            ProfileIntentFailpoint::BeforeDacl,
            ProfileIntentFailpoint::BeforeWrite,
            ProfileIntentFailpoint::BeforeSync,
        ]
        .into_iter()
        .enumerate()
        {
            let name = unique_profile_name(&format!("mf{index}"));
            let result =
                WindowsAppContainerProfileIntent::begin_with_failpoint(name.clone(), failpoint);
            let error = result.err().expect("the injected stage must fail closed");
            assert!(
                error.to_string().contains("forced failure"),
                "unexpected {failpoint:?} error: {error}"
            );
            assert!(!super::appcontainer_cleanup_healthy());

            let session = super::PROFILE_LEDGER_SESSION
                .lock()
                .unwrap()
                .as_ref()
                .expect("a durable cleanup session must exist before marker creation")
                .directory
                .clone();
            assert!(session.exists());
            let marker = session.join(profile_ledger_filename(&name));
            if failpoint == ProfileIntentFailpoint::BeforeMarkerCreate {
                assert!(!directory_contains_path(&marker));
            } else {
                assert!(
                    directory_contains_path(&marker),
                    "{failpoint:?} must retain its marker"
                );
                let retry = retry_pending_appcontainer_profile_cleanup().unwrap_err();
                assert!(retry.to_string().contains("no live owner guard"));
            }
            assert!(shutdown_appcontainer_profile_cleanup().is_err());
            assert!(session.exists(), "latched cleanup must retain its session");

            reset_profile_cleanup_test_state();
            if directory_contains_path(&marker) {
                std::fs::remove_file(&marker).unwrap();
            }
            shutdown_appcontainer_profile_cleanup().unwrap();
            assert!(!session.exists());
        }
    }

    #[test]
    fn failed_immediate_marker_delete_remains_retryable_and_quarantines_launches() {
        let _ledger = isolated_appcontainer_ledger_test();
        let name = unique_profile_name("marker-delete-failure");
        let mut intent = WindowsAppContainerProfileIntent::begin(name.clone()).unwrap();
        let marker = intent.ledger_entry.as_ref().unwrap().path.clone();
        intent.ledger_entry.as_mut().unwrap().forced_remove_failures =
            Some(std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(1)));

        let error = intent.cancel().unwrap_err();
        assert!(error.to_string().contains("forced exact profile-marker"));
        assert!(directory_contains_path(&marker));
        assert!(!super::appcontainer_cleanup_healthy());
        let retry = retry_pending_appcontainer_profile_cleanup().unwrap_err();
        assert!(retry.to_string().contains("no live owner guard"));
        assert!(shutdown_appcontainer_profile_cleanup().is_err());

        let final_cleanup = intent.cancel().unwrap_err();
        assert!(
            final_cleanup
                .to_string()
                .contains("cleanup health is latched")
        );
        assert!(!marker.exists());
        reset_profile_cleanup_test_state();
        shutdown_appcontainer_profile_cleanup().unwrap();
    }

    #[test]
    fn empty_stale_profile_session_is_quarantined_not_removed() {
        let _ledger = isolated_appcontainer_ledger_test();
        let root = ensure_profile_ledger_root().unwrap();
        let session = root.join(format!(
            "stale-empty-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&session).unwrap();
        crate::windows_launcher::secure_owner_only_path(&session, true).unwrap();
        let lock = session.join(".lock");
        std::fs::File::create(&lock).unwrap().sync_all().unwrap();
        crate::windows_launcher::secure_owner_only_path(&lock, false).unwrap();

        let error = retry_pending_appcontainer_profile_cleanup().unwrap_err();
        assert!(
            error
                .to_string()
                .contains("stale AppContainer cleanup session")
        );
        assert!(session.exists());
        assert!(lock.exists());

        std::fs::remove_file(lock).unwrap();
        std::fs::remove_dir(session).unwrap();
        reset_profile_cleanup_test_state();
    }

    #[test]
    fn stale_profile_ledger_quarantines_without_deleting_profile_by_name() {
        let _ledger = isolated_appcontainer_ledger_test();
        use std::io::Write as _;

        let root = ensure_profile_ledger_root().unwrap();
        let session = root.join(format!(
            "stale-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&session).unwrap();
        crate::windows_launcher::secure_owner_only_path(&session, true).unwrap();
        let lock = session.join(".lock");
        std::fs::File::create(&lock).unwrap().sync_all().unwrap();
        crate::windows_launcher::secure_owner_only_path(&lock, false).unwrap();
        let name = unique_profile_name("stale-ledger-test");
        let display = "Common Foundry stale cleanup test\0"
            .encode_utf16()
            .collect::<Vec<_>>();
        let description = "Owned stale cleanup regression\0"
            .encode_utf16()
            .collect::<Vec<_>>();
        let entry = session.join(profile_ledger_filename(&name));
        let mut file = std::fs::File::create(&entry).unwrap();
        file.write_all(b"CMFD-APPCONTAINER-PROFILE-INTENT-V2\n")
            .unwrap();
        file.sync_all().unwrap();
        crate::windows_launcher::secure_owner_only_path(&entry, false).unwrap();

        let encoded_name = hex::encode(
            name[..name.len() - 1]
                .iter()
                .flat_map(|unit| unit.to_le_bytes())
                .collect::<Vec<_>>(),
        );
        let mut holder = Command::new(std::env::current_exe().unwrap());
        holder
            .arg("--exact")
            .arg("process::tests::appcontainer_profile_holder_child")
            .arg("--nocapture")
            .env(PROFILE_HOLDER_ENV, encoded_name)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut holder = holder.spawn().unwrap();
        let mut holder_stdout = std::io::BufReader::new(holder.stdout.take().unwrap());
        let mut ready = String::new();
        loop {
            let mut line = String::new();
            assert_ne!(
                std::io::BufRead::read_line(&mut holder_stdout, &mut line).unwrap(),
                0
            );
            ready.push_str(&line);
            if line.contains("CMFD_PROFILE_HOLDER_READY") {
                break;
            }
        }

        let error = retry_pending_appcontainer_profile_cleanup().unwrap_err();
        assert!(error.to_string().contains("quarantined"));
        assert!(entry.exists());
        assert!(session.exists());

        let recreated =
            try_create_untracked_test_profile(name.clone(), &display, &description).unwrap();
        assert!(
            recreated.is_none(),
            "stale quarantine must not delete or adopt the registered profile"
        );
        drop(holder.stdin.take());
        let output = holder.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "profile-holder child failed: ready={ready:?}, stderr={:?}",
            String::from_utf8_lossy(&output.stderr)
        );
        std::fs::remove_file(entry).unwrap();
        std::fs::remove_file(lock).unwrap();
        std::fs::remove_dir(session).unwrap();
        super::APPCONTAINER_CLEANUP_UNHEALTHY.store(false, std::sync::atomic::Ordering::Release);
    }

    #[test]
    fn appcontainer_profile_holder_child() {
        let Some(encoded) = std::env::var_os(PROFILE_HOLDER_ENV) else {
            return;
        };
        use std::io::{Read as _, Write as _};

        let bytes = hex::decode(encoded.to_string_lossy().as_bytes()).unwrap();
        let mut name = bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        name.push(0);
        let display = "Common Foundry cross-process profile holder\0"
            .encode_utf16()
            .collect::<Vec<_>>();
        let description = "Cross-process stale-ledger nondeletion regression\0"
            .encode_utf16()
            .collect::<Vec<_>>();
        let mut profile = try_create_untracked_test_profile(name, &display, &description)
            .unwrap()
            .expect("create the RAII-owned cross-process profile registration");
        println!("CMFD_PROFILE_HOLDER_READY");
        std::io::stdout().flush().unwrap();
        let mut input = Vec::new();
        std::io::stdin().read_to_end(&mut input).unwrap();
        profile.delete_registration().unwrap();
    }

    #[test]
    fn shutdown_cleanup_never_deletes_another_live_worker_profile() {
        let _ledger = isolated_appcontainer_ledger_test();

        fn create_owned_profile(label: &str) -> (Vec<u16>, WindowsAppContainerProfile) {
            let name = unique_profile_name(&format!("live.{label}"));
            let display = "Common Foundry live shutdown test\0"
                .encode_utf16()
                .collect::<Vec<_>>();
            let description = "Owned live shutdown regression\0"
                .encode_utf16()
                .collect::<Vec<_>>();
            let mut created = try_create_owned_test_profile(name.clone(), &display, &description)
                .unwrap()
                .expect("randomized owned profile name must be unused");
            let profile = created.take_registration();
            (name, profile)
        }

        fn assert_profile_still_registered(name: &[u16]) {
            let display = "Common Foundry collision probe\0"
                .encode_utf16()
                .collect::<Vec<_>>();
            let description = "Must not replace a live profile\0"
                .encode_utf16()
                .collect::<Vec<_>>();
            assert!(
                try_create_untracked_test_profile(name.to_vec(), &display, &description,)
                    .unwrap()
                    .is_none(),
                "the live profile registration unexpectedly disappeared"
            );
        }

        let (first_name, mut first) = create_owned_profile("first");
        let first_entry = first.ledger_entry.as_ref().unwrap().path.clone();
        let (second_name, mut second) = create_owned_profile("second");
        let second_entry = second.ledger_entry.as_ref().unwrap().path.clone();

        shutdown_appcontainer_profile_cleanup().unwrap();
        assert!(first_entry.exists() && second_entry.exists());
        assert_profile_still_registered(&first_name);
        assert_profile_still_registered(&second_name);

        first.delete().unwrap();
        shutdown_appcontainer_profile_cleanup().unwrap();
        assert!(!first_entry.exists());
        assert!(second_entry.exists());
        assert_profile_still_registered(&second_name);

        second.delete().unwrap();
        shutdown_appcontainer_profile_cleanup().unwrap();
        assert!(!second_entry.exists());
    }

    #[test]
    fn managed_process_child_helper() {
        if std::env::var_os(CHILD_ENV).is_some() {
            thread::sleep(Duration::from_secs(30));
        }
    }

    fn spawn_child() -> std::process::Child {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .arg("--exact")
            .arg("process::tests::managed_process_child_helper")
            .arg("--nocapture")
            .env(CHILD_ENV, "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command.spawn().expect("launch managed-process test child")
    }

    fn wait_for_exit(process: &mut ManagedProcess) -> std::process::ExitStatus {
        let started = Instant::now();
        loop {
            if let Some(status) = process.try_wait().expect("query child status") {
                return status;
            }
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "managed child was not reaped after termination"
            );
            thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn std_child_wrapper_owns_pipes_and_lifecycle() {
        let child = spawn_child();
        let id = child.id();
        let mut process = ManagedProcess::from_std(child);

        assert_eq!(process.id(), id);
        assert!(process.take_stdin().is_some());
        assert!(process.take_stdout().is_some());
        assert!(process.take_stderr().is_some());
        assert!(process.try_wait().unwrap().is_none());
        process.kill().expect("terminate std child");
        assert!(!wait_for_exit(&mut process).success());
    }

    #[test]
    fn win32_child_wrapper_owns_raw_process_handle_and_pipes() {
        let mut child = spawn_child();
        let process_id = child.id();
        let process = duplicate_process_handle(&child);
        let stdin = child
            .stdin
            .take()
            .map(|pipe| Box::new(pipe) as BlockingPipeWriter);
        let stdout = child
            .stdout
            .take()
            .map(|pipe| Box::new(pipe) as BlockingPipeReader);
        let stderr = child
            .stderr
            .take()
            .map(|pipe| Box::new(pipe) as BlockingPipeReader);
        let mut process = ManagedProcess::from_win32(
            Win32Child::new(process, process_id, None, None, stdin, stdout, stderr).unwrap(),
        );

        assert_eq!(process.id(), process_id);
        assert!(process.take_stdin().is_some());
        assert!(process.take_stdout().is_some());
        assert!(process.take_stderr().is_some());
        assert!(process.try_wait().unwrap().is_none());
        process.kill().expect("terminate raw Win32 child");
        assert!(!wait_for_exit(&mut process).success());
        child.wait().expect("reap original std child handle");
    }

    #[test]
    fn win32_child_retains_cleanup_after_a_forced_try_wait_failure() {
        use std::sync::{Arc, atomic::AtomicUsize};

        const ENVIRONMENT: &str = "CMFD_FORCED_PROFILE_CLEANUP_CHILD";
        if std::env::var_os(ENVIRONMENT).is_none() {
            let output = Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg("process::tests::win32_child_retains_cleanup_after_a_forced_try_wait_failure")
                .arg("--nocapture")
                .env(ENVIRONMENT, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "forced cleanup subprocess failed: stdout={:?}, stderr={:?}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }

        let mut child = spawn_child();
        let process_id = child.id();
        let process = duplicate_process_handle(&child);
        child.kill().unwrap();
        child.wait().unwrap();

        let failures = Arc::new(AtomicUsize::new(1));
        let mut profile = test_profile();
        profile.force_delete_failures(Arc::clone(&failures));
        let mut process = ManagedProcess::from_win32(
            Win32Child::new(process, process_id, Some(profile), None, None, None, None).unwrap(),
        );
        assert!(
            process.try_wait().is_err(),
            "the forced cleanup failure must be surfaced"
        );
        assert!(
            process.try_wait().unwrap().is_some(),
            "the failed cleanup must remain retained and retryable"
        );
        assert!(
            !super::appcontainer_cleanup_healthy(),
            "an exhausted cleanup attempt must latch worker health"
        );
    }

    fn duplicate_process_handle(child: &std::process::Child) -> OwnedHandle {
        // SAFETY: `GetCurrentProcess` has no preconditions and returns a
        // process-local pseudo handle that must not be closed.
        let current_process = unsafe { GetCurrentProcess() };
        let mut duplicate = std::ptr::null_mut();
        // SAFETY: the pseudo current-process handle and the child's live
        // process handle are valid. `duplicate` receives a new, non-inherited
        // owned handle with the same access rights.
        let duplicated = unsafe {
            DuplicateHandle(
                current_process,
                child.as_raw_handle().cast(),
                current_process,
                &mut duplicate,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        };
        assert_ne!(duplicated, 0, "duplicate child process handle");
        // SAFETY: `DuplicateHandle` returned a fresh owned handle above.
        unsafe { OwnedHandle::from_raw_handle(duplicate.cast()) }
    }
}
