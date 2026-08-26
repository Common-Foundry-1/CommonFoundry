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
    Win32(Win32Child),
}

impl ManagedProcess {
    pub(crate) fn from_std(child: Child) -> Self {
        Self::Std(child)
    }

    #[cfg(windows)]
    #[allow(dead_code)] // Constructed by the AppContainer launcher tranche.
    pub(crate) fn from_win32(child: Win32Child) -> Self {
        Self::Win32(child)
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
    stdin: Option<BlockingPipeWriter>,
    stdout: Option<BlockingPipeReader>,
    stderr: Option<BlockingPipeReader>,
}

#[cfg(windows)]
impl Win32Child {
    #[allow(dead_code)] // Constructed by the AppContainer launcher tranche.
    pub(crate) fn new(
        process: std::os::windows::io::OwnedHandle,
        process_id: u32,
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

    use super::{BlockingPipeReader, BlockingPipeWriter, ManagedProcess, Win32Child};

    const CHILD_ENV: &str = "CMFD_MANAGED_PROCESS_CHILD";

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
            Win32Child::new(process, process_id, stdin, stdout, stderr).unwrap(),
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
