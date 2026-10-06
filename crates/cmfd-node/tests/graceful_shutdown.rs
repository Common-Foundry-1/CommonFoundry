#![cfg(all(
    any(unix, windows),
    not(any(feature = "production-v3-testnet", feature = "production-v4-testnet"))
))]

use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;

static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(0);
static PROCESS_TEST_SERIAL: Mutex<()> = Mutex::new(());
const PROCESS_TIMEOUT: Duration = Duration::from_secs(15);
const PROMPT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(3);

/// Compares chain state across a restart. How the node started (snapshot or
/// replay, background history check pending or done) may differ.
fn assert_status_state_equal(mut actual: Value, mut expected: Value) {
    for status in [&mut actual, &mut expected] {
        let fields = status.as_object_mut().expect("status must be an object");
        for path_dependent in [
            "startup_snapshot_used",
            "history_scrub_complete",
            "history_scrub_verified_records",
        ] {
            fields.remove(path_dependent);
        }
    }
    assert_eq!(actual, expected);
}

struct TestDir(PathBuf);

impl TestDir {
    fn new(label: &str) -> Self {
        let sequence = NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "cmfd-node-{label}-{}-{sequence}",
            std::process::id()
        ));
        if path.exists() {
            fs::remove_dir_all(&path).unwrap();
        }
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        if self.0.exists()
            && let Err(error) = fs::remove_dir_all(&self.0)
            && !thread::panicking()
        {
            panic!("remove isolated test directory {:?}: {error}", self.0);
        }
    }
}

struct ManagedChild(Child);

impl Deref for ManagedChild {
    type Target = Child;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ManagedChild {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(None)) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

struct StalledPeer {
    address: SocketAddr,
    accepted: Receiver<()>,
    release: Option<SyncSender<()>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl StalledPeer {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (accepted_sender, accepted) = mpsc::sync_channel(1);
        let (release, release_receiver) = mpsc::sync_channel(1);
        let thread = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            accepted_sender.send(()).unwrap();
            let _ = release_receiver.recv();
            drop(stream);
        });
        Self {
            address,
            accepted,
            release: Some(release),
            thread: Some(thread),
        }
    }

    fn wait_for_connection(&self) {
        self.accepted.recv_timeout(PROCESS_TIMEOUT).unwrap();
    }
}

impl Drop for StalledPeer {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        // If the test failed before the node connected, wake the blocking
        // accept so cleanup cannot hang while unwinding.
        let _ = TcpStream::connect_timeout(&self.address, Duration::from_millis(100));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn command(data_dir: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_cmfd-node"));
    command.arg("--data-dir").arg(data_dir);
    command
}

fn two_free_addresses() -> (SocketAddr, SocketAddr) {
    let first = TcpListener::bind("127.0.0.1:0").unwrap();
    let second = TcpListener::bind("127.0.0.1:0").unwrap();
    let addresses = (first.local_addr().unwrap(), second.local_addr().unwrap());
    assert_ne!(addresses.0, addresses.1);
    addresses
}

fn spawn_service(mut command: Command) -> ManagedChild {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        use windows_sys::Win32::System::Threading::CREATE_NEW_PROCESS_GROUP;

        command.creation_flags(CREATE_NEW_PROCESS_GROUP);
    }
    ManagedChild(
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    )
}

#[cfg(windows)]
fn spawn_service_with_new_console(mut command: Command) -> ManagedChild {
    use std::os::windows::process::CommandExt;
    use windows_sys::Win32::System::Threading::CREATE_NEW_CONSOLE;

    ManagedChild(
        command
            .creation_flags(CREATE_NEW_CONSOLE)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    )
}

fn signal_interrupt(child: &Child) {
    #[cfg(unix)]
    {
        // SAFETY: the child PID came from a live std::process::Child and SIGINT
        // does not dereference any process-local pointers.
        assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGINT) }, 0);
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Console::{CTRL_BREAK_EVENT, GenerateConsoleCtrlEvent};

        // The child is its own process group, so CTRL_BREAK_EVENT exercises the
        // same registered console handler without interrupting the test runner.
        // SAFETY: the process-group identifier is the live child PID created
        // with CREATE_NEW_PROCESS_GROUP.
        assert_ne!(
            unsafe { GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, child.id()) },
            0
        );
    }
}

#[cfg(unix)]
fn signal_termination(child: &Child) {
    // SAFETY: the child PID came from a live std::process::Child and SIGTERM
    // does not dereference any process-local pointers.
    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGTERM) }, 0);
}

#[cfg(windows)]
struct AttachedChildConsole {
    had_parent_console: bool,
}

#[cfg(windows)]
impl AttachedChildConsole {
    fn attach(child: &Child) -> Self {
        use windows_sys::Win32::System::Console::{
            AttachConsole, FreeConsole, SetConsoleCtrlHandler,
        };

        // SAFETY: these calls change only this test process's console
        // attachment and handler table. The child owns a distinct live console.
        unsafe {
            let had_parent_console = FreeConsole() != 0;
            let console = Self { had_parent_console };
            assert_ne!(AttachConsole(child.id()), 0);
            assert_ne!(SetConsoleCtrlHandler(None, 1), 0);
            console
        }
    }

    fn send_ctrl_c(&self) {
        use windows_sys::Win32::System::Console::{CTRL_C_EVENT, GenerateConsoleCtrlEvent};

        // SAFETY: group zero broadcasts only within the currently attached
        // child console. This test process has explicitly ignored the event.
        assert_ne!(unsafe { GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0) }, 0);
    }
}

#[cfg(windows)]
impl Drop for AttachedChildConsole {
    fn drop(&mut self) {
        use windows_sys::Win32::System::Console::{
            ATTACH_PARENT_PROCESS, AttachConsole, FreeConsole, SetConsoleCtrlHandler,
        };

        // SAFETY: restore this test process to its original parent console and
        // remove its temporary Ctrl+C-ignore setting.
        unsafe {
            let _ = FreeConsole();
            if self.had_parent_console {
                let _ = AttachConsole(ATTACH_PARENT_PROCESS);
            }
            let _ = SetConsoleCtrlHandler(None, 0);
        }
    }
}

fn child_output(child: &mut Child) -> (String, String) {
    let mut stdout = String::new();
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stdout.take() {
        pipe.read_to_string(&mut stdout).unwrap();
    }
    if let Some(mut pipe) = child.stderr.take() {
        pipe.read_to_string(&mut stderr).unwrap();
    }
    (stdout, stderr)
}

fn wait_for_success(child: &mut Child) {
    wait_for_success_with_timeout(child, PROCESS_TIMEOUT);
}

fn wait_for_success_with_timeout(child: &mut Child, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            let (stdout, stderr) = child_output(child);
            assert!(
                status.success(),
                "node exited with {status}; stdout={stdout:?}; stderr={stderr:?}"
            );
            return;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let status = child.wait().unwrap();
            let (stdout, stderr) = child_output(child);
            panic!(
                "node did not stop within {timeout:?}; killed with {status}; stdout={stdout:?}; stderr={stderr:?}"
            );
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn assert_running(child: &mut Child) {
    if let Some(status) = child.try_wait().unwrap() {
        let (stdout, stderr) = child_output(child);
        panic!("node exited early with {status}; stdout={stdout:?}; stderr={stderr:?}");
    }
}

fn rpc_health(address: SocketAddr) -> bool {
    let Ok(mut stream) = TcpStream::connect_timeout(&address, Duration::from_millis(100)) else {
        return false;
    };
    stream
        .set_read_timeout(Some(Duration::from_millis(250)))
        .unwrap();
    if stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut response = String::new();
    stream.read_to_string(&mut response).is_ok() && response.starts_with("HTTP/1.1 200 OK\r\n")
}

fn wait_for_rpc(child: &mut Child, address: SocketAddr) {
    let deadline = Instant::now() + PROCESS_TIMEOUT;
    while Instant::now() < deadline {
        assert_running(child);
        if rpc_health(address) {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("RPC listener {address} did not become healthy");
}

fn connect_to_listener(child: &mut Child, address: SocketAddr) -> TcpStream {
    let deadline = Instant::now() + PROCESS_TIMEOUT;
    while Instant::now() < deadline {
        assert_running(child);
        if let Ok(stream) = TcpStream::connect_timeout(&address, Duration::from_millis(100)) {
            return stream;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("listener {address} did not become reachable");
}

fn connect_live_inbound_peer(child: &mut Child, address: SocketAddr) -> TcpStream {
    let deadline = Instant::now() + PROCESS_TIMEOUT;
    while Instant::now() < deadline {
        assert_running(child);
        if let Ok(mut stream) = TcpStream::connect_timeout(&address, Duration::from_millis(100)) {
            stream
                .set_read_timeout(Some(Duration::from_millis(250)))
                .unwrap();
            let mut first_server_hello_byte = [0_u8; 1];
            if stream.read_exact(&mut first_server_hello_byte).is_ok() {
                return stream;
            }
            let _ = stream.shutdown(Shutdown::Both);
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("P2P listener {address} never began an inbound peer session");
}

fn run_checked(mut command: Command) -> std::process::Output {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "command failed with {}; stdout={:?}; stderr={:?}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn status(data_dir: &Path) -> Value {
    let mut status = command(data_dir);
    status.arg("status");
    serde_json::from_slice(&run_checked(status).stdout).unwrap()
}

fn assert_reusable(address: SocketAddr) {
    let listener = TcpListener::bind(address).unwrap();
    drop(listener);
}

fn assert_success(status: ExitStatus) {
    assert!(status.success(), "command exited with {status}");
}

#[test]
fn interrupt_stops_rpc_and_p2p_releases_resources_and_preserves_replay() {
    let _serial = PROCESS_TEST_SERIAL.lock().unwrap();
    let data_dir = TestDir::new("graceful-run");
    let mut mine = command(data_dir.path());
    mine.args(["mine-once", "--attempts", "1000000"]);
    assert_success(run_checked(mine).status);
    let before = status(data_dir.path());
    assert_eq!(before["accepted_height"], 1);
    assert_eq!(before["storage_healthy"], true);

    let (rpc_address, p2p_address) = two_free_addresses();
    let mut run = command(data_dir.path());
    run.arg("run")
        .arg("--bind")
        .arg(rpc_address.to_string())
        .arg("--p2p-bind")
        .arg(p2p_address.to_string());
    let mut child = spawn_service(run);
    wait_for_rpc(&mut child, rpc_address);
    let inbound_peer = connect_live_inbound_peer(&mut child, p2p_address);
    signal_interrupt(&child);
    wait_for_success_with_timeout(&mut child, PROMPT_SHUTDOWN_TIMEOUT);
    drop(inbound_peer);

    assert_reusable(rpc_address);
    assert_reusable(p2p_address);
    let after = status(data_dir.path());
    assert_status_state_equal(after, before);
}

#[test]
fn interrupt_stops_pool_and_p2p_then_releases_ports_and_data_lock() {
    let _serial = PROCESS_TEST_SERIAL.lock().unwrap();
    let data_dir = TestDir::new("graceful-pool");
    let certificate = data_dir.path().join("pool.crt.der");
    let private_key = data_dir.path().join("pool.key.der");
    let mut generate = command(data_dir.path());
    generate
        .arg("pool-certificate")
        .arg("--certificate")
        .arg(&certificate)
        .arg("--private-key")
        .arg(&private_key);
    assert_success(run_checked(generate).status);
    let before = status(data_dir.path());

    let (pool_address, p2p_address) = two_free_addresses();
    let mut pool = command(data_dir.path());
    pool.arg("pool-serve")
        .arg("--bind")
        .arg(pool_address.to_string())
        .arg("--p2p-bind")
        .arg(p2p_address.to_string())
        .arg("--certificate")
        .arg(&certificate)
        .arg("--private-key")
        .arg(&private_key)
        .arg("--share-leading-zero-bits")
        .arg("0");
    let mut child = spawn_service(pool);
    let mut stalled_pre_tls = connect_to_listener(&mut child, pool_address);
    stalled_pre_tls.write_all(&[0x16]).unwrap();
    thread::sleep(Duration::from_millis(100));
    signal_interrupt(&child);
    wait_for_success_with_timeout(&mut child, PROMPT_SHUTDOWN_TIMEOUT);
    drop(stalled_pre_tls);

    assert_reusable(pool_address);
    assert_reusable(p2p_address);
    let after = status(data_dir.path());
    assert_status_state_equal(after, before);
}

fn wait_for_failure_with_timeout(child: &mut Child, timeout: Duration, expected_error: &str) {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            let (stdout, stderr) = child_output(child);
            assert!(
                !status.success() && stderr.contains(expected_error),
                "node exited with {status}; stdout={stdout:?}; stderr={stderr:?}"
            );
            return;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let status = child.wait().unwrap();
            let (stdout, stderr) = child_output(child);
            panic!(
                "node did not reject the request within {timeout:?}; killed with {status}; stdout={stdout:?}; stderr={stderr:?}"
            );
        }
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn authenticated_local_request_stops_pool_and_releases_resources() {
    let _serial = PROCESS_TEST_SERIAL.lock().unwrap();
    let data_dir = TestDir::new("requested-pool-stop");
    fs::create_dir_all(data_dir.path()).unwrap();
    let certificate = data_dir.path().join("pool.crt.der");
    let private_key = data_dir.path().join("pool.key.der");
    let shutdown_request = data_dir.path().join("pool.shutdown");
    let mut generate = command(data_dir.path());
    generate
        .arg("pool-certificate")
        .arg("--certificate")
        .arg(&certificate)
        .arg("--private-key")
        .arg(&private_key);
    assert_success(run_checked(generate).status);

    let (pool_address, p2p_address) = two_free_addresses();
    let mut pool = command(data_dir.path());
    pool.arg("pool-serve")
        .arg("--bind")
        .arg(pool_address.to_string())
        .arg("--p2p-bind")
        .arg(p2p_address.to_string())
        .arg("--certificate")
        .arg(&certificate)
        .arg("--private-key")
        .arg(&private_key)
        .arg("--share-leading-zero-bits")
        .arg("0")
        .arg("--shutdown-request-file")
        .arg(&shutdown_request);
    let mut child = spawn_service(pool);
    let pool_connection = connect_to_listener(&mut child, pool_address);
    fs::write(&shutdown_request, b"CMFD_POOL_SHUTDOWN_V1\n").unwrap();
    wait_for_success_with_timeout(&mut child, PROMPT_SHUTDOWN_TIMEOUT);
    drop(pool_connection);

    assert_reusable(pool_address);
    assert_reusable(p2p_address);
}

#[test]
fn malformed_local_request_fails_closed_and_releases_resources() {
    let _serial = PROCESS_TEST_SERIAL.lock().unwrap();
    let data_dir = TestDir::new("malformed-pool-stop");
    fs::create_dir_all(data_dir.path()).unwrap();
    let certificate = data_dir.path().join("pool.crt.der");
    let private_key = data_dir.path().join("pool.key.der");
    let shutdown_request = data_dir.path().join("pool.shutdown");
    let mut generate = command(data_dir.path());
    generate
        .arg("pool-certificate")
        .arg("--certificate")
        .arg(&certificate)
        .arg("--private-key")
        .arg(&private_key);
    assert_success(run_checked(generate).status);

    let (pool_address, p2p_address) = two_free_addresses();
    let mut pool = command(data_dir.path());
    pool.arg("pool-serve")
        .arg("--bind")
        .arg(pool_address.to_string())
        .arg("--p2p-bind")
        .arg(p2p_address.to_string())
        .arg("--certificate")
        .arg(&certificate)
        .arg("--private-key")
        .arg(&private_key)
        .arg("--share-leading-zero-bits")
        .arg("0")
        .arg("--shutdown-request-file")
        .arg(&shutdown_request);
    let mut child = spawn_service(pool);
    let pool_connection = connect_to_listener(&mut child, pool_address);
    fs::write(&shutdown_request, b"CMFD_POOL_SHUTDOWN_V0\n").unwrap();
    wait_for_failure_with_timeout(
        &mut child,
        PROMPT_SHUTDOWN_TIMEOUT,
        "shutdown request file is malformed",
    );
    drop(pool_connection);

    assert_reusable(pool_address);
    assert_reusable(p2p_address);
}

#[test]
fn interrupt_stops_a_static_peer_session_stalled_after_connect() {
    let _serial = PROCESS_TEST_SERIAL.lock().unwrap();
    let data_dir = TestDir::new("graceful-static-peer");
    let before = status(data_dir.path());
    let stalled_peer = StalledPeer::start();
    let (rpc_address, p2p_address) = two_free_addresses();
    let mut run = command(data_dir.path());
    run.arg("run")
        .arg("--bind")
        .arg(rpc_address.to_string())
        .arg("--p2p-bind")
        .arg(p2p_address.to_string())
        .arg("--peer")
        .arg(stalled_peer.address.to_string());
    let mut child = spawn_service(run);
    wait_for_rpc(&mut child, rpc_address);
    stalled_peer.wait_for_connection();
    signal_interrupt(&child);
    wait_for_success_with_timeout(&mut child, PROMPT_SHUTDOWN_TIMEOUT);

    assert_reusable(rpc_address);
    assert_reusable(p2p_address);
    assert_status_state_equal(status(data_dir.path()), before);
}

#[cfg(unix)]
#[test]
fn sigterm_exits_zero_and_releases_node_resources() {
    let _serial = PROCESS_TEST_SERIAL.lock().unwrap();
    let data_dir = TestDir::new("sigterm-run");
    let before = status(data_dir.path());
    let (rpc_address, p2p_address) = two_free_addresses();
    let mut run = command(data_dir.path());
    run.arg("run")
        .arg("--bind")
        .arg(rpc_address.to_string())
        .arg("--p2p-bind")
        .arg(p2p_address.to_string());
    let mut child = spawn_service(run);
    wait_for_rpc(&mut child, rpc_address);
    signal_termination(&child);
    wait_for_success(&mut child);

    assert_reusable(rpc_address);
    assert_reusable(p2p_address);
    assert_status_state_equal(status(data_dir.path()), before);
}

#[cfg(windows)]
#[test]
fn literal_windows_ctrl_c_exits_zero_and_releases_node_resources() {
    let _serial = PROCESS_TEST_SERIAL.lock().unwrap();
    let data_dir = TestDir::new("literal-windows-ctrl-c");
    let before = status(data_dir.path());
    let (rpc_address, p2p_address) = two_free_addresses();
    let mut run = command(data_dir.path());
    run.arg("run")
        .arg("--bind")
        .arg(rpc_address.to_string())
        .arg("--p2p-bind")
        .arg(p2p_address.to_string());
    let mut child = spawn_service_with_new_console(run);
    wait_for_rpc(&mut child, rpc_address);

    let console = AttachedChildConsole::attach(&child);
    console.send_ctrl_c();
    wait_for_success(&mut child);
    drop(console);

    assert_reusable(rpc_address);
    assert_reusable(p2p_address);
    assert_status_state_equal(status(data_dir.path()), before);
}
