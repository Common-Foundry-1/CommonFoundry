//! Bounded pipe transport for pool-owned child processes.
use std::io::{Read, Write};
use std::process::{ChildStdin, ChildStdout};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const MAX_BYTES: usize = 1024 * 1024;
const MAX_LINES: usize = 4096;
const MAX_COMMAND: usize = 4096;

#[derive(Debug)]
struct Input {
    bytes: Vec<u8>,
    reply: SyncSender<Result<(), String>>,
}

#[derive(Debug)]
pub(crate) struct WorkerIo {
    input: Option<SyncSender<Input>>,
    output: Option<Receiver<Result<Vec<u8>, String>>>,
    pending: Vec<u8>,
    reader: Option<JoinHandle<()>>,
    writer: Option<JoinHandle<()>>,
}

impl WorkerIo {
    pub(crate) fn new(mut stdin: ChildStdin, mut stdout: ChildStdout) -> std::io::Result<Self> {
        let (input, commands) = mpsc::sync_channel::<Input>(1);
        let (chunks, output) = mpsc::sync_channel(4);
        let reader = std::thread::Builder::new()
            .name("pool-worker-output".into())
            .spawn(move || {
                loop {
                    let mut bytes = vec![0; 4096];
                    match stdout.read(&mut bytes) {
                        Ok(0) => {
                            let _ = chunks.send(Err("worker closed stdout".into()));
                            break;
                        }
                        Ok(count) => {
                            bytes.truncate(count);
                            if chunks.send(Ok(bytes)).is_err() {
                                break;
                            }
                        }
                        Err(error) => {
                            let _ = chunks.send(Err(error.to_string()));
                            break;
                        }
                    }
                }
            })?;
        let writer = std::thread::Builder::new()
            .name("pool-worker-input".into())
            .spawn(move || {
                while let Ok(input) = commands.recv() {
                    let result = stdin
                        .write_all(&input.bytes)
                        .and_then(|()| stdin.flush())
                        .map_err(|error| error.to_string());
                    let failed = result.is_err();
                    let _ = input.reply.send(result);
                    if failed {
                        break;
                    }
                }
            })?;
        Ok(Self {
            input: Some(input),
            output: Some(output),
            pending: vec![],
            reader: Some(reader),
            writer: Some(writer),
        })
    }

    pub(crate) fn write(
        &self,
        bytes: Vec<u8>,
        deadline: Instant,
        stop: Option<&AtomicBool>,
    ) -> Result<(), String> {
        if bytes.len() > MAX_COMMAND {
            return Err("worker command exceeds 4096 bytes".into());
        }
        let (reply, result) = mpsc::sync_channel(1);
        self.input
            .as_ref()
            .ok_or("worker input closed")?
            .try_send(Input { bytes, reply })
            .map_err(|_| "worker input queue unavailable")?;
        recv_until(&result, deadline, stop)?
    }

    pub(crate) fn marker(
        &mut self,
        marker: &str,
        deadline: Instant,
        stop: Option<&AtomicBool>,
    ) -> Result<(), String> {
        let mut bytes_seen = self.pending.len();
        let mut lines = 0;
        loop {
            check_deadline(deadline, stop)?;
            if bytes_seen > MAX_BYTES {
                return Err("worker output exceeded byte limit".into());
            }
            while let Some(end) = self.pending.iter().position(|byte| *byte == b'\n') {
                lines += 1;
                if lines > MAX_LINES {
                    return Err("worker output exceeded line limit".into());
                }
                let line = self.pending.drain(..=end).collect::<Vec<_>>();
                let line = std::str::from_utf8(&line).map_err(|_| "worker output is not UTF-8")?;
                if line.trim_end_matches(['\r', '\n']) == marker {
                    return Ok(());
                }
            }
            let output = self.output.as_ref().ok_or("worker output closed")?;
            let chunk = recv_until(output, deadline, stop)??;
            bytes_seen = bytes_seen
                .checked_add(chunk.len())
                .ok_or("worker output overflow")?;
            self.pending.extend_from_slice(&chunk);
        }
    }

    // Call only after terminating the owned child/process group. Pipe threads
    // do not own GPU resources; do not wait forever for inherited pipe handles.
    pub(crate) fn close(&mut self, deadline: Instant) {
        self.input.take();
        self.output.take();
        self.pending.clear();
        for handle in [&mut self.reader, &mut self.writer] {
            if let Some(thread) = handle.take() {
                while !thread.is_finished() && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(5));
                }
                if thread.is_finished() {
                    let _ = thread.join();
                }
            }
        }
    }
}

fn check_deadline(deadline: Instant, stop: Option<&AtomicBool>) -> Result<(), String> {
    if stop.is_some_and(|stop| stop.load(Ordering::Acquire)) {
        return Err("worker operation cancelled".into());
    }
    if Instant::now() >= deadline {
        return Err("worker operation timed out".into());
    }
    Ok(())
}

fn recv_until<T>(
    receiver: &Receiver<T>,
    deadline: Instant,
    stop: Option<&AtomicBool>,
) -> Result<T, String> {
    loop {
        check_deadline(deadline, stop)?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        match receiver.recv_timeout(remaining.min(Duration::from_millis(25))) {
            Ok(value) => return Ok(value),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err("worker pipe thread exited".into());
            }
        }
    }
}
