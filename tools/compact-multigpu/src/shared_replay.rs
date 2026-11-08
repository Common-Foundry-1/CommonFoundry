//! Replay borrows the fixed service's immutable encoded device model.
use super::*;
use anyhow::Context as _;
use std::ffi::{c_char, CStr, CString};
unsafe extern "C" {
    fn cmfd_shared_model_open(
        b0: *const u8,
        b1: *const u8,
        b2: *const u8,
        base: *const u8,
        first: *const u8,
        error: *mut c_char,
        capacity: usize,
    ) -> i32;
    fn cmfd_shared_model_run(
        mode: *const c_char,
        coefficients: *const c_char,
        prefix: *const c_char,
        error: *mut c_char,
        capacity: usize,
    ) -> i32;
    fn cmfd_shared_model_trim(error: *mut c_char, capacity: usize) -> i32;
    fn cmfd_shared_model_run_batch(
        count: u32,
        coefficients: *const c_char,
        prefix: *const c_char,
        challenges: *const c_char,
        error: *mut c_char,
        capacity: usize,
    ) -> i32;
    fn cmfd_shared_model_close();
}
struct OutputGuard(i32);
impl OutputGuard {
    fn stderr() -> Result<Self> {
        unsafe {
            libc::fflush(std::ptr::null_mut());
            let fd = libc::dup(libc::STDOUT_FILENO);
            ensure!(fd >= 0, "save worker output");
            if libc::dup2(libc::STDERR_FILENO, libc::STDOUT_FILENO) < 0 {
                libc::close(fd);
                anyhow::bail!("redirect replay diagnostics")
            }
            Ok(Self(fd))
        }
    }
}
impl Drop for OutputGuard {
    fn drop(&mut self) {
        unsafe {
            libc::fflush(std::ptr::null_mut());
            libc::dup2(self.0, libc::STDOUT_FILENO);
            libc::close(self.0);
        }
    }
}
fn call(operation: impl FnOnce(*mut c_char, usize) -> i32) -> Result<()> {
    let _output = OutputGuard::stderr()?;
    let mut error = [0i8; 1024];
    let status = operation(error.as_mut_ptr(), error.len());
    ensure!(
        status == 0,
        "shared replay: {}",
        unsafe { CStr::from_ptr(error.as_ptr()) }.to_string_lossy()
    );
    Ok(())
}
pub(crate) struct Model;
impl Model {
    pub(crate) fn open(
        prepared: &PreparedProver,
        banks: &[DeviceBuffer<u8>],
        scope: &TaskScope,
    ) -> Result<Self> {
        ensure!(
            banks.len() == 3 && banks.iter().all(|b| b.len() == BANK_BYTES),
            "shared model shape"
        );
        scope.synchronize_blocking()?;
        call(|error, capacity| unsafe {
            cmfd_shared_model_open(
                banks[0].as_ptr(),
                banks[1].as_ptr(),
                banks[2].as_ptr(),
                prepared.base_input.as_ptr(),
                prepared.encoded_banks[0].as_ptr(),
                error,
                capacity,
            )
        })?;
        Ok(Self)
    }
    pub(crate) fn run(
        &mut self,
        mode: &str,
        coefficients: &Path,
        prefix: &Path,
        batch: u32,
        challenges: &Path,
    ) -> Result<()> {
        ensure!(
            matches!(mode, "search" | "full" | "batch" | "digest"),
            "shared replay mode"
        );
        ensure!(
            coefficients.is_absolute() && prefix.is_absolute(),
            "shared replay paths must be absolute"
        );
        let coefficients =
            CString::new(coefficients.to_str().context("coefficient path encoding")?)?;
        let prefix = CString::new(prefix.to_str().context("witness path encoding")?)?;
        if matches!(mode, "batch" | "digest") {
            ensure!((1..=64).contains(&batch), "shared replay batch size");
            let challenges = if mode == "digest" {
                ensure!(challenges.is_absolute(), "challenge path must be absolute");
                Some(CString::new(
                    challenges.to_str().context("challenge path encoding")?,
                )?)
            } else {
                None
            };
            call(|e, c| unsafe {
                cmfd_shared_model_run_batch(
                    batch,
                    coefficients.as_ptr(),
                    prefix.as_ptr(),
                    challenges.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
                    e,
                    c,
                )
            })
        } else {
            let mode = CString::new(mode)?;
            call(|error, capacity| unsafe {
                cmfd_shared_model_run(
                    mode.as_ptr(),
                    coefficients.as_ptr(),
                    prefix.as_ptr(),
                    error,
                    capacity,
                )
            })
        }
    }
    pub(crate) fn trim(&mut self) -> Result<()> {
        call(|e, c| unsafe { cmfd_shared_model_trim(e, c) })
    }
}
impl Drop for Model {
    fn drop(&mut self) {
        if let Ok(_output) = OutputGuard::stderr() {
            unsafe {
                cmfd_shared_model_close();
            }
        }
    }
}
