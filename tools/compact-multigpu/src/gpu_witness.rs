//! Construct the same fixed-shape trace metadata directly on the GPU.
use super::*;
use anyhow::Context as _;
use sp1_gpu_utils::TraceOffset;
use std::{
    collections::BTreeMap,
    ffi::c_void,
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt},
        prelude::PermissionsExt,
    },
};
unsafe extern "C" {
    fn cudaMemcpy(destination: *mut c_void, source: *const c_void, bytes: usize, kind: i32) -> i32;
    fn cudaDeviceSynchronize() -> i32;
    fn cmfd_resident_trace_layout_kernel() -> sp1_gpu_sys::runtime::KernelPtr;
    fn cmfd_resident_validate_words_kernel() -> sp1_gpu_sys::runtime::KernelPtr;
    fn cmfd_resident_derive_activations_kernel() -> sp1_gpu_sys::runtime::KernelPtr;
    fn cmfd_resident_validate_lifts_kernel() -> sp1_gpu_sys::runtime::KernelPtr;
    fn cudaIpcOpenMemHandle(pointer: *mut *mut c_void, handle: IpcHandle, flags: u32) -> i32;
    fn cudaIpcCloseMemHandle(pointer: *mut c_void) -> i32;
}
pub(crate) fn validate_lifts(
    dynamic: &slop_tensor::TensorView<'_, Felt, TaskScope>,
    pre: &Mle<Ext, TaskScope>,
    next: &Mle<Ext, TaskScope>,
    scope: &TaskScope,
) -> Result<()> {
    let mut invalid = DeviceBuffer::from_host_slice(&[0u32], scope)?;
    let args = args!(
        dynamic.as_ptr(),
        pre.guts().as_ptr(),
        next.guts().as_ptr(),
        BANK_VALUES,
        invalid.as_mut_ptr()
    );
    unsafe {
        scope.launch_kernel(
            cmfd_resident_validate_lifts_kernel(),
            512usize,
            256usize,
            &args,
            0,
        )?;
    }
    scope.synchronize_blocking()?;
    let value = invalid.to_host()?[0];
    ensure!(
        value == 0,
        "cubic capture/lift consistency failed flags={value}"
    );
    Ok(())
}
pub(crate) fn validate_capture(
    trace: &JaggedTraceMle<Felt, TaskScope>,
    label: &str,
    scope: &TaskScope,
) -> Result<()> {
    let dynamic = trace.main_virtual_tensor(LOG_ROWS);
    let mut invalid = DeviceBuffer::from_host_slice(&[0u32], scope)?;
    let null = std::ptr::null::<u32>();
    let args = args!(
        dynamic.as_ptr(),
        null,
        null,
        BANK_VALUES,
        invalid.as_mut_ptr()
    );
    unsafe {
        scope.launch_kernel(
            cmfd_resident_validate_lifts_kernel(),
            512usize,
            256usize,
            &args,
            0,
        )?;
        scope.synchronize_blocking()?;
    }
    let value = invalid.to_host()?[0];
    ensure!(
        value == 0,
        "capture consistency {label} failed flags={value}"
    );
    Ok(())
}
#[repr(C)]
struct IpcHandle {
    bytes: [u8; 64],
}
struct Imported {
    pointer: *mut c_void,
}
impl Imported {
    fn open(encoded: &str, minimum: usize) -> Result<Self> {
        let decoded = hex::decode(encoded)?;
        let bytes: [u8; 64] = decoded
            .try_into()
            .map_err(|_| anyhow::anyhow!("GPU handle length"))?;
        let mut pointer = std::ptr::null_mut();
        ensure!(
            unsafe { cudaIpcOpenMemHandle(&mut pointer, IpcHandle { bytes }, 1) } == 0,
            "open same-device GPU witness"
        );
        let imported = Self { pointer };
        type Range = unsafe extern "C" fn(*mut u64, *mut usize, u64) -> i32;
        unsafe {
            let library = libc::dlopen(
                b"libcuda.so.1\0".as_ptr().cast(),
                libc::RTLD_NOW | libc::RTLD_LOCAL,
            );
            ensure!(!library.is_null(), "CUDA driver range API unavailable");
            let symbol = libc::dlsym(library, b"cuMemGetAddressRange_v2\0".as_ptr().cast());
            if symbol.is_null() {
                libc::dlclose(library);
                anyhow::bail!("CUDA allocation range query unavailable")
            }
            let query: Range = std::mem::transmute(symbol);
            let mut base = 0u64;
            let mut size = 0usize;
            let status = query(&mut base, &mut size, pointer as usize as u64);
            libc::dlclose(library);
            ensure!(
                status == 0 && base == pointer as usize as u64 && size >= minimum,
                "GPU witness allocation bounds"
            );
        }
        Ok(imported)
    }
    fn close(mut self) -> Result<()> {
        ensure!(
            unsafe { cudaIpcCloseMemHandle(self.pointer) } == 0,
            "close imported GPU witness"
        );
        self.pointer = std::ptr::null_mut();
        Ok(())
    }
}
impl Drop for Imported {
    fn drop(&mut self) {
        if !self.pointer.is_null() {
            unsafe { cudaIpcCloseMemHandle(self.pointer) };
        }
    }
}
#[derive(Deserialize, Clone)]
struct Descriptor {
    schema: String,
    pid: u32,
    gpu_uuid: String,
    pre_handle: String,
    act_handle: String,
    pre_bytes: usize,
    act_bytes: usize,
    coefficients_hex: String,
    source_prefix: PathBuf,
}
fn validate_job(descriptor: &Descriptor, challenge: [u8; 32], gpu: &str) -> Result<()> {
    ensure!(
        matches!(
            descriptor.schema.as_str(),
            "CMFD_GPU_WITNESS_V1" | "CMFD_GPU_WITNESS_V2"
        ) && descriptor.pid > 1,
        "GPU witness schema/provider"
    );
    ensure!(
        descriptor.gpu_uuid.eq_ignore_ascii_case(gpu),
        "GPU witness must use the proving GPU"
    );
    ensure!(
        descriptor.pre_bytes == 3 * BANK_VALUES * 4
            && descriptor.act_bytes
                == if descriptor.schema == "CMFD_GPU_WITNESS_V2" {
                    0
                } else {
                    (3 * LAYERS + 1) * CELLS * 4
                },
        "GPU witness geometry"
    );
    ensure!(
        descriptor.pre_handle.len() == 128
            && descriptor.act_handle.len()
                == if descriptor.schema == "CMFD_GPU_WITNESS_V2" {
                    0
                } else {
                    128
                },
        "GPU handle shape"
    );
    let mut expected = Vec::new();
    expected.extend_from_slice(&forgematrix_v4_mask_coefficients(challenge, u32::MAX));
    for layer in 0..3 * LAYERS {
        expected.extend_from_slice(&forgematrix_v4_mask_coefficients(challenge, layer as u32));
    }
    ensure!(
        hex::decode(&descriptor.coefficients_hex)? == expected,
        "GPU witness belongs to another nonce/template"
    );
    Ok(())
}
fn validate_descriptor(descriptor: &Descriptor, challenge: [u8; 32]) -> Result<()> {
    validate_job(
        descriptor,
        challenge,
        &std::env::var("CUDA_VISIBLE_DEVICES")?,
    )?;
    let parent = descriptor
        .source_prefix
        .parent()
        .ok_or_else(|| anyhow::anyhow!("GPU witness parent"))?;
    ensure!(
        parent.is_absolute() && !parent.is_symlink(),
        "GPU witness acknowledgement directory"
    );
    let metadata = std::fs::metadata(parent)?;
    ensure!(
        metadata.uid() == unsafe { libc::geteuid() } && metadata.permissions().mode() & 0o077 == 0,
        "GPU witness directory must be private"
    );
    ensure!(
        !descriptor
            .source_prefix
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir)),
        "GPU witness path traversal"
    );
    Ok(())
}

/// Copy into prover-owned device storage, validate every captured field word,
/// then close imported views before acknowledging producer memory release.
pub(crate) fn from_gpu(
    prefix: &Path,
    challenge: [u8; 32],
    scope: &TaskScope,
) -> Result<Option<Vec<JaggedTraceMle<Felt, TaskScope>>>> {
    let host = PathBuf::from(format!("{}-host-pre-only.json", prefix.display()));
    if host.exists() {
        let mut bytes = Vec::new();
        File::open(host)?.take(65537).read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 65536, "host witness descriptor size");
        let descriptor: serde_json::Value = serde_json::from_slice(&bytes)?;
        ensure!(
            descriptor["schema"] == "CMFD_HOST_PRE_ONLY_V1",
            "host witness schema"
        );
        let mut expected = Vec::new();
        expected.extend_from_slice(&forgematrix_v4_mask_coefficients(challenge, u32::MAX));
        for layer in 0..384 {
            expected.extend_from_slice(&forgematrix_v4_mask_coefficients(challenge, layer));
        }
        ensure!(
            hex::decode(
                descriptor["coefficients_hex"]
                    .as_str()
                    .context("host witness coefficients")?
            )? == expected,
            "host witness nonce/template binding"
        );
        let began = Instant::now();
        let mut traces = Vec::new();
        for bank in 0..3 {
            let path = PathBuf::from(format!("{}-bank{bank}-pre.bin", prefix.display()));
            let words =
                SealedWords::open(&path, BANK_VALUES * 4, MODULUS).map_err(anyhow::Error::msg)?;
            let mut storage = allocate(LOG_ROWS, scope)?;
            unsafe {
                let target = storage.dense.as_mut_ptr().add(ROWS);
                ensure!(
                    cudaMemcpy(
                        target.cast(),
                        words.words().as_ptr().cast(),
                        BANK_VALUES * 4,
                        1
                    ) == 0,
                    "upload sealed preactivation"
                );
                // cudaMemcpy's pageable upload/default stream is independent
                // of TaskScope's nonblocking stream. Complete that transfer
                // before deriving activations or reading the captured words.
                ensure!(
                    cudaDeviceSynchronize() == 0,
                    "complete cross-stream preactivation upload"
                );
                let arguments = args!(target, target.add(BANK_VALUES), BANK_VALUES);
                scope.launch_kernel(
                    cmfd_resident_derive_activations_kernel(),
                    512usize,
                    256usize,
                    &arguments,
                    0,
                )?;
                scope.synchronize_blocking()?;
            }
            traces.push(finish(storage, bank, scope)?);
            validate_capture(
                traces.last().unwrap(),
                &format!("initial-bank-{bank}"),
                scope,
            )?;
        }
        scope.synchronize_blocking()?;
        eprintln!(
            "resident_host_pre_only snapshot_seconds={:.6} host_value_bytes={}",
            began.elapsed().as_secs_f64(),
            3 * BANK_VALUES * 4
        );
        return Ok(Some(traces));
    }
    let path = PathBuf::from(format!("{}-gpu-witness.json", prefix.display()));
    if !path.exists() {
        return Ok(None);
    }
    let began = Instant::now();
    let mut bytes = Vec::new();
    File::open(path)?.take(65537).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 65536, "GPU witness descriptor length");
    let descriptor: Descriptor = serde_json::from_slice(&bytes)?;
    validate_descriptor(&descriptor, challenge)?;
    let pre = Imported::open(&descriptor.pre_handle, descriptor.pre_bytes)?;
    let derived = descriptor.schema == "CMFD_GPU_WITNESS_V2";
    let act = if derived {
        None
    } else {
        Some(Imported::open(
            &descriptor.act_handle,
            descriptor.act_bytes,
        )?)
    };
    let mut result = Vec::new();
    for bank in 0..3 {
        let mut storage = allocate(LOG_ROWS, scope)?;
        unsafe {
            let destination = storage.dense.as_mut_ptr().add(ROWS);
            ensure!(
                cudaMemcpy(
                    destination.cast(),
                    pre.pointer.cast::<u8>().add(bank * BANK_VALUES * 4).cast(),
                    BANK_VALUES * 4,
                    3
                ) == 0,
                "snapshot GPU preactivation"
            );
            if let Some(act) = act.as_ref() {
                ensure!(
                    cudaMemcpy(
                        destination.add(BANK_VALUES).cast(),
                        act.pointer
                            .cast::<u8>()
                            .add((bank * LAYERS + 1) * CELLS * 4)
                            .cast(),
                        BANK_VALUES * 4,
                        3
                    ) == 0,
                    "snapshot GPU activation"
                );
            }
            let mut invalid = DeviceBuffer::from_host_slice(&[0u32], scope)?;
            ensure!(
                cudaDeviceSynchronize() == 0,
                "complete imported witness copies"
            );
            scope.synchronize_blocking()?;
            let arguments = args!(
                destination.cast::<u32>(),
                if derived {
                    BANK_VALUES
                } else {
                    2 * BANK_VALUES
                },
                invalid.as_mut_ptr()
            );
            scope.launch_kernel(
                cmfd_resident_validate_words_kernel(),
                512usize,
                256usize,
                &arguments,
                0,
            )?;
            scope.synchronize_blocking()?;
            ensure!(
                invalid.to_host()?[0] == 0,
                "noncanonical captured GPU witness word"
            );
            if derived {
                let arguments = args!(destination, destination.add(BANK_VALUES), BANK_VALUES);
                scope.launch_kernel(
                    cmfd_resident_derive_activations_kernel(),
                    512usize,
                    256usize,
                    &arguments,
                    0,
                )?;
            }
        }
        result.push(finish(storage, bank, scope)?);
    }
    scope.synchronize_blocking()?;
    pre.close()?;
    if let Some(act) = act {
        act.close()?;
    }
    let copied = PathBuf::from(format!(
        "{}-gpu-witness.copied",
        descriptor.source_prefix.display()
    ));
    let pending = copied.with_extension("copied.pending");
    std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&pending)?
        .write_all(b"copied\n")?;
    std::fs::hard_link(&pending, &copied)?;
    std::fs::remove_file(pending)?;
    let released = PathBuf::from(format!(
        "{}-gpu-witness.released",
        descriptor.source_prefix.display()
    ));
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        if released.exists() {
            ensure!(
                !released.is_symlink(),
                "GPU witness release marker is a symlink"
            );
            let mut marker = Vec::new();
            File::open(&released)?.take(65).read_to_end(&mut marker)?;
            ensure!(
                marker == b"released\n",
                "invalid GPU witness release acknowledgement"
            );
            break;
        }
        ensure!(
            Instant::now() < deadline,
            "GPU witness producer did not release its buffers"
        );
        thread::sleep(Duration::from_millis(1));
    }
    eprintln!(
        "resident_gpu_witness snapshot_seconds={:.6} field_words_checked={} host_witness_bytes=0",
        began.elapsed().as_secs_f64(),
        3 * if derived {
            BANK_VALUES
        } else {
            2 * BANK_VALUES
        }
    );
    Ok(Some(result))
}

struct Storage {
    dense: DeviceTensor<Felt>,
    columns: DeviceTensor<u32>,
    rows: usize,
}
fn allocate(log_rows: u32, scope: &TaskScope) -> Result<Storage> {
    let rows = 1usize << log_rows;
    let count = (DYNAMIC_COLUMNS + 1) * rows;
    let mut dense = DeviceTensor::<Felt>::with_sizes_in([count], scope.clone());
    let mut columns = DeviceTensor::<u32>::with_sizes_in([count / 2], scope.clone());
    unsafe {
        dense.assume_init();
        columns.assume_init();
        let arguments = args!(
            dense.as_mut_ptr(),
            columns.as_mut_ptr(),
            rows,
            DYNAMIC_COLUMNS + 1
        );
        scope.launch_kernel(
            cmfd_resident_trace_layout_kernel(),
            512usize,
            256usize,
            &arguments,
            0,
        )?;
    }
    scope.synchronize_blocking()?;
    Ok(Storage {
        dense,
        columns,
        rows,
    })
}
fn finish(
    storage: Storage,
    bank: usize,
    scope: &TaskScope,
) -> Result<JaggedTraceMle<Felt, TaskScope>> {
    let rows = storage.rows;
    let name = format!("v4-bank-{bank}-dynamic");
    let mut prep = BTreeMap::new();
    let mut main = BTreeMap::new();
    prep.insert(
        name.clone(),
        TraceOffset {
            dense_offset: 0..rows,
            poly_size: rows,
            num_polys: 1,
        },
    );
    main.insert(
        name,
        TraceOffset {
            dense_offset: rows..(DYNAMIC_COLUMNS + 1) * rows,
            poly_size: rows,
            num_polys: DYNAMIC_COLUMNS,
        },
    );
    let dense = TraceDenseData {
        dense: storage.dense.into_inner().into_buffer(),
        preprocessed_offset: rows,
        preprocessed_cols: 1,
        preprocessed_padding: 0,
        main_padding: 0,
        prep_padding_col_count: 0,
        main_padding_col_count: 0,
        preprocessed_table_index: prep,
        main_table_index: main,
    };
    let start = (0..=DYNAMIC_COLUMNS + 1)
        .map(|i| (i * (rows / 2)) as u32)
        .collect::<Vec<_>>();
    let heights = vec![(rows / 2) as u32; DYNAMIC_COLUMNS + 1];
    let trace = JaggedTraceMle::new(
        dense,
        storage.columns.into_inner().into_buffer(),
        DeviceBuffer::from_host_slice(&start, scope)?.into_inner(),
        DeviceBuffer::from_host_slice(&heights, scope)?.into_inner(),
    );
    scope.synchronize_blocking()?;
    Ok(trace)
}
pub(crate) fn trace(
    prefix: &Path,
    bank: usize,
    scope: &TaskScope,
) -> Result<JaggedTraceMle<Felt, TaskScope>> {
    let started = Instant::now();
    let words = SealedWords::open(
        &PathBuf::from(format!("{}-bank{bank}-dynamic.bin", prefix.display())),
        DYNAMIC_BYTES,
        MODULUS,
    )
    .map_err(anyhow::Error::msg)?;
    let mut storage = allocate(LOG_ROWS, scope)?;
    unsafe {
        ensure!(
            cudaMemcpy(
                storage.dense.as_mut_ptr().add(ROWS).cast(),
                words.words().as_ptr().cast(),
                DYNAMIC_BYTES,
                1
            ) == 0,
            "upload validated dynamic values"
        );
        ensure!(
            cudaDeviceSynchronize() == 0,
            "complete cross-stream dynamic upload"
        );
    }
    scope.synchronize_blocking()?;
    let result = finish(storage, bank, scope)?;
    eprintln!("resident_witness bank={bank} host_value_bytes={DYNAMIC_BYTES} metadata_host_bytes={} wall_seconds={:.6}",(DYNAMIC_COLUMNS*2+3)*4,started.elapsed().as_secs_f64());
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn gpu_descriptor_binds_nonce_device_and_exact_allocation_shapes() {
        let challenge = [3u8; 32];
        let mut coefficients = Vec::new();
        coefficients.extend_from_slice(&forgematrix_v4_mask_coefficients(challenge, u32::MAX));
        for layer in 0..384 {
            coefficients.extend_from_slice(&forgematrix_v4_mask_coefficients(challenge, layer));
        }
        let gpu = "GPU-00000000-0000-0000-0000-000000000001";
        let descriptor = Descriptor {
            schema: "CMFD_GPU_WITNESS_V1".into(),
            pid: 123,
            gpu_uuid: gpu.into(),
            pre_handle: "00".repeat(64),
            act_handle: "00".repeat(64),
            pre_bytes: 3 * BANK_VALUES * 4,
            act_bytes: (3 * LAYERS + 1) * CELLS * 4,
            coefficients_hex: hex::encode(coefficients),
            source_prefix: "/private/witness".into(),
        };
        assert!(validate_job(&descriptor, challenge, gpu).is_ok());
        assert!(validate_job(&descriptor, [4; 32], gpu).is_err());
        assert!(validate_job(&descriptor, challenge, "GPU-other").is_err());
        let mut changed = descriptor.clone();
        changed.pre_bytes -= 4;
        assert!(validate_job(&changed, challenge, gpu).is_err());
        changed = descriptor.clone();
        changed.act_handle.pop();
        assert!(validate_job(&changed, challenge, gpu).is_err());
        changed = descriptor.clone();
        changed.schema = "CMFD_GPU_WITNESS_V2".into();
        changed.act_handle.clear();
        changed.act_bytes = 0;
        assert!(validate_job(&changed, challenge, gpu).is_ok());
        changed.act_bytes = 4;
        assert!(validate_job(&changed, challenge, gpu).is_err());
    }
    #[test]
    #[ignore = "requires a reserved GPU"]
    fn derived_activations_match_field_cubes_exactly() {
        run_sync_in_place(|scope| -> Result<()> {
            let values = (0..4097)
                .map(|i| Felt::from_canonical_u32(if i == 4096 { MODULUS - 1 } else { i * 510001 }))
                .collect::<Vec<_>>();
            let input = DeviceBuffer::from_host_slice(&values, &scope)?;
            let mut output =
                DeviceBuffer::from_host_slice(&vec![Felt::zero(); values.len()], &scope)?;
            let arguments = args!(input.as_ptr(), output.as_mut_ptr(), values.len());
            unsafe {
                scope.launch_kernel(
                    cmfd_resident_derive_activations_kernel(),
                    512usize,
                    256usize,
                    &arguments,
                    0,
                )?;
            }
            scope.synchronize_blocking()?;
            assert_eq!(
                output.to_host()?,
                values.into_iter().map(|v| v * v * v).collect::<Vec<_>>()
            );
            Ok(())
        })
        .unwrap()
        .unwrap();
    }
    #[test]
    #[ignore = "requires a reserved GPU"]
    fn gpu_field_validation_rejects_noncanonical_words() {
        run_sync_in_place(|scope| -> Result<()> {
            for (words, expected) in [
                (vec![0u32, 1, MODULUS - 1], 0u32),
                (vec![MODULUS, 0, 1], 1),
                (vec![u32::MAX, 0], 1),
            ] {
                let input = DeviceBuffer::from_host_slice(&words, &scope)?;
                let mut invalid = DeviceBuffer::from_host_slice(&[0u32], &scope)?;
                let arguments = args!(input.as_ptr(), words.len(), invalid.as_mut_ptr());
                unsafe {
                    scope.launch_kernel(
                        cmfd_resident_validate_words_kernel(),
                        512usize,
                        256usize,
                        &arguments,
                        0,
                    )?;
                }
                scope.synchronize_blocking()?;
                assert_eq!(invalid.to_host()?[0], expected);
            }
            Ok(())
        })
        .unwrap()
        .unwrap();
    }
    #[test]
    #[ignore = "requires a reserved GPU"]
    fn generated_metadata_matches_cpu_layout_and_commitment() {
        run_sync_in_place(|scope| -> Result<()> {
            let log = 8;
            let rows = 1 << log;
            let values = (0..DYNAMIC_COLUMNS * rows)
                .map(|i| Felt::from_canonical_usize(i % 2039 + 1))
                .collect::<Vec<_>>();
            let mut dense = vec![Felt::zero(); rows];
            dense.extend_from_slice(&values);
            let layout = AbstractChipLayoutWithHeights::new(vec![(
                "v4-bank-0-dynamic".to_owned(),
                1,
                DYNAMIC_COLUMNS,
                rows,
            )]);
            let cpu = JaggedTraceMle::from_chip_layout(Buffer::from(dense), &layout, log);
            let expected_columns = cpu.0.col_index.as_slice().to_vec();
            let expected_starts = cpu.0.start_indices.as_slice().to_vec();
            let expected_heights = cpu.0.column_heights.as_slice().to_vec();
            let baseline = cpu.into_device(&scope);
            let mut storage = allocate(log, &scope)?;
            unsafe {
                ensure!(
                    cudaMemcpy(
                        storage.dense.as_mut_ptr().add(rows).cast(),
                        values.as_ptr().cast(),
                        values.len() * 4,
                        1
                    ) == 0,
                    "small trace upload"
                )
            }
            let generated = finish(storage, 0, &scope)?;
            assert_eq!(
                DeviceBuffer::from_raw(generated.0.col_index.clone()).to_host()?,
                expected_columns
            );
            assert_eq!(
                DeviceBuffer::from_raw(generated.0.start_indices.clone()).to_host()?,
                expected_starts
            );
            assert_eq!(
                DeviceBuffer::from_raw(generated.0.column_heights.clone()).to_host()?,
                expected_heights
            );
            assert_eq!(
                DeviceBuffer::from_raw(generated.0.dense_data.dense.clone()).to_host()?,
                DeviceBuffer::from_raw(baseline.0.dense_data.dense.clone()).to_host()?
            );
            let prover = FriCudaProver::<TestGC, _, Felt>::new(
                Poseidon2SP1Field16CudaProver::new(&scope),
                FriConfig::new(LOG_BLOWUP, QUERIES, POW_BITS),
                log,
            );
            let (_, a) = commit_multilinears::<TestGC, _>(&baseline, log, false, false, &prover)?;
            let (_, b) = commit_multilinears::<TestGC, _>(&generated, log, false, false, &prover)?;
            assert_eq!(a.original_commitment, b.original_commitment);
            Ok(())
        })
        .unwrap()
        .unwrap();
    }
}
