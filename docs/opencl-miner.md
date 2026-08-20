# ForgeMatrix v2 OpenCL miner (Intel Arc)

The OpenCL backend is a second miner library that speaks the same versioned C
ABI as the [CUDA miner](cuda-miner.md). It exists so Intel Arc — and any other
OpenCL 1.2 GPU — can mine the bounded ForgeMatrix v2 research profile without a
CUDA toolchain.

Nothing about consensus changes. The backend is an untrusted accelerator: it
proposes activation digests, and the CPU reference verifier recomputes every
accepted candidate exactly as it does for CUDA. A wrong or malicious backend
can only waste the miner's own work.

## Trust boundary

The library receives the committed model bytes and the per-nonce mask
coefficients and returns candidate activations. It never sees keys, never
signs, and never decides validity. Its kernel is an exact integer port of the
CUDA kernel: the same coordinate mask, the same cubic reduction modulo
134217689 and 251, the same INT8 by INT8 products accumulated in INT32. No
build option that reassociates or approximates arithmetic is enabled, so CPU,
CUDA, and OpenCL agree bit for bit.

## Requirements

- An OpenCL 1.2 or newer GPU. On Intel Arc that means the Intel graphics
  driver, which ships the OpenCL ICD; no oneAPI or SDK install is needed.
- A device work group size of at least 128. Every Arc A- and B-series card and
  every Xe integrated GPU satisfies this.
- A C++17 compiler to build the library. The OpenCL runtime is loaded by name
  at run time (`OpenCL.dll`, `libOpenCL.so.1`), so no OpenCL headers or import
  library are required at build time.

## Build

```powershell
.\scripts\build-opencl-miner.ps1
```

The script configures `gpu/CMakeLists.txt` with `-DCMFD_ENABLE_CUDA=OFF`,
builds `cmfd-forgematrix-v2-opencl.dll`, runs the CPU differential canary
against it, and prints the library's SHA-256. On Linux the equivalent is:

```bash
cmake -S gpu -B target/gpu-opencl-build -DCMFD_ENABLE_CUDA=OFF
cmake --build target/gpu-opencl-build --target cmfd-forgematrix-v2-opencl
```

## Selecting the backend

The loader looks beside the executable for `cmfd-forgematrix-v2-miner` (CUDA)
first and `cmfd-forgematrix-v2-opencl` second, so a rig that has only the
OpenCL library uses it with no configuration. To pin a choice:

| Variable | Effect |
| --- | --- |
| `CMFD_GPU_BACKEND` | `cuda`, `opencl`, or `auto` (default) |
| `CMFD_OPENCL_MINER_LIBRARY` | Explicit path to the OpenCL library |
| `CMFD_CUDA_MINER_LIBRARY` | Explicit path to the CUDA library |
| `CMFD_CUDA_DEVICE` | Device index used by the desktop wallet |

`cmfd-miner --device` and `--cuda-library` accept the OpenCL library too; a
path whose file name contains `opencl` is recognized as the OpenCL backend.

List what the backend sees:

```powershell
cmfd-miner devices
```

Devices are enumerated across every OpenCL platform in a stable order, so an
index keeps naming the same card between runs. The version shown in a device
label is the OpenCL version, not a CUDA compute capability.

## Measuring throughput

```powershell
cargo run --release -p cmfd-cuda --example hashrate -- --seconds 20 --batch-size 65536
```

The example prepares batches, evaluates them on whichever backend loads, and
computes the candidate prefilter digests, which is exactly the miner's inner
loop. It spot-checks digests against the CPU reference before timing, so a
reported rate always comes from a backend that agreed with `prove_compact`.

Adding `--kernel-only` re-evaluates one prepared batch in a loop. It mines
nothing, since every launch repeats the same nonces, but it shows what the
device sustains with the CPU stages removed.

Measured runs, Intel Arc B580, Windows, batch size 65536:

| Figure | Rate |
| --- | --- |
| Saturating kernel loop (`--kernel-only`) | 38.5 MH/s |
| Kernel share of the mining loop | 33.9 MH/s |
| End to end, one worker thread | 0.54 MH/s |

The gap between the last two rows is not a GPU limit. In the mining loop 81%
of wall time went to `prepare_accelerator_batch` and 17% to the CPU candidate
digests, leaving the kernel 1.6%. Mask preparation is CPU work shared with the
CUDA path, so a single worker thread caps near 0.67 MH/s on this host
regardless of vendor. Raising real hashrate means preparing masks in parallel
with, or on, the GPU, not tuning this backend.

Only the saturating loop loads the card: its compute engine sits near 92%
busy, while the mining loop leaves the GPU idle almost all of the time. A
power limit on the card therefore has no effect on end-to-end hashrate at
present, and per-watt figures taken from the mining loop describe the CPU, not
the GPU.

## Known limits

- The kernel uses a plain INT32 accumulation loop rather than Arc's XMX
  matrix engines. That headroom is unused today because the pipeline is
  CPU-bound; a `cl_intel_subgroup_matrix_multiply_accumulate` path is the
  obvious next step once that changes, and must keep digests identical.
- Per-GPU telemetry (power, temperature, fan) in the standalone miner comes
  from `nvidia-smi` and stays blank for Intel devices. Hashrate, work counts,
  and uptime still report normally.
- The figures above are one host, one card, one run. They are an engineering
  measurement, not a benchmark claim.
