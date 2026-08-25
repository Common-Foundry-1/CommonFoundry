use std::env;
use std::error::Error;
use std::time::Instant;

use cmfd_cuda::{CudaLibrary, GpuBackend, ProductionResidency};

const TRANSITION_MODULUS: i64 = 134_217_689;
const FULL_DEVICE_BYTES: u64 = 6_463_422_464;

fn main() -> Result<(), Box<dyn Error>> {
    let library = CudaLibrary::load_backend(GpuBackend::Cuda, None)?
        .ok_or("CUDA miner library was not found")?;
    let device_index = env::var("CMFD_CUDA_DEVICE")
        .unwrap_or_else(|_| "0".to_owned())
        .parse::<i32>()?;
    let device = library
        .devices()?
        .into_iter()
        .find(|device| device.index == device_index)
        .ok_or("selected CUDA device was not found")?;
    println!("library={}", library.path().display());
    println!("device={}", device.label());

    let dense = dense_vector();
    run_vector(&library, &device, "dense-4x32", &dense)?;

    let production = production_geometry_vector();
    run_vector(&library, &device, "production-layer-128x4096", &production)?;
    Ok(())
}

struct Vector {
    rows: u32,
    width: u32,
    activation: Vec<i8>,
    weights: Vec<i8>,
    coefficients: Vec<u8>,
}

fn dense_vector() -> Vector {
    let rows = 4_u32;
    let width = 32_u32;
    let activation = (0..rows * width)
        .map(|index| ((index * 29 + 7) % 251) as i16 - 125)
        .map(|value| value as i8)
        .collect();
    let weights = (0..width * width)
        .map(|index| ((index * 47 + 13) % 251) as i16 - 125)
        .map(|value| value as i8)
        .collect();
    let coefficients = (0..1 + rows.ilog2() + width.ilog2())
        .map(|index| ((index * 31 + 5) % 251) as u8)
        .collect();
    Vector {
        rows,
        width,
        activation,
        weights,
        coefficients,
    }
}

fn production_geometry_vector() -> Vector {
    let rows = 128_u32;
    let width = 4096_u32;
    let activation = (0..rows * width)
        .map(|index| ((index * 17 + index / width * 19 + 3) % 251) as i16 - 125)
        .map(|value| value as i8)
        .collect::<Vec<_>>();
    // A sparse diagonal has a cheap independent Rust oracle while the GPU
    // still executes the exact full 128x4096 by 4096x4096 GEMM geometry.
    let mut weights = vec![0_i8; (width * width) as usize];
    for index in 0..width as usize {
        weights[index * width as usize + index] = (((index * 23 + 11) % 251) as i16 - 125) as i8;
    }
    let coefficients = (0..1 + rows.ilog2() + width.ilog2())
        .map(|index| ((index * 43 + 9) % 251) as u8)
        .collect();
    Vector {
        rows,
        width,
        activation,
        weights,
        coefficients,
    }
}

fn run_vector(
    library: &CudaLibrary,
    device: &cmfd_cuda::CudaDevice,
    name: &str,
    vector: &Vector,
) -> Result<(), Box<dyn Error>> {
    let cpu_started = Instant::now();
    let expected = cpu_exact_layer(vector);
    let cpu_elapsed = cpu_started.elapsed();
    let mut residencies = vec![ProductionResidency::HostBacked];
    if device.total_memory_bytes >= FULL_DEVICE_BYTES {
        residencies.push(ProductionResidency::FullDevice);
    } else {
        println!(
            "vector={name} residency=FullDevice result=skipped total_device_bytes={} required_device_bytes={FULL_DEVICE_BYTES}",
            device.total_memory_bytes
        );
    }
    for residency in residencies {
        let gpu_started = Instant::now();
        let (actual, active) = library.evaluate_differential_layer_with_residency(
            device.index,
            vector.rows,
            vector.width,
            &vector.activation,
            &vector.weights,
            &vector.coefficients,
            residency,
        )?;
        let gpu_elapsed = gpu_started.elapsed();
        if active != residency {
            return Err(
                format!("{name} requested {residency:?} but backend selected {active:?}").into(),
            );
        }
        if actual != expected {
            let mismatch = actual
                .iter()
                .zip(&expected)
                .position(|(actual, expected)| actual != expected)
                .unwrap_or(0);
            return Err(format!(
                "{name} {residency:?} mismatch at {mismatch}: GPU={} Rust={}",
                actual[mismatch], expected[mismatch]
            )
            .into());
        }
        println!(
            "vector={name} residency={residency:?} values={} digest={} rust_ms={:.3} gpu_ms={:.3} result=exact",
            actual.len(),
            blake3::hash(&actual).to_hex(),
            cpu_elapsed.as_secs_f64() * 1_000.0,
            gpu_elapsed.as_secs_f64() * 1_000.0,
        );
    }
    Ok(())
}

fn cpu_exact_layer(vector: &Vector) -> Vec<u8> {
    let rows = vector.rows as usize;
    let width = vector.width as usize;
    let sparse_diagonal = rows == 128 && width == 4096;
    let mut output = Vec::with_capacity(rows * width);
    for row in 0..rows {
        for column in 0..width {
            let accumulator = if sparse_diagonal {
                i32::from(vector.activation[row * width + column])
                    * i32::from(vector.weights[column * width + column])
            } else {
                (0..width)
                    .map(|common| {
                        i32::from(vector.activation[row * width + common])
                            * i32::from(vector.weights[common * width + column])
                    })
                    .sum()
            };
            let z = accumulator + coordinate_mask(vector, row, column);
            output.push(cubic_reduce(z));
        }
    }
    output
}

fn coordinate_mask(vector: &Vector, row: usize, column: usize) -> i32 {
    let row_bits = vector.rows.ilog2() as usize;
    let column_bits = vector.width.ilog2() as usize;
    let mut mask = i32::from(vector.coefficients[0]);
    for bit in 0..row_bits {
        if (row >> bit) & 1 == 1 {
            mask += i32::from(vector.coefficients[1 + bit]);
        }
    }
    for bit in 0..column_bits {
        if (column >> bit) & 1 == 1 {
            mask += i32::from(vector.coefficients[1 + row_bits + bit]);
        }
    }
    mask
}

fn cubic_reduce(z: i32) -> u8 {
    assert!(i64::from(z).unsigned_abs() < TRANSITION_MODULUS as u64);
    let encoded = if z >= 0 {
        i64::from(z)
    } else {
        TRANSITION_MODULUS + i64::from(z)
    } as u64;
    let modulus = TRANSITION_MODULUS as u64;
    let square = (encoded * encoded) % modulus;
    let cube = (square * encoded) % modulus;
    (cube % 251) as u8
}
