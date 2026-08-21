#![cfg(feature = "whir-prototype")]

use std::path::PathBuf;

use blake3::Hasher;
#[cfg(not(feature = "gpu-proof-prover"))]
use cmfd_consensus::verify_structured_blake3;
use cmfd_consensus::{ExtensionElement, StructuredBlake3Statement};

const FIXTURE_PATH_ENV: &str = "CMFD_TEST_GPU_TREE_PROOF_PATH";
const OUTPUT_CONTEXT: &str = "CMFD/FORGEMATRIX/OUTPUT/V2";

fn fixture_activation() -> Vec<u8> {
    vec![125; 64]
}

fn fixture_statement(activation: &[u8]) -> StructuredBlake3Statement {
    let challenge_digest = [0x42; 32];
    let mut hasher = Hasher::new_derive_key(OUTPUT_CONTEXT);
    hasher.update(&challenge_digest);
    hasher.update(&(activation.len() as u64).to_le_bytes());
    hasher.update(activation);

    StructuredBlake3Statement {
        challenge_digest,
        final_activation_len: activation.len(),
        final_activation_digest: *hasher.finalize().as_bytes(),
        final_activation_point: vec![ExtensionElement { limbs: [0; 3] }; 6],
        // Every fixture activation is centered to zero, so its multilinear
        // extension evaluates to zero at every point.
        final_activation_evaluation: ExtensionElement { limbs: [0; 3] },
    }
}

fn fixture_path() -> PathBuf {
    std::env::var_os(FIXTURE_PATH_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("set {FIXTURE_PATH_ENV} to the cross-build proof path"))
}

#[cfg(feature = "gpu-proof-prover")]
#[test]
#[ignore = "writes a proof with an explicitly selected CUDA library for the CPU-only cross-build test"]
fn write_gpu_tree_proof_for_cpu_only_verifier() {
    let library_path = std::env::var_os("CMFD_TEST_PROOF_CUDA_LIBRARY")
        .expect("set CMFD_TEST_PROOF_CUDA_LIBRARY to the exact CUDA proof library");
    let device_index = std::env::var("CMFD_TEST_PROOF_CUDA_DEVICE")
        .ok()
        .map(|value| value.parse::<i32>().expect("CUDA device must be an i32"))
        .unwrap_or(0);
    let activation = fixture_activation();
    let statement = fixture_statement(&activation);
    let proof = cmfd_consensus::prove_structured_blake3_with_cuda(
        &statement,
        &activation,
        library_path,
        device_index,
    )
    .expect("GPU-generated tree proof must pass its same-build CPU return gate");
    std::fs::write(fixture_path(), proof).expect("write cross-build GPU proof fixture");
}

#[cfg(not(feature = "gpu-proof-prover"))]
#[test]
#[ignore = "reads bytes emitted by the GPU-feature build; run with only whir-prototype enabled"]
fn gpu_tree_proof_verifies_in_cpu_only_build() {
    let activation = fixture_activation();
    let statement = fixture_statement(&activation);
    let proof = std::fs::read(fixture_path()).expect("read cross-build GPU proof fixture");
    verify_structured_blake3(&statement, &proof)
        .expect("GPU-generated proof must verify without the GPU prover feature");
}
