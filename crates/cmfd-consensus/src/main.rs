use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
#[cfg(all(feature = "dory-bls12-381-prototype", feature = "whir-prototype"))]
use cmfd_consensus::dory_bls12_381_blake3::derive_bls_dory_blake3_preprocessing_record;
#[cfg(all(feature = "dory-bls12-381-prototype", feature = "whir-prototype"))]
use cmfd_consensus::dory_v3_qualification::{
    ProductionDoryV3QualificationRequest, run_production_dory_v3_qualification,
};
use cmfd_consensus::forgematrix::CANDIDATE_16GB_PROFILE;
use cmfd_consensus::forgematrix::target_with_leading_zero_bits;
use cmfd_consensus::{
    BlockChallenge, DEFAULT_MONETARY_POLICY, ForgeMatrixVerifier, TEST_PROFILE, v2_test_reference,
};
#[cfg(feature = "dory-bls12-381-prototype")]
use cmfd_consensus::{
    ModelBankManifest, ModelPcsIdentity,
    dory_bls12_381_model_commitment::derive_bls_dory_model_commitment_record,
    dory_bls12_381_prototype::deterministic_bls_dory_setup,
    dory_v3_model_bank_bootstrap::run_production_dory_v3_model_bank_bootstrap,
    dory_v3_model_ceremony::run_production_dory_v3_model_record_v2_ceremony,
    dory_v3_model_combiner::combine_production_dory_v3_model_contributions,
    dory_v3_model_contribution::generate_production_dory_v3_model_contribution,
};

#[derive(Debug, Parser)]
#[command(
    name = "cmfd-consensus",
    version,
    about = "CommonFoundry consensus reference tools"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Emit a deterministic ForgeMatrix test vector.
    Vector,
    /// Mine the small CPU test profile.
    Mine {
        #[arg(long, default_value_t = 12)]
        leading_zero_bits: u16,
        #[arg(long, default_value_t = 100_000)]
        attempts: u64,
    },
    /// Show the subsidy, allocation, and burned fees at a height.
    Economics {
        #[arg(long)]
        height: u64,
        #[arg(long, default_value_t = 0)]
        fees: u64,
    },
    /// Write a binary fixture for the independent CUDA differential test.
    GpuFixture {
        #[arg(long)]
        output: std::path::PathBuf,
        #[arg(long, default_value_t = 7)]
        nonce: u64,
    },
    /// Write the explicit-byte, mod-251 v2 CUDA differential fixture.
    GpuFixtureV2 {
        #[arg(long)]
        output: std::path::PathBuf,
        #[arg(long, default_value_t = 7)]
        nonce: u64,
    },
    /// Report exact memory and work for the unactivated 16 GB candidate.
    Profile16gb,
    /// Authenticate a model bank and emit its reproducible fixed-model BLS commitment record.
    #[cfg(feature = "dory-bls12-381-prototype")]
    BlsModelCommitment {
        /// Canonical binary model bank to authenticate.
        #[arg(long)]
        bank: std::path::PathBuf,
        /// Separately trusted model-bank manifest JSON.
        #[arg(long)]
        manifest: std::path::PathBuf,
        /// Separately trusted ModelPcsIdentity JSON.
        #[arg(long)]
        model_identity: std::path::PathBuf,
        /// Fixed-table geometry and deterministic setup size.
        #[arg(long, default_value_t = 33)]
        padded_variables: usize,
        /// New JSON record path; omit for stdout. Existing files are never overwritten.
        #[arg(long)]
        output: Option<std::path::PathBuf>,
    },
    /// Build the canonical production V2 model bank from a pre-generated raw payload.
    #[cfg(feature = "dory-bls12-381-prototype")]
    DoryV3ModelBankBootstrap {
        /// Exact raw payload: base input followed by 384 layers; every byte must be 0..=250.
        #[arg(long)]
        payload: std::path::PathBuf,
        /// New canonical 184-byte-header V2 bank. Existing paths are never overwritten.
        #[arg(long)]
        bank_output: std::path::PathBuf,
        /// New strict manifest JSON. Existing paths are never overwritten.
        #[arg(long)]
        manifest_output: std::path::PathBuf,
    },
    /// Run the two-pass production Dory V3 Model Record V2 ceremony.
    #[cfg(feature = "dory-bls12-381-prototype")]
    DoryV3ModelRecordCeremony {
        /// Canonical production model bank to authenticate independently twice.
        #[arg(long)]
        bank: std::path::PathBuf,
        /// Separately trusted canonical production model-bank manifest JSON.
        #[arg(long)]
        manifest: std::path::PathBuf,
        /// New canonical Record V2 JSON path. Existing files are never overwritten.
        #[arg(long)]
        output: std::path::PathBuf,
    },
    /// Generate one full-length production ceremony contribution from the operating-system CSPRNG.
    #[cfg(feature = "dory-bls12-381-prototype")]
    DoryV3ModelContributionGenerate {
        /// New 6,442,975,232-byte contribution path. Existing paths are never overwritten.
        /// Use an operator-owned local directory; Windows requires an operator-only parent DACL.
        #[arg(long)]
        output: std::path::PathBuf,
    },
    /// Combine ordered production ceremony contributions bytewise modulo 251.
    #[cfg(feature = "dory-bls12-381-prototype")]
    DoryV3ModelCombine {
        /// Ordered local contribution paths in operator-owned parents, repeated in operator-index order (3 through 16).
        #[arg(long = "contribution", required = true)]
        contributions: Vec<std::path::PathBuf>,
        /// New raw payload in an operator-owned local directory. On Windows the parent must have an operator-only DACL.
        #[arg(long)]
        output: std::path::PathBuf,
    },
    /// Derive the reproducible production BLAKE3 preprocessing-only BLS record.
    #[cfg(all(feature = "dory-bls12-381-prototype", feature = "whir-prototype"))]
    BlsBlake3PreprocessingCommitment {
        /// Existing absolute directory for owned temporary artifacts.
        #[arg(long)]
        scratch: std::path::PathBuf,
        /// New JSON record path; omit for stdout. Existing files are never overwritten.
        #[arg(long)]
        output: Option<std::path::PathBuf>,
    },
    /// Run one unchanged n=33 Dory V3 production qualification.
    #[cfg(all(feature = "dory-bls12-381-prototype", feature = "whir-prototype"))]
    DoryV3Qualify {
        /// Canonical production model bank.
        #[arg(long)]
        bank: std::path::PathBuf,
        /// Canonical production Record V2 JSON.
        #[arg(long)]
        record: std::path::PathBuf,
        /// Strict qualification request JSON containing the block and winning claim.
        #[arg(long)]
        request: std::path::PathBuf,
        /// New absolute runner-owned scratch directory.
        #[arg(long)]
        scratch: std::path::PathBuf,
        /// New canonical proof-wire output path.
        #[arg(long)]
        proof_output: std::path::PathBuf,
        /// New report written last as the completion marker; publication is not crash-atomic.
        #[arg(long)]
        report_output: std::path::PathBuf,
        /// Maximum native BLAKE3 rows materialized in one block.
        #[arg(long)]
        maximum_native_block_rows: usize,
    },
}

fn sample_block(network_id: [u8; 32], target: [u8; 32]) -> BlockChallenge {
    BlockChallenge {
        network_id,
        previous_block: [0x11; 32],
        transaction_root: [0x22; 32],
        height: 42,
        timestamp: 1_777_777_777,
        target,
    }
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Vector => {
            let verifier = ForgeMatrixVerifier::new(TEST_PROFILE)?;
            let block = sample_block([0x33; 32], [0xff; 32]);
            let proof = verifier.prove(&block, 7);
            verifier.verify(&block, &proof)?;
            println!("{}", serde_json::to_string_pretty(&proof)?);
        }
        Command::Mine {
            leading_zero_bits,
            attempts,
        } => {
            let verifier = ForgeMatrixVerifier::new(TEST_PROFILE)?;
            let block = sample_block([0x33; 32], target_with_leading_zero_bits(leading_zero_bits));
            let proof = verifier
                .mine(&block, 0, attempts)
                .with_context(|| format!("no solution in {attempts} attempts"))?;
            verifier.verify(&block, &proof)?;
            println!("{}", serde_json::to_string_pretty(&proof)?);
        }
        Command::Economics { height, fees } => {
            let allocation = DEFAULT_MONETARY_POLICY.allocation(height, fees)?;
            println!("{}", serde_json::to_string_pretty(&allocation)?);
        }
        Command::GpuFixture { output, nonce } => {
            let verifier = ForgeMatrixVerifier::new(TEST_PROFILE)?;
            let fixture = verifier.gpu_fixture(&sample_block([0x33; 32], [0xff; 32]), nonce);
            std::fs::write(&output, fixture)
                .with_context(|| format!("failed to write {}", output.display()))?;
            println!("wrote {}", output.display());
        }
        Command::GpuFixtureV2 { output, nonce } => {
            let oracle = v2_test_reference()?;
            let fixture = oracle.gpu_fixture(
                &sample_block(oracle.descriptor().network_id, [0xff; 32]),
                nonce,
            )?;
            std::fs::write(&output, fixture)
                .with_context(|| format!("failed to write {}", output.display()))?;
            println!("wrote {}", output.display());
        }
        Command::Profile16gb => {
            println!(
                "{}",
                serde_json::to_string_pretty(&CANDIDATE_16GB_PROFILE.metrics())?
            );
        }
        #[cfg(feature = "dory-bls12-381-prototype")]
        Command::BlsModelCommitment {
            bank,
            manifest,
            model_identity,
            padded_variables,
            output,
        } => {
            let manifest_reader = std::fs::File::open(&manifest)
                .with_context(|| format!("failed to open {}", manifest.display()))?;
            let trusted_manifest: ModelBankManifest = serde_json::from_reader(manifest_reader)
                .with_context(|| format!("failed to parse {}", manifest.display()))?;
            let identity_reader = std::fs::File::open(&model_identity)
                .with_context(|| format!("failed to open {}", model_identity.display()))?;
            let trusted_identity: ModelPcsIdentity = serde_json::from_reader(identity_reader)
                .with_context(|| format!("failed to parse {}", model_identity.display()))?;
            let bank_reader = std::fs::File::open(&bank)
                .with_context(|| format!("failed to open {}", bank.display()))?;
            let setup = deterministic_bls_dory_setup(padded_variables)
                .context("failed to derive deterministic BLS setup")?;
            let record = derive_bls_dory_model_commitment_record(
                bank_reader,
                &trusted_manifest,
                &trusted_identity,
                padded_variables,
                &setup,
            )
            .context("failed to derive authenticated fixed-model commitments")?;
            let mut encoded = serde_json::to_vec_pretty(&record)?;
            encoded.push(b'\n');
            if let Some(output) = output {
                use std::io::Write as _;

                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&output)
                    .with_context(|| {
                        format!("failed to create new output file {}", output.display())
                    })?;
                file.write_all(&encoded)
                    .with_context(|| format!("failed to write {}", output.display()))?;
                file.sync_all()
                    .with_context(|| format!("failed to sync {}", output.display()))?;
                println!("wrote {}", output.display());
                println!("record digest {}", record.record_digest);
            } else {
                print!("{}", String::from_utf8(encoded)?);
            }
        }
        #[cfg(feature = "dory-bls12-381-prototype")]
        Command::DoryV3ModelBankBootstrap {
            payload,
            bank_output,
            manifest_output,
        } => {
            let report = run_production_dory_v3_model_bank_bootstrap(
                &payload,
                &bank_output,
                &manifest_output,
            )
            .context("production Dory V3 model-bank bootstrap failed")?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        #[cfg(feature = "dory-bls12-381-prototype")]
        Command::DoryV3ModelRecordCeremony {
            bank,
            manifest,
            output,
        } => {
            let manifest_reader = std::fs::File::open(&manifest)
                .with_context(|| format!("failed to open {}", manifest.display()))?;
            let trusted_manifest: ModelBankManifest = serde_json::from_reader(manifest_reader)
                .with_context(|| format!("failed to parse {}", manifest.display()))?;
            let report =
                run_production_dory_v3_model_record_v2_ceremony(&bank, &trusted_manifest, &output)
                    .context("production Dory V3 Model Record V2 ceremony failed")?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        #[cfg(feature = "dory-bls12-381-prototype")]
        Command::DoryV3ModelContributionGenerate { output } => {
            let report = generate_production_dory_v3_model_contribution(&output)
                .context("production Dory V3 model contribution generation failed")?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        #[cfg(feature = "dory-bls12-381-prototype")]
        Command::DoryV3ModelCombine {
            contributions,
            output,
        } => {
            let report = combine_production_dory_v3_model_contributions(&contributions, &output)
                .context("production Dory V3 contribution combination failed")?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        #[cfg(all(feature = "dory-bls12-381-prototype", feature = "whir-prototype"))]
        Command::BlsBlake3PreprocessingCommitment { scratch, output } => {
            if let Some(output) = &output {
                match std::fs::symlink_metadata(output) {
                    Ok(_) => anyhow::bail!(
                        "refusing to run the ceremony because output already exists: {}",
                        output.display()
                    ),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => {
                        return Err(error).with_context(|| {
                            format!("failed to inspect output path {}", output.display())
                        });
                    }
                }
            }
            let record = derive_bls_dory_blake3_preprocessing_record(&scratch)
                .context("failed to derive production BLAKE3 preprocessing commitment")?;
            let mut encoded = serde_json::to_vec_pretty(&record)?;
            encoded.push(b'\n');
            if let Some(output) = output {
                use std::io::Write as _;

                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&output)
                    .with_context(|| {
                        format!("failed to create new output file {}", output.display())
                    })?;
                file.write_all(&encoded).with_context(|| {
                    format!(
                        "failed to write {}; the newly created output may be incomplete",
                        output.display()
                    )
                })?;
                file.sync_all().with_context(|| {
                    format!(
                        "failed to sync {}; the newly created output may be incomplete",
                        output.display()
                    )
                })?;
                println!("wrote {}", output.display());
                println!("record digest {}", record.record_digest);
            } else {
                print!("{}", String::from_utf8(encoded)?);
            }
        }
        #[cfg(all(feature = "dory-bls12-381-prototype", feature = "whir-prototype"))]
        Command::DoryV3Qualify {
            bank,
            record,
            request,
            scratch,
            proof_output,
            report_output,
            maximum_native_block_rows,
        } => {
            let request_reader = std::fs::File::open(&request)
                .with_context(|| format!("failed to open {}", request.display()))?;
            let qualification_request: ProductionDoryV3QualificationRequest =
                serde_json::from_reader(request_reader)
                    .with_context(|| format!("failed to parse {}", request.display()))?;
            let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let signal_cancel = std::sync::Arc::clone(&cancel);
            ctrlc::set_handler(move || {
                signal_cancel.store(true, std::sync::atomic::Ordering::Relaxed);
            })
            .context("failed to install qualification Ctrl-C handler")?;
            let report = run_production_dory_v3_qualification(
                &bank,
                &record,
                &qualification_request,
                &scratch,
                &proof_output,
                &report_output,
                maximum_native_block_rows,
                cancel.as_ref(),
            )
            .context("production Dory V3 qualification failed")?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
    }
    Ok(())
}
