//! Measures ForgeMatrix v2 accelerator throughput for whichever GPU backend
//! loads, using the same batch preparation and candidate digest work the miner
//! performs. It mines nothing: no block is submitted and no target is met.
//!
//! ```text
//! cargo run --release -p cmfd-cuda --example hashrate -- --seconds 10
//! ```

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use cmfd_consensus::{BlockChallenge, v2_test_reference};
use cmfd_cuda::CudaLibrary;

struct Options {
    batch_size: u32,
    seconds: u64,
    device: i32,
    library: Option<PathBuf>,
    verify: usize,
    kernel_only: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            batch_size: 8_192,
            seconds: 10,
            device: 0,
            library: None,
            verify: 8,
            kernel_only: false,
        }
    }
}

fn parse_options() -> Result<Options, String> {
    let mut options = Options::default();
    let mut arguments = env::args().skip(1);
    while let Some(argument) = arguments.next() {
        let mut value = || {
            arguments
                .next()
                .ok_or_else(|| format!("{argument} needs a value"))
        };
        match argument.as_str() {
            "--batch-size" => {
                options.batch_size = value()?.parse().map_err(|_| "invalid batch size")?
            }
            "--seconds" => options.seconds = value()?.parse().map_err(|_| "invalid seconds")?,
            "--device" => options.device = value()?.parse().map_err(|_| "invalid device index")?,
            "--library" => options.library = Some(PathBuf::from(value()?)),
            "--verify" => options.verify = value()?.parse().map_err(|_| "invalid verify count")?,
            "--kernel-only" => options.kernel_only = true,
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if options.batch_size == 0 || options.batch_size > 65_536 {
        return Err("batch size must be 1 through 65536".to_owned());
    }
    if options.seconds == 0 {
        return Err("seconds must be at least 1".to_owned());
    }
    Ok(options)
}

fn run() -> Result<(), String> {
    let options = parse_options()?;
    let reference = v2_test_reference().map_err(|error| error.to_string())?;
    let descriptor = reference.descriptor();
    let block = BlockChallenge {
        network_id: descriptor.network_id,
        previous_block: [1; 32],
        transaction_root: [2; 32],
        height: 3,
        timestamp: 1_700_000_123,
        target: [0xff; 32],
    };
    let model = reference.accelerator_model();

    let library = CudaLibrary::load(options.library.as_deref())?
        .ok_or_else(|| "no ForgeMatrix GPU backend library was found".to_owned())?;
    let mut miner = library.create(&model, options.device)?;
    println!(
        "{} library: {}",
        library.backend().name(),
        library.path().display()
    );
    println!("GPU {}: {}", options.device, miner.device().label());
    println!(
        "batch size {} | measuring for {} s",
        options.batch_size, options.seconds
    );

    // One warm-up batch pays for kernel compilation and first-touch
    // allocations so they do not land inside the measured window.
    let warmup = reference
        .prepare_accelerator_batch(&block, 0, options.batch_size)
        .map_err(|error| error.to_string())?;
    let warmup_outputs = miner.evaluate(&warmup)?;

    // A rate is only interesting if the backend is right at this batch size,
    // so spot-check evenly spaced nonces of the warm-up batch against the CPU
    // reference before any timing starts.
    if options.verify > 0 {
        let checked = options.verify.min(options.batch_size as usize);
        let stride = (options.batch_size as usize).div_ceil(checked);
        let mut confirmed = 0_usize;
        for index in (0..options.batch_size as usize).step_by(stride) {
            let start = index * warmup.activation_len();
            let output = &warmup_outputs[start..start + warmup.activation_len()];
            let accelerated = warmup
                .candidate_work_digest(index, output)
                .map_err(|error| error.to_string())?;
            let nonce = warmup.nonce_at(index).ok_or("nonce index out of range")?;
            let expected = reference
                .prove_compact(&block, nonce)
                .map_err(|error| error.to_string())?;
            if accelerated != expected.work_digest {
                return Err(format!(
                    "backend disagrees with the CPU reference at nonce {nonce}"
                ));
            }
            confirmed += 1;
        }
        println!("verified {confirmed} digests against the CPU reference");
    }

    // Saturating mode: re-evaluate one prepared batch back to back. It mines
    // nothing useful, because every launch repeats the same nonces, but it is
    // the only way to see what the device sustains once the CPU stages are
    // out of the way, and the only mode that loads the card enough for a
    // power limit to matter.
    if options.kernel_only {
        let budget = Duration::from_secs(options.seconds);
        let started = Instant::now();
        let mut nonces = 0_u64;
        while started.elapsed() < budget {
            miner.evaluate(&warmup)?;
            nonces += u64::from(options.batch_size);
        }
        let elapsed = started.elapsed().as_secs_f64();
        println!();
        println!("saturating kernel loop, no CPU stages");
        println!("nonces evaluated  {nonces}");
        println!("wall time         {elapsed:.2} s");
        println!(
            "kernel only       {:.2} MH/s",
            nonces as f64 / elapsed / 1e6
        );
        return Ok(());
    }

    let budget = Duration::from_secs(options.seconds);
    let started = Instant::now();
    let mut nonce = u64::from(options.batch_size);
    let mut nonces = 0_u64;
    let mut prepare_time = Duration::ZERO;
    let mut evaluate_time = Duration::ZERO;
    let mut digest_time = Duration::ZERO;

    while started.elapsed() < budget {
        let prepare_started = Instant::now();
        let batch = reference
            .prepare_accelerator_batch(&block, nonce, options.batch_size)
            .map_err(|error| error.to_string())?;
        prepare_time += prepare_started.elapsed();

        let evaluate_started = Instant::now();
        let outputs = miner.evaluate(&batch)?;
        evaluate_time += evaluate_started.elapsed();

        // The miner prefilters every candidate on the CPU, so the honest
        // end-to-end rate has to include it.
        let digest_started = Instant::now();
        for (index, output) in outputs.chunks_exact(batch.activation_len()).enumerate() {
            let digest = batch
                .candidate_work_digest(index, output)
                .map_err(|error| error.to_string())?;
            std::hint::black_box(digest);
        }
        digest_time += digest_started.elapsed();

        nonces += u64::from(options.batch_size);
        nonce = nonce.wrapping_add(u64::from(options.batch_size));
    }

    let elapsed = started.elapsed().as_secs_f64();
    let nonces_f64 = nonces as f64;
    println!();
    println!("nonces evaluated  {nonces}");
    println!("wall time         {elapsed:.2} s");
    println!("end-to-end        {:.2} MH/s", nonces_f64 / elapsed / 1e6);
    println!(
        "kernel only       {:.2} MH/s",
        nonces_f64 / evaluate_time.as_secs_f64() / 1e6
    );
    println!(
        "time split        prepare {:.1}% | evaluate {:.1}% | digest {:.1}%",
        100.0 * prepare_time.as_secs_f64() / elapsed,
        100.0 * evaluate_time.as_secs_f64() / elapsed,
        100.0 * digest_time.as_secs_f64() / elapsed
    );
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("hashrate: {error}");
            ExitCode::FAILURE
        }
    }
}
