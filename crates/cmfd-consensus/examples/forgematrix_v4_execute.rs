//! Re-executes the work of one or more ProductionV4 blocks on the CPU and
//! prints the resulting digests and the time taken, one JSON object per block.
//!
//! Usage: forgematrix_v4_execute MODEL_BANK FIXED_RECORD THREADS BLOCKS_JSON [authenticate] [resident]
//!
//! BLOCKS_JSON is either one block object or `{"vectors": [...]}`, with the
//! fields used by `data/forgematrix_v4_execution_vectors_v1.json`: hex
//! `network_id`, `previous_block`, `transaction_root`, `target`, numeric
//! `height` and `timestamp`, and `nonce` as a decimal string or number. With
//! `authenticate`, every layer read is checked against its root. Build with
//! `--release`. Layers are streamed from the bank file, or with `resident`
//! loaded into memory once (each checked against its root) before the first
//! block.

use std::{fs::File, io::BufReader, path::PathBuf, time::Instant};

use anyhow::{Context, Result, bail};
use cmfd_consensus::{
    BlockChallenge, ConsensusPowVerifier, ForgeMatrixV4FileLayerSource,
    ForgeMatrixV4FixedArtifactRecordV1, ForgeMatrixV4LayerSource, ForgeMatrixV4ResidentLayerSource,
    PRODUCTION_V4_MODEL_MANIFEST_DIGEST, forgematrix_v4_challenge_digest,
    forgematrix_v4_execute_challenge,
};
use serde_json::{Value, json};

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let bank_path = PathBuf::from(args.next().context("missing model-bank path")?);
    let record_path = PathBuf::from(args.next().context("missing fixed artifact record")?);
    let threads: usize = args
        .next()
        .context("missing thread count")?
        .to_str()
        .context("thread count is not text")?
        .parse()
        .context("thread count is not a number")?;
    let blocks_path = PathBuf::from(args.next().context("missing blocks JSON")?);
    let (mut authenticate, mut resident) = (false, false);
    for flag in args {
        match flag.to_str() {
            Some("authenticate") if !authenticate => authenticate = true,
            Some("resident") if !resident => resident = true,
            _ => bail!("unexpected argument {flag:?}"),
        }
    }

    let document: Value = serde_json::from_reader(BufReader::new(
        File::open(&blocks_path).with_context(|| format!("open {}", blocks_path.display()))?,
    ))
    .context("decode blocks JSON")?;
    let blocks = match document.get("vectors") {
        Some(vectors) => vectors
            .as_array()
            .context("vectors is not an array")?
            .clone(),
        None => vec![document],
    };
    let blocks = blocks.iter().map(parse_block).collect::<Result<Vec<_>>>()?;
    let (first, _) = blocks.first().context("no blocks")?;

    let record: ForgeMatrixV4FixedArtifactRecordV1 = serde_json::from_reader(BufReader::new(
        File::open(&record_path).with_context(|| format!("open {}", record_path.display()))?,
    ))
    .context("decode fixed artifact record")?;
    let started = Instant::now();
    let (_, identity) = ConsensusPowVerifier::v4_candidate_for_network_with_layer_roots(
        first.network_id,
        record,
        BufReader::with_capacity(
            1024 * 1024,
            File::open(&bank_path).with_context(|| format!("open {}", bank_path.display()))?,
        ),
    )
    .context("authenticate the model bank")?;
    eprintln!(
        "model bank authenticated in {:.1}s",
        started.elapsed().as_secs_f64()
    );
    let started = Instant::now();
    let bank = File::open(&bank_path).with_context(|| format!("open {}", bank_path.display()))?;
    let source: Box<dyn ForgeMatrixV4LayerSource> = if resident {
        Box::new(ForgeMatrixV4ResidentLayerSource::load(
            bank,
            &identity.manifest,
            identity.base_input,
            identity.layer_roots,
        )?)
    } else {
        Box::new(ForgeMatrixV4FileLayerSource::new(
            bank,
            &identity.manifest,
            identity.base_input,
            identity.layer_roots,
        )?)
    };
    if resident {
        eprintln!(
            "model bank loaded into memory in {:.1}s",
            started.elapsed().as_secs_f64()
        );
    }

    for (block, nonce) in blocks {
        let started = Instant::now();
        let challenge_digest =
            forgematrix_v4_challenge_digest(&block, nonce, PRODUCTION_V4_MODEL_MANIFEST_DIGEST);
        let execution =
            forgematrix_v4_execute_challenge(challenge_digest, &*source, threads, authenticate)?;
        let seconds = started.elapsed().as_secs_f64();
        println!(
            "{}",
            json!({
                "height": block.height,
                "nonce": nonce.to_string(),
                "challenge_digest": hex::encode(execution.challenge_digest),
                "final_activation_digest": hex::encode(execution.final_activation_digest),
                "work_digest": hex::encode(execution.work_digest),
                "threads": threads,
                "authenticate": authenticate,
                "bank": if resident { "resident" } else { "streamed" },
                "seconds": (seconds * 1000.0).round() / 1000.0,
            })
        );
    }
    Ok(())
}

fn parse_block(value: &Value) -> Result<(BlockChallenge, u64)> {
    let hex32 = |field: &str| -> Result<[u8; 32]> {
        let text = value[field]
            .as_str()
            .with_context(|| format!("{field} is missing"))?;
        hex::decode(text)
            .with_context(|| format!("{field} is not hex"))?
            .try_into()
            .map_err(|_| anyhow::anyhow!("{field} is not 32 bytes"))
    };
    let number = |field: &str| -> Result<u64> {
        match &value[field] {
            Value::String(text) => text
                .parse()
                .with_context(|| format!("{field} is not a number")),
            other => other
                .as_u64()
                .with_context(|| format!("{field} is missing")),
        }
    };
    Ok((
        BlockChallenge {
            network_id: hex32("network_id")?,
            previous_block: hex32("previous_block")?,
            transaction_root: hex32("transaction_root")?,
            height: number("height")?,
            timestamp: number("timestamp")?,
            target: hex32("target")?,
        },
        number("nonce")?,
    ))
}
