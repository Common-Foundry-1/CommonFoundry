use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};
use cmfd_launch::{
    LOCAL_TIME_ZONE, MAINNET_BEACON_ROUND, MAINNET_LAUNCH_UNIX_SECONDS, MAINNET_LAUNCH_UTC,
    MAX_BEACON_DOCUMENT_BYTES, QUICKNET_CHAIN_HASH, QUICKNET_PUBLIC_KEY, QUICKNET_SCHEME,
    SOURCE_RELEASE_UNIX_SECONDS, SOURCE_RELEASE_UTC, parse_certificate, verify_mainnet_launch,
};
use serde_json::json;

#[derive(Parser)]
#[command(version, about = "Common Foundry authenticated mainnet launch tooling")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print the exact release/start schedule and immutable beacon identity.
    Schedule,
    /// Authenticate an offline beacon response against the frozen mainnet round.
    /// This tool does not activate a node or authorize mainnet release.
    Verify {
        #[arg(long)]
        certificate: PathBuf,
        /// SHA-256 of the finalized canonical mainnet plan (64 lowercase hex).
        #[arg(long)]
        launch_plan_digest: String,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Cli::parse().command {
        Command::Schedule => println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "schema": "CMFD_MAINNET_LAUNCH_SCHEDULE_V1",
                "source_release_utc": SOURCE_RELEASE_UTC,
                "source_release_unix_seconds": SOURCE_RELEASE_UNIX_SECONDS,
                "mining_start_utc": MAINNET_LAUNCH_UTC,
                "mining_start_unix_seconds": MAINNET_LAUNCH_UNIX_SECONDS,
                "local_time_zone": LOCAL_TIME_ZONE,
                "local_time": "12:00:00 CDT (UTC-05:00)",
                "preparation_seconds": MAINNET_LAUNCH_UNIX_SECONDS - SOURCE_RELEASE_UNIX_SECONDS,
                "beacon_chain_hash": QUICKNET_CHAIN_HASH,
                "beacon_public_key": QUICKNET_PUBLIC_KEY,
                "beacon_scheme": QUICKNET_SCHEME,
                "beacon_round": MAINNET_BEACON_ROUND,
                "beacon_url": format!("https://api.drand.sh/v2/beacons/{QUICKNET_CHAIN_HASH}/rounds/{MAINNET_BEACON_ROUND}"),
                "mainnet_activation_authorized": false
            }))?
        ),
        Command::Verify {
            certificate,
            launch_plan_digest,
        } => {
            if launch_plan_digest.len() != 64
                || !launch_plan_digest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(
                    "launch-plan-digest must be 64 lowercase hexadecimal characters".into(),
                );
            }
            let root: [u8; 32] = hex::decode(launch_plan_digest)?
                .try_into()
                .map_err(|_| "invalid launch-plan digest")?;
            let mut bytes = Vec::new();
            File::open(certificate)?
                .take((MAX_BEACON_DOCUMENT_BYTES + 1) as u64)
                .read_to_end(&mut bytes)?;
            let certificate = parse_certificate(&bytes)?;
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            let verified = verify_mainnet_launch(root, &certificate, now)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "schema": "CMFD_AUTHENTICATED_LAUNCH_BEACON_V1",
                    "launch_plan_digest": hex::encode(verified.launch_plan_digest()),
                    "round": verified.round(),
                    "randomness": hex::encode(verified.randomness()),
                    "genesis_hash": hex::encode(verified.genesis_hash()),
                    "mainnet_activation_authorized": false
                }))?
            );
        }
    }
    Ok(())
}
