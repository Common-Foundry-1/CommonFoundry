use std::io::{self, Write};
#[cfg(feature = "production-v3")]
use std::net::Ipv4Addr;
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, RecvTimeoutError, TryRecvError, sync_channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::{Parser, Subcommand};
use cmfd_consensus::forgematrix::target_with_leading_zero_bits;
use cmfd_node::p2p::{spawn_inbound_listener_with_policy, spawn_static_peer_polling};
use cmfd_node::peer::{PeerAddressPolicy, PeerLimits, StaticPeerConfig};
use cmfd_node::pool::{
    DEFAULT_POOL_SOCKET_ADDRESS, DEFAULT_SHARE_LEADING_ZERO_BITS, PoolServerConfig,
    certificate_sha256, generate_pool_certificate, spawn_pool_server,
};
#[cfg(feature = "production-v3")]
use cmfd_node::rcnet_candidate::{
    RcnetLaunchCandidate, RcnetLaunchConfiguration, write_candidate_create_new,
};
use cmfd_node::{
    COMPILED_NETWORK_PROFILE, DEFAULT_DATA_DIR, DEFAULT_MINING_ATTEMPTS, Node,
    canonical_network_info_json_with_artifacts, parse_miner_destination, spawn_rpc_server,
    unix_time_seconds,
};
use cmfd_proof_worker::{ProductionV3VerifierArtifacts, VerifierWorkerConfig};
use serde_json::json;

const SERVICE_SUPERVISION_POLL: Duration = Duration::from_millis(50);

#[cfg(feature = "production-v3")]
fn parse_hex32(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err("expected exactly 64 lowercase hexadecimal characters".to_owned());
    }
    hex::decode(value)
        .map_err(|_| "expected a 32-byte hexadecimal value".to_owned())?
        .try_into()
        .map_err(|_| "expected a 32-byte hexadecimal value".to_owned())
}

#[derive(Debug, Parser)]
#[command(
    name = "cmfd-node",
    version,
    about = "CommonFoundry bounded multi-node Devnet-0 runtime"
)]
struct Cli {
    #[arg(long, global = true, default_value = DEFAULT_DATA_DIR)]
    data_dir: PathBuf,
    /// Increase log verbosity: -v = warn, -vv = info, -vvv = debug, -vvvv =
    /// trace. With no flag, console logging is silent. The file log under
    /// `<data_dir>/logs` is always captured at debug level regardless.
    #[arg(short = 'v', long = "verbose", global = true, action = clap::ArgAction::Count)]
    verbose: u8,
    /// Absolute path to the hash-pinned proof-verifier worker. When omitted,
    /// Devnet retains bounded in-process verification.
    #[arg(long, global = true, requires = "proof_verifier_worker_sha256")]
    proof_verifier_worker: Option<PathBuf>,
    /// Expected SHA-256 of --proof-verifier-worker as 64 hexadecimal
    /// characters.
    #[arg(long, global = true, requires = "proof_verifier_worker")]
    proof_verifier_worker_sha256: Option<String>,
    /// Kill the proof-verifier worker after this many milliseconds.
    #[arg(long, global = true, default_value_t = 30_000)]
    proof_verifier_timeout_ms: u64,
    /// Hard worker address-space/job memory limit in bytes.
    #[arg(long, global = true, default_value_t = 2_147_483_648)]
    proof_verifier_memory_bytes: u64,
    /// Absolute path to the authenticated production V3 model bank.
    #[arg(long, global = true)]
    production_v3_bank: Option<PathBuf>,
    /// Absolute path to the canonical production V3 model-bank manifest.
    #[arg(long, global = true)]
    production_v3_manifest: Option<PathBuf>,
    /// Absolute path to the canonical production V3 Record V2.
    #[arg(long, global = true)]
    production_v3_record_v2: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print the compiled network identity and consensus manifest.
    NetworkInfo,
    /// Derive a canonical RCNet identity candidate from a final Record V2.
    #[cfg(feature = "production-v3")]
    RcnetCandidate {
        #[arg(long)]
        record_v2: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        virtual_genesis_timestamp: u64,
        #[arg(long)]
        bootstrap_ipv4: Ipv4Addr,
        #[arg(long)]
        rpc_port: u16,
        #[arg(long)]
        p2p_port: u16,
        #[arg(long)]
        pool_port: u16,
        #[arg(long, value_parser = parse_hex32)]
        pow_limit: [u8; 32],
        #[arg(long, value_parser = parse_hex32)]
        steward_reward_destination: [u8; 32],
        #[arg(long, value_parser = parse_hex32)]
        community_reward_destination: [u8; 32],
    },
    /// Run loopback RPC and bounded P2P services.
    Run {
        #[arg(long, default_value_t = COMPILED_NETWORK_PROFILE.rpc_address())]
        bind: SocketAddr,
        #[arg(long, default_value_t = COMPILED_NETWORK_PROFILE.p2p_address())]
        p2p_bind: SocketAddr,
        /// Static peer address. Public IPs require --allow-public-peers.
        #[arg(long = "peer")]
        peers: Vec<SocketAddr>,
        /// Explicitly allow unauthenticated, unencrypted public P2P addresses.
        #[arg(long)]
        allow_public_peers: bool,
    },
    /// Mine, validate, persist, and apply one Devnet-0 block locally.
    MineOnce {
        /// 32-byte x-only Schnorr public key as 64 hex characters.
        #[arg(long)]
        miner: Option<String>,
        #[arg(long, default_value_t = DEFAULT_MINING_ATTEMPTS)]
        attempts: u64,
    },
    /// Replay the block log and print current offline node status.
    Status,
    /// Generate a self-signed TLS certificate and print its required SHA-256 pin.
    PoolCertificate {
        /// Output path for the DER-encoded self-signed certificate.
        #[arg(long)]
        certificate: PathBuf,
        /// Output path for the DER-encoded PKCS#8 private key.
        #[arg(long)]
        private_key: PathBuf,
    },
    /// Run the authenticated, non-Stratum Devnet-0 pool service.
    PoolServe {
        #[arg(long, default_value_t = DEFAULT_POOL_SOCKET_ADDRESS)]
        bind: SocketAddr,
        #[arg(long, default_value_t = COMPILED_NETWORK_PROFILE.p2p_address())]
        p2p_bind: SocketAddr,
        /// Static peer address. Public IPs require --allow-public-peers.
        #[arg(long = "peer")]
        peers: Vec<SocketAddr>,
        /// Explicitly allow unauthenticated, unencrypted public P2P addresses.
        #[arg(long)]
        allow_public_peers: bool,
        /// DER-encoded certificate generated by pool-certificate.
        #[arg(long)]
        certificate: PathBuf,
        /// DER-encoded PKCS#8 private key generated by pool-certificate.
        #[arg(long)]
        private_key: PathBuf,
        /// Pool-owned 32-byte x-only Schnorr block-reward destination.
        #[arg(long)]
        miner: Option<String>,
        /// Easier share target. Devnet chain work starts at 8 leading zero bits.
        #[arg(long, default_value_t = DEFAULT_SHARE_LEADING_ZERO_BITS)]
        share_leading_zero_bits: u16,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if cmfd_proof_worker::verifier_worker_mode_requested() {
        std::process::exit(cmfd_proof_worker::worker_main());
    }
    let cli = Cli::parse();
    #[cfg(feature = "production-v3")]
    if let Command::RcnetCandidate {
        record_v2,
        output,
        virtual_genesis_timestamp,
        bootstrap_ipv4,
        rpc_port,
        p2p_port,
        pool_port,
        pow_limit,
        steward_reward_destination,
        community_reward_destination,
    } = &cli.command
    {
        let bytes = std::fs::read(record_v2)?;
        if bytes.len() > 1024 * 1024 {
            return Err("Record V2 exceeds the 1 MiB candidate-generator limit".into());
        }
        let record: cmfd_consensus::dory_v3_model_record::DoryV3ModelCommitmentRecordV2 =
            serde_json::from_slice(&bytes)?;
        if bytes
            != cmfd_consensus::dory_v3_model_record::canonical_dory_v3_model_record_v2_json(
                &record,
            )?
        {
            return Err("Record V2 is not canonically encoded".into());
        }
        let candidate = RcnetLaunchCandidate::from_record(
            &record,
            RcnetLaunchConfiguration {
                virtual_genesis_timestamp: *virtual_genesis_timestamp,
                bootstrap_ipv4: *bootstrap_ipv4,
                rpc_port: *rpc_port,
                p2p_port: *p2p_port,
                pool_port: *pool_port,
                pow_limit: *pow_limit,
                rewards: cmfd_consensus::FixedRewardDestinations {
                    steward: *steward_reward_destination,
                    community: *community_reward_destination,
                },
            },
        )?;
        write_candidate_create_new(output, &candidate)?;
        return Ok(());
    }
    let production_v3_artifacts = production_v3_artifacts(&cli)?;
    if matches!(&cli.command, Command::NetworkInfo) {
        io::stdout()
            .lock()
            .write_all(&canonical_network_info_json_with_artifacts(
                production_v3_artifacts.as_ref(),
            )?)?;
        return Ok(());
    }
    let verifier_worker = verifier_worker_config(&cli, production_v3_artifacts.clone())?;
    let _log_guard = cmfd_node::logging::init_tracing(&cli.data_dir, cli.verbose);
    match cli.command {
        Command::NetworkInfo => unreachable!("network-info exits before node initialization"),
        #[cfg(feature = "production-v3")]
        Command::RcnetCandidate { .. } => {
            unreachable!("RCNet candidate generation exits before node initialization")
        }
        Command::Run {
            bind,
            p2p_bind,
            peers,
            allow_public_peers,
        } => {
            let shutdown = install_shutdown_handler()?;
            let address_policy = peer_address_policy(allow_public_peers);
            let mut node = open_node(
                &cli.data_dir,
                production_v3_artifacts.as_ref(),
                verifier_worker.as_ref(),
            )?;
            node.set_public_peer_mode(allow_public_peers);
            let status = node.status()?;
            let shared = Arc::new(Mutex::new(node));
            let limits = PeerLimits::default();
            let p2p_socket = TcpListener::bind(p2p_bind)?;
            let p2p_address = p2p_socket.local_addr()?;
            let inbound = spawn_inbound_listener_with_policy(
                Arc::clone(&shared),
                p2p_socket,
                limits,
                address_policy,
            )?;
            let poller = if peers.is_empty() {
                None
            } else {
                Some(spawn_static_peer_polling(
                    Arc::clone(&shared),
                    StaticPeerConfig {
                        listen_address: p2p_address,
                        peers: peers.clone(),
                        limits,
                        address_policy,
                    },
                    Duration::from_secs(2),
                )?)
            };
            let rpc = spawn_rpc_server(Arc::clone(&shared), bind)?;
            let rpc_address = rpc.local_addr();
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "rpc": rpc_address.to_string(),
                    "p2p": p2p_address.to_string(),
                    "static_peers": peers.iter().map(ToString::to_string).collect::<Vec<_>>(),
                    "status": status,
                    "public_peer_mode": allow_public_peers,
                    "warning": peer_warning(allow_public_peers)
                }))?
            );
            let service_exit = shutdown.wait_for_service_exit(|| {
                if rpc.is_finished() {
                    Some("RPC")
                } else if inbound.is_finished() {
                    Some("inbound P2P")
                } else if poller.as_ref().is_some_and(|poller| poller.is_finished()) {
                    Some("static-peer polling")
                } else {
                    None
                }
            })?;
            let rpc_result = rpc.stop();
            let poll_result = match poller {
                Some(poller) => poller.stop(),
                None => Ok(()),
            };
            let inbound_result = inbound.stop();
            drop(shared);
            rpc_result?;
            poll_result?;
            inbound_result?;
            if let Some(service) = service_exit {
                return Err(format!("{service} service exited unexpectedly").into());
            }
            Ok(())
        }
        Command::MineOnce { miner, attempts } => {
            let mut node = open_node(
                &cli.data_dir,
                production_v3_artifacts.as_ref(),
                verifier_worker.as_ref(),
            )?;
            let miner_destination = match miner.as_deref() {
                Some(value) => parse_miner_destination(value)?,
                None => node.wallet_destination(),
            };
            let block = node.mine_once(miner_destination, unix_time_seconds()?, attempts)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "accepted": true,
                    "height": block.challenge.height,
                    "block_id": hex::encode(block.block_id()),
                    "proof_type": "forgematrix-v2-reference",
                    "miner": hex::encode(miner_destination),
                    "used_insecure_default_miner": miner.is_none(),
                    "status": node.status()?,
                }))?
            );
            Ok(())
        }
        Command::Status => {
            let node = open_node(
                &cli.data_dir,
                production_v3_artifacts.as_ref(),
                verifier_worker.as_ref(),
            )?;
            println!("{}", serde_json::to_string_pretty(&node.status()?)?);
            Ok(())
        }
        Command::PoolCertificate {
            certificate,
            private_key,
        } => {
            let info = generate_pool_certificate(certificate, private_key)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "certificate": info.certificate_path,
                    "private_key": info.private_key_path,
                    "certificate_sha256": hex::encode(info.certificate_sha256),
                    "format": "DER certificate and DER PKCS#8 private key",
                    "warning": "pin this exact SHA-256 value in every Devnet pool client"
                }))?
            );
            Ok(())
        }
        Command::PoolServe {
            bind,
            p2p_bind,
            peers,
            allow_public_peers,
            certificate,
            private_key,
            miner,
            share_leading_zero_bits,
        } => {
            let shutdown = install_shutdown_handler()?;
            if share_leading_zero_bits >= 8 {
                return Err(
                    "pool share-leading-zero-bits must be between 0 and 7 on Devnet-0".into(),
                );
            }
            let address_policy = peer_address_policy(allow_public_peers);
            let mut node_instance = open_node(
                &cli.data_dir,
                production_v3_artifacts.as_ref(),
                verifier_worker.as_ref(),
            )?;
            node_instance.set_public_peer_mode(allow_public_peers);
            let miner_destination = match miner.as_deref() {
                Some(value) => parse_miner_destination(value)?,
                None => node_instance.wallet_destination(),
            };
            let certificate_der = std::fs::read(&certificate)?;
            let private_key_der = std::fs::read(&private_key)?;
            let pin = certificate_sha256(&certificate_der);
            let node = Arc::new(Mutex::new(node_instance));
            let limits = PeerLimits::default();
            let p2p_socket = TcpListener::bind(p2p_bind)?;
            let p2p_address = p2p_socket.local_addr()?;
            let inbound = spawn_inbound_listener_with_policy(
                Arc::clone(&node),
                p2p_socket,
                limits,
                address_policy,
            )?;
            let poller = if peers.is_empty() {
                None
            } else {
                Some(spawn_static_peer_polling(
                    Arc::clone(&node),
                    StaticPeerConfig {
                        listen_address: p2p_address,
                        peers: peers.clone(),
                        limits,
                        address_policy,
                    },
                    Duration::from_secs(2),
                )?)
            };
            let mut config =
                PoolServerConfig::devnet(bind, certificate_der, private_key_der, miner_destination);
            config.share_target = target_with_leading_zero_bits(share_leading_zero_bits);
            let pool = spawn_pool_server(node, config)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "pool": pool.local_addr().to_string(),
                    "p2p": p2p_address.to_string(),
                    "static_peers": peers.iter().map(ToString::to_string).collect::<Vec<_>>(),
                    "protocol": "CMFD Devnet pool v1 (not Stratum)",
                    "tls": "TLS 1.3 with an exact certificate SHA-256 pin",
                    "certificate_sha256": hex::encode(pin),
                    "share_leading_zero_bits": share_leading_zero_bits,
                    "block_reward_destination": hex::encode(miner_destination),
                    "used_insecure_default_miner": miner.is_none(),
                    "public_peer_mode": allow_public_peers,
                    "p2p_warning": peer_warning(allow_public_peers),
                    "accounting": "session-only accounting records; nonwithdrawable; not funds; not an on-chain balance or payout"
                }))?
            );
            let service_exit = shutdown.wait_for_service_exit(|| {
                if pool.is_finished() {
                    Some("pool")
                } else if inbound.is_finished() {
                    Some("inbound P2P")
                } else if poller.as_ref().is_some_and(|poller| poller.is_finished()) {
                    Some("static-peer polling")
                } else {
                    None
                }
            })?;
            let pool_result = pool.stop();
            let poll_result = match poller {
                Some(poller) => poller.stop(),
                None => Ok(()),
            };
            let inbound_result = inbound.stop();
            pool_result?;
            poll_result?;
            inbound_result?;
            if let Some(service) = service_exit {
                return Err(format!("{service} service exited unexpectedly").into());
            }
            Ok(())
        }
    }
}

struct ShutdownSignal {
    receiver: Receiver<()>,
}

impl ShutdownSignal {
    fn wait_for_service_exit(
        self,
        mut exited: impl FnMut() -> Option<&'static str>,
    ) -> Result<Option<&'static str>, Box<dyn std::error::Error>> {
        loop {
            match self.receiver.try_recv() {
                Ok(()) => return Ok(None),
                Err(TryRecvError::Disconnected) => {
                    return Err("shutdown signal channel disconnected".into());
                }
                Err(TryRecvError::Empty) => {}
            }
            if let Some(service) = exited() {
                return Ok(Some(service));
            }
            match self.receiver.recv_timeout(SERVICE_SUPERVISION_POLL) {
                Ok(()) => return Ok(None),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    return Err("shutdown signal channel disconnected".into());
                }
            }
        }
    }
}

fn install_shutdown_handler() -> Result<ShutdownSignal, ctrlc::Error> {
    // A capacity of one coalesces repeated console events while the main
    // thread is stopping and joining services. The handler performs no I/O or
    // cleanup; it only signals the normal control flow below.
    let (sender, receiver) = sync_channel(1);
    ctrlc::set_handler(move || {
        let _ = sender.try_send(());
    })?;
    Ok(ShutdownSignal { receiver })
}

fn verifier_worker_config(
    cli: &Cli,
    production_v3_artifacts: Option<ProductionV3VerifierArtifacts>,
) -> Result<Option<VerifierWorkerConfig>, Box<dyn std::error::Error>> {
    let Some(worker_executable) = cli.proof_verifier_worker.clone() else {
        return Ok(None);
    };
    let hash = cli
        .proof_verifier_worker_sha256
        .as_deref()
        .ok_or("--proof-verifier-worker-sha256 is required with --proof-verifier-worker")?;
    if hash.len() != 64 {
        return Err("proof-verifier worker SHA-256 must contain exactly 64 hex characters".into());
    }
    let mut worker_sha256 = [0_u8; 32];
    hex::decode_to_slice(hash, &mut worker_sha256)
        .map_err(|_| "proof-verifier worker SHA-256 must contain exactly 64 hex characters")?;
    Ok(Some(VerifierWorkerConfig {
        worker_executable,
        worker_sha256,
        timeout: Duration::from_millis(cli.proof_verifier_timeout_ms),
        memory_limit_bytes: cli.proof_verifier_memory_bytes,
        production_v3_artifacts,
    }))
}

fn production_v3_artifacts(
    cli: &Cli,
) -> Result<Option<ProductionV3VerifierArtifacts>, Box<dyn std::error::Error>> {
    match (
        cli.production_v3_bank.clone(),
        cli.production_v3_manifest.clone(),
        cli.production_v3_record_v2.clone(),
    ) {
        (None, None, None) => Ok(None),
        (Some(bank), Some(manifest), Some(record_v2)) => {
            Ok(Some(ProductionV3VerifierArtifacts {
                bank,
                manifest,
                record_v2,
            }))
        }
        _ => Err("--production-v3-bank, --production-v3-manifest, and --production-v3-record-v2 must be supplied together".into()),
    }
}

fn open_node(
    data_dir: &PathBuf,
    production_v3_artifacts: Option<&ProductionV3VerifierArtifacts>,
    verifier_worker: Option<&VerifierWorkerConfig>,
) -> Result<Node, Box<dyn std::error::Error>> {
    let mut node = Node::open_with_artifacts(data_dir, production_v3_artifacts)?;
    if let Some(config) = verifier_worker {
        node.use_external_proof_verifier(config.clone())?;
    }
    Ok(node)
}

fn peer_address_policy(allow_public_peers: bool) -> PeerAddressPolicy {
    if allow_public_peers {
        PeerAddressPolicy::AllowPublic
    } else {
        PeerAddressPolicy::PrivateOnly
    }
}

fn peer_warning(allow_public_peers: bool) -> &'static str {
    if allow_public_peers {
        "Public Devnet P2P enabled; node RPC remains on loopback"
    } else {
        "Common Foundry Devnet-0 testing network"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_defaults_follow_the_compile_time_network_profile() {
        let cli = Cli::try_parse_from(["cmfd-node", "run"]).unwrap();
        assert_eq!(cli.data_dir, PathBuf::from(DEFAULT_DATA_DIR));
        let Command::Run { bind, p2p_bind, .. } = cli.command else {
            unreachable!()
        };
        assert_eq!(bind, COMPILED_NETWORK_PROFILE.rpc_address());
        assert_eq!(p2p_bind, COMPILED_NETWORK_PROFILE.p2p_address());

        let cli = Cli::try_parse_from([
            "cmfd-node",
            "pool-serve",
            "--certificate",
            "certificate.der",
            "--private-key",
            "private-key.der",
        ])
        .unwrap();
        let Command::PoolServe { bind, p2p_bind, .. } = cli.command else {
            unreachable!()
        };
        assert_eq!(bind, COMPILED_NETWORK_PROFILE.pool_address());
        assert_eq!(p2p_bind, COMPILED_NETWORK_PROFILE.p2p_address());
    }

    #[test]
    fn network_info_accepts_no_command_specific_inputs() {
        assert!(matches!(
            Cli::try_parse_from(["cmfd-node", "network-info"])
                .unwrap()
                .command,
            Command::NetworkInfo
        ));
        assert!(Cli::try_parse_from(["cmfd-node", "network-info", "unexpected"]).is_err());
    }

    #[test]
    fn shutdown_wait_reports_an_unexpected_service_exit() {
        let (_sender, receiver) = sync_channel(1);
        let reason = ShutdownSignal { receiver }
            .wait_for_service_exit(|| Some("RPC"))
            .unwrap();
        assert_eq!(reason, Some("RPC"));
    }

    #[test]
    fn shutdown_signal_wins_when_service_exit_is_also_observed() {
        let (sender, receiver) = sync_channel(1);
        sender.send(()).unwrap();
        let reason = ShutdownSignal { receiver }
            .wait_for_service_exit(|| Some("RPC"))
            .unwrap();
        assert_eq!(reason, None);
    }
}
