use std::io::{self, Write};
#[cfg(feature = "production-v3")]
use std::net::Ipv4Addr;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, RecvTimeoutError, TryRecvError, sync_channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::{Parser, Subcommand};
use cmfd_consensus::forgematrix::target_with_leading_zero_bits;
use cmfd_node::p2p::{
    PeerDiscovery, spawn_inbound_listener_with_discovery, spawn_peer_polling_with_discovery,
};
use cmfd_node::peer::{PeerAddressPolicy, PeerLimits, StaticPeerConfig};
use cmfd_node::pool::{
    DEFAULT_POOL_CONCURRENT_SHARE_VERIFICATIONS, DEFAULT_POOL_CONNECTIONS_PER_SOURCE,
    DEFAULT_POOL_MINIMUM_PAYOUT_ATOMS, DEFAULT_POOL_PAYOUT_FEE_ATOMS,
    DEFAULT_POOL_QUEUED_SHARE_VERIFICATIONS, DEFAULT_POOL_SOCKET_ADDRESS,
    DEFAULT_SHARE_LEADING_ZERO_BITS, PoolPayoutPolicy, PoolServerConfig, certificate_sha256,
    generate_pool_certificate, spawn_pool_server,
};
use cmfd_node::pool_dashboard::{
    DEFAULT_POOL_DASHBOARD_ADDRESS, PoolDashboardConfig, spawn_pool_dashboard,
};
#[cfg(feature = "production-v4-testnet")]
use cmfd_node::production_v4_pool::{
    ProductionV4PersistentPoolVerifier, ProductionV4PoolVerifierConfig,
    ProductionV4PoolWorkerCommand,
};
#[cfg(feature = "production-v3")]
use cmfd_node::rcnet_candidate::{
    RcnetLaunchCandidate, RcnetLaunchConfiguration, write_candidate_create_new,
};
use cmfd_node::{
    COMPILED_NETWORK_PROFILE, DEFAULT_DATA_DIR, DEFAULT_MINING_ATTEMPTS, Node,
    ProductionV4VerifierArtifacts, ProofProfile, canonical_network_info_json_with_record,
    canonical_network_info_json_with_v4_artifacts, compiled_production_v3_worker_sha256,
    parse_miner_destination, production_v3_package_layout, production_v4_package_artifacts,
    spawn_rpc_server, unix_time_seconds,
};
use cmfd_proof_worker::{ProductionV3VerifierRecord, VerifierWorkerConfig};
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
    about = "Common Foundry profile-bound node runtime"
)]
struct Cli {
    #[arg(long, global = true, default_value = DEFAULT_DATA_DIR)]
    data_dir: PathBuf,
    /// Increase log verbosity: -v = warn, -vv = info, -vvv = debug, -vvvv =
    /// trace. With no flag, console logging is silent. The file log under
    /// `<data_dir>/logs` is always captured at debug level regardless.
    #[arg(short = 'v', long = "verbose", global = true, action = clap::ArgAction::Count)]
    verbose: u8,
    /// Absolute path to the hash-pinned proof-verifier worker.
    #[arg(long, global = true, requires = "proof_verifier_worker_sha256")]
    proof_verifier_worker: Option<PathBuf>,
    /// Expected SHA-256 of --proof-verifier-worker as 64 hexadecimal
    /// characters.
    #[arg(long, global = true, requires = "proof_verifier_worker")]
    proof_verifier_worker_sha256: Option<String>,
    /// Kill the proof-verifier worker after this many milliseconds.
    #[arg(long, global = true, default_value_t = 30_000)]
    proof_verifier_timeout_ms: u64,
    /// Kill startup if model authentication and the capability handshake do not
    /// complete within this many milliseconds.
    #[arg(long, global = true, default_value_t = 900_000)]
    proof_verifier_startup_timeout_ms: u64,
    /// Hard worker address-space/job memory limit in bytes.
    #[arg(long, global = true, default_value_t = 2_147_483_648)]
    proof_verifier_memory_bytes: u64,
    /// Measured Linux cgroup-v2 worker CPU quota in microseconds. ProductionV3
    /// requires this together with the period and PID limit.
    #[arg(long, global = true)]
    proof_verifier_cpu_quota_us: Option<u64>,
    /// Measured Linux cgroup-v2 worker CPU period in microseconds.
    #[arg(long, global = true)]
    proof_verifier_cpu_period_us: Option<u64>,
    /// Measured Linux cgroup-v2 maximum verifier task count.
    #[arg(long, global = true)]
    proof_verifier_pids_limit: Option<u64>,
    /// Absolute path to the authenticated production V3 model bank.
    #[arg(long, global = true)]
    production_v3_bank: Option<PathBuf>,
    /// Absolute path to the canonical production V3 model-bank manifest.
    #[arg(long, global = true)]
    production_v3_manifest: Option<PathBuf>,
    /// Absolute path to the canonical production V3 Record V2.
    #[arg(long, global = true)]
    production_v3_record_v2: Option<PathBuf>,
    /// Absolute path to the authenticated ProductionV4 model bank.
    #[arg(long, global = true)]
    production_v4_bank: Option<PathBuf>,
    /// Absolute path to the pinned ProductionV4 fixed artifact record.
    #[arg(long, global = true)]
    production_v4_fixed_record: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)] // Parsed once at startup; boxing CLI fields adds needless indirection.
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
    /// Mine, validate, persist, and apply one bounded reference block locally.
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
    /// Run the authenticated pool for the compiled network profile.
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
        /// Explicitly accept certificate-pinned pool clients from public IP addresses.
        #[arg(long)]
        allow_public_pool_clients: bool,
        /// DER-encoded certificate generated by pool-certificate.
        #[arg(long)]
        certificate: PathBuf,
        /// DER-encoded PKCS#8 private key generated by pool-certificate.
        #[arg(long)]
        private_key: PathBuf,
        /// Pool-owned 32-byte x-only Schnorr block-reward destination.
        #[arg(long)]
        miner: Option<String>,
        /// Easier reference-pool share target; chain work starts at 8 leading zero bits.
        #[arg(long, default_value_t = DEFAULT_SHARE_LEADING_ZERO_BITS)]
        share_leading_zero_bits: u16,
        /// Absolute native path to the persistent ProductionV4 CUDA replay worker.
        #[arg(long)]
        production_v4_pool_replay_worker: Option<PathBuf>,
        /// Absolute native path to the persistent ProductionV4 proof worker.
        #[arg(long)]
        production_v4_pool_proof_worker: Option<PathBuf>,
        /// Absolute native scratch directory shared by the V4 pool workers.
        #[arg(long)]
        production_v4_pool_scratch: Option<PathBuf>,
        /// Run the V4 pool workers through this WSL distribution.
        #[arg(long)]
        production_v4_pool_wsl_distribution: Option<String>,
        /// Enable automatic on-chain settlement of authenticated Devnet share credits.
        #[arg(long)]
        enable_testnet_payouts: bool,
        /// Minimum earned atoms settled to one authenticated payout key.
        #[arg(long, default_value_t = DEFAULT_POOL_MINIMUM_PAYOUT_ATOMS)]
        pool_minimum_payout_atoms: u64,
        /// Burned fee, in atoms, for each pool payout transaction.
        #[arg(long, default_value_t = DEFAULT_POOL_PAYOUT_FEE_ATOMS)]
        pool_payout_fee_atoms: u64,
        /// Maximum simultaneous pool connections accepted from one source IP.
        #[arg(long, default_value_t = DEFAULT_POOL_CONNECTIONS_PER_SOURCE)]
        pool_max_connections_per_source: usize,
        /// Maximum share replays evaluated concurrently by the pool verifier.
        #[arg(long, default_value_t = DEFAULT_POOL_CONCURRENT_SHARE_VERIFICATIONS)]
        pool_max_concurrent_share_verifications: usize,
        /// Maximum authenticated shares waiting for a pool verifier slot.
        #[arg(long, default_value_t = DEFAULT_POOL_QUEUED_SHARE_VERIFICATIONS)]
        pool_max_queued_share_verifications: usize,
        /// Built dashboard directory containing index.html and its static assets.
        #[arg(long)]
        pool_dashboard_assets: Option<PathBuf>,
        /// Public cmfd+tls pool URL displayed by the dashboard.
        #[arg(long)]
        pool_public_url: Option<String>,
        /// Loopback-only address for the read-only pool dashboard.
        #[arg(long, default_value_t = DEFAULT_POOL_DASHBOARD_ADDRESS)]
        pool_dashboard_bind: SocketAddr,
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
    validate_production_v3_override_set(&cli)?;
    let production_v3_record = production_v3_record(&cli)?;
    let production_v4_artifacts = production_v4_artifacts(&cli)?;
    if matches!(&cli.command, Command::NetworkInfo) {
        let bytes = match production_v4_artifacts.as_ref() {
            Some(artifacts) => canonical_network_info_json_with_v4_artifacts(artifacts)?,
            None => canonical_network_info_json_with_record(production_v3_record.as_ref())?,
        };
        io::stdout().lock().write_all(&bytes)?;
        return Ok(());
    }
    let verifier_worker = verifier_worker_config(&cli, production_v3_record.clone())?;
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
                production_v3_record.as_ref(),
                production_v4_artifacts.as_ref(),
                verifier_worker.as_ref(),
            )?;
            node.set_public_peer_mode(allow_public_peers);
            let status = node.status()?;
            let discovery_hello = node.peer_hello();
            let shared = Arc::new(Mutex::new(node));
            let limits = PeerLimits::default();
            let p2p_socket = TcpListener::bind(p2p_bind)?;
            let p2p_address = p2p_socket.local_addr()?;
            let discovery = Arc::new(PeerDiscovery::open(
                &cli.data_dir,
                discovery_hello,
                p2p_address,
                address_policy,
            ));
            let inbound = spawn_inbound_listener_with_discovery(
                Arc::clone(&shared),
                p2p_socket,
                limits,
                address_policy,
                Arc::clone(&discovery),
            )?;
            let poller = Some(spawn_peer_polling_with_discovery(
                Arc::clone(&shared),
                StaticPeerConfig {
                    listen_address: p2p_address,
                    peers: peers.clone(),
                    limits,
                    address_policy,
                },
                Duration::from_secs(2),
                discovery,
            )?);
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
            if let Ok(node) = shared.lock() {
                node.shutdown_proof_verifier();
            }
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
            require_bounded_reference_mining("mine-once")?;
            let mut node = open_node(
                &cli.data_dir,
                production_v3_record.as_ref(),
                production_v4_artifacts.as_ref(),
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
                    "proof_type": COMPILED_NETWORK_PROFILE.proof_name(),
                    "miner": hex::encode(miner_destination),
                    "used_insecure_default_miner": miner.is_none() && node.wallet_is_insecure_demo(),
                    "status": node.status()?,
                }))?
            );
            Ok(())
        }
        Command::Status => {
            let node = open_node(
                &cli.data_dir,
                production_v3_record.as_ref(),
                production_v4_artifacts.as_ref(),
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
                    "warning": format!(
                        "pin this exact SHA-256 value in every {} pool client",
                        COMPILED_NETWORK_PROFILE.short_name()
                    )
                }))?
            );
            Ok(())
        }
        Command::PoolServe {
            bind,
            p2p_bind,
            peers,
            allow_public_peers,
            allow_public_pool_clients,
            certificate,
            private_key,
            miner,
            share_leading_zero_bits,
            production_v4_pool_replay_worker,
            production_v4_pool_proof_worker,
            production_v4_pool_scratch,
            production_v4_pool_wsl_distribution,
            enable_testnet_payouts,
            pool_minimum_payout_atoms,
            pool_payout_fee_atoms,
            pool_max_connections_per_source,
            pool_max_concurrent_share_verifications,
            pool_max_queued_share_verifications,
            pool_dashboard_assets,
            pool_public_url,
            pool_dashboard_bind,
        } => {
            require_pool_mining_profile()?;
            let shutdown = install_shutdown_handler()?;
            if share_leading_zero_bits >= 8 {
                return Err(format!(
                    "pool share-leading-zero-bits must be between 0 and 7 on {}",
                    COMPILED_NETWORK_PROFILE.short_name()
                )
                .into());
            }
            let dashboard_request = match (pool_dashboard_assets, pool_public_url) {
                (Some(assets_directory), Some(public_pool_url)) => {
                    Some((assets_directory, public_pool_url))
                }
                (None, None) => None,
                _ => {
                    return Err(
                        "pool-dashboard-assets and pool-public-url must be supplied together"
                            .into(),
                    );
                }
            };
            let address_policy = peer_address_policy(allow_public_peers);
            let mut node_instance = open_node(
                &cli.data_dir,
                production_v3_record.as_ref(),
                production_v4_artifacts.as_ref(),
                verifier_worker.as_ref(),
            )?;
            node_instance.set_public_peer_mode(allow_public_peers);
            let discovery_hello = node_instance.peer_hello();
            let miner_destination = match miner.as_deref() {
                Some(value) => parse_miner_destination(value)?,
                None => node_instance.wallet_destination(),
            };
            let used_insecure_default_miner =
                miner.is_none() && node_instance.wallet_is_insecure_demo();
            let certificate_der = std::fs::read(&certificate)?;
            let private_key_der = std::fs::read(&private_key)?;
            let pin = certificate_sha256(&certificate_der);
            let node = Arc::new(Mutex::new(node_instance));
            let limits = PeerLimits::default();
            let p2p_socket = TcpListener::bind(p2p_bind)?;
            let p2p_address = p2p_socket.local_addr()?;
            let discovery = Arc::new(PeerDiscovery::open(
                &cli.data_dir,
                discovery_hello,
                p2p_address,
                address_policy,
            ));
            let inbound = spawn_inbound_listener_with_discovery(
                Arc::clone(&node),
                p2p_socket,
                limits,
                address_policy,
                Arc::clone(&discovery),
            )?;
            let poller = Some(spawn_peer_polling_with_discovery(
                Arc::clone(&node),
                StaticPeerConfig {
                    listen_address: p2p_address,
                    peers: peers.clone(),
                    limits,
                    address_policy,
                },
                Duration::from_secs(2),
                discovery,
            )?);
            let mut config =
                PoolServerConfig::devnet(bind, certificate_der, private_key_der, miner_destination);
            config.share_target = target_with_leading_zero_bits(share_leading_zero_bits);
            config.ledger_directory = Some(cli.data_dir.join("pool-ledger"));
            config.max_connections_per_source = pool_max_connections_per_source;
            config.max_concurrent_share_verifications = pool_max_concurrent_share_verifications;
            config.max_queued_share_verifications = pool_max_queued_share_verifications;
            config.allow_public_clients = allow_public_pool_clients;
            if enable_testnet_payouts {
                config.payout_policy = Some(PoolPayoutPolicy {
                    minimum_payout_atoms: pool_minimum_payout_atoms,
                    fee_atoms: pool_payout_fee_atoms,
                });
            }
            configure_production_v4_pool_verifier(
                &mut config,
                production_v4_artifacts.as_ref(),
                production_v4_pool_replay_worker.as_ref(),
                production_v4_pool_proof_worker.as_ref(),
                production_v4_pool_scratch.as_ref(),
                production_v4_pool_wsl_distribution.as_deref(),
            )?;
            let pool = spawn_pool_server(Arc::clone(&node), config)?;
            let dashboard = match dashboard_request {
                Some((assets_directory, public_pool_url)) => Some(spawn_pool_dashboard(
                    pool.dashboard_source(),
                    PoolDashboardConfig {
                        bind: pool_dashboard_bind,
                        assets_directory,
                        public_pool_url,
                        certificate_sha256: pin,
                    },
                )?),
                None => None,
            };
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "pool": pool.local_addr().to_string(),
                    "p2p": p2p_address.to_string(),
                    "static_peers": peers.iter().map(ToString::to_string).collect::<Vec<_>>(),
                    "protocol": format!(
                        "CMFD {} pool v2 (not Stratum)",
                        COMPILED_NETWORK_PROFILE.short_name()
                    ),
                    "tls": "TLS 1.3 with an exact certificate SHA-256 pin",
                    "certificate_sha256": hex::encode(pin),
                    "share_leading_zero_bits": share_leading_zero_bits,
                    "block_reward_destination": hex::encode(miner_destination),
                    "automatic_testnet_payouts": enable_testnet_payouts,
                    "minimum_payout_atoms": pool_minimum_payout_atoms,
                    "payout_fee_atoms": pool_payout_fee_atoms,
                    "max_connections_per_source": pool_max_connections_per_source,
                    "max_concurrent_share_verifications": pool_max_concurrent_share_verifications,
                    "max_queued_share_verifications": pool_max_queued_share_verifications,
                    "dashboard": dashboard.as_ref().map(|dashboard| format!("http://{}", dashboard.local_addr())),
                    "used_insecure_default_miner": used_insecure_default_miner,
                    "public_peer_mode": allow_public_peers,
                    "p2p_warning": peer_warning(allow_public_peers),
                    "accounting": cmfd_node::pool::POOL_ACCOUNTING_SEMANTICS
                }))?
            );
            let service_exit = shutdown.wait_for_service_exit(|| {
                if pool.is_finished() {
                    Some("pool")
                } else if dashboard
                    .as_ref()
                    .is_some_and(|dashboard| dashboard.is_finished())
                {
                    Some("pool dashboard")
                } else if inbound.is_finished() {
                    Some("inbound P2P")
                } else if poller.as_ref().is_some_and(|poller| poller.is_finished()) {
                    Some("static-peer polling")
                } else {
                    None
                }
            })?;
            let dashboard_result = match dashboard {
                Some(dashboard) => dashboard.stop().map(Some),
                None => Ok(None),
            };
            if let Ok(node) = node.lock() {
                node.shutdown_proof_verifier();
            }
            let pool_result = pool.stop();
            let poll_result = match poller {
                Some(poller) => poller.stop(),
                None => Ok(()),
            };
            let inbound_result = inbound.stop();
            dashboard_result?;
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
    production_v3_record: Option<ProductionV3VerifierRecord>,
) -> Result<Option<VerifierWorkerConfig>, Box<dyn std::error::Error>> {
    let production_v3 = COMPILED_NETWORK_PROFILE.proof == ProofProfile::ProductionV3;
    let worker_executable = match (&cli.proof_verifier_worker, production_v3) {
        (Some(path), _) => path.clone(),
        (None, true) => packaged_production_v3_layout()?.worker,
        (None, false) => return Ok(None),
    };
    let worker_sha256 =
        if production_v3 {
            let compiled = compiled_production_v3_worker_sha256()?;
            if let Some(configured) = cli.proof_verifier_worker_sha256.as_deref() {
                let configured = parse_worker_sha256(configured)?;
                if configured != compiled {
                    return Err(
                    "proof-verifier worker SHA-256 does not match the compiled ProductionV3 pin"
                        .into(),
                );
                }
            }
            compiled
        } else {
            parse_worker_sha256(cli.proof_verifier_worker_sha256.as_deref().ok_or(
                "--proof-verifier-worker-sha256 is required with --proof-verifier-worker",
            )?)?
        };
    Ok(Some(VerifierWorkerConfig {
        worker_executable: canonical_regular_file(&worker_executable, "proof-verifier worker")?,
        worker_sha256,
        startup_timeout: Duration::from_millis(cli.proof_verifier_startup_timeout_ms),
        timeout: Duration::from_millis(cli.proof_verifier_timeout_ms),
        memory_limit_bytes: cli.proof_verifier_memory_bytes,
        cpu_quota_micros: cli.proof_verifier_cpu_quota_us,
        cpu_period_micros: cli.proof_verifier_cpu_period_us,
        pids_limit: cli.proof_verifier_pids_limit,
        production_v3_record,
    }))
}

fn production_v3_record(
    cli: &Cli,
) -> Result<Option<ProductionV3VerifierRecord>, Box<dyn std::error::Error>> {
    match cli.production_v3_record_v2.clone() {
        None if COMPILED_NETWORK_PROFILE.proof == ProofProfile::ProductionV3 => {
            let layout = packaged_production_v3_layout()?;
            Ok(Some(layout.record))
        }
        None => Ok(None),
        Some(record_v2) if COMPILED_NETWORK_PROFILE.proof == ProofProfile::ProductionV3 => {
            Ok(Some(ProductionV3VerifierRecord {
                record_v2: canonical_regular_file(&record_v2, "production V3 Record V2")?,
                expected_file: cmfd_node::compiled_production_v3_record_identity()?,
            }))
        }
        Some(_) => {
            Err("production V3 Record V2 was supplied for a non-ProductionV3 profile".into())
        }
    }
}

fn validate_production_v3_override_set(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    if COMPILED_NETWORK_PROFILE.proof != ProofProfile::ProductionV3 {
        return Ok(());
    }
    let worker = cli.proof_verifier_worker.is_some();
    let record = cli.production_v3_record_v2.is_some();
    let bank = cli.production_v3_bank.is_some();
    let manifest = cli.production_v3_manifest.is_some();
    if worker != record {
        return Err(
            "ProductionV3 explicit overrides require both the verifier worker and Record V2 paths"
                .into(),
        );
    }
    if bank != manifest || (bank && !record) {
        return Err("legacy ProductionV3 bank and manifest overrides must be supplied together with the Record V2 override".into());
    }
    Ok(())
}

fn production_v4_artifacts(
    cli: &Cli,
) -> Result<Option<ProductionV4VerifierArtifacts>, Box<dyn std::error::Error>> {
    let is_v4 = COMPILED_NETWORK_PROFILE.proof == ProofProfile::ProductionV4;
    match (
        cli.production_v4_bank.as_ref(),
        cli.production_v4_fixed_record.as_ref(),
        is_v4,
    ) {
        (Some(_), None, _) | (None, Some(_), _) => Err(
            "ProductionV4 overrides require both the model bank and fixed artifact record paths"
                .into(),
        ),
        (Some(_), Some(_), false) => {
            Err("ProductionV4 artifacts were supplied for a non-ProductionV4 profile".into())
        }
        (None, None, false) => Ok(None),
        (Some(bank), Some(fixed_record), true) => Ok(Some(ProductionV4VerifierArtifacts {
            bank: canonical_regular_file(bank, "ProductionV4 model bank")?,
            fixed_record: canonical_regular_file(
                fixed_record,
                "ProductionV4 fixed artifact record",
            )?,
        })),
        (None, None, true) => {
            let executable = std::env::current_exe()
                .map_err(|_| "could not resolve the signed package executable directory")?;
            let packaged = production_v4_package_artifacts(&executable)?;
            Ok(Some(ProductionV4VerifierArtifacts {
                bank: canonical_regular_file(&packaged.bank, "packaged ProductionV4 model bank")?,
                fixed_record: canonical_regular_file(
                    &packaged.fixed_record,
                    "packaged ProductionV4 fixed artifact record",
                )?,
            }))
        }
    }
}

fn configure_production_v4_pool_verifier(
    config: &mut PoolServerConfig,
    artifacts: Option<&ProductionV4VerifierArtifacts>,
    replay_worker: Option<&PathBuf>,
    proof_worker: Option<&PathBuf>,
    scratch_directory: Option<&PathBuf>,
    wsl_distribution: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let supplied = replay_worker.is_some()
        || proof_worker.is_some()
        || scratch_directory.is_some()
        || wsl_distribution.is_some();
    if COMPILED_NETWORK_PROFILE.proof != ProofProfile::ProductionV4 {
        if supplied {
            return Err(
                "ProductionV4 pool worker options were supplied for a non-ProductionV4 profile"
                    .into(),
            );
        }
        return Ok(());
    }
    let (Some(replay_worker), Some(proof_worker), Some(scratch_directory), Some(artifacts)) =
        (replay_worker, proof_worker, scratch_directory, artifacts)
    else {
        return Err("ProductionV4 pool-serve requires replay-worker, proof-worker, and scratch-directory options".into());
    };

    #[cfg(feature = "production-v4-testnet")]
    {
        let replay_worker =
            canonical_regular_file(replay_worker, "ProductionV4 pool replay worker")?;
        let proof_worker = canonical_regular_file(proof_worker, "ProductionV4 pool proof worker")?;
        if !scratch_directory.is_absolute() {
            return Err("ProductionV4 pool scratch directory must be absolute".into());
        }
        let scratch_directory = cmfd_node::plain_package_path(scratch_directory.clone());
        let fixed_artifact_directory = artifacts
            .fixed_record
            .parent()
            .ok_or("ProductionV4 fixed artifact record has no parent directory")?;
        let (replay, proof, worker_scratch_directory) = match wsl_distribution {
            Some(distribution) => production_v4_wsl_pool_workers(
                distribution,
                &replay_worker,
                &proof_worker,
                &artifacts.bank,
                fixed_artifact_directory,
                &scratch_directory,
            )?,
            None => (
                ProductionV4PoolWorkerCommand {
                    program: replay_worker,
                    arguments: vec!["--server".into(), artifacts.bank.as_os_str().to_owned()],
                },
                ProductionV4PoolWorkerCommand {
                    program: proof_worker,
                    arguments: vec![
                        "--server".into(),
                        artifacts.bank.as_os_str().to_owned(),
                        fixed_artifact_directory.as_os_str().to_owned(),
                    ],
                },
                scratch_directory
                    .to_str()
                    .ok_or("ProductionV4 pool scratch directory is not UTF-8")?
                    .to_owned(),
            ),
        };
        let verifier = ProductionV4PersistentPoolVerifier::start(ProductionV4PoolVerifierConfig {
            replay,
            proof,
            scratch_directory,
            worker_scratch_directory,
        })?;
        config.production_v4_share_verifier = Some(Arc::new(verifier));
        Ok(())
    }
    #[cfg(not(feature = "production-v4-testnet"))]
    {
        let _ = (
            config,
            replay_worker,
            proof_worker,
            scratch_directory,
            artifacts,
        );
        Err("ProductionV4 pool support is not compiled into this binary".into())
    }
}

#[cfg(feature = "production-v4-testnet")]
fn production_v4_wsl_pool_workers(
    distribution: &str,
    replay_worker: &Path,
    proof_worker: &Path,
    model_bank: &Path,
    fixed_artifact_directory: &Path,
    scratch_directory: &Path,
) -> Result<
    (
        ProductionV4PoolWorkerCommand,
        ProductionV4PoolWorkerCommand,
        String,
    ),
    Box<dyn std::error::Error>,
> {
    if distribution.is_empty()
        || distribution.len() > 128
        || !distribution
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err("ProductionV4 pool WSL distribution name is invalid".into());
    }
    #[cfg(not(windows))]
    {
        let _ = (
            replay_worker,
            proof_worker,
            model_bank,
            fixed_artifact_directory,
            scratch_directory,
        );
        return Err("ProductionV4 pool WSL workers require Windows".into());
    }
    #[cfg(windows)]
    {
        let system_root = std::env::var_os("SystemRoot").ok_or("SystemRoot is unavailable")?;
        let wsl_path = PathBuf::from(system_root).join("System32").join("wsl.exe");
        let wsl = canonical_regular_file(&wsl_path, "WSL launcher")?;
        let replay_worker = production_v4_wsl_path(&wsl, distribution, replay_worker)?;
        let proof_worker = production_v4_wsl_path(&wsl, distribution, proof_worker)?;
        let model_bank = production_v4_wsl_path(&wsl, distribution, model_bank)?;
        let fixed_artifact_directory =
            production_v4_wsl_path(&wsl, distribution, fixed_artifact_directory)?;
        let worker_scratch_directory =
            production_v4_wsl_path(&wsl, distribution, scratch_directory)?;
        let environment = [
            "CUDA_VISIBLE_DEVICES=0",
            "CUDA_HOME=/usr/local/cuda-12.8",
            "CUDA_PATH=/usr/local/cuda-12.8",
            "CUDAToolkit_ROOT=/usr/local/cuda-12.8",
            "LD_LIBRARY_PATH=/usr/local/cuda-12.8/lib64",
        ];
        let worker_command = |program: String, mut arguments: Vec<std::ffi::OsString>| {
            let mut prefix = vec![
                "-d".into(),
                distribution.into(),
                "--exec".into(),
                "env".into(),
            ];
            prefix.extend(environment.into_iter().map(Into::into));
            prefix.push(program.into());
            prefix.append(&mut arguments);
            ProductionV4PoolWorkerCommand {
                program: wsl.clone(),
                arguments: prefix,
            }
        };
        Ok((
            worker_command(
                replay_worker,
                vec!["--server".into(), model_bank.clone().into()],
            ),
            worker_command(
                proof_worker,
                vec![
                    "--server".into(),
                    model_bank.into(),
                    fixed_artifact_directory.into(),
                ],
            ),
            worker_scratch_directory,
        ))
    }
}

#[cfg(all(feature = "production-v4-testnet", windows))]
fn production_v4_wsl_path(
    wsl: &Path,
    distribution: &str,
    path: &Path,
) -> Result<String, Box<dyn std::error::Error>> {
    let output = std::process::Command::new(wsl)
        .args(["-d", distribution, "--exec", "wslpath", "-a", "-u"])
        .arg(path)
        .output()?;
    if !output.status.success() {
        return Err(format!("failed to convert {} for {distribution}", path.display()).into());
    }
    let converted = String::from_utf8(output.stdout)?;
    let converted = converted.trim();
    if converted.is_empty() || converted.contains(['\r', '\n', '\t']) {
        return Err(format!("WSL returned an invalid path for {}", path.display()).into());
    }
    Ok(converted.to_owned())
}

fn packaged_production_v3_layout()
-> Result<cmfd_node::ProductionV3PackageLayout, Box<dyn std::error::Error>> {
    let executable = std::env::current_exe()
        .map_err(|_| "could not resolve the signed package executable directory")?;
    let mut layout = production_v3_package_layout(&executable)?;
    layout.worker = canonical_regular_file(&layout.worker, "packaged proof-verifier worker")?;
    layout.record.record_v2 =
        canonical_regular_file(&layout.record.record_v2, "packaged production V3 Record V2")?;
    Ok(layout)
}

fn canonical_regular_file(
    path: &Path,
    component: &'static str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if !path.is_absolute() {
        return Err(format!("{component} path must be absolute").into());
    }
    let canonical = cmfd_node::plain_package_path(
        std::fs::canonicalize(path)
            .map_err(|_| format!("{component} is missing from the package"))?,
    );
    if !std::fs::metadata(&canonical)?.is_file() {
        return Err(format!("{component} path is not a regular file").into());
    }
    Ok(canonical)
}

fn parse_worker_sha256(value: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    if value.len() != 64 {
        return Err("proof-verifier worker SHA-256 must contain exactly 64 hex characters".into());
    }
    let mut digest = [0_u8; 32];
    hex::decode_to_slice(value, &mut digest)
        .map_err(|_| "proof-verifier worker SHA-256 must contain exactly 64 hex characters")?;
    Ok(digest)
}

fn open_node(
    data_dir: &PathBuf,
    production_v3_record: Option<&ProductionV3VerifierRecord>,
    production_v4_artifacts: Option<&ProductionV4VerifierArtifacts>,
    verifier_worker: Option<&VerifierWorkerConfig>,
) -> Result<Node, Box<dyn std::error::Error>> {
    if let Some(artifacts) = production_v4_artifacts {
        if production_v3_record.is_some() || verifier_worker.is_some() {
            return Err("ProductionV4 does not accept a ProductionV3 verifier worker".into());
        }
        return Ok(Node::open_with_v4_artifacts(data_dir, artifacts)?);
    }
    match (production_v3_record, verifier_worker) {
        (Some(record), Some(worker)) => Ok(Node::open_with_record_and_verifier_worker(
            data_dir,
            Some(record),
            worker.clone(),
        )?),
        (None, Some(worker)) => {
            let mut node = Node::open_with_artifacts(data_dir, None)?;
            node.use_external_proof_verifier(worker.clone())?;
            Ok(node)
        }
        (None, None) => Ok(Node::open_with_artifacts(data_dir, None)?),
        (Some(_), None) => {
            Err("ProductionV3 requires its proof-verifier worker before block-log replay".into())
        }
    }
}

fn peer_address_policy(allow_public_peers: bool) -> PeerAddressPolicy {
    if allow_public_peers {
        PeerAddressPolicy::AllowPublic
    } else {
        PeerAddressPolicy::PrivateOnly
    }
}

fn require_bounded_reference_mining(command: &str) -> Result<(), Box<dyn std::error::Error>> {
    if COMPILED_NETWORK_PROFILE
        .proof
        .supports_bounded_reference_mining()
    {
        Ok(())
    } else {
        Err(format!(
            "{command} is unavailable for {} ({}); no DevnetV2 fallback is permitted",
            COMPILED_NETWORK_PROFILE.short_name(),
            COMPILED_NETWORK_PROFILE.proof.profile_name()
        )
        .into())
    }
}

fn require_pool_mining_profile() -> Result<(), Box<dyn std::error::Error>> {
    match COMPILED_NETWORK_PROFILE.proof {
        ProofProfile::DevnetV2Reference | ProofProfile::ProductionV4 => Ok(()),
        ProofProfile::ProductionV3 => Err(format!(
            "pool-serve is unavailable for {} ({}); no DevnetV2 fallback is permitted",
            COMPILED_NETWORK_PROFILE.short_name(),
            COMPILED_NETWORK_PROFILE.proof.profile_name()
        )
        .into()),
    }
}

fn peer_warning(allow_public_peers: bool) -> String {
    if allow_public_peers {
        format!(
            "Public {} P2P enabled; node RPC remains on loopback",
            COMPILED_NETWORK_PROFILE.short_name()
        )
    } else {
        format!(
            "{} · {}",
            COMPILED_NETWORK_PROFILE.name,
            COMPILED_NETWORK_PROFILE.network_notice()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_defaults_follow_the_compile_time_network_profile() {
        let cli = Cli::try_parse_from(["cmfd-node", "run"]).unwrap();
        assert_eq!(cli.data_dir, PathBuf::from(DEFAULT_DATA_DIR));
        assert_eq!(cli.proof_verifier_cpu_quota_us, None);
        assert_eq!(cli.proof_verifier_cpu_period_us, None);
        assert_eq!(cli.proof_verifier_pids_limit, None);
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
        let Command::PoolServe {
            bind,
            p2p_bind,
            pool_dashboard_bind,
            ..
        } = cli.command
        else {
            unreachable!()
        };
        assert_eq!(bind, COMPILED_NETWORK_PROFILE.pool_address());
        assert_eq!(p2p_bind, COMPILED_NETWORK_PROFILE.p2p_address());
        assert_eq!(pool_dashboard_bind, DEFAULT_POOL_DASHBOARD_ADDRESS);
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
