#[cfg(feature = "production-v4")]
use std::ffi::{OsStr, OsString};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, RecvTimeoutError, TryRecvError, sync_channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::{Parser, Subcommand};
use cmfd_consensus::forgematrix::target_with_leading_zero_bits;
#[cfg(feature = "production-v4-testnet")]
use cmfd_node::RCNET1_PROFILE;
use cmfd_node::exchange_acl_qualification::{qualify_fixture, qualify_installed_host};
use cmfd_node::exchange_custody_tools::{
    ArchiveRestoreVerifyConfig, CanceledArchiveApplyConfig, CanceledArchivePlanConfig,
    ExternalKeyringFinalizationApplyConfig, ExternalKeyringFinalizationPlanConfig,
    ExternalKeyringTransitionApplyConfig, ExternalKeyringTransitionPlanConfig,
    LegacyKeyringApplyConfig, LegacyKeyringPlanConfig, V3MigrationApplyConfig,
    V3MigrationApprovalPayloadConfig, V3MigrationPlanConfig, V3OfflineControlConfig,
    apply_canceled_archive_compaction, apply_external_keyring_finalization,
    apply_external_keyring_transition, apply_legacy_keyring_import, apply_v3_migration,
    create_exchange_journal_key_create_new, load_exchange_custody_v3_wallet_passphrase,
    persisted_exchange_custody_v3_wallet_security_required, plan_canceled_archive,
    plan_external_keyring_finalization, plan_external_keyring_transition,
    plan_legacy_keyring_import, plan_v3_migration, verify_archive_restore_offline,
    write_v3_migration_approval_payload,
};
use cmfd_node::exchange_rpc::{
    EXCHANGE_CUSTODY_RPC_API_VERSION, EXCHANGE_RPC_API_VERSION, spawn_exchange_rpc_server,
    spawn_exchange_rpc_server_v3,
};
use cmfd_node::p2p::{
    PeerDiscovery, spawn_inbound_listener_with_discovery, spawn_peer_polling_with_discovery,
};
use cmfd_node::peer::{PeerAddressPolicy, PeerLimits, StaticPeerConfig};
use cmfd_node::pool::{
    DEFAULT_POOL_CONCURRENT_SHARE_VERIFICATIONS, DEFAULT_POOL_CONNECTIONS_PER_SOURCE,
    DEFAULT_POOL_LEDGER_MAX_BYTES, DEFAULT_POOL_MINIMUM_PAYOUT_ATOMS,
    DEFAULT_POOL_OPERATOR_FEE_BPS, DEFAULT_POOL_PAYOUT_FEE_ATOMS,
    DEFAULT_POOL_QUEUED_SHARE_VERIFICATIONS, DEFAULT_POOL_SOCKET_ADDRESS,
    DEFAULT_PPLNS_WINDOW_SHARES, DEFAULT_SHARE_LEADING_ZERO_BITS, PoolPayoutPolicy,
    PoolPayoutReconciliationRequest, PoolPplnsPolicy, PoolServerConfig, certificate_sha256,
    generate_pool_certificate, inspect_pool_payout_protection_with_limit,
    reconcile_pool_payout_protection_with_limit, require_existing_pool_ledger, spawn_pool_server,
};
use cmfd_node::pool_dashboard::{
    DEFAULT_POOL_DASHBOARD_ADDRESS, PoolDashboardConfig, spawn_pool_dashboard,
};
#[cfg(feature = "production-v4")]
use cmfd_node::production_v4_pool::{
    ProductionV4PersistentPoolVerifier, ProductionV4PoolVerifierConfig,
    ProductionV4PoolWorkerCommand,
};
#[cfg(feature = "production-v4")]
use cmfd_node::rcnet_candidate::{
    MainnetLaunchPlan, RcnetLaunchCandidate, RcnetLaunchConfiguration, write_candidate_create_new,
    write_mainnet_plan_create_new,
};
use cmfd_node::seed_peers::{SeedSet, SystemSeedResolver};
use cmfd_node::storage::{inspect_block_log, repair_partial_block_log_tail};
#[cfg(test)]
use cmfd_node::wallet_backup::MAXIMUM_PASSPHRASE_BYTES;
#[cfg(feature = "production-v4-testnet")]
use cmfd_node::wallet_backup::create_encrypted_wallet;
use cmfd_node::wallet_backup::{
    create_encrypted_wallet_backup, read_wallet_passphrase_file, restore_encrypted_wallet_backup,
};
use cmfd_node::{
    COMPILED_NETWORK_PROFILE, DEFAULT_DATA_DIR, DEFAULT_MINING_ATTEMPTS, ExchangeCustodyV3Config,
    ExchangeWithdrawalSecurityConfig, Node, ProductionV4VerifierArtifacts, ProofProfile,
    canonical_network_info_json_with_record, canonical_network_info_json_with_v4_artifacts,
    compiled_production_v3_worker_sha256, parse_miner_destination, production_v3_package_layout,
    production_v4_package_artifacts, spawn_rpc_server, unix_time_seconds,
};
use cmfd_proof_worker::{ProductionV3VerifierRecord, VerifierWorkerConfig};
use serde_json::json;
use zeroize::Zeroizing;

const SERVICE_SUPERVISION_POLL: Duration = Duration::from_millis(50);
const POOL_SHUTDOWN_REQUEST_BYTES: &[u8] = b"CMFD_POOL_SHUTDOWN_V1\n";
#[cfg(feature = "production-v4")]
const DISTINCT_PASSWORD_STDIN_MAGIC: &[u8] = b"CMFD/REWARD-CUSTODY/TWO-PASSWORDS/V1\0";
#[cfg(feature = "production-v4")]
type CustodyStdinPasswords = [Zeroizing<Vec<u8>>; 2];

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

#[cfg(feature = "production-v4-testnet")]
fn load_authenticated_rcnet_wallet_passphrase(
    data_dir: &Path,
    candidate: &Path,
    passphrase_file: &Path,
) -> Result<Zeroizing<Vec<u8>>, Box<dyn std::error::Error>> {
    for (path, label) in [
        (data_dir, "--data-dir"),
        (candidate, "--candidate"),
        (passphrase_file, "--passphrase-file"),
    ] {
        if !path.is_absolute() {
            return Err(format!("{label} must be absolute").into());
        }
    }
    if passphrase_file.starts_with(data_dir) {
        return Err("--passphrase-file must be outside --data-dir".into());
    }
    let candidate_metadata = std::fs::symlink_metadata(candidate)?;
    let passphrase_metadata = std::fs::symlink_metadata(passphrase_file)?;
    #[cfg(windows)]
    let unsafe_reparse_point = |metadata: &std::fs::Metadata| {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    };
    #[cfg(not(windows))]
    let unsafe_reparse_point = |_: &std::fs::Metadata| false;
    if !candidate_metadata.is_file()
        || candidate_metadata.file_type().is_symlink()
        || unsafe_reparse_point(&candidate_metadata)
        || candidate_metadata.len() == 0
        || candidate_metadata.len() > 64 * 1024
    {
        return Err("--candidate must be a bounded regular non-symlink file".into());
    }
    if !passphrase_metadata.is_file()
        || passphrase_metadata.file_type().is_symlink()
        || unsafe_reparse_point(&passphrase_metadata)
    {
        return Err("--passphrase-file must be a regular non-symlink file".into());
    }
    let candidate_bytes = std::fs::read(candidate)?;
    if candidate_bytes.len() as u64 != candidate_metadata.len() {
        return Err("--candidate changed while being read".into());
    }
    RcnetLaunchCandidate::parse_exact_compiled_rcnet1(&candidate_bytes)?;
    Ok(read_wallet_passphrase_file(passphrase_file)?)
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
    /// File containing the passphrase used to unlock or create encrypted wallet.key.
    #[arg(long, global = true)]
    wallet_passphrase_file: Option<PathBuf>,
    /// Absolute path to the dedicated raw 32-byte withdrawal-journal authentication key.
    #[arg(long, global = true)]
    exchange_withdrawal_journal_key_file: Option<PathBuf>,
    /// Absolute external file containing the exchange-persisted withdrawal anchor.
    #[arg(long, global = true)]
    exchange_withdrawal_anchor_file: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[cfg(feature = "production-v4")]
#[derive(Debug, clap::Args)]
struct MainnetCustodyPaths {
    /// Absolute, create-new directory outside Git worktrees; contains two wallets.
    #[arg(long)]
    wallets_directory: PathBuf,
    /// Separate absolute, create-new directory for the two encrypted backups.
    #[arg(long)]
    backups_directory: PathBuf,
    /// Separate absolute, create-new directory containing only public plan/report files.
    #[arg(long)]
    public_directory: PathBuf,
    /// Protected passphrase file outside all output directories. Contents are never printed.
    #[arg(
        long,
        required_unless_present = "distinct_passphrases_stdin",
        conflicts_with = "distinct_passphrases_stdin"
    )]
    steward_passphrase_file: Option<PathBuf>,
    #[arg(
        long,
        required_unless_present = "distinct_passphrases_stdin",
        conflicts_with = "distinct_passphrases_stdin"
    )]
    community_passphrase_file: Option<PathBuf>,
    /// Read two distinct length-framed passwords from one anonymous stdin pipe.
    #[arg(long)]
    distinct_passphrases_stdin: bool,
}

#[cfg(feature = "production-v4")]
impl MainnetCustodyPaths {
    fn runtime_paths(&self) -> cmfd_node::mainnet_custody::RewardCustodyPaths {
        cmfd_node::mainnet_custody::RewardCustodyPaths {
            wallets_directory: self.wallets_directory.clone(),
            backups_directory: self.backups_directory.clone(),
            public_directory: self.public_directory.clone(),
            steward_passphrase_file: self.steward_passphrase_file.clone().unwrap_or_default(),
            community_passphrase_file: self.community_passphrase_file.clone().unwrap_or_default(),
        }
    }

    fn read_distinct_stdin_passwords(
        &self,
    ) -> Result<Option<CustodyStdinPasswords>, Box<dyn std::error::Error>> {
        if !self.distinct_passphrases_stdin {
            return Ok(None);
        }
        let mut frame = Zeroizing::new(Vec::new());
        let maximum = DISTINCT_PASSWORD_STDIN_MAGIC.len()
            + 4
            + 2 * cmfd_node::wallet_backup::MAXIMUM_PASSPHRASE_BYTES
            + 1;
        io::stdin()
            .lock()
            .take(maximum as u64)
            .read_to_end(&mut frame)?;
        Ok(Some(parse_distinct_password_frame(&frame)?))
    }
}

#[cfg(feature = "production-v4")]
fn parse_distinct_password_frame(
    frame: &[u8],
) -> Result<CustodyStdinPasswords, Box<dyn std::error::Error>> {
    if !frame.starts_with(DISTINCT_PASSWORD_STDIN_MAGIC) {
        return Err("invalid two-password stdin frame".into());
    }
    fn read_password<'a>(
        frame: &'a [u8],
        offset: &mut usize,
    ) -> Result<&'a [u8], Box<dyn std::error::Error>> {
        let length_bytes = frame
            .get(*offset..*offset + 2)
            .ok_or("truncated two-password stdin frame")?;
        let length = u16::from_le_bytes([length_bytes[0], length_bytes[1]]) as usize;
        *offset += 2;
        if !(cmfd_node::wallet_backup::MINIMUM_PASSPHRASE_BYTES
            ..=cmfd_node::wallet_backup::MAXIMUM_PASSPHRASE_BYTES)
            .contains(&length)
        {
            return Err("each wallet password must contain 12 to 1024 bytes".into());
        }
        let password = frame
            .get(*offset..*offset + length)
            .ok_or("truncated two-password stdin frame")?;
        *offset += length;
        Ok(password)
    }
    let mut offset = DISTINCT_PASSWORD_STDIN_MAGIC.len();
    let steward = read_password(frame, &mut offset)?;
    let community = read_password(frame, &mut offset)?;
    if offset != frame.len() {
        return Err("two-password stdin frame has trailing bytes".into());
    }
    if steward == community {
        return Err("steward and community passwords must differ".into());
    }
    Ok([
        Zeroizing::new(steward.to_vec()),
        Zeroizing::new(community.to_vec()),
    ])
}

#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)] // Parsed once at startup; boxing CLI fields adds needless indirection.
enum Command {
    /// Print the compiled network identity and consensus manifest.
    NetworkInfo,
    /// Print pinned mainnet launch identity before the future beacon is available.
    #[cfg(feature = "production-v4")]
    MainnetLaunchInfo,
    /// Prepare fresh encrypted reward wallets, backups and their candidate plan
    /// offline. Does not approve or activate mainnet or change any release pins.
    #[cfg(feature = "production-v4")]
    MainnetCustodyPrepare {
        #[arg(long, value_parser = parse_hex32)]
        pow_limit: [u8; 32],
        #[arg(long, value_parser = parse_hex32)]
        initial_target: [u8; 32],
        #[command(flatten)]
        paths: MainnetCustodyPaths,
    },
    /// Authenticate prepared reward wallets/backups against the selected plan.
    #[cfg(feature = "production-v4")]
    MainnetCustodyVerify {
        #[arg(long, value_parser = parse_hex32)]
        expected_plan_digest: [u8; 32],
        #[command(flatten)]
        paths: MainnetCustodyPaths,
    },
    /// Replace Community while retaining the approved Steward key. Offline,
    /// create-new outputs only; passwords arrive through the protected stdin frame.
    #[cfg(feature = "production-v4")]
    MainnetCustodyReplaceCommunity {
        #[arg(long)]
        retained_steward_backup: PathBuf,
        #[arg(long, value_parser = parse_hex32)]
        expected_steward_backup_sha256: [u8; 32],
        #[arg(long)]
        source_plan: PathBuf,
        #[arg(long, value_parser = parse_hex32)]
        expected_plan_digest: [u8; 32],
        #[command(flatten)]
        paths: MainnetCustodyPaths,
    },
    /// Write the October mainnet plan from release-pinned artifacts and explicit
    /// reward addresses. Does not activate mainnet or alter RCNet storage.
    #[cfg(feature = "production-v4")]
    MainnetPlan {
        #[arg(long)]
        output: PathBuf,
        /// Largest/easiest target that retargeting may ever select.
        #[arg(long, value_parser = parse_hex32)]
        pow_limit: [u8; 32],
        /// First-block target; must be nonzero and no larger than pow-limit.
        #[arg(long, value_parser = parse_hex32)]
        initial_target: [u8; 32],
        #[arg(long, value_parser = parse_hex32)]
        steward_reward_destination: [u8; 32],
        #[arg(long, value_parser = parse_hex32)]
        community_reward_destination: [u8; 32],
    },
    /// Derive a canonical RCNet identity candidate from authenticated ProductionV4 artifacts.
    #[cfg(feature = "production-v4")]
    RcnetCandidate {
        #[arg(long)]
        model_bank: PathBuf,
        #[arg(long)]
        fixed_record: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        virtual_genesis_timestamp: u64,
        #[arg(long, value_parser = parse_hex32)]
        pow_limit: [u8; 32],
        #[arg(long, value_parser = parse_hex32)]
        steward_reward_destination: [u8; 32],
        #[arg(long, value_parser = parse_hex32)]
        community_reward_destination: [u8; 32],
    },
    /// Create a dedicated encrypted RCNet-1 wallet and independent backup offline.
    #[cfg(feature = "production-v4-testnet")]
    RcnetWalletCreate {
        /// Exact canonical RCNet-1 Candidate V2 document.
        #[arg(long)]
        candidate: PathBuf,
        /// Absolute create-new path for the independently randomized encrypted backup.
        #[arg(long)]
        backup_output: PathBuf,
        /// Absolute path to a passphrase file outside --data-dir.
        #[arg(long)]
        passphrase_file: PathBuf,
    },
    /// Restore a dedicated encrypted RCNet-1 wallet backup offline.
    #[cfg(feature = "production-v4-testnet")]
    RcnetWalletRestore {
        /// Exact canonical RCNet-1 Candidate V2 document.
        #[arg(long)]
        candidate: PathBuf,
        /// Absolute path to the encrypted RCNet-1 wallet backup.
        #[arg(long)]
        input: PathBuf,
        /// Absolute path to a passphrase file outside --data-dir.
        #[arg(long)]
        passphrase_file: PathBuf,
    },
    /// Run loopback RPC and bounded P2P services.
    Run {
        #[arg(long, default_value_t = COMPILED_NETWORK_PROFILE.rpc_address())]
        bind: SocketAddr,
        /// Dedicated loopback address for the authenticated exchange chain RPC.
        /// Disabled unless this and --exchange-rpc-auth-file are both supplied.
        #[arg(long, requires = "exchange_rpc_auth_file")]
        exchange_rpc_bind: Option<SocketAddr>,
        /// File containing `username:password` for HTTP Basic authentication.
        #[arg(long, requires = "exchange_rpc_bind")]
        exchange_rpc_auth_file: Option<PathBuf>,
        /// Separate `username:password` file that enables the preview withdrawal signer.
        /// This credential is accepted only by withdrawal methods.
        #[arg(long, requires = "exchange_rpc_auth_file")]
        exchange_rpc_withdrawal_auth_file: Option<PathBuf>,
        /// Canonical v3 withdrawal-policy document. All v3 custody options are required together.
        #[arg(long)]
        exchange_custody_v3_policy_file: Option<PathBuf>,
        /// Encrypted v3 wallet keyring bound to the live node wallet.
        #[arg(long)]
        exchange_custody_v3_keyring_file: Option<PathBuf>,
        /// External rollback anchor for the encrypted v3 wallet keyring.
        #[arg(long)]
        exchange_custody_v3_keyring_anchor_file: Option<PathBuf>,
        /// External file containing the v3 wallet-keyring passphrase.
        #[arg(long)]
        exchange_custody_v3_keyring_passphrase_file: Option<PathBuf>,
        #[arg(long, default_value_t = COMPILED_NETWORK_PROFILE.p2p_address())]
        p2p_bind: SocketAddr,
        /// Static peer address. Public IPs require --allow-public-peers.
        #[arg(long = "peer")]
        peers: Vec<SocketAddr>,
        /// Do not use the compiled operational RC seed when no --peer is supplied.
        #[arg(long)]
        no_default_seeds: bool,
        /// Explicitly allow unauthenticated, unencrypted public P2P addresses.
        #[arg(long)]
        allow_public_peers: bool,
        /// Opt-in proof pruning: keep full blocks only for this many newest
        /// blocks (at least 288). Older blocks keep their transactions but
        /// drop their proofs, cutting storage from about 12 MB to a few KB
        /// per block. A pruned node cannot serve old blocks to peers or follow
        /// a reorganization deeper than this window.
        #[arg(long)]
        prune_keep_blocks: Option<u64>,
    },
    /// Generate a create-new raw 32-byte withdrawal-journal authentication key.
    ExchangeWithdrawalKeygen {
        /// Absolute output path. Existing files are never overwritten.
        #[arg(long)]
        output: PathBuf,
    },
    /// Create a new exchange deposit or hot-wallet key file (offline; no node
    /// or data directory). Prints the key's destination (x-only public key).
    ExchangeKeyNew {
        /// Output path for the secret key. Existing files are never overwritten.
        #[arg(long)]
        output: PathBuf,
    },
    /// Print the destination (x-only public key) of an existing exchange key file.
    ExchangeKeyShow {
        #[arg(long)]
        key: PathBuf,
    },
    /// Run a Bitcoin Core-compatible wallet daemon for exchanges. It keeps
    /// the exchange's keys in --wallet-dir and reads the chain from an
    /// exchange RPC endpoint (the hosted endpoint or your own node), so no
    /// chain is stored locally. Settings come from cmfd-wallet.conf.
    ExchangeWallet {
        /// Directory holding wallet.json (the keys) and the wallet's state.
        #[arg(long)]
        wallet_dir: PathBuf,
        /// Settings file [default: <wallet-dir>/cmfd-wallet.conf].
        #[arg(long)]
        conf: Option<PathBuf>,
    },
    /// Build and sign a withdrawal from a JSON request (offline; no node or
    /// data directory). Prints the transaction hex for sendrawtransaction.
    ExchangeTxSign {
        /// JSON request: network_id, inputs (txid, vout, value_atoms,
        /// destination_hex, key_file), outputs (destination_hex, value_atoms),
        /// optional change_destination_hex and fee_atoms.
        #[arg(long)]
        request: PathBuf,
    },
    /// Qualify an installed v0.5 custody package under the configured service identity.
    ExchangeV3AclQualify {
        /// Absolute path to the live qualification configuration.
        #[arg(long)]
        config: PathBuf,
        /// Absolute create-new path for qualification evidence.
        #[arg(long)]
        output: PathBuf,
    },
    /// Evaluate a dry ACL fact fixture without claiming host qualification.
    ExchangeV3AclFixtureQualify {
        /// Path to a normalized fixture document.
        #[arg(long)]
        fixture: PathBuf,
        /// Absolute create-new path for fixture evidence.
        #[arg(long)]
        output: PathBuf,
    },
    /// Plan an explicit legacy wallet-key import into an encrypted v3 keyring.
    ExchangeKeyringImportPlan {
        #[arg(long)]
        legacy_key_file: PathBuf,
        /// Required when --legacy-key-file uses the encrypted RCNet wallet format.
        #[arg(long)]
        legacy_wallet_passphrase_file: Option<PathBuf>,
        #[arg(long, value_parser = parse_hex32)]
        keyring_instance_id: [u8; 32],
        #[arg(long)]
        plan_output: PathBuf,
    },
    /// Apply an exact confirmed keyring-import plan to create-new artifacts.
    ExchangeKeyringImportApply {
        #[arg(long)]
        plan_file: PathBuf,
        #[arg(long, value_parser = parse_hex32)]
        confirmation_digest: [u8; 32],
        #[arg(long)]
        keyring_passphrase_file: PathBuf,
        #[arg(long)]
        keyring_output: PathBuf,
        #[arg(long)]
        anchor_output: PathBuf,
    },
    /// Plan conversion of one imported local keyring to an external active key.
    ExchangeKeyringExternalTransitionPlan {
        #[arg(long)]
        source_keyring_file: PathBuf,
        #[arg(long)]
        source_anchor_file: PathBuf,
        #[arg(long)]
        source_keyring_passphrase_file: PathBuf,
        #[arg(long, value_parser = parse_hex32)]
        external_public_key: [u8; 32],
        #[arg(long, value_parser = parse_hex32)]
        external_signer_id: [u8; 32],
        #[arg(long)]
        keyring_output: PathBuf,
        #[arg(long)]
        anchor_output: PathBuf,
        #[arg(long)]
        plan_output: PathBuf,
    },
    /// Apply an exact confirmed import-to-external transition to create-new artifacts.
    ExchangeKeyringExternalTransitionApply {
        #[arg(long)]
        plan_file: PathBuf,
        #[arg(long, value_parser = parse_hex32)]
        confirmation_digest: [u8; 32],
        #[arg(long)]
        source_keyring_passphrase_file: PathBuf,
    },
    /// Plan disabling the retired local key after proving it owns no active-chain UTXOs.
    ExchangeKeyringExternalFinalizationPlan {
        #[arg(long)]
        policy_file: PathBuf,
        #[arg(long)]
        source_keyring_file: PathBuf,
        #[arg(long)]
        source_anchor_file: PathBuf,
        #[arg(long)]
        source_keyring_passphrase_file: PathBuf,
        #[arg(long, value_parser = parse_hex32)]
        legacy_public_key: [u8; 32],
        #[arg(long)]
        decommission_evidence_file: PathBuf,
        #[arg(long, value_parser = parse_hex32)]
        rotation_decision_id: [u8; 32],
        #[arg(long, value_parser = parse_hex32)]
        approval_digest: [u8; 32],
        #[arg(long)]
        keyring_output: PathBuf,
        #[arg(long)]
        keyring_anchor_output: PathBuf,
        #[arg(long)]
        journal_anchor_output: PathBuf,
        #[arg(long)]
        plan_output: PathBuf,
    },
    /// Apply an exact chain-bound finalization plan to create-new artifacts.
    ExchangeKeyringExternalFinalizationApply {
        #[arg(long)]
        plan_file: PathBuf,
        #[arg(long, value_parser = parse_hex32)]
        confirmation_digest: [u8; 32],
    },
    /// Emit one canonical unsigned approval payload for a Released v2 record.
    ExchangeV3MigrationApprovalPayload {
        #[arg(long)]
        policy_file: PathBuf,
        #[arg(long)]
        keyring_file: PathBuf,
        #[arg(long)]
        keyring_anchor_file: PathBuf,
        #[arg(long)]
        keyring_passphrase_file: PathBuf,
        #[arg(long)]
        request_id: String,
        #[arg(long, value_parser = parse_hex32)]
        decision_id: [u8; 32],
        #[arg(long)]
        authorized_at_unix_seconds: u64,
        #[arg(long)]
        expires_at_unix_seconds: u64,
        #[arg(long)]
        output: PathBuf,
    },
    /// Plan authenticated v2-to-v3 withdrawal-journal migration.
    ExchangeV3MigrationPlan {
        #[arg(long)]
        evidence_file: PathBuf,
        #[arg(long)]
        policy_file: PathBuf,
        #[arg(long)]
        keyring_file: PathBuf,
        #[arg(long)]
        keyring_anchor_file: PathBuf,
        #[arg(long)]
        keyring_passphrase_file: PathBuf,
        #[arg(long)]
        validated_snapshot_output: PathBuf,
        #[arg(long)]
        v3_anchor_output: PathBuf,
        #[arg(long)]
        plan_output: PathBuf,
    },
    /// Apply an exact confirmed v2-to-v3 migration plan while offline.
    ExchangeV3MigrationApply {
        #[arg(long)]
        plan_file: PathBuf,
        #[arg(long, value_parser = parse_hex32)]
        confirmation_plan_digest: [u8; 32],
    },
    /// Create an authenticated canceled-record archive and manifest artifact for independent retention.
    ExchangeV3ArchivePlan {
        #[arg(long)]
        policy_file: PathBuf,
        #[arg(long)]
        keyring_file: PathBuf,
        #[arg(long)]
        keyring_anchor_file: PathBuf,
        #[arg(long)]
        keyring_passphrase_file: PathBuf,
        #[arg(long = "request-id", required = true)]
        request_ids: Vec<String>,
        #[arg(long)]
        archive_output: PathBuf,
        #[arg(long)]
        manifest_pin_output: PathBuf,
    },
    /// Compact only the records proven by an exact confirmed archive and pin.
    ExchangeV3ArchiveApply {
        #[arg(long)]
        policy_file: PathBuf,
        #[arg(long)]
        keyring_file: PathBuf,
        #[arg(long)]
        keyring_anchor_file: PathBuf,
        #[arg(long)]
        keyring_passphrase_file: PathBuf,
        #[arg(long)]
        archive_file: PathBuf,
        #[arg(long)]
        manifest_pin_file: PathBuf,
        #[arg(long, value_parser = parse_hex32)]
        confirmation_archive_id: [u8; 32],
        #[arg(long)]
        proposed_anchor_output: PathBuf,
    },
    /// Verify an authenticated archive for restore without writing journal state.
    ExchangeV3ArchiveVerify {
        #[arg(long)]
        archive_file: PathBuf,
        #[arg(long)]
        manifest_pin_file: PathBuf,
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
    /// Create a network-bound, passphrase-encrypted backup of wallet.key.
    WalletBackup {
        #[arg(long)]
        output: PathBuf,
        /// File containing the backup passphrase. Its bytes are never printed.
        #[arg(long)]
        passphrase_file: PathBuf,
    },
    /// Restore wallet.key from a network-bound encrypted backup.
    WalletRestore {
        #[arg(long)]
        input: PathBuf,
        /// File containing the backup passphrase. Its bytes are never printed.
        #[arg(long)]
        passphrase_file: PathBuf,
    },
    /// Inspect the block log without starting network services or verifying proofs.
    StorageInspect,
    /// Quarantine and remove only an incomplete final block-log record.
    StorageRepairTail {
        /// Create-new evidence file that receives the exact removed tail bytes.
        #[arg(long)]
        quarantine_output: PathBuf,
    },
    /// Replay storage and write a locally authenticated fast-start checkpoint.
    StorageCheckpoint,
    /// Offline pool accounting inspection; records holds but never sends payments.
    PoolPayoutStatus {
        /// Use the same fee as pool-serve. Amount is in atomic units.
        #[arg(long)]
        pool_payout_fee_atoms: u64,
        /// Use the same ledger size limit as pool-serve.
        #[arg(long, default_value_t = DEFAULT_POOL_LEDGER_MAX_BYTES)]
        pool_ledger_max_bytes: usize,
    },
    /// Resolve funded payout holds offline without sending or replacing payments.
    PoolPayoutReconcile {
        #[arg(long)]
        pool_payout_fee_atoms: u64,
        /// Use the same ledger size limit as pool-serve.
        #[arg(long, default_value_t = DEFAULT_POOL_LEDGER_MAX_BYTES)]
        pool_ledger_max_bytes: usize,
        #[arg(long, value_parser = parse_hex32)]
        expected_tip: [u8; 32],
        #[arg(long)]
        expected_ledger_generation: u64,
        /// Local audit note; never exposed on the public dashboard.
        #[arg(long)]
        note: String,
        /// Confirm that the incident and all outstanding signed payments were reviewed.
        #[arg(long, required = true)]
        acknowledge_reconciliation: bool,
    },
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
        /// Do not use the compiled operational RC seed when no --peer is supplied.
        #[arg(long)]
        no_default_seeds: bool,
        /// Explicitly allow unauthenticated, unencrypted public P2P addresses.
        #[arg(long)]
        allow_public_peers: bool,
        /// Explicitly accept certificate-pinned pool clients from public IP addresses.
        #[arg(long)]
        allow_public_pool_clients: bool,
        /// Accept miners that identify a valid payout address without proving possession of its key.
        #[arg(long)]
        allow_address_only_payouts: bool,
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
        /// Enable automatic on-chain settlement of authenticated test-network share credits.
        #[arg(long, conflicts_with = "enable_mainnet_payouts")]
        enable_testnet_payouts: bool,
        /// Explicitly enable automatic settlement for a mainnet pool; required on mainnet.
        #[arg(long, conflicts_with = "enable_testnet_payouts")]
        enable_mainnet_payouts: bool,
        /// Minimum earned atoms settled to one authenticated payout key.
        #[arg(long, default_value_t = DEFAULT_POOL_MINIMUM_PAYOUT_ATOMS)]
        pool_minimum_payout_atoms: u64,
        /// Burned fee, in atoms, for each pool payout transaction.
        #[arg(long, default_value_t = DEFAULT_POOL_PAYOUT_FEE_ATOMS)]
        pool_payout_fee_atoms: u64,
        /// Operator fee in basis points, deducted from each mature pool block before PPLNS distribution.
        #[arg(long, default_value_t = DEFAULT_POOL_OPERATOR_FEE_BPS)]
        pool_operator_fee_bps: u16,
        /// Fixed PPLNS share count; zero automatically uses one block of expected share work.
        #[arg(long, default_value_t = DEFAULT_PPLNS_WINDOW_SHARES)]
        pool_pplns_window_shares: usize,
        /// Maximum simultaneous pool connections accepted from one source IP.
        #[arg(long, default_value_t = DEFAULT_POOL_CONNECTIONS_PER_SOURCE)]
        pool_max_connections_per_source: usize,
        /// Maximum share replays evaluated concurrently by the pool verifier.
        #[arg(long, default_value_t = DEFAULT_POOL_CONCURRENT_SHARE_VERIFICATIONS)]
        pool_max_concurrent_share_verifications: usize,
        /// Maximum authenticated shares waiting for a pool verifier slot.
        #[arg(long, default_value_t = DEFAULT_POOL_QUEUED_SHARE_VERIFICATIONS)]
        pool_max_queued_share_verifications: usize,
        /// Largest pool ledger snapshot loaded or written, in bytes (1 MiB to
        /// 1 GiB). Raise it when a large pool's ledger outgrows the default;
        /// pass the same value to pool-payout-status and pool-payout-reconcile.
        #[arg(long, default_value_t = DEFAULT_POOL_LEDGER_MAX_BYTES)]
        pool_ledger_max_bytes: usize,
        /// Built dashboard directory containing index.html and its static assets.
        #[arg(long)]
        pool_dashboard_assets: Option<PathBuf>,
        /// Public cmfd+tls pool URL displayed by the dashboard.
        #[arg(long)]
        pool_public_url: Option<String>,
        /// Loopback-only address for the read-only pool dashboard.
        #[arg(long, default_value_t = DEFAULT_POOL_DASHBOARD_ADDRESS)]
        pool_dashboard_bind: SocketAddr,
        /// Absolute create-new request file used by local operator controls for graceful shutdown.
        #[arg(long)]
        shutdown_request_file: Option<PathBuf>,
        /// Opt-in proof pruning, as for `run`: keep full blocks only for this
        /// many newest blocks (at least 288). Mining jobs, block maturity and
        /// payouts only need recent blocks and transactions, which pruned
        /// blocks keep.
        #[arg(long)]
        prune_keep_blocks: Option<u64>,
    },
}

#[cfg(windows)]
const WINDOWS_CLI_PARSER_STACK_BYTES: usize = 4 * 1024 * 1024;

#[cfg(windows)]
fn parse_cli() -> Result<Cli, Box<dyn std::error::Error>> {
    // clap's generated builder for this intentionally broad operator CLI has
    // a measured nested debug-frame high-water mark above Windows' 1 MiB main
    // stack. Isolate only construction/parsing on a fixed-size thread; all
    // command execution returns to the normal main thread.
    std::thread::Builder::new()
        .name("cmfd-cli-parser".to_owned())
        .stack_size(WINDOWS_CLI_PARSER_STACK_BYTES)
        .spawn(Cli::parse)?
        .join()
        .map_err(|_| "CLI parser thread panicked".into())
}

#[cfg(not(windows))]
fn parse_cli() -> Result<Cli, Box<dyn std::error::Error>> {
    Ok(Cli::parse())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if cmfd_proof_worker::verifier_worker_mode_requested() {
        std::process::exit(cmfd_proof_worker::worker_main());
    }
    let cli = parse_cli()?;
    validate_exchange_withdrawal_cli(&cli)?;
    if matches!(
        &cli.command,
        Command::PoolPayoutStatus { .. } | Command::PoolPayoutReconcile { .. }
    ) {
        require_existing_pool_ledger(&cli.data_dir)?;
    }
    if let Command::ExchangeV3AclQualify { config, output } = &cli.command {
        let evidence = qualify_installed_host(config, output)?;
        println!("{}", serde_json::to_string_pretty(&evidence)?);
        if !evidence.host_qualified {
            return Err(format!(
                "installed-host ACL qualification was rejected; evidence was written to `{}`",
                output.display()
            )
            .into());
        }
        return Ok(());
    }
    if let Command::ExchangeV3AclFixtureQualify { fixture, output } = &cli.command {
        let evidence = qualify_fixture(fixture, output)?;
        println!("{}", serde_json::to_string_pretty(&evidence)?);
        if !evidence.fixture_qualified {
            return Err(format!(
                "ACL fixture qualification was rejected; evidence was written to `{}`",
                output.display()
            )
            .into());
        }
        return Ok(());
    }
    if let Command::ExchangeKeyNew { output } = &cli.command {
        let destination = cmfd_node::exchange_tx_tool::create_key_file(output)?;
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "status": "created",
                "key_file": output,
                "destination_hex": hex::encode(destination),
                "warning": "the key file is the only copy of this secret; back it up and keep it private"
            }))?
        );
        return Ok(());
    }
    if let Command::ExchangeKeyShow { key } = &cli.command {
        let key = cmfd_node::exchange_tx_tool::read_key_file(key)?;
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "destination_hex": hex::encode(cmfd_node::exchange_tx_tool::destination_of(&key)),
            }))?
        );
        return Ok(());
    }
    if let Command::ExchangeWallet { wallet_dir, conf } = &cli.command {
        let _log_guard = cmfd_node::logging::init_tracing(wallet_dir, cli.verbose.max(2));
        let conf = conf
            .clone()
            .unwrap_or_else(|| wallet_dir.join(cmfd_node::exchange_wallet_rpc::CONFIG_FILE));
        cmfd_node::exchange_wallet_rpc::run(
            wallet_dir,
            &conf,
            COMPILED_NETWORK_PROFILE.network_id,
            COMPILED_NETWORK_PROFILE.short_name(),
        )?;
        return Ok(());
    }
    if let Command::ExchangeTxSign { request } = &cli.command {
        let request: cmfd_node::exchange_tx_tool::SignRequest =
            serde_json::from_slice(&std::fs::read(request)?)?;
        let signed = cmfd_node::exchange_tx_tool::sign_request(
            &request,
            COMPILED_NETWORK_PROFILE.network_id,
        )?;
        println!("{}", serde_json::to_string_pretty(&signed)?);
        return Ok(());
    }
    if let Command::ExchangeWithdrawalKeygen { output } = &cli.command {
        create_exchange_withdrawal_journal_key(output)?;
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "status": "created",
                "format": "Common Foundry raw withdrawal-journal key v1",
                "path": output,
                "bytes": 32,
                "warning": "keep this key outside the node data directory and back it up separately"
            }))?
        );
        return Ok(());
    }
    if let Command::ExchangeKeyringImportPlan {
        legacy_key_file,
        legacy_wallet_passphrase_file,
        keyring_instance_id,
        plan_output,
    } = &cli.command
    {
        let report = plan_legacy_keyring_import(&LegacyKeyringPlanConfig {
            data_dir: cli.data_dir.clone(),
            legacy_key_file: legacy_key_file.clone(),
            legacy_wallet_passphrase_file: legacy_wallet_passphrase_file.clone(),
            keyring_instance_id: *keyring_instance_id,
            plan_output: plan_output.clone(),
        })?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    if let Command::ExchangeKeyringImportApply {
        plan_file,
        confirmation_digest,
        keyring_passphrase_file,
        keyring_output,
        anchor_output,
    } = &cli.command
    {
        let report = apply_legacy_keyring_import(&LegacyKeyringApplyConfig {
            data_dir: cli.data_dir.clone(),
            plan_file: plan_file.clone(),
            expected_confirmation_digest: *confirmation_digest,
            passphrase_file: keyring_passphrase_file.clone(),
            keyring_output: keyring_output.clone(),
            anchor_output: anchor_output.clone(),
        })?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    if let Command::ExchangeKeyringExternalTransitionPlan {
        source_keyring_file,
        source_anchor_file,
        source_keyring_passphrase_file,
        external_public_key,
        external_signer_id,
        keyring_output,
        anchor_output,
        plan_output,
    } = &cli.command
    {
        let report = plan_external_keyring_transition(&ExternalKeyringTransitionPlanConfig {
            data_dir: cli.data_dir.clone(),
            source_keyring_file: source_keyring_file.clone(),
            source_anchor_file: source_anchor_file.clone(),
            source_keyring_passphrase_file: source_keyring_passphrase_file.clone(),
            external_public_key: *external_public_key,
            external_signer_id: *external_signer_id,
            keyring_output: keyring_output.clone(),
            anchor_output: anchor_output.clone(),
            plan_output: plan_output.clone(),
        })?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    if let Command::ExchangeKeyringExternalTransitionApply {
        plan_file,
        confirmation_digest,
        source_keyring_passphrase_file,
    } = &cli.command
    {
        let report = apply_external_keyring_transition(&ExternalKeyringTransitionApplyConfig {
            data_dir: cli.data_dir.clone(),
            plan_file: plan_file.clone(),
            expected_confirmation_digest: *confirmation_digest,
            source_keyring_passphrase_file: source_keyring_passphrase_file.clone(),
        })?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    if let Command::ExchangeV3ArchivePlan {
        policy_file,
        keyring_file,
        keyring_anchor_file,
        keyring_passphrase_file,
        request_ids,
        archive_output,
        manifest_pin_output,
    } = &cli.command
    {
        let controls = v3_offline_controls(
            &cli,
            policy_file,
            keyring_file,
            keyring_anchor_file,
            keyring_passphrase_file,
        )?;
        let report = plan_canceled_archive(&CanceledArchivePlanConfig {
            controls,
            request_ids: request_ids.clone(),
            archive_output: archive_output.clone(),
            manifest_pin_output: manifest_pin_output.clone(),
        })?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    if let Command::ExchangeV3ArchiveApply {
        policy_file,
        keyring_file,
        keyring_anchor_file,
        keyring_passphrase_file,
        archive_file,
        manifest_pin_file,
        confirmation_archive_id,
        proposed_anchor_output,
    } = &cli.command
    {
        let controls = v3_offline_controls(
            &cli,
            policy_file,
            keyring_file,
            keyring_anchor_file,
            keyring_passphrase_file,
        )?;
        let report = apply_canceled_archive_compaction(&CanceledArchiveApplyConfig {
            controls,
            archive_file: archive_file.clone(),
            manifest_pin_file: manifest_pin_file.clone(),
            expected_archive_id: *confirmation_archive_id,
            proposed_anchor_output: proposed_anchor_output.clone(),
        })?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    if let Command::ExchangeV3ArchiveVerify {
        archive_file,
        manifest_pin_file,
    } = &cli.command
    {
        let journal_key_file = cli
            .exchange_withdrawal_journal_key_file
            .as_ref()
            .ok_or("archive verification requires --exchange-withdrawal-journal-key-file")?;
        let report = verify_archive_restore_offline(&ArchiveRestoreVerifyConfig {
            data_dir: cli.data_dir.clone(),
            journal_key_file: journal_key_file.to_path_buf(),
            archive_file: archive_file.clone(),
            manifest_pin_file: manifest_pin_file.clone(),
        })?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    #[cfg(feature = "production-v4")]
    if matches!(&cli.command, Command::MainnetLaunchInfo) {
        io::stdout()
            .lock()
            .write_all(&cmfd_node::mainnet_runtime::canonical_mainnet_launch_info_json()?)?;
        return Ok(());
    }
    #[cfg(feature = "production-v4")]
    if let Command::MainnetCustodyReplaceCommunity {
        retained_steward_backup,
        expected_steward_backup_sha256,
        source_plan,
        expected_plan_digest,
        paths,
    } = &cli.command
    {
        let Some([steward, community]) = paths.read_distinct_stdin_passwords()? else {
            return Err("community replacement requires --distinct-passphrases-stdin".into());
        };
        let source = cmfd_node::mainnet_custody::CommunityReplacementSource {
            steward_backup: retained_steward_backup.clone(),
            expected_steward_backup_sha256: *expected_steward_backup_sha256,
            plan: source_plan.clone(),
            expected_plan_digest: *expected_plan_digest,
        };
        let report = cmfd_node::mainnet_custody::replace_community_with_distinct_passwords(
            &paths.runtime_paths(),
            &source,
            &steward,
            &community,
        )?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    #[cfg(feature = "production-v4")]
    if let Command::MainnetCustodyPrepare {
        pow_limit,
        initial_target,
        paths,
    } = &cli.command
    {
        let distinct_passwords = paths.read_distinct_stdin_passwords()?;
        let report = match distinct_passwords.as_ref() {
            Some([steward, community]) => {
                cmfd_node::mainnet_custody::prepare_reward_custody_with_distinct_passwords(
                    &paths.runtime_paths(),
                    *pow_limit,
                    *initial_target,
                    steward,
                    community,
                )?
            }
            None => cmfd_node::mainnet_custody::prepare_reward_custody(
                &paths.runtime_paths(),
                *pow_limit,
                *initial_target,
            )?,
        };
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    #[cfg(feature = "production-v4")]
    if let Command::MainnetCustodyVerify {
        expected_plan_digest,
        paths,
    } = &cli.command
    {
        let distinct_passwords = paths.read_distinct_stdin_passwords()?;
        let report = match distinct_passwords.as_ref() {
            Some([steward, community]) => {
                cmfd_node::mainnet_custody::verify_reward_custody_with_distinct_passwords(
                    &paths.runtime_paths(),
                    *expected_plan_digest,
                    steward,
                    community,
                )?
            }
            None => cmfd_node::mainnet_custody::verify_reward_custody(
                &paths.runtime_paths(),
                *expected_plan_digest,
            )?,
        };
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    #[cfg(feature = "production-v4")]
    if let Command::MainnetPlan {
        output,
        pow_limit,
        initial_target,
        steward_reward_destination,
        community_reward_destination,
    } = &cli.command
    {
        let plan = MainnetLaunchPlan::from_release_artifacts(
            *pow_limit,
            *initial_target,
            cmfd_consensus::FixedRewardDestinations {
                steward: *steward_reward_destination,
                community: *community_reward_destination,
            },
        )?;
        write_mainnet_plan_create_new(output, &plan)?;
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "schema": "CMFD_MAINNET_PLAN_WRITTEN_V2",
                "launch_plan_digest": hex::encode(plan.digest()?),
                "network_id": hex::encode(plan.network_id()?),
                "mainnet_activation_authorized": false
            }))?
        );
        return Ok(());
    }
    #[cfg(feature = "production-v4")]
    if let Command::RcnetCandidate {
        model_bank,
        fixed_record,
        output,
        virtual_genesis_timestamp,
        pow_limit,
        steward_reward_destination,
        community_reward_destination,
    } = &cli.command
    {
        let candidate = RcnetLaunchCandidate::from_artifact_paths(
            model_bank,
            fixed_record,
            RcnetLaunchConfiguration {
                virtual_genesis_timestamp: *virtual_genesis_timestamp,
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
    #[cfg(feature = "production-v4-testnet")]
    if let Command::RcnetWalletCreate {
        candidate,
        backup_output,
        passphrase_file,
    } = &cli.command
    {
        if !backup_output.is_absolute() {
            return Err("--backup-output must be absolute".into());
        }
        let passphrase =
            load_authenticated_rcnet_wallet_passphrase(&cli.data_dir, candidate, passphrase_file)?;
        let info = create_encrypted_wallet(
            &cli.data_dir,
            backup_output,
            RCNET1_PROFILE.network_id,
            passphrase.as_slice(),
        )?;
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "status": "created",
                "format": "CommonFoundry encrypted RCNet-1 wallet v1",
                "network": RCNET1_PROFILE.short_name(),
                "network_id": hex::encode(info.network_id),
                "destination": hex::encode(info.destination),
                "bytes": info.bytes,
                "wallet_data_dir": cli.data_dir,
                "backup": backup_output,
            }))?
        );
        return Ok(());
    }
    #[cfg(feature = "production-v4-testnet")]
    if let Command::RcnetWalletRestore {
        candidate,
        input,
        passphrase_file,
    } = &cli.command
    {
        if !input.is_absolute() {
            return Err("--input must be absolute".into());
        }
        let passphrase =
            load_authenticated_rcnet_wallet_passphrase(&cli.data_dir, candidate, passphrase_file)?;
        let info = restore_encrypted_wallet_backup(
            input,
            &cli.data_dir,
            RCNET1_PROFILE.network_id,
            passphrase.as_slice(),
        )?;
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "status": "restored",
                "format": "CommonFoundry encrypted RCNet-1 wallet v1",
                "network": RCNET1_PROFILE.short_name(),
                "network_id": hex::encode(info.network_id),
                "destination": hex::encode(info.destination),
                "bytes": info.bytes,
                "wallet_data_dir": cli.data_dir,
                "backup": input,
            }))?
        );
        return Ok(());
    }
    if let Command::WalletBackup {
        output,
        passphrase_file,
    } = &cli.command
    {
        let passphrase = read_wallet_passphrase_file(passphrase_file)?;
        let info = create_encrypted_wallet_backup(
            &cli.data_dir,
            output,
            COMPILED_NETWORK_PROFILE.network_id,
            passphrase.as_slice(),
        )?;
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "status": "created",
                "format": "CommonFoundry encrypted wallet backup v1",
                "network": COMPILED_NETWORK_PROFILE.short_name(),
                "network_id": hex::encode(info.network_id),
                "destination": hex::encode(info.destination),
                "bytes": info.bytes,
            }))?
        );
        return Ok(());
    }
    if let Command::WalletRestore {
        input,
        passphrase_file,
    } = &cli.command
    {
        let passphrase = read_wallet_passphrase_file(passphrase_file)?;
        let info = restore_encrypted_wallet_backup(
            input,
            &cli.data_dir,
            COMPILED_NETWORK_PROFILE.network_id,
            passphrase.as_slice(),
        )?;
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "status": "restored",
                "format": "CommonFoundry encrypted wallet backup v1",
                "network": COMPILED_NETWORK_PROFILE.short_name(),
                "network_id": hex::encode(info.network_id),
                "destination": hex::encode(info.destination),
                "bytes": info.bytes,
            }))?
        );
        return Ok(());
    }
    if matches!(&cli.command, Command::StorageInspect) {
        let inspection = inspect_block_log(&cli.data_dir, COMPILED_NETWORK_PROFILE)?;
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "status": if inspection.is_healthy() {
                    "healthy"
                } else {
                    "recoverable_partial_tail"
                },
                "inspection": inspection,
            }))?
        );
        return Ok(());
    }
    if let Command::StorageRepairTail { quarantine_output } = &cli.command {
        let repaired = repair_partial_block_log_tail(
            &cli.data_dir,
            COMPILED_NETWORK_PROFILE,
            quarantine_output,
        )?;
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "status": if repaired.is_some() { "repaired" } else { "no_repair_needed" },
                "repair": repaired,
            }))?
        );
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
    let exchange_custody_v3 = exchange_custody_v3_config(&cli)?;
    let wallet_requires_v3_security = exchange_custody_v3.is_some()
        || persisted_exchange_custody_v3_wallet_security_required(&cli.data_dir);
    let wallet_passphrase = load_runtime_wallet_passphrase(
        &cli.data_dir,
        cli.wallet_passphrase_file.as_deref(),
        wallet_requires_v3_security,
    )?;
    let exchange_withdrawal_security = if exchange_custody_v3.is_some() {
        None
    } else {
        match (
            cli.exchange_withdrawal_journal_key_file.as_ref(),
            cli.exchange_withdrawal_anchor_file.as_ref(),
        ) {
            (Some(journal_key_file), Some(anchor_file)) => Some(
                ExchangeWithdrawalSecurityConfig::new(journal_key_file, anchor_file),
            ),
            (None, None) => None,
            _ => unreachable!("clap requires both exchange withdrawal security files"),
        }
    };
    let _log_guard = cmfd_node::logging::init_tracing(&cli.data_dir, cli.verbose);
    match cli.command {
        Command::NetworkInfo => unreachable!("network-info exits before node initialization"),
        #[cfg(feature = "production-v4")]
        Command::MainnetLaunchInfo => {
            unreachable!("mainnet-launch-info exits before node initialization")
        }
        #[cfg(feature = "production-v4")]
        Command::MainnetPlan { .. }
        | Command::MainnetCustodyPrepare { .. }
        | Command::MainnetCustodyReplaceCommunity { .. }
        | Command::MainnetCustodyVerify { .. } => {
            unreachable!("mainnet plan generation exits before node initialization")
        }
        #[cfg(feature = "production-v4")]
        Command::RcnetCandidate { .. } => {
            unreachable!("RCNet candidate generation exits before node initialization")
        }
        #[cfg(feature = "production-v4-testnet")]
        Command::RcnetWalletCreate { .. } | Command::RcnetWalletRestore { .. } => {
            unreachable!("RCNet wallet maintenance exits before node initialization")
        }
        Command::ExchangeWithdrawalKeygen { .. } => {
            unreachable!("withdrawal journal key generation exits before node initialization")
        }
        Command::ExchangeKeyNew { .. }
        | Command::ExchangeKeyShow { .. }
        | Command::ExchangeWallet { .. }
        | Command::ExchangeTxSign { .. } => {
            unreachable!("exchange key and withdrawal tools exit before node initialization")
        }
        Command::ExchangeV3AclQualify { .. } | Command::ExchangeV3AclFixtureQualify { .. } => {
            unreachable!("ACL qualification exits before node initialization")
        }
        Command::ExchangeKeyringImportPlan { .. }
        | Command::ExchangeKeyringImportApply { .. }
        | Command::ExchangeKeyringExternalTransitionPlan { .. }
        | Command::ExchangeKeyringExternalTransitionApply { .. }
        | Command::ExchangeV3ArchivePlan { .. }
        | Command::ExchangeV3ArchiveApply { .. }
        | Command::ExchangeV3ArchiveVerify { .. } => {
            unreachable!("offline exchange custody command exits before node initialization")
        }
        Command::ExchangeKeyringExternalFinalizationPlan {
            policy_file,
            source_keyring_file,
            source_anchor_file,
            source_keyring_passphrase_file,
            legacy_public_key,
            decommission_evidence_file,
            rotation_decision_id,
            approval_digest,
            keyring_output,
            keyring_anchor_output,
            journal_anchor_output,
            plan_output,
        } => {
            let mut node = open_node(
                &cli.data_dir,
                production_v3_record.as_ref(),
                production_v4_artifacts.as_ref(),
                verifier_worker.as_ref(),
                wallet_passphrase.as_ref().map(|value| value.as_slice()),
                None,
            )?;
            let report = plan_external_keyring_finalization(
                &mut node,
                &ExternalKeyringFinalizationPlanConfig {
                    data_dir: cli.data_dir.clone(),
                    controls: V3OfflineControlConfig {
                        data_dir: cli.data_dir.clone(),
                        journal_key_file: cli
                            .exchange_withdrawal_journal_key_file
                            .clone()
                            .expect("validated finalization journal key"),
                        external_anchor_file: cli
                            .exchange_withdrawal_anchor_file
                            .clone()
                            .expect("validated finalization external anchor"),
                        policy_file,
                        keyring_file: source_keyring_file,
                        keyring_anchor_file: source_anchor_file,
                        keyring_passphrase_file: source_keyring_passphrase_file,
                    },
                    legacy_public_key,
                    decommission_evidence_file,
                    rotation_decision_id,
                    approval_digest,
                    keyring_output,
                    keyring_anchor_output,
                    journal_anchor_output,
                    plan_output,
                },
            )?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        Command::ExchangeKeyringExternalFinalizationApply {
            plan_file,
            confirmation_digest,
        } => {
            let mut node = open_node(
                &cli.data_dir,
                production_v3_record.as_ref(),
                production_v4_artifacts.as_ref(),
                verifier_worker.as_ref(),
                wallet_passphrase.as_ref().map(|value| value.as_slice()),
                None,
            )?;
            let report = apply_external_keyring_finalization(
                &mut node,
                &ExternalKeyringFinalizationApplyConfig {
                    data_dir: cli.data_dir.clone(),
                    journal_key_file: cli
                        .exchange_withdrawal_journal_key_file
                        .clone()
                        .expect("validated finalization journal key"),
                    external_anchor_file: cli
                        .exchange_withdrawal_anchor_file
                        .clone()
                        .expect("validated finalization external anchor"),
                    plan_file,
                    expected_confirmation_digest: confirmation_digest,
                },
            )?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        Command::ExchangeV3MigrationApprovalPayload {
            policy_file,
            keyring_file,
            keyring_anchor_file,
            keyring_passphrase_file,
            request_id,
            decision_id,
            authorized_at_unix_seconds,
            expires_at_unix_seconds,
            output,
        } => {
            let node = open_node(
                &cli.data_dir,
                production_v3_record.as_ref(),
                production_v4_artifacts.as_ref(),
                verifier_worker.as_ref(),
                wallet_passphrase.as_ref().map(|value| value.as_slice()),
                exchange_withdrawal_security.as_ref(),
            )?;
            let report = write_v3_migration_approval_payload(
                &node,
                &V3MigrationApprovalPayloadConfig {
                    data_dir: cli.data_dir.clone(),
                    policy_file,
                    keyring_file,
                    keyring_anchor_file,
                    keyring_passphrase_file,
                    request_id,
                    decision_id,
                    authorized_at_unix_seconds,
                    expires_at_unix_seconds,
                    output,
                },
            )?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        Command::ExchangeV3MigrationPlan {
            evidence_file,
            policy_file,
            keyring_file,
            keyring_anchor_file,
            keyring_passphrase_file,
            validated_snapshot_output,
            v3_anchor_output,
            plan_output,
        } => {
            let node = open_node(
                &cli.data_dir,
                production_v3_record.as_ref(),
                production_v4_artifacts.as_ref(),
                verifier_worker.as_ref(),
                wallet_passphrase.as_ref().map(|value| value.as_slice()),
                exchange_withdrawal_security.as_ref(),
            )?;
            let journal_key_file = cli
                .exchange_withdrawal_journal_key_file
                .clone()
                .expect("validated migration journal key");
            let report = plan_v3_migration(
                &node,
                &V3MigrationPlanConfig {
                    data_dir: cli.data_dir.clone(),
                    journal_key_file,
                    evidence_file,
                    policy_file,
                    keyring_file,
                    keyring_anchor_file,
                    keyring_passphrase_file,
                    validated_snapshot_output,
                    v3_anchor_output,
                    plan_output,
                },
            )?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        Command::ExchangeV3MigrationApply {
            plan_file,
            confirmation_plan_digest,
        } => {
            let node = open_node(
                &cli.data_dir,
                production_v3_record.as_ref(),
                production_v4_artifacts.as_ref(),
                verifier_worker.as_ref(),
                wallet_passphrase.as_ref().map(|value| value.as_slice()),
                exchange_withdrawal_security.as_ref(),
            )?;
            let report = apply_v3_migration(
                node,
                &V3MigrationApplyConfig {
                    data_dir: cli.data_dir.clone(),
                    plan_file,
                    expected_plan_digest: confirmation_plan_digest,
                },
            )?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        Command::Run {
            bind,
            exchange_rpc_bind,
            exchange_rpc_auth_file,
            exchange_rpc_withdrawal_auth_file,
            exchange_custody_v3_policy_file: _,
            exchange_custody_v3_keyring_file: _,
            exchange_custody_v3_keyring_anchor_file: _,
            exchange_custody_v3_keyring_passphrase_file: _,
            p2p_bind,
            peers,
            no_default_seeds,
            allow_public_peers,
            prune_keep_blocks,
        } => {
            let shutdown = install_shutdown_handler()?;
            let (peers, allow_public_peers) =
                effective_operational_peers(peers, allow_public_peers, no_default_seeds)?;
            let address_policy = peer_address_policy(allow_public_peers);
            let mut node = open_node(
                &cli.data_dir,
                production_v3_record.as_ref(),
                production_v4_artifacts.as_ref(),
                verifier_worker.as_ref(),
                wallet_passphrase.as_ref().map(|value| value.as_slice()),
                exchange_withdrawal_security.as_ref(),
            )?;
            node.set_public_peer_mode(allow_public_peers);
            node.configure_pruning(prune_keep_blocks)?;
            if prune_keep_blocks.is_some()
                && let Some(report) = node.prune_block_log()?
            {
                eprintln!("{}", serde_json::to_string(&prune_report_json(&report))?);
            }
            let discovery_hello = node.peer_hello();
            let shared = Arc::new(Mutex::new(node));
            // The startup prune above already ran; the next check is one
            // interval later.
            let pruner = prune_keep_blocks
                .map(|_| {
                    cmfd_node::spawn_pruner(Arc::clone(&shared), cmfd_node::PRUNE_CHECK_INTERVAL)
                })
                .transpose()?;
            let history_scrub = cmfd_node::spawn_history_scrub(Arc::clone(&shared))?;
            let exchange_withdrawals_enabled = exchange_rpc_withdrawal_auth_file.is_some();
            let exchange_custody_v3_active = exchange_custody_v3.is_some();
            let exchange_rpc = match (exchange_rpc_bind, exchange_rpc_auth_file) {
                (Some(exchange_bind), Some(authentication_file)) => {
                    if let Some((custody_config, keyring_passphrase_file)) = exchange_custody_v3 {
                        Some(spawn_exchange_rpc_server_v3(
                            Arc::clone(&shared),
                            exchange_bind,
                            &authentication_file,
                            exchange_rpc_withdrawal_auth_file
                                .as_deref()
                                .expect("validated v3 withdrawal credential"),
                            &custody_config,
                            &keyring_passphrase_file,
                        )?)
                    } else {
                        Some(spawn_exchange_rpc_server(
                            Arc::clone(&shared),
                            exchange_bind,
                            &authentication_file,
                            exchange_rpc_withdrawal_auth_file.as_deref(),
                        )?)
                    }
                }
                (None, None) => None,
                _ => unreachable!("clap requires both exchange RPC options"),
            };
            let status = shared
                .lock()
                .map_err(|_| cmfd_node::NodeError::SharedNodePoisoned)?
                .status()?;
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
            let mut startup = json!({
                "rpc": rpc_address.to_string(),
                "exchange_rpc": exchange_rpc.as_ref().map(|rpc| rpc.local_addr().to_string()),
                "exchange_rpc_api": exchange_rpc.as_ref().map(|_| if exchange_custody_v3_active {
                    EXCHANGE_CUSTODY_RPC_API_VERSION
                } else {
                    EXCHANGE_RPC_API_VERSION
                }),
                "exchange_rpc_withdrawals": exchange_rpc.as_ref().map(|_| exchange_withdrawals_enabled),
                "p2p": p2p_address.to_string(),
                "static_peers": peers.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "status": status,
                "public_peer_mode": allow_public_peers,
                "warning": peer_warning(allow_public_peers)
            });
            if exchange_custody_v3_active {
                startup
                    .as_object_mut()
                    .expect("startup document is an object")
                    .insert("exchange_rpc_custody".to_owned(), json!("v3"));
            }
            println!("{}", serde_json::to_string_pretty(&startup)?);
            let service_exit = shutdown.wait_for_service_exit(|| {
                if rpc.is_finished() {
                    Some("RPC")
                } else if exchange_rpc.as_ref().is_some_and(|rpc| rpc.is_finished()) {
                    Some("exchange RPC")
                } else if inbound.is_finished() {
                    Some("inbound P2P")
                } else if poller.as_ref().is_some_and(|poller| poller.is_finished()) {
                    Some("static-peer polling")
                } else {
                    None
                }
            })?;
            if let Ok(node) = shared.lock() {
                if let Err(error) = node.persist_startup_snapshot() {
                    eprintln!("startup checkpoint not written: {error}");
                }
                if let Err(error) = node.persist_index_cache() {
                    eprintln!("startup index cache not written: {error}");
                }
                node.shutdown_proof_verifier();
            }
            let exchange_rpc_result = match exchange_rpc {
                Some(exchange_rpc) => exchange_rpc.stop(),
                None => Ok(()),
            };
            let rpc_result = rpc.stop();
            let poll_result = match poller {
                Some(poller) => poller.stop(),
                None => Ok(()),
            };
            let inbound_result = inbound.stop();
            if let Some(pruner) = pruner {
                pruner.stop();
            }
            history_scrub.stop();
            drop(shared);
            exchange_rpc_result?;
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
                wallet_passphrase.as_ref().map(|value| value.as_slice()),
                exchange_withdrawal_security.as_ref(),
            )?;
            let miner_destination = match miner.as_deref() {
                Some(value) => parse_miner_destination(value)?,
                None => node.wallet_destination(),
            };
            let block = node.mine_once(miner_destination, unix_time_seconds()?, attempts)?;
            node.persist_startup_snapshot()?;
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
                wallet_passphrase.as_ref().map(|value| value.as_slice()),
                exchange_withdrawal_security.as_ref(),
            )?;
            println!("{}", serde_json::to_string_pretty(&node.status()?)?);
            Ok(())
        }
        Command::PoolPayoutStatus {
            pool_payout_fee_atoms,
            pool_ledger_max_bytes,
        } => {
            let mut node = open_node(
                &cli.data_dir,
                production_v3_record.as_ref(),
                production_v4_artifacts.as_ref(),
                verifier_worker.as_ref(),
                wallet_passphrase.as_ref().map(|value| value.as_slice()),
                exchange_withdrawal_security.as_ref(),
            )?;
            let report = inspect_pool_payout_protection_with_limit(
                &mut node,
                pool_payout_fee_atoms,
                pool_ledger_max_bytes,
            )?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        Command::PoolPayoutReconcile {
            pool_payout_fee_atoms,
            pool_ledger_max_bytes,
            expected_tip,
            expected_ledger_generation,
            note,
            acknowledge_reconciliation,
        } => {
            if !acknowledge_reconciliation {
                return Err("payout reconciliation must be acknowledged".into());
            }
            let mut node = open_node(
                &cli.data_dir,
                production_v3_record.as_ref(),
                production_v4_artifacts.as_ref(),
                verifier_worker.as_ref(),
                wallet_passphrase.as_ref().map(|value| value.as_slice()),
                exchange_withdrawal_security.as_ref(),
            )?;
            let report = reconcile_pool_payout_protection_with_limit(
                &mut node,
                PoolPayoutReconciliationRequest {
                    expected_tip,
                    expected_ledger_generation,
                    fee_atoms: pool_payout_fee_atoms,
                    operator_note: note,
                },
                pool_ledger_max_bytes,
            )?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        Command::StorageCheckpoint => {
            let node = open_node(
                &cli.data_dir,
                production_v3_record.as_ref(),
                production_v4_artifacts.as_ref(),
                verifier_worker.as_ref(),
                wallet_passphrase.as_ref().map(|value| value.as_slice()),
                exchange_withdrawal_security.as_ref(),
            )?;
            node.persist_startup_snapshot()?;
            node.persist_index_cache()?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "status": "checkpoint_written",
                    "network": COMPILED_NETWORK_PROFILE.short_name(),
                    "node": node.status()?,
                }))?
            );
            Ok(())
        }
        Command::WalletBackup { .. }
        | Command::WalletRestore { .. }
        | Command::StorageInspect
        | Command::StorageRepairTail { .. } => {
            unreachable!("offline maintenance commands exit before node initialization")
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
            no_default_seeds,
            allow_public_peers,
            allow_public_pool_clients,
            allow_address_only_payouts,
            certificate,
            private_key,
            miner,
            share_leading_zero_bits,
            production_v4_pool_replay_worker,
            production_v4_pool_proof_worker,
            production_v4_pool_scratch,
            production_v4_pool_wsl_distribution,
            enable_testnet_payouts,
            enable_mainnet_payouts,
            pool_minimum_payout_atoms,
            pool_payout_fee_atoms,
            pool_operator_fee_bps,
            pool_pplns_window_shares,
            pool_max_connections_per_source,
            pool_max_concurrent_share_verifications,
            pool_max_queued_share_verifications,
            pool_ledger_max_bytes,
            pool_dashboard_assets,
            pool_public_url,
            pool_dashboard_bind,
            shutdown_request_file,
            prune_keep_blocks,
        } => {
            require_pool_mining_profile()?;
            let automatic_payouts = pool_payouts_enabled(
                enable_testnet_payouts,
                enable_mainnet_payouts,
                cfg!(feature = "production-mainnet"),
            )?;
            let (peers, allow_public_peers) =
                effective_operational_peers(peers, allow_public_peers, no_default_seeds)?;
            let shutdown =
                install_shutdown_handler()?.with_request_file(shutdown_request_file.as_deref())?;
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
                wallet_passphrase.as_ref().map(|value| value.as_slice()),
                exchange_withdrawal_security.as_ref(),
            )?;
            node_instance.set_public_peer_mode(allow_public_peers);
            node_instance.configure_pruning(prune_keep_blocks)?;
            if prune_keep_blocks.is_some()
                && let Some(report) = node_instance.prune_block_log()?
            {
                eprintln!("{}", serde_json::to_string(&prune_report_json(&report))?);
            }
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
            // The startup prune above already ran; the next check is one
            // interval later.
            let pruner = prune_keep_blocks
                .map(|_| {
                    cmfd_node::spawn_pruner(Arc::clone(&node), cmfd_node::PRUNE_CHECK_INTERVAL)
                })
                .transpose()?;
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
            config.ledger_max_bytes = pool_ledger_max_bytes;
            config.allow_public_clients = allow_public_pool_clients;
            config.allow_address_only_payouts = allow_address_only_payouts;
            config.pplns_policy = Some(PoolPplnsPolicy {
                operator_fee_bps: pool_operator_fee_bps,
                window_shares: pool_pplns_window_shares,
            });
            if automatic_payouts {
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
                    "automatic_payouts": automatic_payouts,
                    "automatic_testnet_payouts": enable_testnet_payouts,
                    "address_only_payouts": allow_address_only_payouts,
                    "minimum_payout_atoms": pool_minimum_payout_atoms,
                    "payout_fee_atoms": pool_payout_fee_atoms,
                    "operator_fee_bps": pool_operator_fee_bps,
                    "pplns_window_shares": if pool_pplns_window_shares == 0 { json!("automatic") } else { json!(pool_pplns_window_shares) },
                    "max_connections_per_source": pool_max_connections_per_source,
                    "max_concurrent_share_verifications": pool_max_concurrent_share_verifications,
                    "max_queued_share_verifications": pool_max_queued_share_verifications,
                    "ledger_max_bytes": pool_ledger_max_bytes,
                    "dashboard": dashboard.as_ref().map(|dashboard| format!("http://{}", dashboard.local_addr())),
                    "used_insecure_default_miner": used_insecure_default_miner,
                    "public_peer_mode": allow_public_peers,
                    "p2p_warning": peer_warning(allow_public_peers),
                    "prune_keep_blocks": prune_keep_blocks,
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
                if let Err(error) = node.persist_startup_snapshot() {
                    eprintln!("startup checkpoint not written: {error}");
                }
                if let Err(error) = node.persist_index_cache() {
                    eprintln!("startup index cache not written: {error}");
                }
                node.shutdown_proof_verifier();
            }
            let pool_result = pool.stop();
            let poll_result = match poller {
                Some(poller) => poller.stop(),
                None => Ok(()),
            };
            let inbound_result = inbound.stop();
            if let Some(pruner) = pruner {
                pruner.stop();
            }
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
    request_file: Option<PathBuf>,
}

impl ShutdownSignal {
    fn with_request_file(mut self, path: Option<&Path>) -> io::Result<Self> {
        let Some(path) = path else {
            return Ok(self);
        };
        if !path.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "shutdown request file must be absolute",
            ));
        }
        let parent = path.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "shutdown request file has no parent directory",
            )
        })?;
        if !parent.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "shutdown request parent directory is missing",
            ));
        }
        match std::fs::symlink_metadata(path) {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "shutdown request file already exists",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        self.request_file = Some(path.to_path_buf());
        Ok(self)
    }

    fn request_file_exists(&self) -> io::Result<bool> {
        let Some(path) = self.request_file.as_deref() else {
            return Ok(false);
        };
        let metadata = match std::fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        };
        if !metadata.file_type().is_file()
            || metadata.len() != POOL_SHUTDOWN_REQUEST_BYTES.len() as u64
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "shutdown request file is malformed",
            ));
        }
        let mut bytes = Vec::with_capacity(POOL_SHUTDOWN_REQUEST_BYTES.len());
        std::fs::File::open(path)?
            .take(POOL_SHUTDOWN_REQUEST_BYTES.len() as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes != POOL_SHUTDOWN_REQUEST_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "shutdown request file is malformed",
            ));
        }
        Ok(true)
    }

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
            if self.request_file_exists()? {
                return Ok(None);
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

fn prune_report_json(report: &cmfd_node::PruneReport) -> serde_json::Value {
    json!({
        "pruned_below_height": report.anchor_height,
        "newly_pruned_blocks": report.newly_pruned_blocks,
        "dropped_side_blocks": report.dropped_side_blocks,
        "log_bytes_before": report.log_bytes_before,
        "log_bytes_after": report.log_bytes_after,
    })
}

fn install_shutdown_handler() -> Result<ShutdownSignal, ctrlc::Error> {
    // A capacity of one coalesces repeated console events while the main
    // thread is stopping and joining services. The handler performs no I/O or
    // cleanup; it only signals the normal control flow below.
    let (sender, receiver) = sync_channel(1);
    ctrlc::set_handler(move || {
        let _ = sender.try_send(());
    })?;
    Ok(ShutdownSignal {
        receiver,
        request_file: None,
    })
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

    #[cfg(feature = "production-v4")]
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
                    environment: vec![],
                },
                ProductionV4PoolWorkerCommand {
                    program: proof_worker,
                    arguments: production_v4_proof_worker_server_arguments(
                        artifacts.bank.as_os_str(),
                        fixed_artifact_directory.as_os_str(),
                    ),
                    environment: vec![],
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
    #[cfg(not(feature = "production-v4"))]
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

#[cfg(feature = "production-v4")]
fn production_v4_proof_worker_server_arguments(
    model_bank: &OsStr,
    fixed_artifact_directory: &OsStr,
) -> Vec<OsString> {
    vec![
        "--server".into(),
        hex::encode(COMPILED_NETWORK_PROFILE.network_id).into(),
        model_bank.to_owned(),
        fixed_artifact_directory.to_owned(),
    ]
}

#[cfg(feature = "production-v4")]
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
        Err("ProductionV4 pool WSL workers require Windows".into())
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
        let selected_device =
            cmfd_node::production_v4_pool::production_v4_worker_cuda_visible_device(None)?;
        let environment = [
            format!("CUDA_VISIBLE_DEVICES={selected_device}"),
            "CUDA_HOME=/usr/local/cuda-12.8".to_owned(),
            "CUDA_PATH=/usr/local/cuda-12.8".to_owned(),
            "CUDAToolkit_ROOT=/usr/local/cuda-12.8".to_owned(),
            "LD_LIBRARY_PATH=/usr/local/cuda-12.8/lib64".to_owned(),
        ];
        let worker_command = |program: String, mut arguments: Vec<std::ffi::OsString>| {
            let mut prefix = vec![
                "-d".into(),
                distribution.into(),
                "--exec".into(),
                "env".into(),
            ];
            prefix.extend(environment.iter().cloned().map(Into::into));
            prefix.push(program.into());
            prefix.append(&mut arguments);
            ProductionV4PoolWorkerCommand {
                program: wsl.clone(),
                arguments: prefix,
                environment: vec![],
            }
        };
        Ok((
            worker_command(
                replay_worker,
                vec!["--server".into(), model_bank.clone().into()],
            ),
            worker_command(
                proof_worker,
                production_v4_proof_worker_server_arguments(
                    OsStr::new(&model_bank),
                    OsStr::new(&fixed_artifact_directory),
                ),
            ),
            worker_scratch_directory,
        ))
    }
}

#[cfg(all(feature = "production-v4", windows))]
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
    wallet_passphrase: Option<&[u8]>,
    exchange_withdrawal_security: Option<&ExchangeWithdrawalSecurityConfig>,
) -> Result<Node, Box<dyn std::error::Error>> {
    Ok(
        Node::open_with_runtime_security_wallet_and_exchange_withdrawal(
            data_dir,
            production_v3_record,
            production_v4_artifacts,
            verifier_worker,
            wallet_passphrase,
            exchange_withdrawal_security,
        )?,
    )
}

fn create_exchange_withdrawal_journal_key(output: &Path) -> Result<(), Box<dyn std::error::Error>> {
    create_exchange_journal_key_create_new(output)?;
    Ok(())
}

fn validate_exchange_withdrawal_cli(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    let archive_verify = matches!(&cli.command, Command::ExchangeV3ArchiveVerify { .. });
    if archive_verify {
        if cli.exchange_withdrawal_journal_key_file.is_none() {
            return Err(
                "archive verification requires --exchange-withdrawal-journal-key-file".into(),
            );
        }
    } else if cli.exchange_withdrawal_journal_key_file.is_some()
        != cli.exchange_withdrawal_anchor_file.is_some()
    {
        return Err("--exchange-withdrawal-journal-key-file and \
            --exchange-withdrawal-anchor-file must be supplied together"
            .into());
    }
    if let Command::Run {
        exchange_rpc_bind,
        exchange_rpc_auth_file,
        exchange_rpc_withdrawal_auth_file,
        exchange_custody_v3_policy_file,
        exchange_custody_v3_keyring_file,
        exchange_custody_v3_keyring_anchor_file,
        exchange_custody_v3_keyring_passphrase_file,
        ..
    } = &cli.command
    {
        let v3_inputs = [
            exchange_custody_v3_policy_file.is_some(),
            exchange_custody_v3_keyring_file.is_some(),
            exchange_custody_v3_keyring_anchor_file.is_some(),
            exchange_custody_v3_keyring_passphrase_file.is_some(),
        ];
        let any_v3_input = v3_inputs.iter().any(|present| *present);
        let all_v3_inputs = v3_inputs.iter().all(|present| *present);
        if any_v3_input && !all_v3_inputs {
            return Err("v3 exchange custody activation requires all of \
                --exchange-custody-v3-policy-file, --exchange-custody-v3-keyring-file, \
                --exchange-custody-v3-keyring-anchor-file, and \
                --exchange-custody-v3-keyring-passphrase-file"
                .into());
        }
        if all_v3_inputs
            && (exchange_rpc_bind.is_none()
                || exchange_rpc_auth_file.is_none()
                || exchange_rpc_withdrawal_auth_file.is_none()
                || cli.exchange_withdrawal_journal_key_file.is_none()
                || cli.exchange_withdrawal_anchor_file.is_none())
        {
            return Err(
                "v3 exchange custody activation requires --exchange-rpc-bind, \
                --exchange-rpc-auth-file, --exchange-rpc-withdrawal-auth-file, \
                --exchange-withdrawal-journal-key-file, and \
                --exchange-withdrawal-anchor-file"
                    .into(),
            );
        }
    }
    if matches!(
        &cli.command,
        Command::Run {
            exchange_rpc_withdrawal_auth_file: Some(_),
            ..
        }
    ) && (cli.exchange_withdrawal_journal_key_file.is_none()
        || cli.exchange_withdrawal_anchor_file.is_none())
    {
        return Err("--exchange-rpc-withdrawal-auth-file requires both \
            --exchange-withdrawal-journal-key-file and --exchange-withdrawal-anchor-file"
            .into());
    }
    if matches!(
        &cli.command,
        Command::ExchangeV3MigrationApprovalPayload { .. }
            | Command::ExchangeV3MigrationPlan { .. }
            | Command::ExchangeV3MigrationApply { .. }
            | Command::ExchangeKeyringExternalFinalizationPlan { .. }
            | Command::ExchangeKeyringExternalFinalizationApply { .. }
            | Command::ExchangeV3ArchivePlan { .. }
            | Command::ExchangeV3ArchiveApply { .. }
    ) && (cli.exchange_withdrawal_journal_key_file.is_none()
        || cli.exchange_withdrawal_anchor_file.is_none())
    {
        return Err("v3 exchange custody tools require both \
            --exchange-withdrawal-journal-key-file and --exchange-withdrawal-anchor-file"
            .into());
    }
    Ok(())
}

fn exchange_custody_v3_config(
    cli: &Cli,
) -> Result<Option<(ExchangeCustodyV3Config, PathBuf)>, Box<dyn std::error::Error>> {
    let Command::Run {
        exchange_custody_v3_policy_file,
        exchange_custody_v3_keyring_file,
        exchange_custody_v3_keyring_anchor_file,
        exchange_custody_v3_keyring_passphrase_file,
        ..
    } = &cli.command
    else {
        return Ok(None);
    };
    match (
        exchange_custody_v3_policy_file,
        exchange_custody_v3_keyring_file,
        exchange_custody_v3_keyring_anchor_file,
        exchange_custody_v3_keyring_passphrase_file,
    ) {
        (Some(policy), Some(keyring), Some(keyring_anchor), Some(passphrase)) => {
            let (journal_key, external_anchor) = required_exchange_withdrawal_security(cli)?;
            let passphrase = canonical_external_v3_passphrase_file(&cli.data_dir, passphrase)?;
            Ok(Some((
                ExchangeCustodyV3Config::new(
                    journal_key,
                    external_anchor,
                    policy,
                    keyring,
                    keyring_anchor,
                ),
                passphrase,
            )))
        }
        (None, None, None, None) => Ok(None),
        _ => Err("incomplete v3 exchange custody activation".into()),
    }
}

fn load_runtime_wallet_passphrase(
    data_dir: &Path,
    passphrase_file: Option<&Path>,
    exchange_custody_v3_enabled: bool,
) -> Result<Option<Zeroizing<Vec<u8>>>, Box<dyn std::error::Error>> {
    match passphrase_file {
        Some(path) if exchange_custody_v3_enabled => Ok(Some(
            load_exchange_custody_v3_wallet_passphrase(data_dir, path)?,
        )),
        Some(path) => Ok(Some(read_wallet_passphrase_file(path)?)),
        None => Ok(None),
    }
}

fn canonical_external_v3_passphrase_file(
    data_dir: &Path,
    passphrase_file: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if !passphrase_file.is_absolute() {
        return Err("--exchange-custody-v3-keyring-passphrase-file must be absolute".into());
    }
    let metadata = std::fs::symlink_metadata(passphrase_file)?;
    #[cfg(windows)]
    let is_reparse_point = {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    };
    #[cfg(not(windows))]
    let is_reparse_point = false;
    if metadata.file_type().is_symlink() || is_reparse_point || !metadata.is_file() {
        return Err(
            "--exchange-custody-v3-keyring-passphrase-file must be a regular non-symlink file"
                .into(),
        );
    }
    let canonical_data_dir = std::fs::canonicalize(data_dir)?;
    let canonical_passphrase_file = std::fs::canonicalize(passphrase_file)?;
    let lexical_data_dir = if data_dir.is_absolute() {
        data_dir.to_path_buf()
    } else {
        std::env::current_dir()?.join(data_dir)
    };
    if passphrase_file.starts_with(&lexical_data_dir)
        || canonical_passphrase_file.starts_with(&canonical_data_dir)
    {
        return Err(
            "--exchange-custody-v3-keyring-passphrase-file must be outside --data-dir".into(),
        );
    }
    Ok(canonical_passphrase_file)
}

fn required_exchange_withdrawal_security(
    cli: &Cli,
) -> Result<(&Path, &Path), Box<dyn std::error::Error>> {
    match (
        cli.exchange_withdrawal_journal_key_file.as_deref(),
        cli.exchange_withdrawal_anchor_file.as_deref(),
    ) {
        (Some(key), Some(anchor)) => Ok((key, anchor)),
        _ => Err("both exchange withdrawal security paths are required".into()),
    }
}

fn v3_offline_controls(
    cli: &Cli,
    policy_file: &Path,
    keyring_file: &Path,
    keyring_anchor_file: &Path,
    keyring_passphrase_file: &Path,
) -> Result<V3OfflineControlConfig, Box<dyn std::error::Error>> {
    let (journal_key_file, external_anchor_file) = required_exchange_withdrawal_security(cli)?;
    Ok(V3OfflineControlConfig {
        data_dir: cli.data_dir.clone(),
        journal_key_file: journal_key_file.to_path_buf(),
        external_anchor_file: external_anchor_file.to_path_buf(),
        policy_file: policy_file.to_path_buf(),
        keyring_file: keyring_file.to_path_buf(),
        keyring_anchor_file: keyring_anchor_file.to_path_buf(),
        keyring_passphrase_file: keyring_passphrase_file.to_path_buf(),
    })
}

fn peer_address_policy(allow_public_peers: bool) -> PeerAddressPolicy {
    if allow_public_peers {
        PeerAddressPolicy::AllowPublic
    } else {
        PeerAddressPolicy::PrivateOnly
    }
}

fn effective_operational_peers(
    peers: Vec<SocketAddr>,
    allow_public_peers: bool,
    no_default_seeds: bool,
) -> Result<(Vec<SocketAddr>, bool), Box<dyn std::error::Error>> {
    effective_operational_peers_for_build(
        peers,
        allow_public_peers,
        no_default_seeds,
        if cfg!(any(
            feature = "production-rc",
            feature = "production-mainnet"
        )) {
            COMPILED_NETWORK_PROFILE.bootstrap_peers()
        } else {
            Vec::new()
        },
    )
}

fn effective_operational_peers_for_build(
    mut peers: Vec<SocketAddr>,
    mut allow_public_peers: bool,
    no_default_seeds: bool,
    default_seeds: Vec<SocketAddr>,
) -> Result<(Vec<SocketAddr>, bool), Box<dyn std::error::Error>> {
    if peers.is_empty() && !no_default_seeds && !default_seeds.is_empty() {
        let endpoints = default_seeds
            .iter()
            .map(|seed| seed.to_string().parse())
            .collect::<Result<Vec<_>, _>>()?;
        peers = SeedSet::new(endpoints)?.resolve(&SystemSeedResolver)?;
        allow_public_peers = true;
    }
    Ok((peers, allow_public_peers))
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

fn pool_payouts_enabled(
    enable_testnet_payouts: bool,
    enable_mainnet_payouts: bool,
    mainnet_build: bool,
) -> Result<bool, Box<dyn std::error::Error>> {
    if mainnet_build {
        if enable_testnet_payouts {
            return Err("--enable-testnet-payouts cannot enable mainnet settlement".into());
        }
        if !enable_mainnet_payouts {
            return Err("mainnet pool-serve requires --enable-mainnet-payouts".into());
        }
    } else if enable_mainnet_payouts {
        return Err("--enable-mainnet-payouts requires a production-mainnet build".into());
    }
    Ok(enable_testnet_payouts || enable_mainnet_payouts)
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

    #[cfg(feature = "production-v4")]
    fn distinct_frame(steward: &[u8], community: &[u8]) -> Vec<u8> {
        let mut frame = DISTINCT_PASSWORD_STDIN_MAGIC.to_vec();
        for password in [steward, community] {
            frame.extend_from_slice(&(password.len() as u16).to_le_bytes());
            frame.extend_from_slice(password);
        }
        frame
    }

    #[cfg(feature = "production-v4")]
    #[test]
    fn separate_password_frame_is_exact_bounded_and_distinct() {
        let steward = b"disposable steward test password";
        let community = b"disposable community test password";
        let frame = distinct_frame(steward, community);
        let parsed = parse_distinct_password_frame(&frame).unwrap();
        assert_eq!(parsed[0].as_slice(), steward);
        assert_eq!(parsed[1].as_slice(), community);
        assert!(parse_distinct_password_frame(&frame[..frame.len() - 1]).is_err());
        let mut trailing = frame.clone();
        trailing.push(0);
        assert!(parse_distinct_password_frame(&trailing).is_err());
        let mut wrong_magic = frame.clone();
        wrong_magic[0] ^= 1;
        assert!(parse_distinct_password_frame(&wrong_magic).is_err());
        assert!(parse_distinct_password_frame(&distinct_frame(steward, steward)).is_err());
        assert!(parse_distinct_password_frame(&distinct_frame(b"short", community)).is_err());
        assert!(
            parse_distinct_password_frame(&distinct_frame(
                &vec![b'x'; MAXIMUM_PASSPHRASE_BYTES + 1],
                community,
            ))
            .is_err()
        );
    }

    #[cfg(feature = "production-v4")]
    #[test]
    fn separate_password_stdin_conflicts_with_file_and_shared_modes() {
        let base = [
            "cmfd-node",
            "mainnet-custody-prepare",
            "--pow-limit",
            "003fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "--initial-target",
            "000ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccb",
            "--wallets-directory",
            "wallets",
            "--backups-directory",
            "backups",
            "--public-directory",
            "public",
        ];
        let mut separate = base.to_vec();
        separate.push("--distinct-passphrases-stdin");
        assert!(Cli::try_parse_from(&separate).is_ok());
        let mut with_file = separate.clone();
        with_file.extend(["--steward-passphrase-file", "steward.txt"]);
        assert!(Cli::try_parse_from(&with_file).is_err());
        let mut with_shared = separate;
        with_shared.push("--shared-passphrase-stdin");
        assert!(Cli::try_parse_from(&with_shared).is_err());
    }

    #[test]
    fn pool_payout_activation_is_explicit_and_network_specific() {
        assert!(!pool_payouts_enabled(false, false, false).unwrap());
        assert!(pool_payouts_enabled(true, false, false).unwrap());
        assert!(pool_payouts_enabled(false, true, true).unwrap());
        assert!(pool_payouts_enabled(false, false, true).is_err());
        assert!(pool_payouts_enabled(true, false, true).is_err());
        assert!(pool_payouts_enabled(false, true, false).is_err());
        assert!(
            Cli::try_parse_from([
                "cmfd-node",
                "pool-serve",
                "--certificate",
                "certificate.der",
                "--private-key",
                "private-key.der",
                "--enable-testnet-payouts",
                "--enable-mainnet-payouts",
            ])
            .is_err()
        );
    }

    #[cfg(feature = "production-v4")]
    #[test]
    fn production_v4_proof_worker_arguments_bind_the_compiled_network() {
        let arguments = production_v4_proof_worker_server_arguments(
            OsStr::new("/srv/commonfoundry/MODEL-V2.bank"),
            OsStr::new("/srv/commonfoundry/fixed"),
        );
        assert_eq!(
            arguments,
            vec![
                OsString::from("--server"),
                OsString::from(hex::encode(COMPILED_NETWORK_PROFILE.network_id)),
                OsString::from("/srv/commonfoundry/MODEL-V2.bank"),
                OsString::from("/srv/commonfoundry/fixed"),
            ]
        );
    }

    #[test]
    fn cli_defaults_follow_the_compile_time_network_profile() {
        let cli = Cli::try_parse_from(["cmfd-node", "run"]).unwrap();
        assert_eq!(cli.data_dir, PathBuf::from(DEFAULT_DATA_DIR));
        assert_eq!(cli.proof_verifier_cpu_quota_us, None);
        assert_eq!(cli.proof_verifier_cpu_period_us, None);
        assert_eq!(cli.proof_verifier_pids_limit, None);
        assert_eq!(cli.wallet_passphrase_file, None);
        assert_eq!(cli.exchange_withdrawal_journal_key_file, None);
        assert_eq!(cli.exchange_withdrawal_anchor_file, None);
        let Command::Run {
            bind,
            exchange_rpc_bind,
            exchange_rpc_auth_file,
            exchange_rpc_withdrawal_auth_file,
            exchange_custody_v3_policy_file,
            exchange_custody_v3_keyring_file,
            exchange_custody_v3_keyring_anchor_file,
            exchange_custody_v3_keyring_passphrase_file,
            p2p_bind,
            ..
        } = cli.command
        else {
            unreachable!()
        };
        assert_eq!(bind, COMPILED_NETWORK_PROFILE.rpc_address());
        assert_eq!(exchange_rpc_bind, None);
        assert_eq!(exchange_rpc_auth_file, None);
        assert_eq!(exchange_rpc_withdrawal_auth_file, None);
        assert_eq!(exchange_custody_v3_policy_file, None);
        assert_eq!(exchange_custody_v3_keyring_file, None);
        assert_eq!(exchange_custody_v3_keyring_anchor_file, None);
        assert_eq!(exchange_custody_v3_keyring_passphrase_file, None);
        assert_eq!(p2p_bind, COMPILED_NETWORK_PROFILE.p2p_address());

        assert!(
            Cli::try_parse_from(["cmfd-node", "run", "--exchange-rpc-bind", "127.0.0.1:38101",])
                .is_err()
        );
        let exchange = Cli::try_parse_from([
            "cmfd-node",
            "run",
            "--exchange-rpc-bind",
            "127.0.0.1:38101",
            "--exchange-rpc-auth-file",
            "exchange-rpc.auth",
        ])
        .unwrap();
        assert!(matches!(
            exchange.command,
            Command::Run {
                exchange_rpc_bind: Some(address),
                exchange_rpc_auth_file: Some(path),
                ..
            } if address == "127.0.0.1:38101".parse().unwrap()
                && path == Path::new("exchange-rpc.auth")
        ));
        assert!(
            Cli::try_parse_from([
                "cmfd-node",
                "run",
                "--exchange-rpc-withdrawal-auth-file",
                "withdrawal.auth",
            ])
            .is_err()
        );
        let missing_withdrawal_security = Cli::try_parse_from([
            "cmfd-node",
            "run",
            "--exchange-rpc-bind",
            "127.0.0.1:38101",
            "--exchange-rpc-auth-file",
            "exchange-rpc.auth",
            "--exchange-rpc-withdrawal-auth-file",
            "withdrawal.auth",
        ])
        .unwrap();
        assert!(validate_exchange_withdrawal_cli(&missing_withdrawal_security).is_err());
        let partial_security = Cli::try_parse_from([
            "cmfd-node",
            "--exchange-withdrawal-journal-key-file",
            "withdrawal-journal.key",
            "run",
        ])
        .unwrap();
        assert!(validate_exchange_withdrawal_cli(&partial_security).is_err());
        let withdrawal = Cli::try_parse_from([
            "cmfd-node",
            "run",
            "--exchange-rpc-bind",
            "127.0.0.1:38101",
            "--exchange-rpc-auth-file",
            "exchange-rpc.auth",
            "--exchange-rpc-withdrawal-auth-file",
            "withdrawal.auth",
            "--exchange-withdrawal-journal-key-file",
            "withdrawal-journal.key",
            "--exchange-withdrawal-anchor-file",
            "withdrawal-anchor.json",
        ])
        .unwrap();
        validate_exchange_withdrawal_cli(&withdrawal).unwrap();
        assert!(matches!(
            withdrawal.command,
            Command::Run {
                exchange_rpc_withdrawal_auth_file: Some(path),
                ..
            } if path == Path::new("withdrawal.auth")
        ));
        assert_eq!(
            withdrawal.exchange_withdrawal_journal_key_file,
            Some(PathBuf::from("withdrawal-journal.key"))
        );
        assert_eq!(
            withdrawal.exchange_withdrawal_anchor_file,
            Some(PathBuf::from("withdrawal-anchor.json"))
        );

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
            pool_operator_fee_bps,
            pool_pplns_window_shares,
            prune_keep_blocks,
            ..
        } = cli.command
        else {
            unreachable!()
        };
        assert_eq!(bind, COMPILED_NETWORK_PROFILE.pool_address());
        assert_eq!(p2p_bind, COMPILED_NETWORK_PROFILE.p2p_address());
        assert_eq!(pool_dashboard_bind, DEFAULT_POOL_DASHBOARD_ADDRESS);
        assert_eq!(pool_operator_fee_bps, 300);
        assert_eq!(pool_pplns_window_shares, 0);
        assert_eq!(prune_keep_blocks, None);

        let cli = Cli::try_parse_from([
            "cmfd-node",
            "pool-serve",
            "--certificate",
            "certificate.der",
            "--private-key",
            "private-key.der",
            "--prune-keep-blocks",
            "720",
        ])
        .unwrap();
        let Command::PoolServe {
            prune_keep_blocks, ..
        } = cli.command
        else {
            unreachable!()
        };
        assert_eq!(prune_keep_blocks, Some(720));
    }

    #[test]
    fn pool_payout_reconciliation_cli_requires_exact_state_and_acknowledgment() {
        assert!(Cli::try_parse_from(["cmfd-node", "pool-payout-status"]).is_err());
        assert!(
            Cli::try_parse_from([
                "cmfd-node",
                "pool-payout-status",
                "--pool-payout-fee-atoms",
                "1"
            ])
            .is_ok()
        );
        let tip = "11".repeat(32);
        let arguments = [
            "cmfd-node",
            "pool-payout-reconcile",
            "--pool-payout-fee-atoms",
            "1",
            "--expected-tip",
            &tip,
            "--expected-ledger-generation",
            "2",
            "--note",
            "Funding reconciled",
        ];
        assert!(Cli::try_parse_from(arguments).is_err());
        assert!(
            Cli::try_parse_from(
                arguments
                    .into_iter()
                    .chain(["--acknowledge-reconciliation"])
            )
            .is_ok()
        );
    }

    #[test]
    fn production_rc_seed_defaults_are_explicit_replaceable_and_disableable() {
        let seed = vec![cmfd_node::seed_peers::PRODUCTION_RC_SEED];
        let (defaults, public) =
            effective_operational_peers_for_build(Vec::new(), false, false, seed.clone()).unwrap();
        assert_eq!(defaults, vec![cmfd_node::seed_peers::PRODUCTION_RC_SEED]);
        assert!(public);

        let explicit = vec!["10.1.2.3:19444".parse().unwrap()];
        assert_eq!(
            effective_operational_peers_for_build(explicit.clone(), false, false, seed.clone())
                .unwrap(),
            (explicit, false)
        );
        assert_eq!(
            effective_operational_peers_for_build(Vec::new(), false, true, seed).unwrap(),
            (Vec::new(), false)
        );
        assert_eq!(
            effective_operational_peers_for_build(Vec::new(), false, false, Vec::new()).unwrap(),
            (Vec::new(), false)
        );
    }

    #[test]
    fn mainnet_seed_selection_keeps_the_mainnet_port_and_dials_the_relay_too() {
        let seed: SocketAddr = "173.249.35.251:29444".parse().unwrap();
        let relay: SocketAddr = "209.145.48.36:29444".parse().unwrap();
        let (peers, public) =
            effective_operational_peers_for_build(Vec::new(), false, false, vec![seed, relay])
                .unwrap();
        assert_eq!(peers, vec![seed, relay]);
        assert!(public);
        assert_eq!(
            effective_operational_peers_for_build(Vec::new(), false, true, vec![seed, relay])
                .unwrap(),
            (Vec::new(), false)
        );
        // An explicit --peer list replaces every compiled default, relay included.
        let explicit = vec!["203.0.113.5:29444".parse().unwrap()];
        assert_eq!(
            effective_operational_peers_for_build(explicit.clone(), true, false, vec![seed, relay])
                .unwrap(),
            (explicit, true)
        );
    }

    #[test]
    fn run_v3_custody_requires_the_complete_explicit_activation_set() {
        let partial = Cli::try_parse_from([
            "cmfd-node",
            "run",
            "--exchange-custody-v3-policy-file",
            "C:/controls/policy.json",
        ])
        .unwrap();
        assert!(validate_exchange_withdrawal_cli(&partial).is_err());

        let missing_rpc_and_journal_controls = Cli::try_parse_from([
            "cmfd-node",
            "run",
            "--exchange-custody-v3-policy-file",
            "C:/controls/policy.json",
            "--exchange-custody-v3-keyring-file",
            "C:/node/exchange-keyring.bin",
            "--exchange-custody-v3-keyring-anchor-file",
            "C:/controls/keyring.anchor",
            "--exchange-custody-v3-keyring-passphrase-file",
            "C:/controls/keyring.passphrase",
        ])
        .unwrap();
        assert!(validate_exchange_withdrawal_cli(&missing_rpc_and_journal_controls).is_err());

        let complete = Cli::try_parse_from([
            "cmfd-node",
            "--exchange-withdrawal-journal-key-file",
            "C:/controls/journal.key",
            "--exchange-withdrawal-anchor-file",
            "C:/controls/journal.anchor",
            "run",
            "--exchange-rpc-bind",
            "127.0.0.1:38101",
            "--exchange-rpc-auth-file",
            "C:/controls/integration.auth",
            "--exchange-rpc-withdrawal-auth-file",
            "C:/controls/withdrawal.auth",
            "--exchange-custody-v3-policy-file",
            "C:/controls/policy.json",
            "--exchange-custody-v3-keyring-file",
            "C:/node/exchange-keyring.bin",
            "--exchange-custody-v3-keyring-anchor-file",
            "C:/controls/keyring.anchor",
            "--exchange-custody-v3-keyring-passphrase-file",
            "C:/controls/keyring.passphrase",
        ])
        .unwrap();
        validate_exchange_withdrawal_cli(&complete).unwrap();
        assert!(matches!(
            complete.command,
            Command::Run {
                exchange_custody_v3_policy_file: Some(policy),
                exchange_custody_v3_keyring_file: Some(keyring),
                exchange_custody_v3_keyring_anchor_file: Some(keyring_anchor),
                exchange_custody_v3_keyring_passphrase_file: Some(passphrase),
                ..
            } if policy == Path::new("C:/controls/policy.json")
                && keyring == Path::new("C:/node/exchange-keyring.bin")
                && keyring_anchor == Path::new("C:/controls/keyring.anchor")
                && passphrase == Path::new("C:/controls/keyring.passphrase")
        ));
    }

    #[test]
    fn run_v3_keyring_passphrase_must_be_a_regular_file_outside_data_dir() {
        let root = std::env::temp_dir().join(format!(
            "cmfd-v3-run-passphrase-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let data_dir = root.join("node");
        let controls_dir = root.join("controls");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&data_dir).unwrap();
        std::fs::create_dir(&controls_dir).unwrap();
        let external = controls_dir.join("keyring.passphrase");
        let inside = data_dir.join("keyring.passphrase");
        std::fs::write(&external, b"correct horse battery staple").unwrap();
        std::fs::write(&inside, b"correct horse battery staple").unwrap();

        assert_eq!(
            canonical_external_v3_passphrase_file(&data_dir, &external).unwrap(),
            std::fs::canonicalize(&external).unwrap()
        );
        assert!(canonical_external_v3_passphrase_file(&data_dir, &inside).is_err());
        assert!(
            canonical_external_v3_passphrase_file(&data_dir, Path::new("relative.passphrase"))
                .is_err()
        );

        std::fs::remove_file(external).unwrap();
        std::fs::remove_file(inside).unwrap();
        std::fs::remove_dir(controls_dir).unwrap();
        std::fs::remove_dir(data_dir).unwrap();
        std::fs::remove_dir(root).unwrap();
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
    fn acl_qualification_commands_require_explicit_inputs() {
        let live = Cli::try_parse_from([
            "cmfd-node",
            "exchange-v3-acl-qualify",
            "--config",
            "C:/controls/acl-config.json",
            "--output",
            "C:/evidence/acl-live.json",
        ])
        .unwrap();
        assert!(matches!(
            live.command,
            Command::ExchangeV3AclQualify { config, output }
                if config == Path::new("C:/controls/acl-config.json")
                    && output == Path::new("C:/evidence/acl-live.json")
        ));

        let fixture = Cli::try_parse_from([
            "cmfd-node",
            "exchange-v3-acl-fixture-qualify",
            "--fixture",
            "C:/fixtures/acl.json",
            "--output",
            "C:/evidence/acl-fixture.json",
        ])
        .unwrap();
        assert!(matches!(
            fixture.command,
            Command::ExchangeV3AclFixtureQualify { fixture, output }
                if fixture == Path::new("C:/fixtures/acl.json")
                    && output == Path::new("C:/evidence/acl-fixture.json")
        ));
        assert!(Cli::try_parse_from(["cmfd-node", "exchange-v3-acl-qualify"]).is_err());
        assert!(Cli::try_parse_from(["cmfd-node", "exchange-v3-acl-fixture-qualify"]).is_err());
    }

    #[test]
    fn offline_wallet_commands_require_explicit_files() {
        let backup = Cli::try_parse_from([
            "cmfd-node",
            "--data-dir",
            "wallet-data",
            "wallet-backup",
            "--output",
            "wallet.cmfd-backup",
            "--passphrase-file",
            "passphrase.txt",
        ])
        .unwrap();
        assert_eq!(backup.data_dir, PathBuf::from("wallet-data"));
        assert!(matches!(
            backup.command,
            Command::WalletBackup { output, passphrase_file }
                if output == Path::new("wallet.cmfd-backup")
                    && passphrase_file == Path::new("passphrase.txt")
        ));

        let restore = Cli::try_parse_from([
            "cmfd-node",
            "wallet-restore",
            "--input",
            "wallet.cmfd-backup",
            "--passphrase-file",
            "passphrase.txt",
        ])
        .unwrap();
        assert!(matches!(restore.command, Command::WalletRestore { .. }));
        assert!(Cli::try_parse_from(["cmfd-node", "wallet-backup"]).is_err());
        assert!(Cli::try_parse_from(["cmfd-node", "wallet-restore"]).is_err());
    }

    #[cfg(feature = "production-v4-testnet")]
    #[test]
    fn rcnet_wallet_create_requires_candidate_backup_and_passphrase() {
        let create = Cli::try_parse_from([
            "cmfd-node",
            "--data-dir",
            "C:/custody/wallet",
            "rcnet-wallet-create",
            "--candidate",
            "C:/artifacts/RCNET1-LAUNCH-CANDIDATE-V2.json",
            "--backup-output",
            "D:/backups/rcnet-wallet.cmfd-backup",
            "--passphrase-file",
            "C:/custody-secrets/rcnet-wallet.passphrase",
        ])
        .unwrap();
        assert!(matches!(
            create.command,
            Command::RcnetWalletCreate {
                candidate,
                backup_output,
                passphrase_file,
            } if candidate == Path::new("C:/artifacts/RCNET1-LAUNCH-CANDIDATE-V2.json")
                && backup_output == Path::new("D:/backups/rcnet-wallet.cmfd-backup")
                && passphrase_file == Path::new("C:/custody-secrets/rcnet-wallet.passphrase")
        ));
        assert!(Cli::try_parse_from(["cmfd-node", "rcnet-wallet-create"]).is_err());

        let restore = Cli::try_parse_from([
            "cmfd-node",
            "--data-dir",
            "C:/custody/restored-wallet",
            "rcnet-wallet-restore",
            "--candidate",
            "C:/artifacts/RCNET1-LAUNCH-CANDIDATE-V2.json",
            "--input",
            "D:/backups/rcnet-wallet.cmfd-backup",
            "--passphrase-file",
            "C:/custody-secrets/rcnet-wallet.passphrase",
        ])
        .unwrap();
        assert!(matches!(
            restore.command,
            Command::RcnetWalletRestore {
                candidate,
                input,
                passphrase_file,
            } if candidate == Path::new("C:/artifacts/RCNET1-LAUNCH-CANDIDATE-V2.json")
                && input == Path::new("D:/backups/rcnet-wallet.cmfd-backup")
                && passphrase_file == Path::new("C:/custody-secrets/rcnet-wallet.passphrase")
        ));
        assert!(Cli::try_parse_from(["cmfd-node", "rcnet-wallet-restore"]).is_err());
    }

    #[test]
    fn live_wallet_passphrase_file_is_a_global_option() {
        let cli = Cli::try_parse_from([
            "cmfd-node",
            "--wallet-passphrase-file",
            "private-wallet-passphrase.txt",
            "status",
        ])
        .unwrap();
        assert_eq!(
            cli.wallet_passphrase_file,
            Some(PathBuf::from("private-wallet-passphrase.txt"))
        );
        assert!(matches!(cli.command, Command::Status));
    }

    #[test]
    fn withdrawal_journal_keygen_is_create_new_and_exactly_32_bytes() {
        let directory = std::env::temp_dir().join(format!(
            "cmfd-withdrawal-keygen-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).unwrap();
        #[cfg(windows)]
        {
            let identity = std::process::Command::new("whoami.exe").output().unwrap();
            assert!(identity.status.success());
            let identity = String::from_utf8(identity.stdout).unwrap();
            let grant = format!("{}:(OI)(CI)(F)", identity.trim());
            assert!(
                std::process::Command::new("icacls.exe")
                    .arg(&directory)
                    .arg("/inheritance:r")
                    .arg("/grant:r")
                    .arg(grant)
                    .status()
                    .unwrap()
                    .success()
            );
        }
        let output = directory.join("withdrawal-journal.key");
        let cli = Cli::try_parse_from([
            "cmfd-node",
            "exchange-withdrawal-keygen",
            "--output",
            output.to_str().unwrap(),
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::ExchangeWithdrawalKeygen { output: ref parsed } if parsed == &output
        ));

        create_exchange_withdrawal_journal_key(&output).unwrap();
        let first = std::fs::read(&output).unwrap();
        assert_eq!(first.len(), 32);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&output).unwrap().permissions().mode() & 0o077,
                0
            );
        }
        assert!(create_exchange_withdrawal_journal_key(&output).is_err());
        assert_eq!(std::fs::read(&output).unwrap(), first);
        assert!(create_exchange_withdrawal_journal_key(Path::new("relative.key")).is_err());

        std::fs::remove_file(output).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn v3_offline_operator_commands_require_explicit_confirmations_and_controls() {
        let digest = "11".repeat(32);
        let import = Cli::try_parse_from([
            "cmfd-node",
            "exchange-keyring-import-plan",
            "--legacy-key-file",
            "C:/controls/wallet.key",
            "--legacy-wallet-passphrase-file",
            "C:/controls/legacy.passphrase",
            "--keyring-instance-id",
            &digest,
            "--plan-output",
            "C:/controls/keyring-plan.json",
        ])
        .unwrap();
        assert!(matches!(
            import.command,
            Command::ExchangeKeyringImportPlan {
                legacy_wallet_passphrase_file: Some(_),
                ..
            }
        ));
        assert!(
            Cli::try_parse_from([
                "cmfd-node",
                "exchange-keyring-import-apply",
                "--plan-file",
                "C:/controls/keyring-plan.json",
            ])
            .is_err()
        );

        let external_transition = Cli::try_parse_from([
            "cmfd-node",
            "--data-dir",
            "C:/node",
            "exchange-keyring-external-transition-plan",
            "--source-keyring-file",
            "C:/node/imported-keyring.bin",
            "--source-anchor-file",
            "C:/provisioning/imported-keyring.anchor",
            "--source-keyring-passphrase-file",
            "C:/provisioning/keyring.passphrase",
            "--external-public-key",
            &digest,
            "--external-signer-id",
            &"22".repeat(32),
            "--keyring-output",
            "C:/node/external-keyring.bin",
            "--anchor-output",
            "C:/provisioning/external-keyring.anchor",
            "--plan-output",
            "C:/provisioning/external-transition-plan.json",
        ])
        .unwrap();
        assert!(matches!(
            external_transition.command,
            Command::ExchangeKeyringExternalTransitionPlan {
                external_public_key,
                external_signer_id,
                ..
            } if external_public_key == [0x11; 32] && external_signer_id == [0x22; 32]
        ));
        assert!(
            Cli::try_parse_from([
                "cmfd-node",
                "exchange-keyring-external-transition-apply",
                "--plan-file",
                "C:/provisioning/external-transition-plan.json",
            ])
            .is_err()
        );

        let finalization = Cli::try_parse_from([
            "cmfd-node",
            "--data-dir",
            "C:/node",
            "--exchange-withdrawal-journal-key-file",
            "C:/node-secrets/journal.key",
            "--exchange-withdrawal-anchor-file",
            "C:/controls/journal.anchor",
            "exchange-keyring-external-finalization-plan",
            "--policy-file",
            "C:/controls/policy.json",
            "--source-keyring-file",
            "C:/node/mixed-keyring.bin",
            "--source-anchor-file",
            "C:/controls/mixed-keyring.anchor",
            "--source-keyring-passphrase-file",
            "C:/controls/keyring.passphrase",
            "--legacy-public-key",
            &digest,
            "--decommission-evidence-file",
            "C:/controls/legacy-decommission.json",
            "--rotation-decision-id",
            &"22".repeat(32),
            "--approval-digest",
            &"33".repeat(32),
            "--keyring-output",
            "C:/node/finalized-keyring.bin",
            "--keyring-anchor-output",
            "C:/staging/finalized-keyring.anchor",
            "--journal-anchor-output",
            "C:/staging/finalized-journal.anchor",
            "--plan-output",
            "C:/staging/finalization-plan.json",
        ])
        .unwrap();
        validate_exchange_withdrawal_cli(&finalization).unwrap();
        assert!(matches!(
            finalization.command,
            Command::ExchangeKeyringExternalFinalizationPlan {
                legacy_public_key,
                ..
            } if legacy_public_key == [0x11; 32]
        ));
        assert!(
            Cli::try_parse_from([
                "cmfd-node",
                "exchange-keyring-external-finalization-apply",
                "--plan-file",
                "C:/staging/finalization-plan.json",
            ])
            .is_err()
        );

        let archive_without_security = Cli::try_parse_from([
            "cmfd-node",
            "exchange-v3-archive-verify",
            "--archive-file",
            "C:/controls/archive.bin",
            "--manifest-pin-file",
            "C:/controls/archive.pin",
        ])
        .unwrap();
        assert!(validate_exchange_withdrawal_cli(&archive_without_security).is_err());
        let archive_verify = Cli::try_parse_from([
            "cmfd-node",
            "--exchange-withdrawal-journal-key-file",
            "C:/controls/journal.key",
            "exchange-v3-archive-verify",
            "--archive-file",
            "C:/controls/archive.bin",
            "--manifest-pin-file",
            "C:/controls/archive.pin",
        ])
        .unwrap();
        validate_exchange_withdrawal_cli(&archive_verify).unwrap();
        assert!(archive_verify.exchange_withdrawal_anchor_file.is_none());
        let archive = Cli::try_parse_from([
            "cmfd-node",
            "--exchange-withdrawal-journal-key-file",
            "C:/controls/journal.key",
            "--exchange-withdrawal-anchor-file",
            "C:/controls/journal.anchor",
            "exchange-v3-archive-apply",
            "--policy-file",
            "C:/controls/policy.json",
            "--keyring-file",
            "C:/node/keyring.bin",
            "--keyring-anchor-file",
            "C:/controls/keyring.anchor",
            "--keyring-passphrase-file",
            "C:/controls/keyring.passphrase",
            "--archive-file",
            "C:/controls/archive.bin",
            "--manifest-pin-file",
            "C:/controls/archive.pin",
            "--confirmation-archive-id",
            &digest,
            "--proposed-anchor-output",
            "C:/controls/compacted.anchor",
        ])
        .unwrap();
        validate_exchange_withdrawal_cli(&archive).unwrap();
        assert!(matches!(
            archive.command,
            Command::ExchangeV3ArchiveApply { .. }
        ));

        let migration_payload = Cli::try_parse_from([
            "cmfd-node",
            "--exchange-withdrawal-journal-key-file",
            "C:/controls/journal.key",
            "--exchange-withdrawal-anchor-file",
            "C:/controls/journal.anchor",
            "exchange-v3-migration-approval-payload",
            "--policy-file",
            "C:/controls/policy.json",
            "--keyring-file",
            "C:/node/keyring.bin",
            "--keyring-anchor-file",
            "C:/controls/keyring.anchor",
            "--keyring-passphrase-file",
            "C:/controls/keyring.passphrase",
            "--request-id",
            "migrated-withdrawal-0001",
            "--decision-id",
            &digest,
            "--authorized-at-unix-seconds",
            "100",
            "--expires-at-unix-seconds",
            "200",
            "--output",
            "C:/controls/migrated-withdrawal-0001.approval.json",
        ])
        .unwrap();
        validate_exchange_withdrawal_cli(&migration_payload).unwrap();
        assert!(matches!(
            migration_payload.command,
            Command::ExchangeV3MigrationApprovalPayload {
                decision_id,
                authorized_at_unix_seconds: 100,
                expires_at_unix_seconds: 200,
                ..
            } if decision_id == [0x11; 32]
        ));

        let migration = Cli::try_parse_from([
            "cmfd-node",
            "--exchange-withdrawal-journal-key-file",
            "C:/controls/journal.key",
            "--exchange-withdrawal-anchor-file",
            "C:/controls/journal.anchor",
            "exchange-v3-migration-apply",
            "--plan-file",
            "C:/controls/migration-plan.json",
            "--confirmation-plan-digest",
            &digest,
        ])
        .unwrap();
        validate_exchange_withdrawal_cli(&migration).unwrap();
        assert!(matches!(
            migration.command,
            Command::ExchangeV3MigrationApply {
                confirmation_plan_digest,
                ..
            } if confirmation_plan_digest == [0x11; 32]
        ));
    }

    #[test]
    fn storage_maintenance_commands_are_explicit() {
        assert!(matches!(
            Cli::try_parse_from(["cmfd-node", "storage-inspect"])
                .unwrap()
                .command,
            Command::StorageInspect
        ));
        let repair = Cli::try_parse_from([
            "cmfd-node",
            "storage-repair-tail",
            "--quarantine-output",
            "blocks.tail.quarantine",
        ])
        .unwrap();
        assert!(matches!(
            repair.command,
            Command::StorageRepairTail { quarantine_output }
                if quarantine_output == Path::new("blocks.tail.quarantine")
        ));
        assert!(Cli::try_parse_from(["cmfd-node", "storage-repair-tail"]).is_err());
    }

    #[test]
    fn passphrase_file_is_bounded_and_trims_one_line_ending() {
        let path = std::env::temp_dir().join(format!(
            "cmfd-wallet-passphrase-{}-{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, b"correct horse battery staple\r\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert_eq!(
            load_runtime_wallet_passphrase(Path::new("unused"), Some(&path), false)
                .unwrap()
                .unwrap()
                .as_slice(),
            b"correct horse battery staple"
        );
        std::fs::write(&path, b"too short\n").unwrap();
        assert!(read_wallet_passphrase_file(&path).is_err());
        std::fs::write(&path, vec![b'x'; MAXIMUM_PASSPHRASE_BYTES + 3]).unwrap();
        assert!(read_wallet_passphrase_file(&path).is_err());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn v3_runtime_wallet_passphrase_rejects_node_controlled_path() {
        let root = std::env::temp_dir().join(format!(
            "cmfd-v3-wallet-passphrase-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let data_dir = root.join("node");
        std::fs::create_dir_all(&data_dir).unwrap();
        let passphrase = root.join("wallet.passphrase");
        std::fs::write(&passphrase, b"correct horse battery staple\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&passphrase, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        assert!(
            load_runtime_wallet_passphrase(&data_dir, Some(&passphrase), true).is_err(),
            "v3 must reject a wallet passphrase controlled by the node identity"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn persisted_v3_latch_keeps_wallet_passphrase_hardened_without_flags() {
        let root = std::env::temp_dir().join(format!(
            "cmfd-persisted-v3-wallet-passphrase-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let data_dir = root.join("node");
        std::fs::create_dir_all(&data_dir).unwrap();
        std::fs::write(
            data_dir.join("exchange-withdrawals.v3.initialized"),
            b"persisted v3 enrollment",
        )
        .unwrap();
        let passphrase = root.join("wallet.passphrase");
        std::fs::write(&passphrase, b"correct horse battery staple\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&passphrase, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        let hardened = persisted_exchange_custody_v3_wallet_security_required(&data_dir);
        assert!(hardened);
        assert!(load_runtime_wallet_passphrase(&data_dir, Some(&passphrase), hardened).is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn shutdown_wait_reports_an_unexpected_service_exit() {
        let (_sender, receiver) = sync_channel(1);
        let reason = ShutdownSignal {
            receiver,
            request_file: None,
        }
        .wait_for_service_exit(|| Some("RPC"))
        .unwrap();
        assert_eq!(reason, Some("RPC"));
    }

    #[test]
    fn shutdown_signal_wins_when_service_exit_is_also_observed() {
        let (sender, receiver) = sync_channel(1);
        sender.send(()).unwrap();
        let reason = ShutdownSignal {
            receiver,
            request_file: None,
        }
        .wait_for_service_exit(|| Some("RPC"))
        .unwrap();
        assert_eq!(reason, None);
    }
}
