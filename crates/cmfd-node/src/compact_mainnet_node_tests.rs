use super::*;
use cmfd_consensus::compact_mainnet_fork::*;

fn hello(fingerprint: [u8; 32], height: u64) -> peer::PeerHello {
    peer::PeerHello {
        network_id: COMPACT_MAINNET_NETWORK_ID,
        consensus_fingerprint: fingerprint,
        node_nonce: [7; 32],
        tip: [8; 32],
        height,
        cumulative_work: peer::ChainWork::ZERO,
    }
}

#[test]
fn compact_mainnet_peer_transition_preserves_pre_height_coexistence() {
    let fork = CompactMainnetForkIdentity::pinned().fingerprint();
    let old = COMPACT_MAINNET_PREDECESSOR_FINGERPRINT;
    assert_eq!(
        peer::scheduled_peer_fingerprint(COMPACT_MAINNET_NETWORK_ID, fork, 67534),
        old
    );
    assert_eq!(
        peer::scheduled_peer_fingerprint(COMPACT_MAINNET_NETWORK_ID, fork, 67535),
        fork
    );
    assert!(peer::compatible_fork_hellos(
        &hello(old, 67534),
        &hello(old, 67534)
    ));
    assert!(peer::compatible_fork_hellos(
        &hello(old, 0),
        &hello(fork, 67536)
    ));
    assert!(peer::compatible_fork_hellos(
        &hello(fork, 67536),
        &hello(old, 0)
    ));
    assert!(!peer::compatible_fork_hellos(
        &hello(fork, 67536),
        &hello(old, 67535)
    ));
    assert!(!peer::compatible_fork_hellos(
        &hello(old, 67535),
        &hello(old, 67535)
    ));
    assert!(!peer::compatible_fork_hellos(
        &hello(fork, 67536),
        &hello([0x77; 32], 67534)
    ));
    let mut other = hello(fork, 67536);
    other.network_id[0] ^= 1;
    assert!(!peer::compatible_fork_hellos(&hello(fork, 67536), &other));
    // An active-chain reorganization below H restores legacy wire identity,
    // while the persisted/configured fork identity stays bound to both rules.
    assert_eq!(
        peer::scheduled_peer_fingerprint(COMPACT_MAINNET_NETWORK_ID, fork, 67534),
        old
    );
}

#[test]
fn compact_mainnet_metadata_upgrade_is_backed_up_and_preserves_wallet_bytes() {
    let mut random = [0; 16];
    getrandom::fill(&mut random).unwrap();
    let root = std::env::temp_dir().join(format!("cmfd-compact-meta-{}", hex::encode(random)));
    fs::create_dir(&root).unwrap();
    let log_path = root.join("blocks.log");
    let log = File::create(&log_path).unwrap();
    let mut bytes = [0u8; METADATA_BYTES];
    bytes[..4].copy_from_slice(&METADATA_MAGIC);
    bytes[4..6].copy_from_slice(&METADATA_VERSION.to_le_bytes());
    bytes[6..8].copy_from_slice(&METADATA_WALLET_KEY_FLAG.to_le_bytes());
    bytes[8..40].copy_from_slice(&COMPACT_MAINNET_PREDECESSOR_FINGERPRINT);
    fs::write(root.join(METADATA_FILE), bytes).unwrap();
    fs::write(root.join("wallet.key"), b"unchanged fixture wallet bytes").unwrap();
    let fork = CompactMainnetForkIdentity::pinned().fingerprint();
    let state = load_metadata(&root, fork, &log, &log_path, false).unwrap();
    assert_eq!(state, MetadataState::CompactMainnetUpgrade);
    write_metadata(&root, fork, state).unwrap();
    assert_eq!(
        fs::read(root.join("network.meta.pre-compact-67535")).unwrap(),
        bytes
    );
    assert_eq!(
        fs::read(root.join("wallet.key")).unwrap(),
        b"unchanged fixture wallet bytes"
    );
    assert_eq!(
        load_metadata(&root, fork, &log, &log_path, false).unwrap(),
        MetadataState::Current
    );
    assert!(matches!(
        load_metadata(
            &root,
            COMPACT_MAINNET_PREDECESSOR_FINGERPRINT,
            &log,
            &log_path,
            false
        ),
        Err(NodeError::FingerprintMismatch)
    ));
    drop(log);
    for name in [
        "blocks.log",
        METADATA_FILE,
        "network.meta.pre-compact-67535",
        "wallet.key",
    ] {
        fs::remove_file(root.join(name)).unwrap();
    }
    fs::remove_dir(root).unwrap();
}
