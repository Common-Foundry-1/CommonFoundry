//! Transport-only fixtures: no mainnet node, wallet data, GPU or live pool.
use super::*;
use cmfd_consensus::compact_mainnet_fork::{
    COMPACT_MAINNET_NETWORK_ID, COMPACT_MAINNET_PREDECESSOR_FINGERPRINT, CompactMainnetForkIdentity,
};

fn config(address: SocketAddr, pin: [u8; 32], signed: bool) -> PoolClientConfig {
    let signer = PoolPayoutSigner::new(SigningKey::from_bytes(&[0x13; 32]).unwrap());
    PoolClientConfig {
        address,
        certificate_sha256: pin,
        worker: "fork-compat-test".to_owned(),
        payout: signer.payout(),
        payout_signer: signed.then_some(signer),
        expected_network_id: COMPACT_MAINNET_NETWORK_ID,
        expected_consensus_fingerprint: COMPACT_MAINNET_PREDECESSOR_FINGERPRINT,
        compact_mainnet_compatibility: false,
    }
}

fn compact() -> [u8; 32] {
    CompactMainnetForkIdentity::pinned().fingerprint()
}

/// The mock independently verifies the Hello and its payout signature, then
/// acknowledges it and sends a job. It never executes or accepts a block.
fn mock_pool(
    network_id: [u8; 32],
    advertised: [u8; 32],
    acknowledged: [u8; 32],
    signed: bool,
) -> (SocketAddr, [u8; 32], JoinHandle<Result<(), PoolError>>) {
    let identity = generate_simple_self_signed(vec!["cmfd-pool.local".to_owned()]).unwrap();
    let certificate = identity.cert.der().to_vec();
    let pin = certificate_sha256(&certificate);
    let tls = server_tls_config(certificate, identity.signing_key.serialize_der()).unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let worker = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        let socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(PoolError::ConnectionClosed);
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => return Err(error.into()),
            }
        };
        socket.set_nonblocking(false)?;
        socket.set_read_timeout(Some(Duration::from_secs(5)))?;
        socket.set_write_timeout(Some(Duration::from_secs(5)))?;
        let tls = ServerConnection::new(Arc::new(tls))
            .map_err(|error| PoolError::Tls(error.to_string()))?;
        let mut stream = StreamOwned::new(tls, socket);
        let nonce = [0x61; 32];
        write_frame(
            &mut stream,
            &ServerMessage::AuthChallenge {
                protocol_version: POOL_PROTOCOL_VERSION,
                network_id,
                consensus_fingerprint: advertised,
                nonce,
            },
        )?;
        let hello: ClientMessage = read_frame(&mut stream)?;
        let ClientMessage::Hello {
            protocol_version,
            network_id: hello_network,
            consensus_fingerprint,
            worker,
            payout,
            payout_signature,
        } = hello
        else {
            panic!("expected Hello");
        };
        assert_eq!(protocol_version, POOL_PROTOCOL_VERSION);
        assert_eq!(hello_network, network_id);
        assert_eq!(consensus_fingerprint, advertised);
        assert_eq!(worker, "fork-compat-test");
        if signed {
            let digest = payout_auth_digest(network_id, advertised, nonce, &worker, payout);
            VerifyingKey::from_bytes(&payout)
                .unwrap()
                .verify(
                    &digest,
                    &Signature::try_from(payout_signature.as_slice()).unwrap(),
                )
                .unwrap();
        } else {
            assert!(payout_signature.is_empty());
        }
        write_frame(
            &mut stream,
            &ServerMessage::HelloAck {
                protocol_version: POOL_PROTOCOL_VERSION,
                network_id,
                consensus_fingerprint: acknowledged,
                session_id: 7,
                accounting_semantics: "transport test".to_owned(),
                persistence: "transport test".to_owned(),
            },
        )?;
        if advertised != acknowledged {
            return Ok(());
        }
        write_frame(
            &mut stream,
            &ServerMessage::Job {
                job: PoolJob {
                    job_id: [7; 32],
                    challenge: BlockChallenge {
                        network_id,
                        previous_block: [2; 32],
                        transaction_root: [3; 32],
                        height: 67_535,
                        timestamp: 5,
                        target: [0x80; 32],
                    },
                    share_target: [0xff; 32],
                },
            },
        )?;
        // Check that compatibility did not add proof bytes to share submissions.
        match read_frame::<_, ClientMessage>(&mut stream)? {
            ClientMessage::SubmitShare { job_id, nonce } => {
                assert_eq!(job_id, [7; 32]);
                assert_eq!(nonce, 42);
            }
            _ => panic!("expected nonce-only SubmitShare"),
        }
        Ok(())
    });
    (address, pin, worker)
}

#[test]
fn compact_pool_compatibility_accepts_both_pins_and_binds_signed_hello() {
    for advertised in [COMPACT_MAINNET_PREDECESSOR_FINGERPRINT, compact()] {
        for signed in [false, true] {
            let (address, pin, worker) =
                mock_pool(COMPACT_MAINNET_NETWORK_ID, advertised, advertised, signed);
            let config = config(address, pin, signed)
                .with_compact_mainnet_compatibility()
                .unwrap();
            let mut client = PoolClient::connect(config).unwrap();
            assert_eq!(client.consensus_fingerprint(), advertised);
            assert_eq!(client.current_job().challenge.height, 67_535);
            write_frame(
                &mut client.stream,
                &ClientMessage::SubmitShare {
                    job_id: [7; 32],
                    nonce: 42,
                },
            )
            .unwrap();
            worker.join().unwrap().unwrap();
        }
    }
}

#[test]
fn compact_pool_compatibility_rejects_unknown_pin_before_sending_hello() {
    let (address, pin, worker) =
        mock_pool(COMPACT_MAINNET_NETWORK_ID, [0x77; 32], [0x77; 32], true);
    let config = config(address, pin, true)
        .with_compact_mainnet_compatibility()
        .unwrap();
    assert!(matches!(
        PoolClient::connect(config),
        Err(PoolError::FingerprintMismatch)
    ));
    assert!(worker.join().unwrap().is_err());
}

#[test]
fn compact_pool_compatibility_rejects_network_mismatch_before_sending_hello() {
    let (address, pin, worker) = mock_pool([0x77; 32], compact(), compact(), true);
    let config = config(address, pin, true)
        .with_compact_mainnet_compatibility()
        .unwrap();
    assert!(matches!(
        PoolClient::connect(config),
        Err(PoolError::NetworkMismatch)
    ));
    assert!(worker.join().unwrap().is_err());
}

#[test]
fn compact_pool_compatibility_cannot_switch_pin_during_handshake() {
    for (advertised, acknowledged) in [
        (COMPACT_MAINNET_PREDECESSOR_FINGERPRINT, compact()),
        (compact(), COMPACT_MAINNET_PREDECESSOR_FINGERPRINT),
    ] {
        let (address, pin, worker) =
            mock_pool(COMPACT_MAINNET_NETWORK_ID, advertised, acknowledged, true);
        let config = config(address, pin, true)
            .with_compact_mainnet_compatibility()
            .unwrap();
        assert!(matches!(
            PoolClient::connect(config),
            Err(PoolError::FingerprintMismatch)
        ));
        worker.join().unwrap().unwrap();
    }
}

#[test]
fn compact_pool_compatibility_preserves_tls_pin_check() {
    let (address, _, worker) = mock_pool(COMPACT_MAINNET_NETWORK_ID, compact(), compact(), false);
    let config = config(address, [0x77; 32], false)
        .with_compact_mainnet_compatibility()
        .unwrap();
    assert!(matches!(
        PoolClient::connect(config),
        Err(PoolError::CertificatePinMismatch)
    ));
    assert!(worker.join().unwrap().is_err());
}

#[test]
fn compact_pool_compatibility_is_explicit_and_mainnet_only() {
    let address = "127.0.0.1:1".parse().unwrap();
    let strict = config(address, [0; 32], false);
    assert!(strict.accepts_consensus_fingerprint(COMPACT_MAINNET_PREDECESSOR_FINGERPRINT));
    assert!(!strict.accepts_consensus_fingerprint(compact()));
    let compatible = strict.with_compact_mainnet_compatibility().unwrap();
    assert!(compatible.accepts_consensus_fingerprint(compact()));
    assert!(!compatible.accepts_consensus_fingerprint([0x77; 32]));
    let mut wrong_network = compatible.clone();
    wrong_network.expected_network_id[0] ^= 1;
    assert!(!wrong_network.accepts_consensus_fingerprint(compact()));
    assert!(matches!(
        wrong_network.with_compact_mainnet_compatibility(),
        Err(PoolError::NetworkMismatch)
    ));
    let mut wrong_predecessor = compatible;
    wrong_predecessor.expected_consensus_fingerprint[0] ^= 1;
    assert!(!wrong_predecessor.accepts_consensus_fingerprint(compact()));
    assert!(matches!(
        wrong_predecessor.with_compact_mainnet_compatibility(),
        Err(PoolError::FingerprintMismatch)
    ));
}
