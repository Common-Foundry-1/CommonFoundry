//! Offline acceptance exercise for the real pool's configured CPU verifier.
//! Inputs are frozen mainnet templates; no listener or chain store is opened.
use super::configure_production_v4_pool_verifier;
use cmfd_consensus::compact_mainnet_fork::COMPACT_MAINNET_NETWORK_ID;
use cmfd_consensus::{
    BlockProof, ConsensusPowVerifier, ForgeMatrixV4FixedArtifactRecordV1,
    ForgeMatrixV4FileLayerSource,
};
use cmfd_node::{BlockTemplate, ProductionV4VerifierArtifacts, pool::PoolServerConfig};
use serde::Deserialize;
use std::{
    fs,
    io::BufReader,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

#[derive(Deserialize)]
struct Request {
    at: f64,
    template: PathBuf,
    digest: String,
}
#[derive(Deserialize)]
struct Fixture {
    bank: PathBuf,
    record: PathBuf,
    output: PathBuf,
    duration_s: f64,
    winners: Vec<Request>,
    #[serde(default)]
    post_window_winner: Option<Request>,
    shares: Vec<Request>,
    rotations: Vec<f64>,
}

fn template(path: &Path) -> (BlockTemplate, u64) {
    let mut doc: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let nonce = doc["nonce"].as_u64().unwrap();
    let template = BlockTemplate {
        challenge: serde_json::from_value(doc["challenge"].take()).unwrap(),
        coinbase: serde_json::from_value(doc["coinbase"].take()).unwrap(),
        transactions: serde_json::from_value(doc["transactions"].take()).unwrap(),
        total_fees_burned: 0,
    };
    (template, nonce)
}

fn wait_until(start: Instant, at: f64) {
    std::thread::sleep(
        (start + Duration::from_secs_f64(at)).saturating_duration_since(Instant::now()),
    );
}

#[test]
#[ignore = "requires installed authenticated mainnet artifacts, CPU prover and offline workload"]
fn cpu_pool_release_qualification() {
    let _ = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .try_init();
    let f: Fixture = serde_json::from_slice(
        &fs::read(std::env::var_os("CMFD_CPU_QUALIFICATION").unwrap()).unwrap(),
    )
    .unwrap();
    assert!(!f.shares.is_empty() && !f.winners.is_empty() && !f.output.exists());
    fs::create_dir_all(&f.output).unwrap();
    let record: ForgeMatrixV4FixedArtifactRecordV1 =
        serde_json::from_slice(&fs::read(&f.record).unwrap()).unwrap();
    let (engine, identity) = ConsensusPowVerifier::v4_candidate_for_network_with_layer_roots(
        COMPACT_MAINNET_NETWORK_ID,
        record,
        BufReader::with_capacity(64 << 20, fs::File::open(&f.bank).unwrap()),
    )
    .unwrap();
    drop(engine);
    let source = ForgeMatrixV4FileLayerSource::new(
        fs::File::open(&f.bank).unwrap(),
        &identity.manifest,
        Arc::clone(&identity.base_input),
        Arc::clone(&identity.layer_roots),
    )
    .unwrap();
    cmfd_node::work_gate::aria_set_shared_layer_source(Arc::new(source));
    let artifacts = ProductionV4VerifierArtifacts {
        bank: f.bank.clone(),
        fixed_record: f.record.clone(),
    };
    let mut config =
        PoolServerConfig::devnet("127.0.0.1:0".parse().unwrap(), vec![], vec![], [0; 32]);
    assert!(
        configure_production_v4_pool_verifier(
            &mut config,
            Some(&artifacts),
            None,
            &[],
            None,
            None,
            false,
            false,
            false,
            None,
            None,
            None
        )
        .unwrap()
        .is_none()
    );
    let worker = config.production_v4_share_verifier.unwrap();
    let get = |r: &Request| {
        let (template, nonce) = template(&r.template);
        let result = worker.evaluate(&template, nonce, [255; 32]).unwrap();
        assert_eq!(hex::encode(result.work_digest), r.digest);
        result
    };
    assert!(get(&f.shares[0]).chain_proof.is_none());
    let save = |r: &Request, name: String| {
        let Some(BlockProof::V4Candidate(packet)) = get(r).chain_proof else {
            panic!("expected compact block proof")
        };
        fs::write(f.output.join(name), &packet.transparent_proof).unwrap();
    };
    save(&f.winners[0], "warmup.proof.bin".into());
    let start = Instant::now();
    std::thread::scope(|scope| {
        let winners=scope.spawn(|| {
            let mut rows=Vec::new();
            for (i,r) in f.winners.iter().enumerate() {
                wait_until(start,r.at);
                let dispatch=start.elapsed().as_secs_f64();
                save(r,format!("candidate-{i:02}.proof.bin"));
                rows.push(serde_json::json!({"id":i,"arrival_s":r.at,"dispatch_s":dispatch,"done_s":start.elapsed().as_secs_f64()}));
            }
            rows
        });
        let mut shares = Vec::new();
        for (i, r) in f.shares.iter().enumerate() {
            wait_until(start, r.at);
            let dispatch = start.elapsed().as_secs_f64();
            assert!(get(r).chain_proof.is_none());
            let done = start.elapsed().as_secs_f64();
            let stale = f
                .rotations
                .iter()
                .any(|&rotation| r.at < rotation && rotation <= done);
            shares.push(serde_json::json!({"id":i,"arrival_s":r.at,"dispatch_s":dispatch,"done_s":done,"stale":stale,"digest":r.digest}));
        }
        let proofs = winners.join().unwrap();
        wait_until(start, f.duration_s);
        fs::write(f.output.join("traffic.json"),serde_json::to_vec_pretty(&serde_json::json!({"shares":shares,"proofs":proofs,"wall_s":start.elapsed().as_secs_f64()})).unwrap()).unwrap();
    });
    if let Some(winner) = &f.post_window_winner {
        save(winner, "alternate.proof.bin".into());
    }
}
