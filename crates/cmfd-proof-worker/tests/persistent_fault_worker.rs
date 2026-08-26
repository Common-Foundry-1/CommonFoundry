use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;
use std::time::Duration;

use cmfd_consensus::{
    BLOCK_VERSION, Block, BlockChallenge, Coinbase, ConsensusPowVerifier, v2_test_reference,
};
use cmfd_proof_worker::{PersistentVerifierWorker, VerifierWorkerConfig, VerifierWorkerError};
use sha2::{Digest, Sha256};

const SERVER_MODE: &str = "--verify-block-server";
const PROTOCOL_VERSION: u32 = 3;
const STARTUP_REQUEST_MAGIC: &[u8; 8] = b"CMFDVHQ1";
const STARTUP_RESPONSE_MAGIC: &[u8; 8] = b"CMFDVHR1";
const RESPONSE_MAGIC: &[u8; 8] = b"CMFDVWR1";
const STARTUP_SELF_TEST_DOMAIN: &[u8] = b"Common Foundry persistent verifier startup self-test v2";
const CONTAINMENT_PROFILE_DOMAIN: &[u8] = b"Common Foundry verifier containment profile v1";
const PROFILE_V2_REFERENCE: u8 = 2;
const SANDBOX_UNCONFINED: u8 = 0;
const STATUS_FAILURE: u8 = 1;
const ERROR_INTERNAL: u16 = 4;
const AUTH_FAILURE_MARKER: u8 = 0xfa;
const PROTOCOL_FAILURE_MARKER: u8 = 0xa5;
const WORKER_FAILURE_MARKER: u8 = 0xa6;

fn main() {
    if std::env::args().nth(1).as_deref() == Some(SERVER_MODE) {
        std::process::exit(run_fault_server().unwrap_or(1));
    }
    run_matrix();
}

fn run_matrix() {
    let executable = std::env::current_exe().unwrap();
    let executable_sha256 = sha256(&executable);

    let memory_base = 512_u64 * 1024 * 1024;
    let memory_candidates = || (0_u64..=4_096).map(|page| memory_base + page * 4_096);
    let auth_memory = memory_candidates()
        .find(|memory| containment_profile(*memory)[0] == AUTH_FAILURE_MARKER)
        .expect("test must find a page-aligned authentication marker");
    let (verifier, block) = candidate_block(0x11);
    let error = PersistentVerifierWorker::start(
        worker_config(&executable, executable_sha256, auth_memory),
        verifier,
        block.challenge.network_id,
    )
    .err()
    .expect("a mismatched startup self-test must fail authentication");
    assert!(matches!(&error, VerifierWorkerError::Startup(_)));
    assert!(!error.is_dispatched_proof_failure());

    let normal_memory = memory_candidates()
        .find(|memory| containment_profile(*memory)[0] != AUTH_FAILURE_MARKER)
        .unwrap();
    let (verifier, block) = candidate_block(PROTOCOL_FAILURE_MARKER);
    let worker = PersistentVerifierWorker::start(
        worker_config(&executable, executable_sha256, normal_memory),
        verifier,
        block.challenge.network_id,
    )
    .unwrap();
    let error = worker
        .verify_block(&block)
        .expect_err("malformed request response must fail closed");
    assert!(matches!(
        &error,
        VerifierWorkerError::DispatchedRequest(source)
            if matches!(source.as_ref(), VerifierWorkerError::Protocol(_))
    ));
    assert!(error.is_dispatched_proof_failure());

    let (verifier, block) = candidate_block(WORKER_FAILURE_MARKER);
    let worker = PersistentVerifierWorker::start(
        worker_config(&executable, executable_sha256, normal_memory),
        verifier,
        block.challenge.network_id,
    )
    .unwrap();
    let error = worker
        .verify_block(&block)
        .expect_err("request-scoped worker error must fail closed");
    assert!(matches!(
        &error,
        VerifierWorkerError::DispatchedRequest(source)
            if matches!(
                source.as_ref(),
                VerifierWorkerError::WorkerReported { code: ERROR_INTERNAL, .. }
            )
    ));
    assert!(error.is_dispatched_proof_failure());
}

fn candidate_block(marker: u8) -> (ConsensusPowVerifier, Block) {
    let reference = v2_test_reference().unwrap();
    let network_id = reference.descriptor().network_id;
    let verifier = ConsensusPowVerifier::v2_reference(reference);
    let challenge = BlockChallenge {
        network_id,
        previous_block: [marker; 32],
        transaction_root: [2; 32],
        height: 1,
        timestamp: 60,
        target: [0xff; 32],
    };
    let proof = verifier.mine(&challenge, 7, 1).unwrap();
    (
        verifier,
        Block {
            version: BLOCK_VERSION,
            challenge,
            proof,
            coinbase: Coinbase {
                height: 1,
                outputs: Vec::new(),
            },
            transactions: Vec::new(),
        },
    )
}

fn worker_config(
    executable: &Path,
    executable_sha256: [u8; 32],
    memory_limit_bytes: u64,
) -> VerifierWorkerConfig {
    VerifierWorkerConfig {
        worker_executable: executable.to_path_buf(),
        worker_sha256: executable_sha256,
        startup_timeout: Duration::from_secs(10),
        timeout: Duration::from_secs(10),
        memory_limit_bytes,
        cpu_quota_micros: None,
        cpu_period_micros: None,
        pids_limit: None,
        production_v3_record: None,
    }
}

fn containment_profile(memory_limit_bytes: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CONTAINMENT_PROFILE_DOMAIN);
    hasher.update([PROFILE_V2_REFERENCE, SANDBOX_UNCONFINED, 0]);
    hasher.update(memory_limit_bytes.to_le_bytes());
    hasher.update([0]);
    hasher.finalize().into()
}

fn run_fault_server() -> Result<i32, ()> {
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    let startup = read_frame(&mut input).map_err(|_| ())?;
    if startup.len() != 142
        || startup.get(..8) != Some(STARTUP_REQUEST_MAGIC.as_slice())
        || startup.get(8..12) != Some(PROTOCOL_VERSION.to_le_bytes().as_slice())
    {
        return Err(());
    }
    let profile = startup[12];
    let sandbox = startup[13];
    let network_id = &startup[14..46];
    let verifier_identity = &startup[46..78];
    let containment = &startup[78..110];
    let challenge = &startup[110..142];
    let mut self_test = Sha256::new();
    self_test.update(STARTUP_SELF_TEST_DOMAIN);
    self_test.update([profile, sandbox]);
    self_test.update(network_id);
    self_test.update(verifier_identity);
    self_test.update(containment);
    self_test.update(challenge);
    let mut self_test: [u8; 32] = self_test.finalize().into();
    if containment[0] == AUTH_FAILURE_MARKER {
        self_test[0] ^= 1;
    }
    let mut startup_response = Vec::with_capacity(143);
    startup_response.extend_from_slice(STARTUP_RESPONSE_MAGIC);
    startup_response.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    startup_response.extend_from_slice(&[0, profile, sandbox]);
    startup_response.extend_from_slice(network_id);
    startup_response.extend_from_slice(verifier_identity);
    startup_response.extend_from_slice(containment);
    startup_response.extend_from_slice(&self_test);
    write_frame(&mut output, &startup_response).map_err(|_| ())?;
    if containment[0] == AUTH_FAILURE_MARKER {
        let _ = read_frame(&mut input);
        return Ok(0);
    }

    let request = read_frame(&mut input).map_err(|_| ())?;
    let protocol_marker = [PROTOCOL_FAILURE_MARKER; 32];
    let worker_marker = [WORKER_FAILURE_MARKER; 32];
    let response = if request
        .windows(protocol_marker.len())
        .any(|window| window == protocol_marker)
    {
        b"malformed-response".to_vec()
    } else if request
        .windows(worker_marker.len())
        .any(|window| window == worker_marker)
    {
        encode_error_response(ERROR_INTERNAL, "request failed after dispatch")
    } else {
        return Err(());
    };
    write_frame(&mut output, &response).map_err(|_| ())?;
    Ok(0)
}

fn encode_error_response(code: u16, message: &str) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(RESPONSE_MAGIC);
    response.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    response.push(STATUS_FAILURE);
    response.extend_from_slice(&code.to_le_bytes());
    response.extend_from_slice(&(message.len() as u16).to_le_bytes());
    response.extend_from_slice(message.as_bytes());
    response
}

fn read_frame(reader: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut length = [0_u8; 4];
    reader.read_exact(&mut length)?;
    let mut bytes = vec![0_u8; u32::from_le_bytes(length) as usize];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn write_frame(writer: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    writer.write_all(&(bytes.len() as u32).to_le_bytes())?;
    writer.write_all(bytes)?;
    writer.flush()
}

fn sha256(path: &Path) -> [u8; 32] {
    let mut file = File::open(path).unwrap();
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).unwrap();
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    hasher.finalize().into()
}
