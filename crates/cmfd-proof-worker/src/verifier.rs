use std::ffi::OsStr;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use cmfd_consensus::{
    Block, ConsensusPowVerifier, ExternalPreverificationBinding, MAX_BLOCK_BYTES,
    PreverifiedBlockProof, decode_block, encode_block, v2_reference_for_network,
};
use thiserror::Error;

use super::{ProofWorkerError, exchange_with_child, spawn_contained, verify_file_hash};

const REQUEST_MAGIC: &[u8; 8] = b"CMFDVWQ1";
const RESPONSE_MAGIC: &[u8; 8] = b"CMFDVWR1";
const PROTOCOL_VERSION: u32 = 1;
const VERIFY_MODE: &str = "--verify-block";
const V3_BANK_ARGUMENT: &str = "--production-v3-bank";
const V3_MANIFEST_ARGUMENT: &str = "--production-v3-manifest";
const V3_RECORD_ARGUMENT: &str = "--production-v3-record-v2";
const REQUEST_FIXED_BYTES: usize = 8 + 4 + 32 + 32 + 32 + 4;
const SUCCESS_RESPONSE_BYTES: usize = 8 + 4 + 1 + 32 + 32;
const ERROR_RESPONSE_FIXED_BYTES: usize = 8 + 4 + 1 + 2 + 2;
const MAX_ERROR_BYTES: usize = 1_024;
const STATUS_SUCCESS: u8 = 0;
const STATUS_FAILURE: u8 = 1;
const ERROR_REQUEST: u16 = 1;
const ERROR_UNSUPPORTED_VERIFIER: u16 = 2;
const ERROR_PROOF_REJECTED: u16 = 3;
const ERROR_INTERNAL: u16 = 4;

/// Largest canonical verifier request, including one complete bounded block.
pub const MAX_VERIFIER_REQUEST_BYTES: usize = REQUEST_FIXED_BYTES + MAX_BLOCK_BYTES;
/// Largest canonical verifier response, including bounded diagnostic text.
pub const MAX_VERIFIER_RESPONSE_BYTES: usize = ERROR_RESPONSE_FIXED_BYTES + MAX_ERROR_BYTES;

/// Explicit executable identity and hard resource limits for one verifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifierWorkerConfig {
    pub worker_executable: PathBuf,
    pub worker_sha256: [u8; 32],
    pub timeout: Duration,
    pub memory_limit_bytes: u64,
    pub production_v3_artifacts: Option<ProductionV3VerifierArtifacts>,
}

/// Local paths to the three authenticated artifacts required by the V3
/// verifier. Paths are process configuration only and never enter consensus.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionV3VerifierArtifacts {
    pub bank: PathBuf,
    pub manifest: PathBuf,
    pub record_v2: PathBuf,
}

impl ProductionV3VerifierArtifacts {
    fn validate(&self) -> Result<(), VerifierWorkerError> {
        if !self.bank.is_absolute() || !self.manifest.is_absolute() || !self.record_v2.is_absolute()
        {
            return Err(VerifierWorkerError::InvalidConfig(
                "production V3 artifact paths must be absolute",
            ));
        }
        if self.bank == self.manifest
            || self.bank == self.record_v2
            || self.manifest == self.record_v2
        {
            return Err(VerifierWorkerError::InvalidConfig(
                "production V3 artifact paths must be pairwise distinct",
            ));
        }
        Ok(())
    }
}

impl VerifierWorkerConfig {
    pub fn validate(&self) -> Result<(), VerifierWorkerError> {
        if !self.worker_executable.is_absolute() {
            return Err(VerifierWorkerError::InvalidConfig(
                "worker executable path must be absolute",
            ));
        }
        if self.timeout.is_zero() {
            return Err(VerifierWorkerError::InvalidConfig(
                "worker timeout must be nonzero",
            ));
        }
        if self.memory_limit_bytes == 0 {
            return Err(VerifierWorkerError::InvalidConfig(
                "worker memory limit must be nonzero",
            ));
        }
        if usize::try_from(self.memory_limit_bytes).is_err() {
            return Err(VerifierWorkerError::InvalidConfig(
                "worker memory limit does not fit this platform",
            ));
        }
        if let Some(artifacts) = &self.production_v3_artifacts {
            artifacts.validate()?;
        }
        Ok(())
    }

    /// Validates the shape and caller-supplied executable identity before a
    /// node advertises the external verifier as available.
    pub fn validate_executable(&self) -> Result<(), VerifierWorkerError> {
        self.validate()?;
        verify_file_hash(
            "verifier worker executable",
            &self.worker_executable,
            self.worker_sha256,
        )?;
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum VerifierWorkerError {
    #[error("invalid verifier-worker configuration: {0}")]
    InvalidConfig(&'static str),
    #[error(transparent)]
    Process(#[from] ProofWorkerError),
    #[error("could not encode the verifier request block: {0}")]
    BlockEncoding(String),
    #[error("invalid verifier-worker protocol: {0}")]
    Protocol(#[from] VerifierProtocolError),
    #[error("verifier worker rejected the proof: {0}")]
    ProofRejected(String),
    #[error("verifier worker failed ({code}): {message}")]
    WorkerReported { code: u16, message: String },
    #[error("verifier worker response does not match the requested statement")]
    ResponseMismatch,
    #[error("could not issue the externally verified capability: {0}")]
    Capability(String),
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum VerifierProtocolError {
    #[error("message exceeds its protocol size bound")]
    TooLarge,
    #[error("message is truncated")]
    Truncated,
    #[error("message has trailing bytes")]
    TrailingBytes,
    #[error("message has the wrong magic")]
    Magic,
    #[error("unsupported protocol version {0}")]
    Version(u32),
    #[error("message length is invalid")]
    InvalidLength,
    #[error("message contains an invalid response status")]
    InvalidStatus,
    #[error("worker error code is not defined by this protocol version")]
    InvalidErrorCode,
    #[error("worker error text is not canonical UTF-8")]
    InvalidUtf8,
}

#[derive(Debug, PartialEq, Eq)]
struct VerifierRequest {
    network_id: [u8; 32],
    verifier_identity: [u8; 32],
    statement_identity: [u8; 32],
    block: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
enum VerifierResponse {
    Success {
        verifier_identity: [u8; 32],
        statement_identity: [u8; 32],
    },
    Failure {
        code: u16,
        message: String,
    },
}

/// Verifies one complete canonical block proof in a hash-pinned, killable,
/// memory-bounded child process and returns a capability bound to the exact
/// parent verifier, challenge, and proof bytes.
pub fn verify_block_out_of_process(
    config: &VerifierWorkerConfig,
    verifier: &ConsensusPowVerifier,
    block: &Block,
) -> Result<PreverifiedBlockProof, VerifierWorkerError> {
    config.validate_executable()?;
    let canonical = encode_block(block)
        .map_err(|error| VerifierWorkerError::BlockEncoding(error.to_string()))?;
    let binding = verifier
        .external_preverification_binding(&block.challenge, &block.proof)
        .map_err(|error| VerifierWorkerError::Capability(error.to_string()))?;
    let request = encode_request(VerifierRequest {
        network_id: block.challenge.network_id,
        verifier_identity: binding.verifier_identity(),
        statement_identity: binding.statement_identity(),
        block: canonical,
    })?;
    let mut command = Command::new(&config.worker_executable);
    command.arg(VERIFY_MODE);
    if let Some(artifacts) = &config.production_v3_artifacts {
        command
            .arg(V3_BANK_ARGUMENT)
            .arg(&artifacts.bank)
            .arg(V3_MANIFEST_ARGUMENT)
            .arg(&artifacts.manifest)
            .arg(V3_RECORD_ARGUMENT)
            .arg(&artifacts.record_v2);
    }
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = spawn_contained(&mut command, Some(config.memory_limit_bytes))?;
    let response =
        exchange_with_child(child, request, config.timeout, MAX_VERIFIER_RESPONSE_BYTES)?;
    require_matching_success(&response, binding)?;

    // SAFETY: the exact binding was returned by the caller-pinned worker only
    // after a canonical request, successful exit, bounded wall time, bounded
    // address space/job memory, and bounded stdout/stderr. Every failure above
    // returns without issuing a capability.
    unsafe { verifier.issue_external_preverification(&block.challenge, &block.proof, binding) }
        .map_err(|error| VerifierWorkerError::Capability(error.to_string()))
}

fn require_matching_success(
    response: &[u8],
    binding: ExternalPreverificationBinding,
) -> Result<(), VerifierWorkerError> {
    let (echoed_verifier, echoed_statement) = match decode_response(response)? {
        VerifierResponse::Success {
            verifier_identity,
            statement_identity,
        } => (verifier_identity, statement_identity),
        VerifierResponse::Failure { code, message } if code == ERROR_PROOF_REJECTED => {
            return Err(VerifierWorkerError::ProofRejected(message));
        }
        VerifierResponse::Failure { code, message } => {
            return Err(VerifierWorkerError::WorkerReported { code, message });
        }
    };
    if echoed_verifier != binding.verifier_identity()
        || echoed_statement != binding.statement_identity()
    {
        return Err(VerifierWorkerError::ResponseMismatch);
    }
    Ok(())
}

fn encode_request(request: VerifierRequest) -> Result<Vec<u8>, VerifierProtocolError> {
    if request.block.is_empty() || request.block.len() > MAX_BLOCK_BYTES {
        return Err(VerifierProtocolError::InvalidLength);
    }
    let block_len =
        u32::try_from(request.block.len()).map_err(|_| VerifierProtocolError::InvalidLength)?;
    let mut output = Vec::with_capacity(REQUEST_FIXED_BYTES + request.block.len());
    output.extend_from_slice(REQUEST_MAGIC);
    output.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    output.extend_from_slice(&request.network_id);
    output.extend_from_slice(&request.verifier_identity);
    output.extend_from_slice(&request.statement_identity);
    output.extend_from_slice(&block_len.to_le_bytes());
    output.extend_from_slice(&request.block);
    Ok(output)
}

fn decode_request(bytes: &[u8]) -> Result<VerifierRequest, VerifierProtocolError> {
    if bytes.len() > MAX_VERIFIER_REQUEST_BYTES {
        return Err(VerifierProtocolError::TooLarge);
    }
    let mut cursor = Cursor::new(bytes);
    if cursor.take(8)? != REQUEST_MAGIC {
        return Err(VerifierProtocolError::Magic);
    }
    let version = cursor.read_u32()?;
    if version != PROTOCOL_VERSION {
        return Err(VerifierProtocolError::Version(version));
    }
    let network_id = cursor.read_array()?;
    let verifier_identity = cursor.read_array()?;
    let statement_identity = cursor.read_array()?;
    let block_len =
        usize::try_from(cursor.read_u32()?).map_err(|_| VerifierProtocolError::InvalidLength)?;
    if block_len == 0 || block_len > MAX_BLOCK_BYTES || block_len != cursor.remaining() {
        return Err(VerifierProtocolError::InvalidLength);
    }
    let block = cursor.take(block_len)?.to_vec();
    cursor.finish()?;
    Ok(VerifierRequest {
        network_id,
        verifier_identity,
        statement_identity,
        block,
    })
}

fn encode_success_response(binding: ExternalPreverificationBinding) -> Vec<u8> {
    let mut output = Vec::with_capacity(SUCCESS_RESPONSE_BYTES);
    output.extend_from_slice(RESPONSE_MAGIC);
    output.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    output.push(STATUS_SUCCESS);
    output.extend_from_slice(&binding.verifier_identity());
    output.extend_from_slice(&binding.statement_identity());
    output
}

fn encode_error_response(code: u16, message: &str) -> Vec<u8> {
    let message = truncate_utf8(message, MAX_ERROR_BYTES);
    let mut output = Vec::with_capacity(ERROR_RESPONSE_FIXED_BYTES + message.len());
    output.extend_from_slice(RESPONSE_MAGIC);
    output.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    output.push(STATUS_FAILURE);
    output.extend_from_slice(&code.to_le_bytes());
    output.extend_from_slice(&(message.len() as u16).to_le_bytes());
    output.extend_from_slice(message.as_bytes());
    output
}

fn decode_response(bytes: &[u8]) -> Result<VerifierResponse, VerifierProtocolError> {
    if bytes.len() > MAX_VERIFIER_RESPONSE_BYTES {
        return Err(VerifierProtocolError::TooLarge);
    }
    let mut cursor = Cursor::new(bytes);
    if cursor.take(8)? != RESPONSE_MAGIC {
        return Err(VerifierProtocolError::Magic);
    }
    let version = cursor.read_u32()?;
    if version != PROTOCOL_VERSION {
        return Err(VerifierProtocolError::Version(version));
    }
    let response = match cursor.read_u8()? {
        STATUS_SUCCESS => VerifierResponse::Success {
            verifier_identity: cursor.read_array()?,
            statement_identity: cursor.read_array()?,
        },
        STATUS_FAILURE => {
            let code = cursor.read_u16()?;
            if !(ERROR_REQUEST..=ERROR_INTERNAL).contains(&code) {
                return Err(VerifierProtocolError::InvalidErrorCode);
            }
            let length = usize::from(cursor.read_u16()?);
            if length > MAX_ERROR_BYTES || length != cursor.remaining() {
                return Err(VerifierProtocolError::InvalidLength);
            }
            let message = std::str::from_utf8(cursor.take(length)?)
                .map_err(|_| VerifierProtocolError::InvalidUtf8)?
                .to_owned();
            VerifierResponse::Failure { code, message }
        }
        _ => return Err(VerifierProtocolError::InvalidStatus),
    };
    cursor.finish()?;
    Ok(response)
}

fn run_verifier_worker() -> Result<ExternalPreverificationBinding, (u16, String)> {
    let artifacts = parse_verifier_worker_arguments(std::env::args_os().skip(1))
        .map_err(|message| (ERROR_REQUEST, message.to_owned()))?;
    let request_bytes = read_stdin_bounded()
        .map_err(|error| (ERROR_INTERNAL, format!("could not read request: {error}")))?;
    let request =
        decode_request(&request_bytes).map_err(|error| (ERROR_REQUEST, error.to_string()))?;
    let block = decode_block(&request.block, request.network_id)
        .map_err(|error| (ERROR_REQUEST, error.to_string()))?;
    let canonical = encode_block(&block).map_err(|error| (ERROR_REQUEST, error.to_string()))?;
    if canonical != request.block {
        return Err((
            ERROR_REQUEST,
            "block request is not canonically encoded".to_owned(),
        ));
    }

    let verifier = match artifacts {
        Some(artifacts) => load_production_v3_verifier(request.network_id, &artifacts)?,
        None => {
            let reference = v2_reference_for_network(request.network_id).map_err(|error| {
                (
                    ERROR_INTERNAL,
                    format!("could not load V2 verifier: {error}"),
                )
            })?;
            ConsensusPowVerifier::v2_reference(reference)
        }
    };
    let expected = verifier
        .external_preverification_binding(&block.challenge, &block.proof)
        .map_err(|error| (ERROR_UNSUPPORTED_VERIFIER, error.to_string()))?;
    if request.verifier_identity != expected.verifier_identity() {
        return Err((
            ERROR_UNSUPPORTED_VERIFIER,
            "worker does not support the requested verifier identity".to_owned(),
        ));
    }
    if request.statement_identity != expected.statement_identity() {
        return Err((
            ERROR_REQUEST,
            "request binding does not match the canonical block".to_owned(),
        ));
    }
    verifier
        .verify(&block.challenge, &block.proof)
        .map_err(|error| (ERROR_PROOF_REJECTED, error.to_string()))?;
    Ok(expected)
}

fn parse_verifier_worker_arguments(
    arguments: impl IntoIterator<Item = std::ffi::OsString>,
) -> Result<Option<ProductionV3VerifierArtifacts>, &'static str> {
    let arguments = arguments.into_iter().collect::<Vec<_>>();
    if arguments.len() == 1 && arguments[0].as_os_str() == OsStr::new(VERIFY_MODE) {
        return Ok(None);
    }
    if arguments.len() != 7
        || arguments[0].as_os_str() != OsStr::new(VERIFY_MODE)
        || arguments[1].as_os_str() != OsStr::new(V3_BANK_ARGUMENT)
        || arguments[3].as_os_str() != OsStr::new(V3_MANIFEST_ARGUMENT)
        || arguments[5].as_os_str() != OsStr::new(V3_RECORD_ARGUMENT)
    {
        return Err(
            "expected --verify-block alone or with the exact production V3 bank, manifest, and Record V2 arguments",
        );
    }
    let artifacts = ProductionV3VerifierArtifacts {
        bank: PathBuf::from(&arguments[2]),
        manifest: PathBuf::from(&arguments[4]),
        record_v2: PathBuf::from(&arguments[6]),
    };
    artifacts
        .validate()
        .map_err(|_| "production V3 verifier artifact paths are invalid")?;
    Ok(Some(artifacts))
}

#[cfg(feature = "production-v3")]
fn load_production_v3_verifier(
    network_id: [u8; 32],
    artifacts: &ProductionV3VerifierArtifacts,
) -> Result<ConsensusPowVerifier, (u16, String)> {
    cmfd_consensus::dory_v3_model_bank_record_validation::load_production_dory_v3_consensus_verifier(
        network_id,
        &artifacts.bank,
        &artifacts.manifest,
        &artifacts.record_v2,
    )
    .map(|loaded| loaded.into_verifier())
    .map_err(|error| {
        (
            ERROR_INTERNAL,
            format!("could not authenticate production V3 verifier artifacts: {error}"),
        )
    })
}

#[cfg(not(feature = "production-v3"))]
fn load_production_v3_verifier(
    _network_id: [u8; 32],
    _artifacts: &ProductionV3VerifierArtifacts,
) -> Result<ConsensusPowVerifier, (u16, String)> {
    Err((
        ERROR_UNSUPPORTED_VERIFIER,
        "this proof worker was built without production V3 verifier support".to_owned(),
    ))
}

pub(super) fn verifier_mode_requested() -> bool {
    std::env::args_os().nth(1).as_deref() == Some(OsStr::new(VERIFY_MODE))
}

pub(super) fn verifier_worker_main() -> i32 {
    let response = match run_verifier_worker() {
        Ok(binding) => encode_success_response(binding),
        Err((code, message)) => encode_error_response(code, &message),
    };
    match io::stdout().write_all(&response) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn read_stdin_bounded() -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    io::stdin()
        .take((MAX_VERIFIER_REQUEST_BYTES as u64).saturating_add(1))
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn truncate_utf8(value: &str, max_bytes: usize) -> &str {
    if value.len() <= max_bytes {
        return value;
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.position
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], VerifierProtocolError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(VerifierProtocolError::Truncated)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(VerifierProtocolError::Truncated)?;
        self.position = end;
        Ok(value)
    }

    fn read_u8(&mut self) -> Result<u8, VerifierProtocolError> {
        Ok(self.take(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16, VerifierProtocolError> {
        Ok(u16::from_le_bytes(self.read_array()?))
    }

    fn read_u32(&mut self) -> Result<u32, VerifierProtocolError> {
        Ok(u32::from_le_bytes(self.read_array()?))
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], VerifierProtocolError> {
        self.take(N)?
            .try_into()
            .map_err(|_| VerifierProtocolError::Truncated)
    }

    fn finish(self) -> Result<(), VerifierProtocolError> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(VerifierProtocolError::TrailingBytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use cmfd_consensus::{
        BLOCK_VERSION, BlockChallenge, BlockProof, Coinbase, ForgeMatrixV3CandidateProof,
        v2_test_reference,
    };

    use super::*;

    fn candidate_block() -> (ConsensusPowVerifier, Block) {
        let reference = v2_test_reference().unwrap();
        let network_id = reference.descriptor().network_id;
        let verifier = ConsensusPowVerifier::v2_reference(reference);
        let challenge = BlockChallenge {
            network_id,
            previous_block: [1; 32],
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

    #[test]
    fn verifier_request_round_trips_and_rejects_noncanonical_lengths() {
        let (verifier, block) = candidate_block();
        let binding = verifier
            .external_preverification_binding(&block.challenge, &block.proof)
            .unwrap();
        let canonical = encode_block(&block).unwrap();
        let request = VerifierRequest {
            network_id: block.challenge.network_id,
            verifier_identity: binding.verifier_identity(),
            statement_identity: binding.statement_identity(),
            block: canonical,
        };
        let encoded = encode_request(request).unwrap();
        let decoded = decode_request(&encoded).unwrap();
        assert_eq!(decoded.network_id, block.challenge.network_id);
        assert_eq!(decoded.verifier_identity, binding.verifier_identity());
        assert_eq!(decoded.statement_identity, binding.statement_identity());
        assert_eq!(decoded.block, encode_block(&block).unwrap());

        let mut truncated = encoded.clone();
        truncated.pop();
        assert_eq!(
            decode_request(&truncated),
            Err(VerifierProtocolError::InvalidLength)
        );
        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            decode_request(&trailing),
            Err(VerifierProtocolError::InvalidLength)
        );
        assert_eq!(
            decode_request(&vec![0; MAX_VERIFIER_REQUEST_BYTES + 1]),
            Err(VerifierProtocolError::TooLarge)
        );
    }

    #[test]
    fn verifier_response_binds_both_identities_and_rejects_malformed_streams() {
        let (verifier, block) = candidate_block();
        let binding = verifier
            .external_preverification_binding(&block.challenge, &block.proof)
            .unwrap();
        let encoded = encode_success_response(binding);
        assert_eq!(
            decode_response(&encoded).unwrap(),
            VerifierResponse::Success {
                verifier_identity: binding.verifier_identity(),
                statement_identity: binding.statement_identity(),
            }
        );

        let mut substituted = encoded.clone();
        substituted[SUCCESS_RESPONSE_BYTES - 1] ^= 1;
        let VerifierResponse::Success {
            verifier_identity,
            statement_identity,
        } = decode_response(&substituted).unwrap()
        else {
            unreachable!();
        };
        assert!(
            verifier_identity != binding.verifier_identity()
                || statement_identity != binding.statement_identity()
        );
        assert!(matches!(
            require_matching_success(&substituted, binding),
            Err(VerifierWorkerError::ResponseMismatch)
        ));

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            decode_response(&trailing),
            Err(VerifierProtocolError::TrailingBytes)
        );
        let mut bad_status = encoded;
        bad_status[12] = 9;
        assert_eq!(
            decode_response(&bad_status),
            Err(VerifierProtocolError::InvalidStatus)
        );
    }

    #[test]
    fn v3_candidate_remains_unsupported_by_the_worker_verifier() {
        let (verifier, mut block) = candidate_block();
        block.proof = BlockProof::V3Candidate(Box::new(ForgeMatrixV3CandidateProof {
            algorithm_version: 3,
            proof_version: 1,
            nonce: 7,
            model_manifest_digest: [3; 32],
            challenge_digest: [4; 32],
            final_activation_digest: [5; 32],
            work_digest: [6; 32],
            structured_proof: vec![1],
        }));
        assert!(verifier.verify(&block.challenge, &block.proof).is_err());
    }

    #[test]
    fn verifier_worker_arguments_never_infer_or_fallback_between_profiles() {
        assert_eq!(
            parse_verifier_worker_arguments([std::ffi::OsString::from(VERIFY_MODE)]).unwrap(),
            None
        );

        let root = std::env::current_dir().unwrap();
        let bank = root.join("model.bank");
        let manifest = root.join("model.manifest.json");
        let record_v2 = root.join("model.record-v2.json");
        let parsed = parse_verifier_worker_arguments([
            std::ffi::OsString::from(VERIFY_MODE),
            std::ffi::OsString::from(V3_BANK_ARGUMENT),
            bank.clone().into_os_string(),
            std::ffi::OsString::from(V3_MANIFEST_ARGUMENT),
            manifest.clone().into_os_string(),
            std::ffi::OsString::from(V3_RECORD_ARGUMENT),
            record_v2.clone().into_os_string(),
        ])
        .unwrap()
        .unwrap();
        assert_eq!(
            parsed,
            ProductionV3VerifierArtifacts {
                bank,
                manifest,
                record_v2,
            }
        );

        assert!(
            parse_verifier_worker_arguments([
                std::ffi::OsString::from(VERIFY_MODE),
                std::ffi::OsString::from(V3_BANK_ARGUMENT),
            ])
            .is_err()
        );
    }

    #[test]
    fn verifier_config_requires_absolute_path_and_nonzero_limits() {
        let mut config = VerifierWorkerConfig {
            worker_executable: PathBuf::from("worker"),
            worker_sha256: [0; 32],
            timeout: Duration::from_secs(1),
            memory_limit_bytes: 1,
            production_v3_artifacts: None,
        };
        assert!(matches!(
            config.validate(),
            Err(VerifierWorkerError::InvalidConfig(_))
        ));
        config.worker_executable = std::env::current_exe().unwrap();
        config.timeout = Duration::ZERO;
        assert!(matches!(
            config.validate(),
            Err(VerifierWorkerError::InvalidConfig(_))
        ));
        config.timeout = Duration::from_secs(1);
        config.memory_limit_bytes = 0;
        assert!(matches!(
            config.validate(),
            Err(VerifierWorkerError::InvalidConfig(_))
        ));
        config.memory_limit_bytes = 1;
        config.production_v3_artifacts = Some(ProductionV3VerifierArtifacts {
            bank: PathBuf::from("relative-bank"),
            manifest: PathBuf::from("relative-manifest"),
            record_v2: PathBuf::from("relative-record"),
        });
        assert!(matches!(
            config.validate(),
            Err(VerifierWorkerError::InvalidConfig(_))
        ));
    }
}
