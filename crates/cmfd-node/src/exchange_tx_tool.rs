//! Offline deposit-key and withdrawal-signing tool for exchange integrations.
//!
//! Runs without a node, data directory or network access. Secret keys stay in
//! local files chosen by the operator; the signed transaction is returned as
//! canonical wire hex for `sendrawtransaction`. Inputs, amounts and owners
//! come from the caller (normally `getaddressutxos`); the node still validates
//! the transaction against its own chain state when it is submitted.

use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use cmfd_consensus::wire::encode_transaction;
use cmfd_consensus::{
    InputWitness, MAX_TRANSACTION_INPUTS, MAX_TRANSACTION_OUTPUTS, OutPoint, OutputLock,
    TRANSACTION_VERSION, Transaction, TxInput, TxOutput,
};
use k256::schnorr::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

const KEY_FILE_BYTES: usize = 64;

#[derive(Debug, Error)]
pub enum ExchangeTxError {
    #[error("{0}")]
    Invalid(String),
    #[error("{operation} `{path}` failed: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },
}

fn invalid(message: impl Into<String>) -> ExchangeTxError {
    ExchangeTxError::Invalid(message.into())
}

/// One withdrawal to sign. Amounts are decimal atom strings.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignRequest {
    pub network_id: String,
    pub inputs: Vec<SignInput>,
    pub outputs: Vec<SignOutput>,
    /// Receives everything above outputs plus fee. Without it, inputs minus
    /// outputs must equal the fee exactly.
    #[serde(default)]
    pub change_destination_hex: Option<String>,
    pub fee_atoms: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignInput {
    pub txid: String,
    pub vout: u32,
    pub value_atoms: String,
    /// The output's owner as reported by `getaddressutxos`; the key file must match it.
    pub destination_hex: String,
    pub key_file: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignOutput {
    pub destination_hex: String,
    pub value_atoms: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SignedWithdrawal {
    pub txid: String,
    pub transaction_hex: String,
    pub bytes: usize,
    pub input_atoms: String,
    pub output_atoms: String,
    pub change_atoms: String,
    pub fee_atoms: String,
}

/// Creates a new key file (create-new, owner-only on Unix) and returns the
/// key's destination (x-only public key).
pub fn create_key_file(path: &Path) -> Result<[u8; 32], ExchangeTxError> {
    let key = SigningKey::random(&mut k256::elliptic_curve::rand_core::OsRng);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let io = |operation, source| ExchangeTxError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    };
    let mut file = options
        .open(path)
        .map_err(|source| io("create key file", source))?;
    let encoded = Zeroizing::new(format!("{}\n", hex::encode(key.to_bytes())));
    file.write_all(encoded.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|source| io("write key file", source))?;
    Ok(destination_of(&key))
}

/// Reads a key file written by [`create_key_file`]: 64 hex characters,
/// optionally followed by one line ending.
pub fn read_key_file(path: &Path) -> Result<SigningKey, ExchangeTxError> {
    let mut contents = Zeroizing::new(Vec::new());
    File::open(path)
        .and_then(|file| {
            file.take(KEY_FILE_BYTES as u64 + 3)
                .read_to_end(&mut contents)
        })
        .map_err(|source| ExchangeTxError::Io {
            operation: "read key file",
            path: path.to_path_buf(),
            source,
        })?;
    let text = std::str::from_utf8(&contents)
        .map_err(|_| invalid(format!("key file `{}` is not text", path.display())))?;
    let text = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(text);
    let mut secret = Zeroizing::new([0_u8; 32]);
    if text.len() != KEY_FILE_BYTES || hex::decode_to_slice(text, secret.as_mut()).is_err() {
        return Err(invalid(format!(
            "key file `{}` must contain exactly 64 hexadecimal characters",
            path.display()
        )));
    }
    SigningKey::from_bytes(secret.as_ref())
        .map_err(|_| invalid(format!("key file `{}` is not a valid key", path.display())))
}

pub fn destination_of(key: &SigningKey) -> [u8; 32] {
    key.verifying_key().to_bytes().into()
}

/// Builds and signs one withdrawal for `network_id` after checking every key
/// against its input owner and the network's fee floor.
pub fn sign_request(
    request: &SignRequest,
    network_id: [u8; 32],
) -> Result<SignedWithdrawal, ExchangeTxError> {
    if hex32(&request.network_id, "network_id")? != network_id {
        return Err(invalid(
            "network_id does not match the network this binary was built for",
        ));
    }
    if request.inputs.is_empty() || request.inputs.len() > MAX_TRANSACTION_INPUTS {
        return Err(invalid(format!(
            "a withdrawal needs 1 to {MAX_TRANSACTION_INPUTS} inputs"
        )));
    }
    let change_destination = request
        .change_destination_hex
        .as_deref()
        .map(|value| destination(value, "change_destination_hex"))
        .transpose()?;
    let output_limit = MAX_TRANSACTION_OUTPUTS - usize::from(change_destination.is_some());
    if request.outputs.is_empty() || request.outputs.len() > output_limit {
        return Err(invalid(format!(
            "a withdrawal needs 1 to {output_limit} payment outputs"
        )));
    }

    let mut seen = HashSet::new();
    let mut inputs = Vec::with_capacity(request.inputs.len());
    let mut keys = Vec::with_capacity(request.inputs.len());
    let mut input_atoms = 0_u64;
    for (position, input) in request.inputs.iter().enumerate() {
        let previous = OutPoint {
            txid: hex32(&input.txid, "input txid")?,
            index: input.vout,
        };
        if !seen.insert(previous) {
            return Err(invalid(format!(
                "input {position} spends a duplicated output"
            )));
        }
        let owner = destination(&input.destination_hex, "input destination_hex")?;
        let key = read_key_file(&input.key_file)?;
        if destination_of(&key) != owner {
            return Err(invalid(format!(
                "input {position}: key file `{}` does not own destination {}",
                input.key_file.display(),
                input.destination_hex
            )));
        }
        input_atoms = input_atoms
            .checked_add(atoms(&input.value_atoms, "input value_atoms")?)
            .ok_or_else(|| invalid("input total overflows"))?;
        inputs.push(TxInput {
            previous,
            witness: InputWitness::Key {
                public_key: owner,
                signature: Vec::new(),
            },
        });
        keys.push(key);
    }

    let mut outputs = Vec::with_capacity(request.outputs.len() + 1);
    let mut output_atoms = 0_u64;
    for output in &request.outputs {
        let value = atoms(&output.value_atoms, "output value_atoms")?;
        output_atoms = output_atoms
            .checked_add(value)
            .ok_or_else(|| invalid("output total overflows"))?;
        outputs.push(key_output(
            destination(&output.destination_hex, "output destination_hex")?,
            value,
        ));
    }
    let fee = atoms(&request.fee_atoms, "fee_atoms")?;
    let available = input_atoms
        .checked_sub(output_atoms)
        .and_then(|rest| rest.checked_sub(fee))
        .ok_or_else(|| {
            invalid(format!(
                "inputs ({input_atoms}) do not cover outputs ({output_atoms}) plus fee ({fee})"
            ))
        })?;
    let change = match change_destination {
        Some(change_destination) => {
            if available > 0 {
                outputs.push(key_output(change_destination, available));
            }
            available
        }
        None if available == 0 => 0,
        None => {
            return Err(invalid(format!(
                "inputs exceed outputs plus fee by {available} atoms; add change_destination_hex or raise the fee explicitly"
            )));
        }
    };

    let mut transaction = Transaction {
        network_id,
        version: TRANSACTION_VERSION,
        inputs,
        outputs,
    };
    let key_refs: Vec<&SigningKey> = keys.iter().collect();
    transaction
        .sign_all(&key_refs)
        .map_err(|error| invalid(format!("signing failed: {error}")))?;
    let encoded = encode_transaction(&transaction)
        .map_err(|error| invalid(format!("transaction is not encodable: {error}")))?;
    let required = crate::required_relay_fee(encoded.len(), network_id);
    if fee < required {
        return Err(invalid(format!(
            "fee {fee} atoms is below the network minimum of {required} atoms"
        )));
    }
    Ok(SignedWithdrawal {
        txid: hex::encode(transaction.txid()),
        transaction_hex: hex::encode(&encoded),
        bytes: encoded.len(),
        input_atoms: input_atoms.to_string(),
        output_atoms: output_atoms.to_string(),
        change_atoms: change.to_string(),
        fee_atoms: fee.to_string(),
    })
}

fn key_output(destination: [u8; 32], value: u64) -> TxOutput {
    // Ordinary outputs carry no lock; they are spendable once confirmed.
    TxOutput {
        value,
        lock: OutputLock::Key(destination),
        spendable_height: 0,
    }
}

fn hex32(value: &str, field: &str) -> Result<[u8; 32], ExchangeTxError> {
    let mut bytes = [0_u8; 32];
    if value.len() != 64
        || value.bytes().any(|byte| byte.is_ascii_uppercase())
        || hex::decode_to_slice(value, &mut bytes).is_err()
    {
        return Err(invalid(format!(
            "{field} must be 64 lowercase hexadecimal characters"
        )));
    }
    Ok(bytes)
}

fn destination(value: &str, field: &str) -> Result<[u8; 32], ExchangeTxError> {
    let bytes = hex32(value, field)?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|_| invalid(format!("{field} is not a valid x-only public key")))?;
    Ok(bytes)
}

fn atoms(value: &str, field: &str) -> Result<u64, ExchangeTxError> {
    let parsed = (!value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && (value == "0" || !value.starts_with('0')))
    .then(|| value.parse::<u64>().ok())
    .flatten()
    .ok_or_else(|| invalid(format!("{field} must be a canonical decimal atom string")))?;
    if parsed == 0 {
        return Err(invalid(format!("{field} must be greater than zero")));
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use cmfd_consensus::wire::{decode_block, decode_transaction};
    use cmfd_consensus::{COINBASE_MATURITY, PRODUCTION_V4_RCNET1_NETWORK_ID};

    use super::*;
    use crate::{DEFAULT_MINING_ATTEMPTS, DEVNET_GENESIS_TIMESTAMP, DEVNET_PROFILE, Node};

    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "cmfd-exchange-tx-{label}-{}-{}",
                std::process::id(),
                NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn mine(node: &mut Node, destination: [u8; 32]) {
        let timestamp = DEVNET_GENESIS_TIMESTAMP + node.state.next_height() * 60;
        node.mine_once(destination, timestamp, DEFAULT_MINING_ATTEMPTS)
            .unwrap();
    }

    fn request(
        network_id: [u8; 32],
        inputs: Vec<SignInput>,
        outputs: Vec<SignOutput>,
        change: Option<[u8; 32]>,
        fee: u64,
    ) -> SignRequest {
        SignRequest {
            network_id: hex::encode(network_id),
            inputs,
            outputs,
            change_destination_hex: change.map(hex::encode),
            fee_atoms: fee.to_string(),
        }
    }

    #[test]
    fn key_files_are_create_new_and_round_trip() {
        let dir = TestDirectory::new("keys");
        let path = dir.0.join("deposit.key");
        let destination = create_key_file(&path).unwrap();
        assert_eq!(destination_of(&read_key_file(&path).unwrap()), destination);
        assert!(matches!(
            create_key_file(&path),
            Err(ExchangeTxError::Io { .. })
        ));
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.len(), 65);
        std::fs::write(&path, text.trim_end()).unwrap();
        assert_eq!(destination_of(&read_key_file(&path).unwrap()), destination);
        std::fs::write(&path, "zz").unwrap();
        assert!(matches!(
            read_key_file(&path),
            Err(ExchangeTxError::Invalid(_))
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let fresh = dir.0.join("fresh.key");
            create_key_file(&fresh).unwrap();
            assert_eq!(
                std::fs::metadata(&fresh).unwrap().permissions().mode() & 0o077,
                0
            );
        }
    }

    #[test]
    fn signed_withdrawal_is_accepted_and_mined_by_the_node() {
        let data = TestDirectory::new("node");
        let keys = TestDirectory::new("node-keys");
        let hot_key = keys.0.join("hot.key");
        let hot = create_key_file(&hot_key).unwrap();
        let customer = create_key_file(&keys.0.join("customer.key")).unwrap();
        let mut node = Node::open_with_profile(&data.0, DEVNET_PROFILE).unwrap();
        let miner = node.wallet_destination();
        mine(&mut node, hot);
        let funded = node.active_block_id_at_height(1).unwrap();
        let block = node.canonical_block(funded).unwrap().unwrap();
        let block = decode_block(&block, DEVNET_PROFILE.network_id).unwrap();
        let coinbase_value = block.coinbase.outputs[0].value;
        for _ in 0..COINBASE_MATURITY {
            mine(&mut node, miner);
        }

        let signed = sign_request(
            &request(
                DEVNET_PROFILE.network_id,
                vec![SignInput {
                    txid: hex::encode(block.coinbase_outpoint_id()),
                    vout: 0,
                    value_atoms: coinbase_value.to_string(),
                    destination_hex: hex::encode(hot),
                    key_file: hot_key.clone(),
                }],
                vec![SignOutput {
                    destination_hex: hex::encode(customer),
                    value_atoms: "100000000".to_owned(),
                }],
                Some(hot),
                1_000,
            ),
            DEVNET_PROFILE.network_id,
        )
        .unwrap();
        assert_eq!(
            signed.change_atoms,
            (coinbase_value - 100_000_000 - 1_000).to_string()
        );
        let transaction = decode_transaction(
            &hex::decode(&signed.transaction_hex).unwrap(),
            DEVNET_PROFILE.network_id,
        )
        .unwrap();
        assert_eq!(hex::encode(transaction.txid()), signed.txid);
        node.submit_transaction(transaction).unwrap();
        mine(&mut node, miner);
        let paid = node
            .state
            .utxos()
            .iter()
            .filter(|(outpoint, output)| {
                hex::encode(outpoint.txid) == signed.txid
                    && output.lock == OutputLock::Key(customer)
            })
            .map(|(_, output)| output.value)
            .sum::<u64>();
        assert_eq!(paid, 100_000_000);
    }

    #[test]
    fn requests_that_would_lose_funds_or_use_the_wrong_key_are_refused() {
        let keys = TestDirectory::new("refusals");
        let owner_key = keys.0.join("owner.key");
        let owner = create_key_file(&owner_key).unwrap();
        let other_key = keys.0.join("other.key");
        create_key_file(&other_key).unwrap();
        let recipient = create_key_file(&keys.0.join("recipient.key")).unwrap();
        let network = DEVNET_PROFILE.network_id;
        let rcnet = PRODUCTION_V4_RCNET1_NETWORK_ID;
        let input = |key_file: &Path, value: u64| SignInput {
            txid: hex::encode([7_u8; 32]),
            vout: 0,
            value_atoms: value.to_string(),
            destination_hex: hex::encode(owner),
            key_file: key_file.to_path_buf(),
        };
        let pay = |value: u64| SignOutput {
            destination_hex: hex::encode(recipient),
            value_atoms: value.to_string(),
        };
        let refused = |request: SignRequest, network_id: [u8; 32], needle: &str| match sign_request(
            &request, network_id,
        ) {
            Err(ExchangeTxError::Invalid(message)) => {
                assert!(message.contains(needle), "{message}")
            }
            other => panic!("expected refusal containing {needle:?}, got {other:?}"),
        };
        let one = |key: &Path| vec![input(key, 10_000)];
        refused(
            request(network, one(&other_key), vec![pay(5_000)], Some(owner), 100),
            network,
            "does not own",
        );
        refused(
            request(network, one(&owner_key), vec![pay(5_000)], None, 100),
            network,
            "add change_destination_hex",
        );
        refused(
            request(network, one(&owner_key), vec![pay(9_950)], Some(owner), 100),
            network,
            "do not cover",
        );
        refused(
            request(
                network,
                vec![input(&owner_key, 10_000), input(&owner_key, 10_000)],
                vec![pay(5_000)],
                Some(owner),
                100,
            ),
            network,
            "duplicated",
        );
        refused(
            request(network, one(&owner_key), vec![pay(5_000)], Some(owner), 100),
            rcnet,
            "network_id does not match",
        );
        refused(
            request(rcnet, one(&owner_key), vec![pay(5_000)], Some(owner), 100),
            rcnet,
            "below the network minimum",
        );
        // Exact amounts without change are accepted.
        sign_request(
            &request(network, one(&owner_key), vec![pay(9_900)], None, 100),
            network,
        )
        .unwrap();
    }
}
