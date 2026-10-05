//! Golden vectors for the browser wallet, produced by the real consensus and wallet-backup code.
use std::path::PathBuf;

use cmfd_consensus::wire::{decode_transaction, encode_transaction, network_magic};
use cmfd_consensus::{InputWitness, OutPoint, OutputLock, Transaction, TxInput, TxOutput};
use k256::schnorr::signature::Verifier;
use k256::schnorr::{Signature, SigningKey, VerifyingKey};
use serde_json::{Value, json};

const MAINNET: &str = "88296bc39c10e8bc1dd4818d4d42412fe5f08210651110377f495da299812f62";

fn mainnet() -> [u8; 32] {
    hex::decode(MAINNET).unwrap().try_into().unwrap()
}

fn key(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32]).unwrap()
}

fn owner(key: &SigningKey) -> [u8; 32] {
    key.verifying_key().to_bytes().into()
}

fn unsigned_input(txid: u8, index: u32) -> TxInput {
    TxInput {
        previous: OutPoint { txid: [txid; 32], index },
        witness: InputWitness::Key { public_key: [0; 32], signature: Vec::new() },
    }
}

fn vector(name: &str, mut tx: Transaction, signer: &SigningKey) -> Value {
    let unsigned = json!({
        "network_id": hex::encode(tx.network_id),
        "version": tx.version,
        "inputs": tx.inputs.iter().map(|i| json!({"txid": hex::encode(i.previous.txid), "index": i.previous.index})).collect::<Vec<_>>(),
        "outputs": tx.outputs.iter().map(|o| {
            let OutputLock::Key(k) = o.lock else { unreachable!() };
            json!({"value": o.value.to_string(), "destination": hex::encode(k), "spendable_height": o.spendable_height})
        }).collect::<Vec<_>>(),
    });
    let keys = vec![signer; tx.inputs.len()];
    tx.sign_all(&keys).unwrap();
    let frame = encode_transaction(&tx).unwrap();
    let signature = match &tx.inputs[0].witness {
        InputWitness::Key { signature, .. } => hex::encode(signature),
        _ => unreachable!(),
    };
    json!({
        "name": name,
        "secret": hex::encode(signer.to_bytes()),
        "public_key": hex::encode(owner(signer)),
        "transaction": unsigned,
        "signing_digest": hex::encode(tx.signing_digest()),
        "signature": signature,
        "txid": hex::encode(tx.txid()),
        "frame": hex::encode(frame),
    })
}

fn vectors() -> Value {
    let network_id = mainnet();
    let sender = key(0x11);
    let recipient = owner(&key(0x22));
    let one_input = Transaction {
        network_id,
        version: 1,
        inputs: vec![unsigned_input(0xaa, 1)],
        outputs: vec![
            TxOutput { value: 123_456_789, lock: OutputLock::Key(recipient), spendable_height: 3_567 },
            TxOutput { value: 987_654_321, lock: OutputLock::Key(owner(&sender)), spendable_height: 3_567 },
        ],
    };
    let three_inputs = Transaction {
        network_id,
        version: 1,
        inputs: vec![unsigned_input(0x01, 0), unsigned_input(0x02, 7), unsigned_input(0xfe, 65_535)],
        outputs: vec![TxOutput { value: u64::MAX / 3, lock: OutputLock::Key(recipient), spendable_height: 0 }],
    };
    let secrets: Vec<Value> = [0x01u8, 0x11, 0x7f, 0xfe]
        .iter()
        .map(|b| json!({"secret": hex::encode([*b; 32]), "public_key": hex::encode(owner(&key(*b)))}))
        .collect();
    json!({
        "network_id": MAINNET,
        "network_magic": hex::encode(network_magic(&network_id)),
        "secrets": secrets,
        "transactions": [
            vector("one_input_two_outputs", one_input, &sender),
            vector("three_inputs_one_output", three_inputs, &key(0x7f)),
        ],
    })
}

/// Decodes a browser-built frame with the consensus decoder and checks every signature.
fn verify(frame_hex: &str) -> Value {
    let frame = hex::decode(frame_hex).unwrap();
    let tx = decode_transaction(&frame, mainnet()).unwrap();
    let digest = tx.signing_digest();
    for input in &tx.inputs {
        let InputWitness::Key { public_key, signature } = &input.witness else { panic!("wrong witness") };
        let key = VerifyingKey::from_bytes(public_key).unwrap();
        let signature = Signature::try_from(signature.as_slice()).unwrap();
        key.verify(&digest, &signature).expect("signature verifies");
    }
    assert_eq!(encode_transaction(&tx).unwrap(), frame, "frame is canonical");
    json!({"txid": hex::encode(tx.txid()), "inputs": tx.inputs.len(), "outputs": tx.outputs.len()})
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let out = match args.get(1).map(String::as_str) {
        Some("vectors") => vectors(),
        Some("verify") => verify(&args[2]),
        // backup-create <scratch-dir> <passphrase> <secret-byte>: a backup of a known secret.
        Some("backup-create") => {
            let dir = PathBuf::from(&args[2]);
            let byte: u8 = args[4].parse().unwrap();
            let data = dir.join("data");
            std::fs::create_dir_all(&data).unwrap();
            std::fs::write(data.join("wallet.key"), [byte; 32]).unwrap();
            let backup = dir.join("known.cmfd-backup");
            let info = cmfd_node::wallet_backup::migrate_plaintext_wallet_key(&data, &backup, mainnet(), args[3].as_bytes()).unwrap();
            json!({"backup": backup, "secret": hex::encode([byte; 32]), "destination": hex::encode(info.destination)})
        }
        // backup-verify <backup-file> <scratch-dir> <passphrase>: restore and authenticate with the node code.
        Some("backup-verify") => {
            let data = PathBuf::from(&args[3]);
            std::fs::create_dir_all(&data).unwrap();
            let info = cmfd_node::wallet_backup::restore_encrypted_wallet_backup(PathBuf::from(&args[2]).as_path(), &data, mainnet(), args[4].as_bytes()).unwrap();
            let destination = cmfd_node::wallet_backup::authenticate_encrypted_wallet(&data, mainnet(), args[4].as_bytes()).unwrap();
            assert_eq!(destination, info.destination);
            json!({"destination": hex::encode(destination)})
        }
        _ => panic!("usage: vectors | verify <frame> | backup-create <dir> <pass> <byte> | backup-verify <file> <dir> <pass>"),
    };
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
