use k256::schnorr::{Signature, SigningKey, VerifyingKey, signature::Signer, signature::Verifier};

#[test]
fn signatures_and_public_keys_match_the_previous_library() {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/legacy-schnorr.json")).unwrap();
    assert_eq!(vectors["generator"], "k256 0.13.4");
    for row in vectors["signatures"].as_array().unwrap() {
        let secret = hex::decode(row["secret"].as_str().unwrap()).unwrap();
        let message = hex::decode(row["message"].as_str().unwrap()).unwrap();
        let public = hex::decode(row["public_key"].as_str().unwrap()).unwrap();
        let encoded = hex::decode(row["signature"].as_str().unwrap()).unwrap();
        let key = SigningKey::from_slice(&secret).unwrap();
        assert_eq!(key.verifying_key().to_bytes().as_slice(), public);
        let previous = Signature::try_from(encoded.as_slice()).unwrap();
        VerifyingKey::from_slice(&public)
            .unwrap()
            .verify(&message, &previous)
            .unwrap();
        let current: Signature = key.sign(&message);
        assert_eq!(current.to_bytes().as_slice(), encoded);
    }
}
