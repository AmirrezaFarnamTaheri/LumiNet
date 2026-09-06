use lumicore::security::encrypted_payload_envelope::{
    EncryptedPayloadCodec, EncryptedPayloadEnvelope, EnvelopeError,
};

#[test]
fn test_encrypt_and_decrypt_plaintext() {
    let passphrase = "test-secret-passphrase-whitevpn";
    let message = "https://example.com/sub/token123?param=val";

    let encrypted_json = EncryptedPayloadCodec::encrypt(message.as_bytes(), passphrase)
        .expect("encryption failed");

    let envelope: EncryptedPayloadEnvelope = serde_json::from_str(&encrypted_json)
        .expect("json parse failed");
    assert_eq!(envelope.version, 1);
    assert_eq!(envelope.algorithm, "AES-GCM");
    assert_eq!(envelope.encoding, "base64url");
    assert!(!envelope.iv.is_empty());
    assert!(!envelope.ciphertext.is_empty());

    let decrypted = EncryptedPayloadCodec::decrypt_text(&encrypted_json, passphrase)
        .expect("decryption failed");
    assert_eq!(decrypted, message);
}

#[test]
fn test_wrong_passphrase_fails_decryption() {
    let encrypted_json = EncryptedPayloadCodec::encrypt(b"secret payload", "correct-key")
        .unwrap();

    let err = EncryptedPayloadCodec::decrypt(&encrypted_json, "wrong-key")
        .expect_err("decryption should fail with wrong key");

    match err {
        EnvelopeError::CryptoError(_) => {}
        other => panic!("expected CryptoError, got {:?}", other),
    }
}

#[test]
fn test_parse_and_encrypt_ip_list() {
    let raw_ips = "192.0.2.1   198.51.100.1\n203.0.113.5\n\n192.0.2.1\ninvalid-ip  999.999.999.999\n1.1.1.1";
    let parsed = EncryptedPayloadCodec::parse_plaintext_ips(raw_ips);
    // Should deduplicate and keep valid IPv4
    assert_eq!(parsed, vec!["192.0.2.1", "198.51.100.1", "203.0.113.5", "1.1.1.1"]);

    let passphrase = "secure-clean-ip-key";
    let encrypted = EncryptedPayloadCodec::encrypt_ip_list(
        &["1.1.1.1", "8.8.8.8", "1.0.0.1"],
        passphrase,
    ).unwrap();

    let decrypted_ips = EncryptedPayloadCodec::decrypt_ip_list(&encrypted, passphrase)
        .unwrap();
    assert_eq!(decrypted_ips, vec!["1.1.1.1", "8.8.8.8", "1.0.0.1"]);
}
