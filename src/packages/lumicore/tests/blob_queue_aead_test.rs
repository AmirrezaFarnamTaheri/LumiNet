use lumicore::relay::{
    compute_nonce, derive_blob_key, derive_mux_lane_key_v4, open_blob_envelope,
    seal_blob_envelope, AdaptiveStreamCoalescer, BlobError, CoalesceTier, BLOB_MAGIC,
    BLOB_VERSION, DIRECTION_DOWN, DIRECTION_UP, FLAG_DATA, FLAG_FINAL,
};
use std::time::Duration;

#[test]
fn test_derive_blob_key_and_mux_lane_key() {
    let raw_secret = "super_covert_password_1234";
    let key1 = derive_blob_key(raw_secret).expect("derive key from raw passphrase");
    assert_eq!(key1.len(), 32);

    let sid = [0x42u8; 16];
    let lane0 = derive_mux_lane_key_v4(raw_secret, &sid, DIRECTION_UP, "client-a", "run-1", 0)
        .expect("derive lane 0 key");
    let lane1 = derive_mux_lane_key_v4(raw_secret, &sid, DIRECTION_UP, "client-a", "run-1", 1)
        .expect("derive lane 1 key");

    assert_eq!(lane0.len(), 32);
    assert_eq!(lane1.len(), 32);
    assert_ne!(lane0, lane1, "different lanes must have distinct keys");

    // Hex key
    let hex_secret = "hex:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    let key_hex = derive_blob_key(hex_secret).expect("derive hex key");
    assert_eq!(key_hex[0], 0x01);
    assert_eq!(key_hex[31], 0x20);
}

#[test]
fn test_seal_and_open_blob_envelope_roundtrip() {
    let key = [0x55u8; 32];
    let sid = [0xAAu8; 16];
    let seq = 1337u64;
    let plaintext = b"Hello, Covert Dead-Drop Tunneling Plane!";

    let sealed = seal_blob_envelope(&key, &sid, DIRECTION_UP, seq, plaintext, false)
        .expect("seal envelope");

    assert_eq!(&sealed[0..4], BLOB_MAGIC);
    assert_eq!(sealed[4], BLOB_VERSION);

    let (env, decrypted) = open_blob_envelope(&key, &sealed).expect("open envelope");
    assert_eq!(env.session_id, sid);
    assert_eq!(env.direction, DIRECTION_UP);
    assert_eq!(env.sequence, seq);
    assert_eq!(env.flags, FLAG_DATA);
    assert_eq!(env.plaintext_len, plaintext.len() as u32);
    assert_eq!(decrypted.as_slice(), plaintext);
}

#[test]
fn test_seal_and_open_final_envelope() {
    let key = [0x33u8; 32];
    let sid = [0xBBu8; 16];
    let seq = 42u64;
    let plaintext = b"FINAL_STREAM_EOF";

    let sealed = seal_blob_envelope(&key, &sid, DIRECTION_DOWN, seq, plaintext, true)
        .expect("seal final envelope");

    let (env, decrypted) = open_blob_envelope(&key, &sealed).expect("open envelope");
    assert_eq!(env.direction, DIRECTION_DOWN);
    assert_eq!(env.flags, FLAG_FINAL);
    assert_eq!(decrypted.as_slice(), plaintext);
}

#[test]
fn test_open_corrupted_envelope() {
    let key = [0x11u8; 32];
    let sid = [0x22u8; 16];
    let plaintext = b"Test corruption resiliency";

    let mut sealed = seal_blob_envelope(&key, &sid, DIRECTION_UP, 1, plaintext, false).unwrap();

    // 1. Corrupt magic
    sealed[0] = b'X';
    assert_eq!(open_blob_envelope(&key, &sealed), Err(BlobError::BadMagic));

    // Restore magic, corrupt payload byte
    sealed[0] = b'S';
    let last_idx = sealed.len() - 1;
    sealed[last_idx] ^= 0xFF;
    assert!(matches!(
        open_blob_envelope(&key, &sealed),
        Err(BlobError::CryptoError(_))
    ));
}

#[test]
fn test_adaptive_stream_coalescer() {
    assert_eq!(
        AdaptiveStreamCoalescer::evaluate_tier(1024),
        CoalesceTier::Interactive
    );
    assert_eq!(
        AdaptiveStreamCoalescer::evaluate_tier(16 * 1024),
        CoalesceTier::Medium
    );
    assert_eq!(
        AdaptiveStreamCoalescer::evaluate_tier(128 * 1024),
        CoalesceTier::Bulk
    );
    assert_eq!(
        AdaptiveStreamCoalescer::evaluate_tier(512 * 1024),
        CoalesceTier::ForcedBulk
    );

    // Test flush decisions
    assert!(!AdaptiveStreamCoalescer::should_flush(
        1000,
        Duration::from_millis(2)
    ));
    assert!(AdaptiveStreamCoalescer::should_flush(
        1000,
        Duration::from_millis(16)
    ));
    assert!(AdaptiveStreamCoalescer::should_flush(
        300 * 1024,
        Duration::from_millis(1)
    ));
}
