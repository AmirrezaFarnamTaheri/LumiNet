use lumicore::crypto::lower_base36::{decode, encode, encode_to_string, LowerBase36Error};
use lumicore::transport::dns_fragment_store::{CollectResult, DnsFragmentStore};
use lumicore::transport::multi_level_queue::MultiLevelQueue;
use lumicore::transport::packed_control_block::{
    pack_control_blocks, parse_packed_control_blocks, ControlBlock, PACKED_CONTROL_BLOCK_SIZE,
};
use std::time::Duration;

#[test]
fn test_lower_base36_codec() {
    // 1. Empty
    assert_eq!(encode(&[]), Vec::<u8>::new());
    assert_eq!(decode(&[]).unwrap(), Vec::<u8>::new());

    // 2. Exact 7-byte chunk => 11 chars
    let input7 = b"1234567";
    let encoded7 = encode_to_string(input7);
    assert_eq!(encoded7.len(), 11);
    let decoded7 = decode(encoded7.as_bytes()).unwrap();
    assert_eq!(decoded7, input7);

    // 3. Various lengths (1 to 20 bytes)
    for len in 1..=20 {
        let input: Vec<u8> = (0..len).map(|i| (i * 17 + 3) as u8).collect();
        let enc = encode(&input);
        let dec = decode(&enc).expect("decode should succeed");
        assert_eq!(dec, input, "failed at length {}", len);
    }

    // 4. Case insensitivity
    let upper = b"0ZZZZZZZZZZ";
    let lower = b"0zzzzzzzzzz";
    let dec_upper = decode(upper).unwrap();
    let dec_lower = decode(lower).unwrap();
    assert_eq!(dec_upper, dec_lower);

    // 5. Invalid character
    assert!(matches!(
        decode(b"0123456!89a"),
        Err(LowerBase36Error::InvalidCharacter('!'))
    ));
}

#[test]
fn test_multi_level_queue_priorities() {
    let mlq = MultiLevelQueue::<String>::new(16);

    // Push with different priorities: 5 (lowest), 3, 1, 0 (highest)
    assert!(mlq.push(5, 105, "p5-item".to_string()));
    assert!(mlq.push(3, 103, "p3-item".to_string()));
    assert!(mlq.push(1, 101, "p1-item".to_string()));
    assert!(mlq.push(0, 100, "p0-item".to_string()));

    // Key deduplication: re-pushing key 100 fails
    assert!(!mlq.push(0, 100, "duplicate".to_string()));
    assert_eq!(mlq.len(), 4);

    // Peek should observe highest priority (0)
    let (item, prio) = mlq.peek().unwrap();
    assert_eq!(item, "p0-item");
    assert_eq!(prio, 0);

    // Pops must arrive in strict priority order (0, 1, 3, 5)
    let (item0, prio0) = mlq.pop().unwrap();
    assert_eq!(item0, "p0-item");
    assert_eq!(prio0, 0);

    let (item1, prio1) = mlq.pop().unwrap();
    assert_eq!(item1, "p1-item");
    assert_eq!(prio1, 1);

    // Direct removal by key
    let removed = mlq.remove_by_key(105).unwrap();
    assert_eq!(removed, "p5-item");

    // Only p3 remains
    assert_eq!(mlq.len(), 1);
    let (item3, prio3) = mlq.pop().unwrap();
    assert_eq!(item3, "p3-item");
    assert_eq!(prio3, 3);

    // Now empty
    assert!(mlq.pop().is_none());
    assert_eq!(mlq.len(), 0);
}

#[test]
fn test_dns_fragment_store() {
    let store = DnsFragmentStore::<u64>::new(8);
    let retention = Duration::from_millis(500);

    // Single-fragment packet
    let res_single = store.collect(1, b"hello single", 0, 1, retention);
    assert_eq!(res_single, CollectResult::Assembled(b"hello single".to_vec()));

    // Duplicate within retention window is suppressed
    let res_dup = store.collect(1, b"hello single", 0, 1, retention);
    assert_eq!(res_dup, CollectResult::DuplicateSuppressed);

    // Multi-fragment packet (2 chunks) arriving out of order
    let key = 42;
    let res_frag1 = store.collect(key, b" world!", 1, 2, retention);
    assert_eq!(res_frag1, CollectResult::Incomplete);

    let res_frag0 = store.collect(key, b"hello", 0, 2, retention);
    assert_eq!(res_frag0, CollectResult::Assembled(b"hello world!".to_vec()));

    // Duplicate multi-fragment arrival suppressed
    let res_multi_dup = store.collect(key, b"hello", 0, 2, retention);
    assert_eq!(res_multi_dup, CollectResult::DuplicateSuppressed);
}

#[test]
fn test_packed_control_blocks() {
    assert_eq!(PACKED_CONTROL_BLOCK_SIZE, 7);

    let b1 = ControlBlock::new(0x01, 100, 1, 0, 1);
    let b2 = ControlBlock::new(0x02, 100, 2, 0, 1);
    let b3 = ControlBlock::new(0x06, 200, 1, 0, 1);

    let packed = pack_control_blocks(&[b1, b2, b3]);
    assert_eq!(packed.len(), 21);

    let unpacked = parse_packed_control_blocks(&packed);
    assert_eq!(unpacked.len(), 3);
    assert_eq!(unpacked[0], b1);
    assert_eq!(unpacked[1], b2);
    assert_eq!(unpacked[2], b3);
}
