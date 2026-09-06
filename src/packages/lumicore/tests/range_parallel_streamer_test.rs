use lumicore::relay::range_parallel_streamer::*;

#[test]
fn test_compute_chunks_boundary_handling() {
    let total = 700_000u64;
    let chunk_sz = 256 * 1024u64; // 262,144 bytes
    let chunks = compute_chunks(total, chunk_sz).expect("compute chunks failed");

    // 700,000 / 262,144 = 2 full chunks + 1 partial chunk = 3 chunks
    assert_eq!(chunks.len(), 3);

    assert_eq!(chunks[0].chunk_index, 0);
    assert_eq!(chunks[0].start_byte, 0);
    assert_eq!(chunks[0].end_byte, 262143);
    assert_eq!(chunks[0].length(), 262144);
    assert_eq!(chunks[0].to_range_header(), "bytes=0-262143");

    assert_eq!(chunks[1].chunk_index, 1);
    assert_eq!(chunks[1].start_byte, 262144);
    assert_eq!(chunks[1].end_byte, 524287);
    assert_eq!(chunks[1].length(), 262144);
    assert_eq!(chunks[1].to_range_header(), "bytes=262144-524287");

    assert_eq!(chunks[2].chunk_index, 2);
    assert_eq!(chunks[2].start_byte, 524288);
    assert_eq!(chunks[2].end_byte, 699999);
    assert_eq!(chunks[2].length(), 175712);
    assert_eq!(chunks[2].to_range_header(), "bytes=524288-699999");
}

#[test]
fn test_parse_content_range() {
    // Valid standard Content-Range
    let res1 = parse_content_range("bytes 0-262143/1048576");
    assert_eq!(res1, Some((0, 262143, 1048576)));

    // Valid with mixed case and whitespace
    let res2 = parse_content_range("  BYTES 100-200/500  ");
    assert_eq!(res2, Some((100, 200, 500)));

    // Malformed cases
    assert_eq!(parse_content_range("invalid"), None);
    assert_eq!(parse_content_range("bytes 200-100/500"), None); // start > end
    assert_eq!(parse_content_range("bytes 0-500/500"), None); // end >= total
}

#[test]
fn test_range_parallel_stitcher_in_order_and_out_of_order() {
    let total = 30u64;
    let mut stitcher = RangeParallelStitcher::new(total).expect("create stitcher failed");

    let chunk0 = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    let chunk1 = vec![11, 12, 13, 14, 15, 16, 17, 18, 19, 20];
    let chunk2 = vec![21, 22, 23, 24, 25, 26, 27, 28, 29, 30];

    // Ingest chunk 1 first (out-of-order)
    stitcher.ingest_chunk(10, chunk1).unwrap();
    // Cannot drain yet because chunk 0 is missing
    assert_eq!(stitcher.drain_contiguous(), Vec::<u8>::new());
    assert!(!stitcher.is_complete());

    // Ingest chunk 2
    stitcher.ingest_chunk(20, chunk2).unwrap();
    assert_eq!(stitcher.drain_contiguous(), Vec::<u8>::new());

    // Ingest chunk 0
    stitcher.ingest_chunk(0, chunk0).unwrap();

    // Now everything drains contiguously in order 1..=30
    let drained = stitcher.drain_contiguous();
    assert_eq!(drained.len(), 30);
    let expected: Vec<u8> = (1..=30).collect();
    assert_eq!(drained, expected);
    assert!(stitcher.is_complete());
}
