//! # Multi-Path Micro-Dispersal Tests (TDD RED Phase)
//!
//! Verifies zero-copy byte stream chunking into MicroFrames, multi-runner striping,
//! and out-of-order sequence reassembly.
//!
//! Source: RFC 9293 (Stream Reassembly)
//! Best Practices: /leonardomso-rust-skills (mem-zero-copy, err-thiserror-lib, own-borrow-over-clone)

use bytes::Bytes;
use lumicore::relay::dispersal::{
    DispersalReassembler, EdgeEndpoint, EdgeRunnerType, MicroDisperser, MicroFrame,
};

#[test]
fn test_frame_chunking_and_multipath_striping() {
    let endpoints = vec![
        EdgeEndpoint {
            runner_type: EdgeRunnerType::CloudflareWorkers,
            url: "https://cf.example.workers.dev/relay".to_string(),
        },
        EdgeEndpoint {
            runner_type: EdgeRunnerType::VercelEdge,
            url: "https://edge.vercel.app/api/relay".to_string(),
        },
        EdgeEndpoint {
            runner_type: EdgeRunnerType::AWSLambda,
            url: "https://lambda.us-east-1.amazonaws.com/relay".to_string(),
        },
    ];

    let disperser = MicroDisperser::new(endpoints, 100); // 100 byte chunks

    let original_data = vec![0x42u8; 250]; // 250 bytes -> 3 frames (100, 100, 50)
    let frames = disperser.chunk_payload("session-123", "target.com:443", &original_data);

    assert_eq!(frames.len(), 3);
    assert_eq!(frames[0].chunk_idx, 0);
    assert_eq!(frames[0].data.len(), 100);
    assert_eq!(frames[1].chunk_idx, 1);
    assert_eq!(frames[1].data.len(), 100);
    assert_eq!(frames[2].chunk_idx, 2);
    assert_eq!(frames[2].data.len(), 50);

    // Verify endpoint assignment cycles across available endpoints
    assert_ne!(frames[0].endpoint_url, frames[1].endpoint_url);
}

#[test]
fn test_out_of_order_frame_reassembly() {
    let mut reassembler = DispersalReassembler::new();

    let frame0 = MicroFrame {
        session_id: "s1".to_string(),
        seq: 0,
        chunk_idx: 0,
        total_chunks: 3,
        data: Bytes::from_static(b"HELLO "),
        endpoint_url: "ep1".to_string(),
    };

    let frame1 = MicroFrame {
        session_id: "s1".to_string(),
        seq: 1,
        chunk_idx: 1,
        total_chunks: 3,
        data: Bytes::from_static(b"DISPERSED "),
        endpoint_url: "ep2".to_string(),
    };

    let frame2 = MicroFrame {
        session_id: "s1".to_string(),
        seq: 2,
        chunk_idx: 2,
        total_chunks: 3,
        data: Bytes::from_static(b"WORLD!"),
        endpoint_url: "ep3".to_string(),
    };

    // Feed out-of-order: Frame 2 first, then Frame 1, then Frame 0
    reassembler.push_frame(frame2);
    assert_eq!(reassembler.drain_contiguous().len(), 0); // No contiguous output yet

    reassembler.push_frame(frame1);
    assert_eq!(reassembler.drain_contiguous().len(), 0); // Still waiting for seq 0

    reassembler.push_frame(frame0);
    // Now seq 0, 1, 2 are all present
    let assembled = reassembler.drain_contiguous();
    assert_eq!(&assembled[..], b"HELLO DISPERSED WORLD!");
}
