//! # QUIC Stream Multiplexer
//!
//! Production QUIC stream multiplexing engine managing bidirectional and unidirectional
//! streams, offset tracking, flow control credit windows, and out-of-order frame reassembly.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QuicStreamType {
    ClientBidirectional,
    ServerBidirectional,
    ClientUnidirectional,
    ServerUnidirectional,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicStreamFrame {
    pub stream_id: u64,
    pub offset: u64,
    pub fin: bool,
    pub data: Vec<u8>,
}

struct StreamState {
    stream_type: QuicStreamType,
    send_offset: u64,
    recv_offset: u64,
    max_send_credit: u64,
    received_chunks: BTreeMap<u64, Vec<u8>>,
    fin_received: bool,
    fin_offset: Option<u64>,
}

pub struct QuicStreamMultiplexer {
    streams: HashMap<u64, StreamState>,
    next_client_bidi: u64,
    next_client_uni: u64,
    default_stream_window: u64,
}

impl QuicStreamMultiplexer {
    pub fn new(default_stream_window: u64) -> Self {
        Self {
            streams: HashMap::new(),
            next_client_bidi: 0, // Client bidi streams: 0, 4, 8, 12...
            next_client_uni: 2,  // Client uni streams: 2, 6, 10, 14...
            default_stream_window: default_stream_window.max(1024),
        }
    }

    pub fn open_stream(&mut self, stream_type: QuicStreamType) -> u64 {
        let stream_id = match stream_type {
            QuicStreamType::ClientBidirectional => {
                let id = self.next_client_bidi;
                self.next_client_bidi += 4;
                id
            }
            QuicStreamType::ClientUnidirectional => {
                let id = self.next_client_uni;
                self.next_client_uni += 4;
                id
            }
            QuicStreamType::ServerBidirectional => 1,
            QuicStreamType::ServerUnidirectional => 3,
        };

        self.streams.insert(
            stream_id,
            StreamState {
                stream_type,
                send_offset: 0,
                recv_offset: 0,
                max_send_credit: self.default_stream_window,
                received_chunks: BTreeMap::new(),
                fin_received: false,
                fin_offset: None,
            },
        );

        stream_id
    }

    pub fn write_stream_data(
        &mut self,
        stream_id: u64,
        data: &[u8],
        fin: bool,
    ) -> Result<QuicStreamFrame, String> {
        let stream = self.streams.get_mut(&stream_id).ok_or("Stream not found")?;

        let len = data.len() as u64;
        if stream.send_offset + len > stream.max_send_credit {
            return Err("Flow control window exceeded".to_string());
        }

        let frame = QuicStreamFrame {
            stream_id,
            offset: stream.send_offset,
            fin,
            data: data.to_vec(),
        };

        stream.send_offset += len;
        Ok(frame)
    }

    pub fn receive_stream_frame(&mut self, frame: QuicStreamFrame) -> Result<Vec<u8>, String> {
        let stream = self.streams.entry(frame.stream_id).or_insert_with(|| StreamState {
            stream_type: QuicStreamType::ClientBidirectional,
            send_offset: 0,
            recv_offset: 0,
            max_send_credit: self.default_stream_window,
            received_chunks: BTreeMap::new(),
            fin_received: false,
            fin_offset: None,
        });

        if frame.fin {
            stream.fin_received = true;
            stream.fin_offset = Some(frame.offset + frame.data.len() as u64);
        }

        stream.received_chunks.insert(frame.offset, frame.data);

        // Reassemble contiguous bytes starting from recv_offset
        let mut assembled = Vec::new();
        while let Some(&offset) = stream.received_chunks.keys().next() {
            if offset == stream.recv_offset {
                let chunk = stream.received_chunks.remove(&offset).unwrap();
                stream.recv_offset += chunk.len() as u64;
                assembled.extend_from_slice(&chunk);
            } else if offset < stream.recv_offset {
                // Overlapping or duplicate chunk, discard
                stream.received_chunks.remove(&offset);
            } else {
                // Gap in data stream
                break;
            }
        }

        Ok(assembled)
    }

    pub fn grant_flow_control_credit(&mut self, stream_id: u64, additional_bytes: u64) {
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.max_send_credit += additional_bytes;
        }
    }

    pub fn is_stream_closed(&self, stream_id: u64) -> bool {
        if let Some(stream) = self.streams.get(&stream_id) {
            if stream.fin_received {
                if let Some(fin_off) = stream.fin_offset {
                    return stream.recv_offset >= fin_off;
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quic_stream_multiplexer_ordered_reassembly() {
        let mut mux = QuicStreamMultiplexer::new(65536);
        let s0 = mux.open_stream(QuicStreamType::ClientBidirectional);
        assert_eq!(s0, 0);

        let frame1 = mux.write_stream_data(s0, b"Hello ", false).unwrap();
        assert_eq!(frame1.offset, 0);

        let frame2 = mux.write_stream_data(s0, b"World!", true).unwrap();
        assert_eq!(frame2.offset, 6);
        assert!(frame2.fin);

        // Test out-of-order receive: receive frame2 before frame1
        let mut receiver = QuicStreamMultiplexer::new(65536);
        let part2 = receiver.receive_stream_frame(frame2).unwrap();
        assert!(part2.is_empty(), "Cannot assemble out-of-order frame without offset 0");

        let part1 = receiver.receive_stream_frame(frame1).unwrap();
        // Upon receiving frame 1, both frame 1 and buffered frame 2 should be assembled!
        assert_eq!(part1, b"Hello World!");
        assert!(receiver.is_stream_closed(s0));
    }
}
