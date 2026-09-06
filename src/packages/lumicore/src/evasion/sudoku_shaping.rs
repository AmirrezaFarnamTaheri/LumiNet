//! # Sudoku Shaping (Xray "finalmask" / "Sudoku" technique)
//!
//! Deterministic-yet-pseudo-random padding sequence that defeats passive DPI
//! fingerprinting of TLS record length distributions.
//!
//! re-implementation, not a line-by-line copy. The Xray "finalmask" technique
//! walks a 9x9 lookup table containing padding lengths; the walk direction is
//! chosen by the current byte so that observers cannot predict the next
//! padding length from the past few, yet both endpoints derive the same
//! sequence without additional signalling.
//!
//! ## Algorithm
//!
//! 1. The shape is a fixed 9x9 matrix of `u16` padding lengths. Each row is
//!    a permutation of the digits 1..=9 (no zeros, no repeats) so the per-row
//!    distribution is uniform.
//! 2. Before each payload chunk we emit `prefix_len` random bytes
//!    (XORed through a 16-bit LFSR seeded from a 32-bit key) so the wire
//!    trace does not leak the location of the real payload boundaries.
//! 3. After each chunk we emit `matrix[prev_row][prev_col] - prev_byte` filler
//!    bytes from the same LFSR, where `(prev_row, prev_col)` and `prev_byte`
//!    are derived deterministically from the running PRNG state.
//! 4. The receiver strips the same shape because it knows the seed, so
//!    padding is fully recoverable but not predictable to a passive observer
//!    who only sees the encrypted stream.

use rand::{RngCore, SeedableRng};
use rand::rngs::StdRng;
use thiserror::Error;

/// Side of the channel emitting or receiving shaped traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShapingRole {
    /// Adds filler bytes to outgoing data.
    Sender,
    /// Strips filler bytes from incoming data.
    Receiver,
}

/// Direction the cursor walks through the 9x9 matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkMode {
    /// Cursor = (cursor + 1) % 81 every step.
    Linear,
    /// Cursor walks diagonally (row+col) % 9, providing better dispersion for
    /// short bursts of identical payloads.
    Diagonal,
    /// Cursor uses the high nibble of the last payload byte to choose the
    /// next row; the low nibble chooses the column. This is the
    /// classic "finalmask" rule.
    PayloadGuided,
}

/// Sudoku shaping configuration.
#[derive(Debug, Clone)]
pub struct SudokuConfig {
    /// 32-bit seed shared by sender and receiver.
    pub seed: u32,
    /// Number of bytes to prepend as a random prefix (XORed through LFSR).
    /// Set to 0 to disable prefixing.
    pub prefix_len: usize,
    /// Walk mode for the matrix cursor.
    pub walk_mode: WalkMode,
    /// When `true`, the `shape` step appends filler only. When `false`, it
    /// also interleaves a random byte every `interleave_step` bytes.
    pub interleave_enabled: bool,
    /// Distance between interleaved random bytes when enabled.
    pub interleave_step: usize,
}

impl Default for SudokuConfig {
    fn default() -> Self {
        Self {
            seed: 0x9e3779b1,
            prefix_len: 16,
            walk_mode: WalkMode::PayloadGuided,
            interleave_enabled: true,
            interleave_step: 32,
        }
    }
}

/// Errors that can occur while shaping or unshaping a buffer.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ShapingError {
    /// The shaped buffer is shorter than the configured prefix length.
    #[error("shaped buffer is shorter than prefix_len ({got} < {expected})")]
    PrefixUnderflow { got: usize, expected: usize },
    /// The shaped buffer is shorter than the expected filler block.
    #[error("filler block underflow: need {needed} bytes, have {got}")]
    FillerUnderflow { needed: usize, got: usize },
    /// The internal 16-bit LFSR was asked for more data than it can produce.
    #[error("LFSR request of {requested} bytes exceeds 16-bit state capacity")]
    LfsrExhausted { requested: usize },
}

/// The fixed 9x9 Sudoku shaping matrix.
///
/// Each row is a permutation of the digits 1..=9 so the per-row distribution
/// is uniform. Rows and columns were chosen to maximise the Hamming distance
/// between adjacent cells under all three walk modes.
pub const SUDOKU_MATRIX: [[u16; 9]; 9] = [
    [3, 7, 1, 9, 5, 2, 8, 4, 6],
    [9, 2, 6, 4, 8, 7, 1, 5, 3],
    [5, 8, 4, 1, 3, 6, 9, 7, 2],
    [2, 1, 9, 7, 6, 4, 5, 3, 8],
    [6, 4, 7, 3, 1, 8, 2, 9, 5],
    [8, 5, 3, 6, 9, 1, 4, 2, 7],
    [1, 9, 5, 2, 4, 3, 7, 6, 8],
    [4, 3, 8, 5, 7, 9, 6, 1, 2],
    [7, 6, 2, 8, 1, 5, 3, 9, 4],
];

/// 16-bit linear-feedback shift register. Period = 65535 (the all-zero state
/// is forbidden, so the maximum sequence length is `2^16 - 1`).
#[derive(Debug, Clone, Copy)]
pub struct Lfsr16 {
    state: u16,
}

impl Lfsr16 {
    /// Build an LFSR from a non-zero seed. A seed of 0 is replaced by 0xACE1
    /// so the all-zero state is never reached.
    pub fn new(seed: u16) -> Self {
        let state = if seed == 0 { 0xACE1 } else { seed };
        Self { state }
    }

    /// Advance the LFSR by one step and return the low byte of the new state.
    /// Uses the polynomial `x^16 + x^14 + x^13 + x^11 + 1`, the same one
    /// Xray ships in its maskmasks implementation.
    pub fn next_byte(&mut self) -> u8 {
        // Galois form: tap bits 16, 14, 13, 11.
        let bit = ((self.state >> 0) ^ (self.state >> 2) ^ (self.state >> 3) ^ (self.state >> 5))
            & 1;
        self.state = (self.state >> 1) | (bit << 15);
        (self.state & 0xFF) as u8
    }

    /// Fill `buf` with LFSR bytes. Returns `LfsrExhausted` if `buf` exceeds
    /// the LFSR's period of 65535 bytes, but in practice the engine feeds
    /// the LFSR in small (<1 KiB) chunks so this branch is unreachable.
    pub fn fill(&mut self, buf: &mut [u8]) -> Result<(), ShapingError> {
        if buf.len() > usize::from(u16::MAX) {
            return Err(ShapingError::LfsrExhausted {
                requested: buf.len(),
            });
        }
        for byte in buf.iter_mut() {
            *byte = self.next_byte();
        }
        Ok(())
    }
}

/// Cursor over the 9x9 Sudoku matrix.
#[derive(Debug, Clone, Copy)]
pub struct SudokuCursor {
    row: usize,
    col: usize,
    step: u64,
}

impl SudokuCursor {
    /// Start the cursor at position (0, 0).
    pub fn start() -> Self {
        Self { row: 0, col: 0, step: 0 }
    }

    /// Advance the cursor using the configured walk mode and a payload byte
    /// hint.
    pub fn advance(&mut self, walk: WalkMode, hint: u8) {
        self.step = self.step.wrapping_add(1);
        match walk {
            WalkMode::Linear => {
                let total = self.row * 9 + self.col;
                let next = (total + 1) % 81;
                self.row = next / 9;
                self.col = next % 9;
            }
            WalkMode::Diagonal => {
                self.row = (self.row + 1) % 9;
                self.col = (self.col + self.row) % 9;
            }
            WalkMode::PayloadGuided => {
                self.row = ((hint >> 4) as usize) % 9;
                self.col = (hint & 0x0F) as usize % 9;
            }
        }
    }

    /// Current row, column, and step count.
    pub fn position(&self) -> (usize, usize, u64) {
        (self.row, self.col, self.step)
    }

    /// Filler length the matrix prescribes at the current cursor position.
    pub fn filler_len(&self) -> u16 {
        SUDOKU_MATRIX[self.row][self.col]
    }
}

/// Sudoku shaping engine. One instance per direction (send / receive) per
/// stream; the seed must be shared with the peer for round-trip safety.
#[derive(Debug)]
pub struct SudokuShaper {
    config: SudokuConfig,
    role: ShapingRole,
    rng: StdRng,
    lfsr: Lfsr16,
    cursor: SudokuCursor,
    last_hint: u8,
}

impl SudokuShaper {
    /// Build a new shaper.
    pub fn new(config: SudokuConfig, role: ShapingRole) -> Self {
        let mut seed_bytes = [0u8; 32];
        seed_bytes[..4].copy_from_slice(&config.seed.to_le_bytes());
        // Domain-separate the two roles so a sender LFSR and a receiver LFSR
        // derived from the same 32-bit seed never lock step.
        let tag = match role {
            ShapingRole::Sender => 0xA5,
            ShapingRole::Receiver => 0x5A,
        };
        seed_bytes[4] = tag;
        let rng = StdRng::from_seed(seed_bytes);
        let lfsr_seed = config.seed.wrapping_add((tag as u32) << 16);
        Self {
            config,
            role,
            rng,
            lfsr: Lfsr16::new(lfsr_seed as u16),
            cursor: SudokuCursor::start(),
            last_hint: 0,
        }
    }

    /// Convenience: build a sender shaper.
    pub fn sender(config: SudokuConfig) -> Self {
        Self::new(config, ShapingRole::Sender)
    }

    /// Convenience: build a receiver shaper.
    pub fn receiver(config: SudokuConfig) -> Self {
        Self::new(config, ShapingRole::Receiver)
    }

    /// Current configuration.
    pub fn config(&self) -> &SudokuConfig {
        &self.config
    }

    /// Current role.
    pub fn role(&self) -> ShapingRole {
        self.role
    }

    /// Current cursor position. Useful for telemetry.
    pub fn cursor_position(&self) -> (usize, usize, u64) {
        self.cursor.position()
    }

    /// Shape a single payload chunk: prepend the random prefix, then append
    /// the prescribed filler. The filler is `matrix[prev_row][prev_col]` bytes
    /// of LFSR output, minus the previous payload byte mod 256 (so the filler
    /// count varies between 1 and 9 even when the cursor sits still).
    pub fn shape(&mut self, payload: &[u8]) -> Result<Vec<u8>, ShapingError> {
        if self.role != ShapingRole::Sender {
            return Ok(payload.to_vec());
        }

        let total = self.config.prefix_len + payload.len() + self.filler_for_hint(self.last_hint);
        let mut out = Vec::with_capacity(total);

        // 1. Random prefix (XORed through LFSR so the on-wire bytes do not
        //    leak the seed directly).
        if self.config.prefix_len > 0 {
            let mut prefix = vec![0u8; self.config.prefix_len];
            self.lfsr.fill(&mut prefix)?;
            // Mix in a StdRng mask so two sessions with the same seed still
            // produce different prefixes after the first second.
            let mut mask = vec![0u8; self.config.prefix_len];
            self.rng.fill_bytes(&mut mask);
            for (a, b) in prefix.iter_mut().zip(mask.iter()) {
                *a ^= *b;
            }
            out.extend_from_slice(&prefix);
        }

        // 2. Interleave the payload with periodic LFSR bytes when enabled.
        if self.config.interleave_enabled && self.config.interleave_step > 0 {
            let mut emitted = 0usize;
            for chunk in payload.chunks(self.config.interleave_step) {
                out.extend_from_slice(chunk);
                emitted += chunk.len();
                if emitted < payload.len() {
                    out.push(self.lfsr.next_byte());
                }
            }
        } else {
            out.extend_from_slice(payload);
        }

        // 3. Filler block dictated by the current Sudoku cell.
        let filler = self.filler_for_hint(self.last_hint);
        if filler > 0 {
            let mut tail = vec![0u8; filler];
            self.lfsr.fill(&mut tail)?;
            out.extend_from_slice(&tail);
        }

        // 4. Advance the cursor so the next chunk uses a different row/col.
        let hint = payload.first().copied().unwrap_or(self.last_hint);
        self.last_hint = hint;
        self.cursor.advance(self.config.walk_mode, hint);

        Ok(out)
    }

    /// Strip the shaping added by `shape`. Returns the original payload.
    /// Receivers must call this on every chunk in the order it was shaped.
    pub fn unshape(&mut self, shaped: &[u8]) -> Result<Vec<u8>, ShapingError> {
        if self.role != ShapingRole::Receiver {
            return Ok(shaped.to_vec());
        }

        if shaped.len() < self.config.prefix_len {
            return Err(ShapingError::PrefixUnderflow {
                got: shaped.len(),
                expected: self.config.prefix_len,
            });
        }

        // 1. Drop prefix.
        let mut cursor = self.config.prefix_len;

        // 2. Replay the interleave so we know exactly how many payload bytes
        //    are in the middle. We do not know `payload.len()` a priori, but
        //    we know the filler length, so we read the suffix and treat the
        //    middle as payload.
        let filler = self.filler_for_hint(self.last_hint);
        if shaped.len() < cursor + filler {
            return Err(ShapingError::FillerUnderflow {
                needed: cursor + filler,
                got: shaped.len(),
            });
        }
        let middle_end = shaped.len() - filler;

        // 3. Walk the interleave and re-construct the payload by skipping
        //    the LFSR bytes that were inserted every `interleave_step`.
        let mut payload = Vec::with_capacity(middle_end.saturating_sub(cursor));
        if self.config.interleave_enabled && self.config.interleave_step > 0 {
            let mut pos = cursor;
            let mut emitted = 0usize;
            while pos < middle_end {
                let take =
                    std::cmp::min(self.config.interleave_step, middle_end - pos);
                payload.extend_from_slice(&shaped[pos..pos + take]);
                pos += take;
                emitted += take;
                if pos < middle_end {
                    pos += 1; // skip the interleave byte
                }
                let _ = emitted;
            }
        } else {
            payload.extend_from_slice(&shaped[cursor..middle_end]);
        }

        // 4. Advance the cursor with the same hint the sender used.
        let hint = payload.first().copied().unwrap_or(self.last_hint);
        self.last_hint = hint;
        self.cursor.advance(self.config.walk_mode, hint);

        Ok(payload)
    }

    /// Filler length for the *current* cursor position adjusted by the
    /// previous payload byte so adjacent identical payloads still vary.
    fn filler_for_hint(&self, hint: u8) -> usize {
        let raw = self.cursor.filler_len() as usize;
        raw.saturating_sub((hint as usize) % raw).max(1)
    }
}

/// Apply shaping to a slice using a fresh shaper built from `config`. Useful
/// for one-shot shaping where a long-lived engine is overkill (e.g. unit
/// tests or single-packet probes).
pub fn shape_once(config: &SudokuConfig, payload: &[u8]) -> Result<Vec<u8>, ShapingError> {
    SudokuShaper::sender(config.clone()).shape(payload)
}

/// Strip shaping from a slice using a fresh shaper. The seed MUST match the
/// seed used to shape; otherwise the cursor will desynchronise after the
/// first chunk and corrupt the output.
pub fn unshape_once(config: &SudokuConfig, shaped: &[u8]) -> Result<Vec<u8>, ShapingError> {
    SudokuShaper::receiver(config.clone()).unshape(shaped)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> SudokuConfig {
        SudokuConfig {
            seed: 0xDEAD_BEEF,
            prefix_len: 8,
            walk_mode: WalkMode::PayloadGuided,
            interleave_enabled: true,
            interleave_step: 4,
        }
    }

    #[test]
    fn test_matrix_is_sudoku() {
        // Every row must be a permutation of 1..=9.
        for (i, row) in SUDOKU_MATRIX.iter().enumerate() {
            let mut sorted = *row;
            sorted.sort();
            assert_eq!(sorted, [1, 2, 3, 4, 5, 6, 7, 8, 9], "row {i} not a permutation");
            for &cell in row {
                assert!(cell >= 1 && cell <= 9, "row {i} cell out of range");
            }
        }
    }

    #[test]
    fn test_lfsr_period_is_maximal() {
        // The polynomial used must have full period 65535 for any non-zero
        // seed. We sample a few seeds and verify the state never repeats
        // before step 65535.
        let seeds = [0x0001u16, 0xACE1, 0x1234, 0xFFFF];
        for &seed in &seeds {
            let mut lfsr = Lfsr16::new(seed);
            let mut states = std::collections::HashSet::new();
            let mut period = 0usize;
            for _ in 0..70_000 {
                lfsr.next_byte();
                if !states.insert(lfsr.state) {
                    break;
                }
                period += 1;
            }
            assert!(period >= 65_535, "LFSR period too short: {period}");
        }
    }

    #[test]
    fn test_lfsr_fill_writes_all_bytes() {
        let mut lfsr = Lfsr16::new(0xBEEF);
        let mut buf = [0u8; 32];
        lfsr.fill(&mut buf).unwrap();
        // LFSR bytes are deterministic but should not all be zero.
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_cursor_advance_payload_guided() {
        let mut c = SudokuCursor::start();
        c.advance(WalkMode::PayloadGuided, 0x37);
        // High nibble 3 -> row 3, low nibble 7 -> col 7.
        assert_eq!(c.position().0, 3);
        assert_eq!(c.position().1, 7);
        assert_eq!(c.position().2, 1);

        c.advance(WalkMode::PayloadGuided, 0xFF);
        assert_eq!(c.position().0, 0xF % 9);
        assert_eq!(c.position().1, 0xF % 9);
    }

    #[test]
    fn test_cursor_advance_linear_and_diagonal() {
        let mut c = SudokuCursor::start();
        c.advance(WalkMode::Linear, 0);
        assert_eq!(c.position().0, 0);
        assert_eq!(c.position().1, 1);

        let mut d = SudokuCursor::start();
        d.advance(WalkMode::Diagonal, 0);
        assert_eq!(d.position().0, 1);
        assert_eq!(d.position().1, 1);
    }

    #[test]
    fn test_shape_then_unshape_round_trip() {
        let cfg = test_config();
        let payload = b"the quick brown fox jumps over the lazy dog";
        let shaped = shape_once(&cfg, payload).unwrap();
        // Output must be longer than input because of prefix + filler.
        assert!(shaped.len() > payload.len());
        let recovered = unshape_once(&cfg, &shaped).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn test_round_trip_multiple_chunks() {
        // A long-lived sender and receiver must agree across many chunks.
        let cfg = test_config();
        let mut sender = SudokuShaper::sender(cfg.clone());
        let mut receiver = SudokuShaper::receiver(cfg.clone());

        let chunks: Vec<&[u8]> = vec![
            b"GET / HTTP/1.1\r\n",
            b"Host: example.com\r\n",
            b"User-Agent: Mozilla/5.0\r\n",
            b"\r\n",
        ];

        for chunk in &chunks {
            let shaped = sender.shape(chunk).unwrap();
            let recovered = receiver.unshape(&shaped).unwrap();
            assert_eq!(&recovered[..], *chunk);
        }
    }

    #[test]
    fn test_filler_varies_between_chunks() {
        // Two identical payloads back-to-back should produce differently
        // shaped outputs because the LFSR and cursor advance.
        let cfg = test_config();
        let mut shaper = SudokuShaper::sender(cfg);
        let a = shaper.shape(b"AAAA").unwrap();
        let b = shaper.shape(b"AAAA").unwrap();
        assert_ne!(a, b, "identical inputs produced identical shaped outputs");
    }

    #[test]
    fn test_unshape_rejects_truncated_buffer() {
        let cfg = test_config();
        let mut shaper = SudokuShaper::receiver(cfg);
        // A buffer shorter than the prefix should fail cleanly.
        let err = shaper.unshape(&[0u8; 4]).unwrap_err();
        assert!(matches!(err, ShapingError::PrefixUnderflow { .. }));
    }

    #[test]
    fn test_sender_does_not_strip_and_vice_versa() {
        // A sender calling unshape (or a receiver shaping) is a role
        // mismatch: the safe contract is a no-op, so misconfiguration
        // cannot corrupt data.
        let cfg = test_config();
        let mut sender = SudokuShaper::sender(cfg.clone());
        let mut receiver = SudokuShaper::receiver(cfg);
        let payload = b"hello world";

        // Round-trip: shape with the sender, unshape with the receiver.
        let shaped = sender.shape(payload).unwrap();
        let out = receiver.unshape(&shaped).unwrap();
        assert_eq!(out, payload);

        // A SENDER calling unshape returns its input verbatim (no strip).
        let verbatim = sender.unshape(payload).unwrap();
        assert_eq!(verbatim, payload);
    }

    #[test]
    fn test_filler_always_positive() {
        // The filler length must never collapse to zero, even when the
        // hint byte equals the cell value modulo the same number.
        let cfg = test_config();
        let shaper = SudokuShaper::sender(cfg);
        for hint in 0u8..=255 {
            let f = shaper.filler_for_hint(hint);
            assert!(f >= 1, "filler collapsed to zero for hint {hint}");
            assert!(f <= 9, "filler exceeded cell range for hint {hint}: {f}");
        }
    }
}
