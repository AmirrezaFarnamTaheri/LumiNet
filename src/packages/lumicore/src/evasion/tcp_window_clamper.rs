//! # TCP Window Clamper & RST Poison Filter
//!
//! Forces fine-grained packet segmentation during critical handshake phases
//! by clamping the TCP window advertisement, and detects/drops rogue RST
//! injection packets. Ported and enhanced from zydou/GFW.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowClampMode {
    Fixed(u16),
    HandshakeOnly(u16),
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpWindowClamper {
    pub mode: WindowClampMode,
    pub clamped_window_size: u16,
    pub max_acceptable_rst_drift: u32,
}

impl Default for TcpWindowClamper {
    fn default() -> Self {
        Self {
            mode: WindowClampMode::HandshakeOnly(2),
            clamped_window_size: 2,
            max_acceptable_rst_drift: 4096,
        }
    }
}

impl TcpWindowClamper {
    pub fn new(mode: WindowClampMode) -> Self {
        let size = match mode {
            WindowClampMode::Fixed(s) | WindowClampMode::HandshakeOnly(s) => s,
            WindowClampMode::Disabled => 65535,
        };
        Self {
            mode,
            clamped_window_size: size,
            max_acceptable_rst_drift: 4096,
        }
    }

    /// Evaluates outbound TCP window size to clamp.
    pub fn clamp_outbound_window(&self, original_window: u16, is_handshake_in_flight: bool) -> u16 {
        match self.mode {
            WindowClampMode::Fixed(target) => original_window.min(target),
            WindowClampMode::HandshakeOnly(target) => {
                if is_handshake_in_flight {
                    original_window.min(target)
                } else {
                    original_window
                }
            }
            WindowClampMode::Disabled => original_window,
        }
    }

    /// Validates whether an incoming RST packet is legitimate or an injected poison packet.
    /// Injected RST packets often have sequence numbers outside the active receive window
    /// or lack proper correlation with the connection's last ACK sequence.
    pub fn is_rst_legitimate(&self, rst_seq: u32, last_ack_seq: u32, current_window: u32) -> bool {
        // Legitimate RST seq must fall within [last_ack_seq, last_ack_seq + window]
        let diff = rst_seq.wrapping_sub(last_ack_seq);
        let max_window = current_window.max(self.max_acceptable_rst_drift);
        diff <= max_window
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_window_clamping() {
        let clamper = TcpWindowClamper::new(WindowClampMode::HandshakeOnly(4));
        // During handshake: clamped to 4
        assert_eq!(clamper.clamp_outbound_window(64240, true), 4);
        // After handshake: restored to original
        assert_eq!(clamper.clamp_outbound_window(64240, false), 64240);
    }

    #[test]
    fn test_rst_validation() {
        let clamper = TcpWindowClamper::default();
        let last_ack = 100_000;
        let window = 10_000;

        // In-window RST is legitimate
        assert!(clamper.is_rst_legitimate(105_000, last_ack, window));

        // Out-of-window forged RST is rejected
        assert!(!clamper.is_rst_legitimate(500_000, last_ack, window));
    }
}
