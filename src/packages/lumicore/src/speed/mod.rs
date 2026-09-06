//! # Speed Test Module
//!
//! Download/upload throughput and latency testing.

mod tester;
pub mod batch_speed_matrix;

pub use batch_speed_matrix::*;
pub use tester::SpeedTester;
