//! Hidden-service primitives.
//!
//! Introduction-point set with breadth-first round-robin rotation
//!.

pub mod intro_point_set;

pub use intro_point_set::{IntroPointError, IntroductionPoint, IntroductionPointSet};
