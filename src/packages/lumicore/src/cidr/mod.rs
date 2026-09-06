//! # CIDR Module
//!
//! IP address expansion and CIDR block parsing.

mod blackrock;
mod expander;
pub mod vm_timer;

pub use blackrock::BlackRock;
pub use expander::{expand_cidr, CidrExpander};
