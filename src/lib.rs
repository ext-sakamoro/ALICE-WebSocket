//! ALICE-WebSocket: Pure Rust WebSocket protocol implementation.
//!
//! Provides frame parsing, masking/unmasking, handshake generation,
//! ping/pong, close frames, fragmentation, text/binary messages, and extensions.

#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(
    clippy::module_name_repetitions,
    clippy::struct_excessive_bools,
    clippy::many_single_char_names,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::wildcard_imports,
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::cast_possible_truncation,
    clippy::cast_lossless
)]

pub mod assembler;
pub mod base64;
pub mod buffer;
pub mod close_code;
pub mod close_payload;
pub mod errors;
pub mod extensions;
pub mod frame;
pub mod handshake;
pub mod masking;
pub mod opcode;
pub mod prelude;
mod sha1;

#[cfg(test)]
mod integration_tests;

// Backward-compat re-exports.
pub use crate::assembler::*;
pub use crate::base64::*;
pub use crate::buffer::*;
pub use crate::close_code::*;
pub use crate::close_payload::*;
pub use crate::errors::*;
pub use crate::extensions::*;
pub use crate::frame::*;
pub use crate::handshake::*;
pub use crate::masking::*;
pub use crate::opcode::*;
