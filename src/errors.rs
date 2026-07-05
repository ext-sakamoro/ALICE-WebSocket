//! `WsError` — WebSocket operation errors.

use std::fmt;

// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur during WebSocket operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WsError {
    /// Frame data is incomplete (need more bytes).
    Incomplete,
    /// Invalid opcode value.
    InvalidOpcode(u8),
    /// Control frame payload exceeds 125 bytes.
    ControlFrameTooLarge,
    /// Control frame is fragmented.
    FragmentedControlFrame,
    /// Reserved bits are set without negotiated extensions.
    ReservedBitsSet,
    /// Invalid UTF-8 in a text frame.
    InvalidUtf8,
    /// Invalid close code.
    InvalidCloseCode(u16),
    /// Handshake header is missing or malformed.
    HandshakeError(String),
    /// Invalid `Sec-WebSocket-Accept` value.
    InvalidAccept,
    /// Fragmentation protocol violation.
    FragmentationError(String),
    /// Payload length overflow.
    PayloadTooLarge,
}

impl fmt::Display for WsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Incomplete => write!(f, "incomplete frame data"),
            Self::InvalidOpcode(v) => write!(f, "invalid opcode: {v:#x}"),
            Self::ControlFrameTooLarge => write!(f, "control frame payload > 125 bytes"),
            Self::FragmentedControlFrame => write!(f, "control frame must not be fragmented"),
            Self::ReservedBitsSet => write!(f, "reserved bits set without extensions"),
            Self::InvalidUtf8 => write!(f, "invalid UTF-8 in text frame"),
            Self::InvalidCloseCode(c) => write!(f, "invalid close code: {c}"),
            Self::HandshakeError(s) => write!(f, "handshake error: {s}"),
            Self::InvalidAccept => write!(f, "invalid Sec-WebSocket-Accept"),
            Self::FragmentationError(s) => write!(f, "fragmentation error: {s}"),
            Self::PayloadTooLarge => write!(f, "payload length overflow"),
        }
    }
}

impl std::error::Error for WsError {}
