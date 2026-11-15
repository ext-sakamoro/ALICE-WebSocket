//! `WsError` — WebSocket operation errors.

use std::fmt;

use crate::mask::MaskError;

// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur during WebSocket operations.
///
/// The enum is `#[non_exhaustive]` (since 2.0.0): a `match` needs a `_` arm, so new protocol and transport
/// errors can be added without breaking callers.
#[non_exhaustive]
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
    /// Payload length overflow, or a payload longer than the caller's limit
    /// (see [`Frame::parse_limited`](crate::frame::Frame::parse_limited)).
    PayloadTooLarge,
    /// A frame from the server has the mask bit set (RFC 6455 Section 5.1: a client must close the
    /// connection when it receives a masked frame).
    MaskedServerFrame,
    /// The server answered the upgrade request with this HTTP status instead of 101.
    HandshakeStatus(u16),
    /// An I/O error on the underlying stream (`kind` and the error's text; `std::io::Error` is not `Clone`).
    Io {
        kind: std::io::ErrorKind,
        message: String,
    },
    /// The connection is closed (a close frame was sent or received) and the operation needs an open one.
    Closed,
    /// The TLS layer failed for a reason other than the server's certificate.
    Tls(String),
    /// The server's certificate was rejected (unknown issuer, wrong name, expired, ...).
    Certificate(String),
    /// The mask source could not produce an unpredictable mask key or handshake nonce; nothing was sent.
    Mask(MaskError),
}

impl From<MaskError> for WsError {
    fn from(e: MaskError) -> Self {
        Self::Mask(e)
    }
}

impl From<std::io::Error> for WsError {
    fn from(e: std::io::Error) -> Self {
        Self::Io {
            kind: e.kind(),
            message: e.to_string(),
        }
    }
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
            Self::MaskedServerFrame => write!(f, "masked frame from the server"),
            Self::HandshakeStatus(s) => write!(f, "handshake refused with HTTP status {s}"),
            Self::Io { kind, message } => write!(f, "i/o error ({kind:?}): {message}"),
            Self::Closed => write!(f, "connection closed"),
            Self::Tls(s) => write!(f, "tls error: {s}"),
            Self::Certificate(s) => write!(f, "certificate rejected: {s}"),
            Self::Mask(e) => write!(f, "mask source failed: {e}"),
        }
    }
}

impl std::error::Error for WsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Mask(e) => Some(e),
            _ => None,
        }
    }
}
