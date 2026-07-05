//! `CloseCode` + validation (per RFC 6455).

use crate::errors::WsError;

// Close codes
// ---------------------------------------------------------------------------

/// Well-known WebSocket close status codes (RFC 6455 Section 7.4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseCode {
    Normal,
    GoingAway,
    ProtocolError,
    Unsupported,
    NoStatus,
    Abnormal,
    InvalidPayload,
    PolicyViolation,
    TooLarge,
    MandatoryExtension,
    InternalError,
    TlsHandshake,
    Other(u16),
}

impl CloseCode {
    /// Convert a `u16` into a `CloseCode`.
    #[must_use]
    pub const fn from_u16(code: u16) -> Self {
        match code {
            1000 => Self::Normal,
            1001 => Self::GoingAway,
            1002 => Self::ProtocolError,
            1003 => Self::Unsupported,
            1005 => Self::NoStatus,
            1006 => Self::Abnormal,
            1007 => Self::InvalidPayload,
            1008 => Self::PolicyViolation,
            1009 => Self::TooLarge,
            1010 => Self::MandatoryExtension,
            1011 => Self::InternalError,
            1015 => Self::TlsHandshake,
            other => Self::Other(other),
        }
    }

    /// Convert to `u16`.
    #[must_use]
    pub const fn to_u16(self) -> u16 {
        match self {
            Self::Normal => 1000,
            Self::GoingAway => 1001,
            Self::ProtocolError => 1002,
            Self::Unsupported => 1003,
            Self::NoStatus => 1005,
            Self::Abnormal => 1006,
            Self::InvalidPayload => 1007,
            Self::PolicyViolation => 1008,
            Self::TooLarge => 1009,
            Self::MandatoryExtension => 1010,
            Self::InternalError => 1011,
            Self::TlsHandshake => 1015,
            Self::Other(c) => c,
        }
    }

    /// Returns `true` if this close code is valid to send in a close frame.
    #[must_use]
    pub const fn is_sendable(self) -> bool {
        let c = self.to_u16();
        // 1005, 1006, 1015 must not be sent
        // Valid ranges: 1000-1003, 1007-1011, 3000-4999
        matches!(c, 1000..=1003 | 1007..=1011 | 3000..=4999)
    }
}

/// Validate that a close code is legal to appear in a close frame.
///
/// # Errors
///
/// Returns `WsError::InvalidCloseCode` if the code is not valid.
pub const fn validate_close_code(code: u16) -> Result<(), WsError> {
    match code {
        1000..=1003 | 1007..=1011 | 3000..=4999 => Ok(()),
        _ => Err(WsError::InvalidCloseCode(code)),
    }
}
