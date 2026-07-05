//! `Opcode` — WebSocket frame opcodes (per RFC 6455).

use crate::errors::WsError;

// Opcodes
// ---------------------------------------------------------------------------

/// WebSocket frame opcodes (RFC 6455 Section 5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Opcode {
    Continuation = 0x0,
    Text = 0x1,
    Binary = 0x2,
    Close = 0x8,
    Ping = 0x9,
    Pong = 0xA,
}

impl Opcode {
    /// Parse a 4-bit opcode value.
    ///
    /// # Errors
    ///
    /// Returns `WsError::InvalidOpcode` if the value is not a recognized opcode.
    pub const fn from_u8(v: u8) -> Result<Self, WsError> {
        match v {
            0x0 => Ok(Self::Continuation),
            0x1 => Ok(Self::Text),
            0x2 => Ok(Self::Binary),
            0x8 => Ok(Self::Close),
            0x9 => Ok(Self::Ping),
            0xA => Ok(Self::Pong),
            _ => Err(WsError::InvalidOpcode(v)),
        }
    }

    /// Returns `true` for control opcodes (Close, Ping, Pong).
    #[must_use]
    pub const fn is_control(self) -> bool {
        matches!(self, Self::Close | Self::Ping | Self::Pong)
    }

    /// Returns `true` for data opcodes (Continuation, Text, Binary).
    #[must_use]
    pub const fn is_data(self) -> bool {
        !self.is_control()
    }
}
