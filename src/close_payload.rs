//! `ClosePayload` — close frame code + reason.

use crate::close_code::{validate_close_code, CloseCode};

use crate::errors::WsError;

// Close frame payload
// ---------------------------------------------------------------------------

/// Parsed close frame payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosePayload {
    pub code: CloseCode,
    pub reason: String,
}

impl ClosePayload {
    /// Parse a close frame payload.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid close code or non-UTF-8 reason.
    pub fn parse(data: &[u8]) -> Result<Option<Self>, WsError> {
        if data.is_empty() {
            return Ok(None);
        }
        if data.len() == 1 {
            return Err(WsError::InvalidCloseCode(0));
        }
        let code = u16::from_be_bytes([data[0], data[1]]);
        validate_close_code(code)?;
        let reason = if data.len() > 2 {
            std::str::from_utf8(&data[2..])
                .map_err(|_| WsError::InvalidUtf8)?
                .to_owned()
        } else {
            String::new()
        };
        Ok(Some(Self {
            code: CloseCode::from_u16(code),
            reason,
        }))
    }

    /// Serialize to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(2 + self.reason.len());
        buf.extend_from_slice(&self.code.to_u16().to_be_bytes());
        buf.extend_from_slice(self.reason.as_bytes());
        buf
    }
}
