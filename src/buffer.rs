//! `FrameBuffer` — 部分 read streaming parser.

use crate::errors::WsError;
use crate::frame::Frame;

// Frame buffer (streaming parser)
// ---------------------------------------------------------------------------

/// Buffered frame parser for streaming data.
#[derive(Debug)]
pub struct FrameBuffer {
    buffer: Vec<u8>,
    allow_rsv: bool,
}

impl Default for FrameBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameBuffer {
    /// Create a new frame buffer.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            buffer: Vec::new(),
            allow_rsv: false,
        }
    }

    /// Create a frame buffer that allows RSV bits.
    #[must_use]
    pub const fn with_extensions() -> Self {
        Self {
            buffer: Vec::new(),
            allow_rsv: true,
        }
    }

    /// Append data to the internal buffer.
    pub fn extend(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    /// Try to parse and return the next complete frame.
    ///
    /// # Errors
    ///
    /// Returns errors from `Frame::parse_with_extensions`.
    pub fn try_parse(&mut self) -> Result<Option<Frame>, WsError> {
        if self.buffer.is_empty() {
            return Ok(None);
        }
        match Frame::parse_with_extensions(&self.buffer, self.allow_rsv) {
            Ok((frame, consumed)) => {
                self.buffer.drain(..consumed);
                Ok(Some(frame))
            }
            Err(WsError::Incomplete) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Number of buffered bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Returns `true` if the buffer is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Clear the buffer.
    pub fn clear(&mut self) {
        self.buffer.clear();
    }
}
