//! `MessageAssembler` — fragmented `Message` 組み立て.

use crate::errors::WsError;
use crate::frame::Frame;
use crate::opcode::Opcode;

// Message assembler (fragmentation)
// ---------------------------------------------------------------------------

/// Assembles fragmented WebSocket frames into complete messages.
#[derive(Debug)]
pub struct MessageAssembler {
    opcode: Option<Opcode>,
    fragments: Vec<u8>,
}

impl Default for MessageAssembler {
    fn default() -> Self {
        Self::new()
    }
}

impl MessageAssembler {
    /// Create a new assembler.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            opcode: None,
            fragments: Vec::new(),
        }
    }

    /// Returns `true` if a fragmented message is in progress.
    #[must_use]
    pub const fn in_progress(&self) -> bool {
        self.opcode.is_some()
    }

    /// Feed a frame into the assembler.
    ///
    /// Returns `Some(Message)` when a complete message is assembled.
    ///
    /// # Errors
    ///
    /// Returns `WsError::FragmentationError` on protocol violations.
    ///
    /// # Panics
    ///
    /// This method does not panic under normal usage.
    pub fn feed(&mut self, frame: &Frame) -> Result<Option<Message>, WsError> {
        // Control frames are always complete
        if frame.opcode.is_control() {
            return Ok(Some(Message {
                opcode: frame.opcode,
                payload: frame.payload.clone(),
            }));
        }

        match frame.opcode {
            Opcode::Text | Opcode::Binary => {
                if self.opcode.is_some() {
                    return Err(WsError::FragmentationError(
                        "new data frame while fragment in progress".into(),
                    ));
                }
                if frame.fin {
                    // Unfragmented message
                    if frame.opcode == Opcode::Text {
                        std::str::from_utf8(&frame.payload).map_err(|_| WsError::InvalidUtf8)?;
                    }
                    return Ok(Some(Message {
                        opcode: frame.opcode,
                        payload: frame.payload.clone(),
                    }));
                }
                // Start of fragmented message
                self.opcode = Some(frame.opcode);
                self.fragments.clone_from(&frame.payload);
                Ok(None)
            }
            Opcode::Continuation => {
                if self.opcode.is_none() {
                    return Err(WsError::FragmentationError(
                        "continuation without start frame".into(),
                    ));
                }
                self.fragments.extend_from_slice(&frame.payload);
                if frame.fin {
                    let opcode = self.opcode.take().expect("checked above");
                    let payload = std::mem::take(&mut self.fragments);
                    if opcode == Opcode::Text {
                        std::str::from_utf8(&payload).map_err(|_| WsError::InvalidUtf8)?;
                    }
                    Ok(Some(Message { opcode, payload }))
                } else {
                    Ok(None)
                }
            }
            _ => Ok(None),
        }
    }

    /// Reset the assembler, discarding any in-progress message.
    pub fn reset(&mut self) {
        self.opcode = None;
        self.fragments.clear();
    }
}

/// A fully assembled WebSocket message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub opcode: Opcode,
    pub payload: Vec<u8>,
}

impl Message {
    /// Interpret the payload as a UTF-8 string (for text messages).
    ///
    /// # Errors
    ///
    /// Returns `WsError::InvalidUtf8` if the payload is not valid UTF-8.
    pub fn as_text(&self) -> Result<&str, WsError> {
        std::str::from_utf8(&self.payload).map_err(|_| WsError::InvalidUtf8)
    }

    /// Fragment this message into frames of at most `max_size` bytes each.
    #[must_use]
    pub fn fragment(&self, max_size: usize) -> Vec<Frame> {
        let max_size = if max_size == 0 { 1 } else { max_size };

        if self.payload.len() <= max_size {
            return vec![Frame::new(self.opcode, self.payload.clone())];
        }

        let chunks: Vec<&[u8]> = self.payload.chunks(max_size).collect();
        let mut frames = Vec::with_capacity(chunks.len());

        for (i, chunk) in chunks.iter().enumerate() {
            let is_first = i == 0;
            let is_last = i == chunks.len() - 1;

            let opcode = if is_first {
                self.opcode
            } else {
                Opcode::Continuation
            };

            let mut frame = Frame::new(opcode, chunk.to_vec());
            frame.fin = is_last;
            frames.push(frame);
        }

        frames
    }
}
