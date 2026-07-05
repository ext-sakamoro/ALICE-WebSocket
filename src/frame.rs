//! `Frame` — WebSocket frame parse / encode.

use crate::errors::WsError;

use crate::masking::apply_mask_in_place;

use crate::close_code::CloseCode;
use crate::close_payload::ClosePayload;
use crate::opcode::Opcode;

// Frame
// ---------------------------------------------------------------------------

/// A parsed WebSocket frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub fin: bool,
    pub rsv1: bool,
    pub rsv2: bool,
    pub rsv3: bool,
    pub opcode: Opcode,
    pub masked: bool,
    pub mask_key: [u8; 4],
    pub payload: Vec<u8>,
}

impl Frame {
    /// Create a new frame with default values.
    #[must_use]
    pub const fn new(opcode: Opcode, payload: Vec<u8>) -> Self {
        Self {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode,
            masked: false,
            mask_key: [0; 4],
            payload,
        }
    }

    /// Create a text frame.
    #[must_use]
    pub fn text(s: &str) -> Self {
        Self::new(Opcode::Text, s.as_bytes().to_vec())
    }

    /// Create a binary frame.
    #[must_use]
    pub const fn binary(data: Vec<u8>) -> Self {
        Self::new(Opcode::Binary, data)
    }

    /// Create a ping frame.
    #[must_use]
    pub const fn ping(payload: Vec<u8>) -> Self {
        Self::new(Opcode::Ping, payload)
    }

    /// Create a pong frame.
    #[must_use]
    pub const fn pong(payload: Vec<u8>) -> Self {
        Self::new(Opcode::Pong, payload)
    }

    /// Create a close frame with optional code and reason.
    #[must_use]
    pub fn close(code: Option<CloseCode>, reason: &str) -> Self {
        let payload = code.map_or_else(Vec::new, |c| {
            let cp = ClosePayload {
                code: c,
                reason: reason.to_owned(),
            };
            cp.to_bytes()
        });
        Self::new(Opcode::Close, payload)
    }

    /// Create a continuation frame.
    #[must_use]
    pub const fn continuation(payload: Vec<u8>, fin: bool) -> Self {
        let mut f = Self::new(Opcode::Continuation, payload);
        f.fin = fin;
        f
    }

    /// Set the mask key and mark this frame as masked.
    pub const fn set_mask(&mut self, key: [u8; 4]) {
        self.masked = true;
        self.mask_key = key;
    }

    /// Total header size in bytes for this frame.
    #[must_use]
    pub const fn header_size(&self) -> usize {
        let mut size = 2; // first two bytes
        let len = self.payload.len();
        if len >= 126 {
            if len <= 65535 {
                size += 2;
            } else {
                size += 8;
            }
        }
        if self.masked {
            size += 4;
        }
        size
    }

    /// Serialize this frame to bytes (payload is NOT masked even if `masked` is set;
    /// use `serialize_masked` to apply masking during serialization).
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        self.serialize_inner(false)
    }

    /// Serialize this frame to bytes, applying the mask to the payload.
    #[must_use]
    pub fn serialize_masked(&self) -> Vec<u8> {
        self.serialize_inner(true)
    }

    fn serialize_inner(&self, apply_mask: bool) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.header_size() + self.payload.len());

        let mut b0: u8 = self.opcode as u8;
        if self.fin {
            b0 |= 0x80;
        }
        if self.rsv1 {
            b0 |= 0x40;
        }
        if self.rsv2 {
            b0 |= 0x20;
        }
        if self.rsv3 {
            b0 |= 0x10;
        }
        buf.push(b0);

        let len = self.payload.len();
        let mask_bit: u8 = if self.masked { 0x80 } else { 0 };

        if len < 126 {
            #[allow(clippy::cast_possible_truncation)]
            buf.push(mask_bit | len as u8);
        } else if len <= 65535 {
            buf.push(mask_bit | 126);
            #[allow(clippy::cast_possible_truncation)]
            let len16 = len as u16;
            buf.extend_from_slice(&len16.to_be_bytes());
        } else {
            buf.push(mask_bit | 127);
            #[allow(clippy::cast_possible_truncation)]
            let len64 = len as u64;
            buf.extend_from_slice(&len64.to_be_bytes());
        }

        if self.masked {
            buf.extend_from_slice(&self.mask_key);
        }

        if apply_mask && self.masked {
            let mut payload = self.payload.clone();
            apply_mask_in_place(&mut payload, self.mask_key);
            buf.extend_from_slice(&payload);
        } else {
            buf.extend_from_slice(&self.payload);
        }

        buf
    }

    /// Parse a single frame from a byte buffer.
    /// Returns the frame and the number of bytes consumed.
    ///
    /// # Errors
    ///
    /// Returns `WsError::Incomplete` if data is insufficient, or other errors
    /// for protocol violations.
    pub fn parse(data: &[u8]) -> Result<(Self, usize), WsError> {
        Self::parse_with_extensions(data, false)
    }

    /// Parse a frame, optionally allowing RSV bits (for extensions).
    ///
    /// # Errors
    ///
    /// Returns errors for protocol violations or incomplete data.
    pub fn parse_with_extensions(data: &[u8], allow_rsv: bool) -> Result<(Self, usize), WsError> {
        if data.len() < 2 {
            return Err(WsError::Incomplete);
        }

        let b0 = data[0];
        let b1 = data[1];

        let fin = b0 & 0x80 != 0;
        let rsv1 = b0 & 0x40 != 0;
        let rsv2 = b0 & 0x20 != 0;
        let rsv3 = b0 & 0x10 != 0;

        if !allow_rsv && (rsv1 || rsv2 || rsv3) {
            return Err(WsError::ReservedBitsSet);
        }

        let opcode = Opcode::from_u8(b0 & 0x0F)?;
        let masked = b1 & 0x80 != 0;
        let payload_len_7 = b1 & 0x7F;

        let mut offset: usize = 2;

        let payload_len: usize = match payload_len_7.cmp(&126) {
            std::cmp::Ordering::Less => payload_len_7 as usize,
            std::cmp::Ordering::Equal => {
                if data.len() < offset + 2 {
                    return Err(WsError::Incomplete);
                }
                let len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
                offset += 2;
                len
            }
            std::cmp::Ordering::Greater => {
                if data.len() < offset + 8 {
                    return Err(WsError::Incomplete);
                }
                let len = u64::from_be_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                    data[offset + 4],
                    data[offset + 5],
                    data[offset + 6],
                    data[offset + 7],
                ]);
                offset += 8;
                if len > u64::from(u32::MAX) {
                    return Err(WsError::PayloadTooLarge);
                }
                #[allow(clippy::cast_possible_truncation)]
                let result = len as usize;
                result
            }
        };

        // Control frame validation
        if opcode.is_control() {
            if payload_len > 125 {
                return Err(WsError::ControlFrameTooLarge);
            }
            if !fin {
                return Err(WsError::FragmentedControlFrame);
            }
        }

        let mut mask_key = [0u8; 4];
        if masked {
            if data.len() < offset + 4 {
                return Err(WsError::Incomplete);
            }
            mask_key.copy_from_slice(&data[offset..offset + 4]);
            offset += 4;
        }

        if data.len() < offset + payload_len {
            return Err(WsError::Incomplete);
        }

        let mut payload = data[offset..offset + payload_len].to_vec();

        if masked {
            apply_mask_in_place(&mut payload, mask_key);
        }

        let consumed = offset + payload_len;

        Ok((
            Self {
                fin,
                rsv1,
                rsv2,
                rsv3,
                opcode,
                masked,
                mask_key,
                payload,
            },
            consumed,
        ))
    }
}
