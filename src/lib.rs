#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(
    clippy::module_name_repetitions,
    clippy::struct_excessive_bools,
    clippy::many_single_char_names
)]

//! ALICE-WebSocket: Pure Rust WebSocket protocol implementation.
//!
//! Provides frame parsing, masking/unmasking, handshake generation,
//! ping/pong, close frames, fragmentation, text/binary messages, and extensions.

use std::fmt;
use std::fmt::Write as _;

// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
// Masking
// ---------------------------------------------------------------------------

/// Apply or remove the WebSocket mask in-place (XOR with 4-byte key).
pub fn apply_mask_in_place(data: &mut [u8], key: [u8; 4]) {
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= key[i & 3];
    }
}

/// Apply mask, returning a new `Vec<u8>`.
#[must_use]
pub fn apply_mask(data: &[u8], key: [u8; 4]) -> Vec<u8> {
    let mut out = data.to_vec();
    apply_mask_in_place(&mut out, key);
    out
}

// ---------------------------------------------------------------------------
// SHA-1 (minimal, for handshake only)
// ---------------------------------------------------------------------------

/// Minimal SHA-1 implementation for WebSocket handshake.
/// Not for general cryptographic use.
struct Sha1 {
    h: [u32; 5],
    buffer: [u8; 64],
    buf_len: usize,
    total_len: u64,
}

impl Sha1 {
    const fn new() -> Self {
        Self {
            h: [
                0x6745_2301,
                0xEFCD_AB89,
                0x98BA_DCFE,
                0x1032_5476,
                0xC3D2_E1F0,
            ],
            buffer: [0u8; 64],
            buf_len: 0,
            total_len: 0,
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.total_len += data.len() as u64;
        let mut pos = 0;

        // Fill buffer first
        if self.buf_len > 0 {
            let space = 64 - self.buf_len;
            let to_copy = data.len().min(space);
            self.buffer[self.buf_len..self.buf_len + to_copy].copy_from_slice(&data[..to_copy]);
            self.buf_len += to_copy;
            pos = to_copy;

            if self.buf_len == 64 {
                let block = self.buffer;
                self.process_block(&block);
                self.buf_len = 0;
            }
        }

        // Process full blocks
        while pos + 64 <= data.len() {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[pos..pos + 64]);
            self.process_block(&block);
            pos += 64;
        }

        // Store remaining
        if pos < data.len() {
            let remaining = data.len() - pos;
            self.buffer[..remaining].copy_from_slice(&data[pos..]);
            self.buf_len = remaining;
        }
    }

    fn process_block(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 80];
        for (i, wi) in w.iter_mut().enumerate().take(16) {
            let j = i * 4;
            *wi = u32::from_be_bytes([block[j], block[j + 1], block[j + 2], block[j + 3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];

        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDCu32),
                _ => (b ^ c ^ d, 0xCA62_C1D6u32),
            };

            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
    }

    fn finalize(mut self) -> [u8; 20] {
        let bit_len = self.total_len * 8;

        // Padding
        let mut padding = vec![0x80u8];
        let pad_len = if self.buf_len < 56 {
            55 - self.buf_len
        } else {
            119 - self.buf_len
        };
        padding.resize(1 + pad_len, 0);
        padding.extend_from_slice(&bit_len.to_be_bytes());

        self.update(&padding);

        let mut result = [0u8; 20];
        for (i, h) in self.h.iter().enumerate() {
            result[i * 4..i * 4 + 4].copy_from_slice(&h.to_be_bytes());
        }
        result
    }
}

/// Compute SHA-1 hash.
fn sha1(data: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finalize()
}

// ---------------------------------------------------------------------------
// Base64
// ---------------------------------------------------------------------------

const BASE64_CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode bytes to base64.
#[must_use]
pub fn base64_encode(data: &[u8]) -> String {
    let mut result = String::with_capacity(data.len().div_ceil(3) * 4);
    let chunks = data.chunks(3);

    for chunk in chunks {
        let b0 = chunk[0];
        let b1 = if chunk.len() > 1 { chunk[1] } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] } else { 0 };

        result.push(BASE64_CHARS[(b0 >> 2) as usize] as char);
        result.push(BASE64_CHARS[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);

        if chunk.len() > 1 {
            result.push(BASE64_CHARS[(((b1 & 0x0F) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            result.push('=');
        }

        if chunk.len() > 2 {
            result.push(BASE64_CHARS[(b2 & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }

    result
}

/// Decode base64 to bytes.
///
/// # Errors
///
/// Returns `WsError::HandshakeError` if the input is not valid base64.
pub fn base64_decode(input: &str) -> Result<Vec<u8>, WsError> {
    fn val(c: u8) -> Result<u8, WsError> {
        match c {
            b'A'..=b'Z' => Ok(c - b'A'),
            b'a'..=b'z' => Ok(c - b'a' + 26),
            b'0'..=b'9' => Ok(c - b'0' + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(WsError::HandshakeError("invalid base64 char".into())),
        }
    }

    let input = input.trim_end_matches('=');
    let bytes = input.as_bytes();
    let mut result = Vec::with_capacity(bytes.len() * 3 / 4);

    let mut i = 0;
    while i < bytes.len() {
        let a = val(bytes[i])?;
        let b = if i + 1 < bytes.len() {
            val(bytes[i + 1])?
        } else {
            0
        };
        let c = if i + 2 < bytes.len() {
            val(bytes[i + 2])?
        } else {
            0
        };
        let d = if i + 3 < bytes.len() {
            val(bytes[i + 3])?
        } else {
            0
        };

        result.push((a << 2) | (b >> 4));
        if i + 2 < bytes.len() {
            result.push((b << 4) | (c >> 2));
        }
        if i + 3 < bytes.len() {
            result.push((c << 6) | d);
        }

        i += 4;
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// Handshake
// ---------------------------------------------------------------------------

/// The magic GUID used in WebSocket handshakes (RFC 6455 Section 4.2.2).
pub const WEBSOCKET_GUID: &str = "258EAFA5-E914-47DA-95CA-5AB5DC11E545";

/// Compute the `Sec-WebSocket-Accept` value from a client key.
#[must_use]
pub fn compute_accept_key(client_key: &str) -> String {
    let mut input = String::with_capacity(client_key.len() + WEBSOCKET_GUID.len());
    input.push_str(client_key);
    input.push_str(WEBSOCKET_GUID);
    let hash = sha1(input.as_bytes());
    base64_encode(&hash)
}

/// Parsed HTTP header: name and value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub name: String,
    pub value: String,
}

/// A client WebSocket handshake request.
#[derive(Debug, Clone)]
pub struct HandshakeRequest {
    pub path: String,
    pub host: String,
    pub key: String,
    pub version: String,
    pub protocols: Vec<String>,
    pub extensions: Vec<String>,
    pub headers: Vec<Header>,
}

impl HandshakeRequest {
    /// Generate the HTTP request string.
    #[must_use]
    pub fn to_http(&self) -> String {
        let mut s = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {}\r\nSec-WebSocket-Version: {}\r\n",
            self.path, self.host, self.key, self.version
        );
        if !self.protocols.is_empty() {
            let _ = write!(
                s,
                "Sec-WebSocket-Protocol: {}\r\n",
                self.protocols.join(", ")
            );
        }
        if !self.extensions.is_empty() {
            let _ = write!(
                s,
                "Sec-WebSocket-Extensions: {}\r\n",
                self.extensions.join(", ")
            );
        }
        for h in &self.headers {
            let _ = write!(s, "{}: {}\r\n", h.name, h.value);
        }
        s.push_str("\r\n");
        s
    }

    /// Create a default handshake request for a given host and path.
    #[must_use]
    pub fn new(host: &str, path: &str, key: &str) -> Self {
        Self {
            path: path.to_owned(),
            host: host.to_owned(),
            key: key.to_owned(),
            version: "13".to_owned(),
            protocols: Vec::new(),
            extensions: Vec::new(),
            headers: Vec::new(),
        }
    }

    /// Parse from HTTP request bytes.
    ///
    /// # Errors
    ///
    /// Returns `WsError::HandshakeError` if the request is malformed.
    pub fn parse(data: &[u8]) -> Result<Self, WsError> {
        let text = std::str::from_utf8(data)
            .map_err(|_| WsError::HandshakeError("invalid UTF-8".into()))?;

        let mut lines = text.lines();

        let request_line = lines
            .next()
            .ok_or_else(|| WsError::HandshakeError("empty request".into()))?;

        let parts: Vec<&str> = request_line.split_whitespace().collect();
        if parts.len() < 3 || parts[0] != "GET" {
            return Err(WsError::HandshakeError("invalid request line".into()));
        }

        let path = parts[1].to_owned();

        let mut host = String::new();
        let mut key = String::new();
        let mut version = String::new();
        let mut protocols = Vec::new();
        let mut extensions = Vec::new();
        let mut headers = Vec::new();

        for line in lines {
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                let name = name.trim();
                let value = value.trim();
                let lower = name.to_ascii_lowercase();
                match lower.as_str() {
                    "host" => value.clone_into(&mut host),
                    "sec-websocket-key" => value.clone_into(&mut key),
                    "sec-websocket-version" => value.clone_into(&mut version),
                    "sec-websocket-protocol" => {
                        protocols = value.split(',').map(|s| s.trim().to_owned()).collect();
                    }
                    "sec-websocket-extensions" => {
                        extensions = value.split(',').map(|s| s.trim().to_owned()).collect();
                    }
                    _ => {
                        headers.push(Header {
                            name: name.to_owned(),
                            value: value.to_owned(),
                        });
                    }
                }
            }
        }

        if key.is_empty() {
            return Err(WsError::HandshakeError("missing Sec-WebSocket-Key".into()));
        }

        Ok(Self {
            path,
            host,
            key,
            version,
            protocols,
            extensions,
            headers,
        })
    }
}

/// A server WebSocket handshake response.
#[derive(Debug, Clone)]
pub struct HandshakeResponse {
    pub accept: String,
    pub protocol: Option<String>,
    pub extensions: Vec<String>,
    pub headers: Vec<Header>,
}

impl HandshakeResponse {
    /// Create a response from a client key.
    #[must_use]
    pub fn from_key(key: &str) -> Self {
        Self {
            accept: compute_accept_key(key),
            protocol: None,
            extensions: Vec::new(),
            headers: Vec::new(),
        }
    }

    /// Generate the HTTP response string.
    #[must_use]
    pub fn to_http(&self) -> String {
        let mut s = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n",
            self.accept
        );
        if let Some(ref proto) = self.protocol {
            let _ = write!(s, "Sec-WebSocket-Protocol: {proto}\r\n");
        }
        if !self.extensions.is_empty() {
            let _ = write!(
                s,
                "Sec-WebSocket-Extensions: {}\r\n",
                self.extensions.join(", ")
            );
        }
        for h in &self.headers {
            let _ = write!(s, "{}: {}\r\n", h.name, h.value);
        }
        s.push_str("\r\n");
        s
    }

    /// Parse a server response to validate the handshake.
    ///
    /// # Errors
    ///
    /// Returns `WsError::HandshakeError` on malformed responses.
    pub fn parse(data: &[u8]) -> Result<Self, WsError> {
        let text = std::str::from_utf8(data)
            .map_err(|_| WsError::HandshakeError("invalid UTF-8".into()))?;

        let mut lines = text.lines();

        let status_line = lines
            .next()
            .ok_or_else(|| WsError::HandshakeError("empty response".into()))?;

        if !status_line.contains("101") {
            return Err(WsError::HandshakeError(format!(
                "expected 101, got: {status_line}"
            )));
        }

        let mut accept = String::new();
        let mut protocol = None;
        let mut extensions = Vec::new();
        let mut headers = Vec::new();

        for line in lines {
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                let name = name.trim();
                let value = value.trim();
                let lower = name.to_ascii_lowercase();
                match lower.as_str() {
                    "sec-websocket-accept" => value.clone_into(&mut accept),
                    "sec-websocket-protocol" => protocol = Some(value.to_owned()),
                    "sec-websocket-extensions" => {
                        extensions = value.split(',').map(|s| s.trim().to_owned()).collect();
                    }
                    _ => {
                        headers.push(Header {
                            name: name.to_owned(),
                            value: value.to_owned(),
                        });
                    }
                }
            }
        }

        if accept.is_empty() {
            return Err(WsError::HandshakeError(
                "missing Sec-WebSocket-Accept".into(),
            ));
        }

        Ok(Self {
            accept,
            protocol,
            extensions,
            headers,
        })
    }

    /// Validate the accept key against the original client key.
    ///
    /// # Errors
    ///
    /// Returns `WsError::InvalidAccept` if the accept value doesn't match.
    pub fn validate(&self, client_key: &str) -> Result<(), WsError> {
        let expected = compute_accept_key(client_key);
        if self.accept == expected {
            Ok(())
        } else {
            Err(WsError::InvalidAccept)
        }
    }
}

// ---------------------------------------------------------------------------
// Extensions
// ---------------------------------------------------------------------------

/// Parsed WebSocket extension with parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extension {
    pub name: String,
    pub params: Vec<ExtensionParam>,
}

/// A single extension parameter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionParam {
    pub key: String,
    pub value: Option<String>,
}

impl Extension {
    /// Parse an extension header value (e.g., `"permessage-deflate; client_max_window_bits"`).
    #[must_use]
    pub fn parse_list(header: &str) -> Vec<Self> {
        header
            .split(',')
            .filter_map(|ext_str| {
                let ext_str = ext_str.trim();
                if ext_str.is_empty() {
                    return None;
                }
                let mut parts = ext_str.split(';');
                let name = parts.next()?.trim().to_owned();
                if name.is_empty() {
                    return None;
                }
                let params = parts
                    .map(|p| {
                        let p = p.trim();
                        if let Some((k, v)) = p.split_once('=') {
                            ExtensionParam {
                                key: k.trim().to_owned(),
                                value: Some(v.trim().trim_matches('"').to_owned()),
                            }
                        } else {
                            ExtensionParam {
                                key: p.to_owned(),
                                value: None,
                            }
                        }
                    })
                    .collect();
                Some(Self { name, params })
            })
            .collect()
    }

    /// Serialize to header value format.
    #[must_use]
    pub fn to_header_value(extensions: &[Self]) -> String {
        extensions
            .iter()
            .map(|ext| {
                let mut s = ext.name.clone();
                for p in &ext.params {
                    s.push_str("; ");
                    s.push_str(&p.key);
                    if let Some(ref v) = p.value {
                        s.push('=');
                        s.push_str(v);
                    }
                }
                s
            })
            .collect::<Vec<_>>()
            .join(", ")
    }
}

// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // === Opcode tests ===

    #[test]
    fn opcode_from_u8_valid() {
        assert_eq!(Opcode::from_u8(0x0).unwrap(), Opcode::Continuation);
        assert_eq!(Opcode::from_u8(0x1).unwrap(), Opcode::Text);
        assert_eq!(Opcode::from_u8(0x2).unwrap(), Opcode::Binary);
        assert_eq!(Opcode::from_u8(0x8).unwrap(), Opcode::Close);
        assert_eq!(Opcode::from_u8(0x9).unwrap(), Opcode::Ping);
        assert_eq!(Opcode::from_u8(0xA).unwrap(), Opcode::Pong);
    }

    #[test]
    fn opcode_from_u8_invalid() {
        assert_eq!(Opcode::from_u8(0x3), Err(WsError::InvalidOpcode(0x3)));
        assert_eq!(Opcode::from_u8(0x7), Err(WsError::InvalidOpcode(0x7)));
        assert_eq!(Opcode::from_u8(0xB), Err(WsError::InvalidOpcode(0xB)));
        assert_eq!(Opcode::from_u8(0xF), Err(WsError::InvalidOpcode(0xF)));
    }

    #[test]
    fn opcode_is_control() {
        assert!(Opcode::Close.is_control());
        assert!(Opcode::Ping.is_control());
        assert!(Opcode::Pong.is_control());
        assert!(!Opcode::Text.is_control());
        assert!(!Opcode::Binary.is_control());
        assert!(!Opcode::Continuation.is_control());
    }

    #[test]
    fn opcode_is_data() {
        assert!(Opcode::Text.is_data());
        assert!(Opcode::Binary.is_data());
        assert!(Opcode::Continuation.is_data());
        assert!(!Opcode::Close.is_data());
        assert!(!Opcode::Ping.is_data());
        assert!(!Opcode::Pong.is_data());
    }

    // === Close code tests ===

    #[test]
    fn close_code_roundtrip() {
        let codes = [
            (1000, CloseCode::Normal),
            (1001, CloseCode::GoingAway),
            (1002, CloseCode::ProtocolError),
            (1003, CloseCode::Unsupported),
            (1005, CloseCode::NoStatus),
            (1006, CloseCode::Abnormal),
            (1007, CloseCode::InvalidPayload),
            (1008, CloseCode::PolicyViolation),
            (1009, CloseCode::TooLarge),
            (1010, CloseCode::MandatoryExtension),
            (1011, CloseCode::InternalError),
            (1015, CloseCode::TlsHandshake),
        ];
        for (num, code) in codes {
            assert_eq!(CloseCode::from_u16(num), code);
            assert_eq!(code.to_u16(), num);
        }
    }

    #[test]
    fn close_code_other() {
        let code = CloseCode::from_u16(4000);
        assert_eq!(code, CloseCode::Other(4000));
        assert_eq!(code.to_u16(), 4000);
    }

    #[test]
    fn close_code_sendable() {
        assert!(CloseCode::Normal.is_sendable());
        assert!(CloseCode::GoingAway.is_sendable());
        assert!(CloseCode::ProtocolError.is_sendable());
        assert!(!CloseCode::NoStatus.is_sendable());
        assert!(!CloseCode::Abnormal.is_sendable());
        assert!(!CloseCode::TlsHandshake.is_sendable());
        assert!(CloseCode::Other(3000).is_sendable());
        assert!(CloseCode::Other(4999).is_sendable());
        assert!(!CloseCode::Other(2999).is_sendable());
    }

    #[test]
    fn validate_close_code_valid() {
        assert!(validate_close_code(1000).is_ok());
        assert!(validate_close_code(1007).is_ok());
        assert!(validate_close_code(3000).is_ok());
        assert!(validate_close_code(4999).is_ok());
    }

    #[test]
    fn validate_close_code_invalid() {
        assert!(validate_close_code(1004).is_err());
        assert!(validate_close_code(1005).is_err());
        assert!(validate_close_code(1006).is_err());
        assert!(validate_close_code(999).is_err());
        assert!(validate_close_code(5000).is_err());
    }

    // === Close payload tests ===

    #[test]
    fn close_payload_parse_empty() {
        assert_eq!(ClosePayload::parse(&[]).unwrap(), None);
    }

    #[test]
    fn close_payload_parse_single_byte() {
        assert!(ClosePayload::parse(&[0x00]).is_err());
    }

    #[test]
    fn close_payload_parse_code_only() {
        let data = 1000u16.to_be_bytes();
        let cp = ClosePayload::parse(&data).unwrap().unwrap();
        assert_eq!(cp.code, CloseCode::Normal);
        assert_eq!(cp.reason, "");
    }

    #[test]
    fn close_payload_parse_code_and_reason() {
        let mut data = vec![0x03, 0xE8]; // 1000
        data.extend_from_slice(b"goodbye");
        let cp = ClosePayload::parse(&data).unwrap().unwrap();
        assert_eq!(cp.code, CloseCode::Normal);
        assert_eq!(cp.reason, "goodbye");
    }

    #[test]
    fn close_payload_parse_invalid_utf8() {
        let mut data = vec![0x03, 0xE8]; // 1000
        data.extend_from_slice(&[0xFF, 0xFE]);
        assert_eq!(ClosePayload::parse(&data), Err(WsError::InvalidUtf8));
    }

    #[test]
    fn close_payload_roundtrip() {
        let cp = ClosePayload {
            code: CloseCode::GoingAway,
            reason: "server shutdown".into(),
        };
        let bytes = cp.to_bytes();
        let parsed = ClosePayload::parse(&bytes).unwrap().unwrap();
        assert_eq!(parsed, cp);
    }

    // === Masking tests ===

    #[test]
    fn mask_unmask_roundtrip() {
        let key = [0x37, 0xFA, 0x21, 0x3D];
        let original = b"Hello, WebSocket!";
        let masked = apply_mask(original, key);
        assert_ne!(&masked, original);
        let unmasked = apply_mask(&masked, key);
        assert_eq!(&unmasked, original);
    }

    #[test]
    fn mask_empty_data() {
        let key = [1, 2, 3, 4];
        let result = apply_mask(&[], key);
        assert!(result.is_empty());
    }

    #[test]
    fn mask_in_place_single_byte() {
        let key = [0xAB, 0, 0, 0];
        let mut data = vec![0x00];
        apply_mask_in_place(&mut data, key);
        assert_eq!(data, vec![0xAB]);
    }

    #[test]
    fn mask_wraps_around_key() {
        let key = [1, 2, 3, 4];
        let data = vec![0, 0, 0, 0, 0, 0, 0, 0];
        let masked = apply_mask(&data, key);
        assert_eq!(masked, vec![1, 2, 3, 4, 1, 2, 3, 4]);
    }

    // === Frame construction tests ===

    #[test]
    fn frame_text() {
        let f = Frame::text("hello");
        assert!(f.fin);
        assert_eq!(f.opcode, Opcode::Text);
        assert_eq!(f.payload, b"hello");
        assert!(!f.masked);
    }

    #[test]
    fn frame_binary() {
        let f = Frame::binary(vec![1, 2, 3]);
        assert_eq!(f.opcode, Opcode::Binary);
        assert_eq!(f.payload, vec![1, 2, 3]);
    }

    #[test]
    fn frame_ping() {
        let f = Frame::ping(vec![]);
        assert_eq!(f.opcode, Opcode::Ping);
        assert!(f.fin);
    }

    #[test]
    fn frame_pong() {
        let f = Frame::pong(vec![0xAA]);
        assert_eq!(f.opcode, Opcode::Pong);
        assert_eq!(f.payload, vec![0xAA]);
    }

    #[test]
    fn frame_close_no_code() {
        let f = Frame::close(None, "");
        assert_eq!(f.opcode, Opcode::Close);
        assert!(f.payload.is_empty());
    }

    #[test]
    fn frame_close_with_code() {
        let f = Frame::close(Some(CloseCode::Normal), "bye");
        assert_eq!(f.opcode, Opcode::Close);
        let cp = ClosePayload::parse(&f.payload).unwrap().unwrap();
        assert_eq!(cp.code, CloseCode::Normal);
        assert_eq!(cp.reason, "bye");
    }

    #[test]
    fn frame_continuation() {
        let f = Frame::continuation(vec![1, 2], false);
        assert!(!f.fin);
        assert_eq!(f.opcode, Opcode::Continuation);
    }

    #[test]
    fn frame_set_mask() {
        let mut f = Frame::text("x");
        f.set_mask([1, 2, 3, 4]);
        assert!(f.masked);
        assert_eq!(f.mask_key, [1, 2, 3, 4]);
    }

    // === Frame serialization tests ===

    #[test]
    fn serialize_small_frame() {
        let f = Frame::text("Hi");
        let bytes = f.serialize();
        assert_eq!(bytes[0], 0x81); // FIN + TEXT
        assert_eq!(bytes[1], 2); // payload length
        assert_eq!(&bytes[2..], b"Hi");
    }

    #[test]
    fn serialize_medium_frame() {
        let payload = vec![0x42; 200];
        let f = Frame::binary(payload.clone());
        let bytes = f.serialize();
        assert_eq!(bytes[0], 0x82); // FIN + BINARY
        assert_eq!(bytes[1], 126); // extended 16-bit length
        let len = u16::from_be_bytes([bytes[2], bytes[3]]);
        assert_eq!(len, 200);
        assert_eq!(&bytes[4..], payload.as_slice());
    }

    #[test]
    fn serialize_large_frame() {
        let payload = vec![0x00; 70000];
        let f = Frame::binary(payload.clone());
        let bytes = f.serialize();
        assert_eq!(bytes[1], 127); // extended 64-bit length
        let len = u64::from_be_bytes([
            bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9],
        ]);
        assert_eq!(len, 70000);
    }

    #[test]
    fn serialize_masked_frame() {
        let mut f = Frame::text("AB");
        f.set_mask([0x01, 0x02, 0x03, 0x04]);
        let bytes = f.serialize_masked();
        assert_eq!(bytes[1] & 0x80, 0x80); // mask bit
        assert_eq!(&bytes[2..6], &[0x01, 0x02, 0x03, 0x04]);
        // payload is masked
        assert_eq!(bytes[6], b'A' ^ 0x01);
        assert_eq!(bytes[7], b'B' ^ 0x02);
    }

    #[test]
    fn serialize_rsv_bits() {
        let mut f = Frame::ping(vec![]);
        f.rsv1 = true;
        f.rsv2 = true;
        f.rsv3 = true;
        let bytes = f.serialize();
        assert_eq!(bytes[0] & 0x70, 0x70);
    }

    // === Frame parsing tests ===

    #[test]
    fn parse_simple_text() {
        let f = Frame::text("test");
        let bytes = f.serialize();
        let (parsed, consumed) = Frame::parse(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed.opcode, Opcode::Text);
        assert_eq!(parsed.payload, b"test");
        assert!(parsed.fin);
    }

    #[test]
    fn parse_binary_frame() {
        let f = Frame::binary(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let bytes = f.serialize();
        let (parsed, _) = Frame::parse(&bytes).unwrap();
        assert_eq!(parsed.opcode, Opcode::Binary);
        assert_eq!(parsed.payload, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn parse_masked_frame() {
        let mut f = Frame::text("hi");
        f.set_mask([0x37, 0xFA, 0x21, 0x3D]);
        let bytes = f.serialize_masked();
        let (parsed, _) = Frame::parse(&bytes).unwrap();
        assert_eq!(parsed.payload, b"hi"); // unmasked
        assert!(parsed.masked);
    }

    #[test]
    fn parse_incomplete() {
        assert_eq!(Frame::parse(&[0x81]), Err(WsError::Incomplete));
    }

    #[test]
    fn parse_incomplete_payload() {
        let bytes = vec![0x81, 0x05, 0x41]; // says 5 bytes but only 1
        assert_eq!(Frame::parse(&bytes), Err(WsError::Incomplete));
    }

    #[test]
    fn parse_incomplete_extended16() {
        let bytes = vec![0x81, 126, 0x00]; // missing second byte of length
        assert_eq!(Frame::parse(&bytes), Err(WsError::Incomplete));
    }

    #[test]
    fn parse_incomplete_extended64() {
        let bytes = vec![0x81, 127, 0, 0, 0]; // missing most of length
        assert_eq!(Frame::parse(&bytes), Err(WsError::Incomplete));
    }

    #[test]
    fn parse_reserved_bits_rejected() {
        let bytes = vec![0xC1, 0x00]; // RSV1 set
        assert_eq!(Frame::parse(&bytes), Err(WsError::ReservedBitsSet));
    }

    #[test]
    fn parse_reserved_bits_allowed_with_extensions() {
        let bytes = vec![0xC1, 0x00]; // RSV1 set, FIN+Text
        let (frame, _) = Frame::parse_with_extensions(&bytes, true).unwrap();
        assert!(frame.rsv1);
    }

    #[test]
    fn parse_invalid_opcode() {
        let bytes = vec![0x83, 0x00]; // opcode 3 is reserved
        assert_eq!(Frame::parse(&bytes), Err(WsError::InvalidOpcode(3)));
    }

    #[test]
    fn parse_control_frame_too_large() {
        let mut bytes = vec![0x89, 126, 0x00, 0x80]; // ping with 128 byte payload
        bytes.extend(vec![0; 128]);
        assert_eq!(Frame::parse(&bytes), Err(WsError::ControlFrameTooLarge));
    }

    #[test]
    fn parse_fragmented_control_frame() {
        let bytes = vec![0x09, 0x00]; // ping without FIN
        assert_eq!(Frame::parse(&bytes), Err(WsError::FragmentedControlFrame));
    }

    #[test]
    fn parse_medium_payload() {
        let payload = vec![0xAB; 300];
        let f = Frame::binary(payload.clone());
        let bytes = f.serialize();
        let (parsed, consumed) = Frame::parse(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn parse_large_payload() {
        let payload = vec![0xCD; 70000];
        let f = Frame::binary(payload.clone());
        let bytes = f.serialize();
        let (parsed, consumed) = Frame::parse(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn parse_roundtrip_all_opcodes() {
        let opcodes = [
            Opcode::Text,
            Opcode::Binary,
            Opcode::Close,
            Opcode::Ping,
            Opcode::Pong,
        ];
        for op in opcodes {
            let f = Frame::new(op, vec![0x01, 0x02]);
            let bytes = f.serialize();
            let (parsed, _) = Frame::parse(&bytes).unwrap();
            assert_eq!(parsed.opcode, op);
            assert_eq!(parsed.payload, vec![0x01, 0x02]);
        }
    }

    #[test]
    fn parse_empty_payload() {
        let f = Frame::binary(vec![]);
        let bytes = f.serialize();
        let (parsed, _) = Frame::parse(&bytes).unwrap();
        assert!(parsed.payload.is_empty());
    }

    #[test]
    fn parse_exactly_125_byte_control() {
        let f = Frame::ping(vec![0x42; 125]);
        let bytes = f.serialize();
        let (parsed, _) = Frame::parse(&bytes).unwrap();
        assert_eq!(parsed.payload.len(), 125);
    }

    #[test]
    fn parse_multiple_frames_in_buffer() {
        let f1 = Frame::text("one");
        let f2 = Frame::text("two");
        let mut bytes = f1.serialize();
        bytes.extend(f2.serialize());

        let (p1, consumed1) = Frame::parse(&bytes).unwrap();
        assert_eq!(p1.payload, b"one");

        let (p2, _) = Frame::parse(&bytes[consumed1..]).unwrap();
        assert_eq!(p2.payload, b"two");
    }

    #[test]
    fn header_size_small() {
        let f = Frame::text("hi");
        assert_eq!(f.header_size(), 2);
    }

    #[test]
    fn header_size_medium() {
        let f = Frame::binary(vec![0; 200]);
        assert_eq!(f.header_size(), 4);
    }

    #[test]
    fn header_size_large() {
        let f = Frame::binary(vec![0; 70000]);
        assert_eq!(f.header_size(), 10);
    }

    #[test]
    fn header_size_masked() {
        let mut f = Frame::text("hi");
        f.set_mask([1, 2, 3, 4]);
        assert_eq!(f.header_size(), 6); // 2 + 4
    }

    // === Base64 tests ===

    #[test]
    fn base64_encode_empty() {
        assert_eq!(base64_encode(&[]), "");
    }

    #[test]
    fn base64_encode_hello() {
        assert_eq!(base64_encode(b"Hello"), "SGVsbG8=");
    }

    #[test]
    fn base64_encode_padding() {
        assert_eq!(base64_encode(b"a"), "YQ==");
        assert_eq!(base64_encode(b"ab"), "YWI=");
        assert_eq!(base64_encode(b"abc"), "YWJj");
    }

    #[test]
    fn base64_roundtrip() {
        let data = b"WebSocket protocol test data 1234567890!@#";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn base64_decode_invalid() {
        assert!(base64_decode("!!!").is_err());
    }

    // === SHA-1 / handshake key tests ===

    #[test]
    fn sha1_empty() {
        let result = sha1(b"");
        let hex: String = result.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    #[test]
    fn sha1_abc() {
        let result = sha1(b"abc");
        let hex: String = result.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "a9993e364706816aba3e25717850c26c9cd0d89d");
    }

    #[test]
    fn compute_accept_key_rfc_example() {
        // RFC 6455 Section 4.2.2 example
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let accept = compute_accept_key(key);
        assert_eq!(accept, "fPgBbBWxQ5p/OQE7IpV6s8+HiTg=");
    }

    // === Handshake request tests ===

    #[test]
    fn handshake_request_to_http() {
        let req = HandshakeRequest::new("example.com", "/chat", "dGhlIHNhbXBsZSBub25jZQ==");
        let http = req.to_http();
        assert!(http.contains("GET /chat HTTP/1.1\r\n"));
        assert!(http.contains("Host: example.com\r\n"));
        assert!(http.contains("Upgrade: websocket\r\n"));
        assert!(http.contains("Connection: Upgrade\r\n"));
        assert!(http.contains("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"));
        assert!(http.contains("Sec-WebSocket-Version: 13\r\n"));
    }

    #[test]
    fn handshake_request_with_protocols() {
        let mut req = HandshakeRequest::new("host", "/", "key123");
        req.protocols = vec!["chat".into(), "superchat".into()];
        let http = req.to_http();
        assert!(http.contains("Sec-WebSocket-Protocol: chat, superchat\r\n"));
    }

    #[test]
    fn handshake_request_with_extensions() {
        let mut req = HandshakeRequest::new("host", "/", "key123");
        req.extensions = vec!["permessage-deflate".into()];
        let http = req.to_http();
        assert!(http.contains("Sec-WebSocket-Extensions: permessage-deflate\r\n"));
    }

    #[test]
    fn handshake_request_parse() {
        let raw = b"GET /ws HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: testkey\r\nSec-WebSocket-Version: 13\r\n\r\n";
        let req = HandshakeRequest::parse(raw).unwrap();
        assert_eq!(req.path, "/ws");
        assert_eq!(req.host, "example.com");
        assert_eq!(req.key, "testkey");
        assert_eq!(req.version, "13");
    }

    #[test]
    fn handshake_request_parse_with_protocols() {
        let raw = b"GET / HTTP/1.1\r\nHost: h\r\nSec-WebSocket-Key: k\r\nSec-WebSocket-Protocol: chat, superchat\r\n\r\n";
        let req = HandshakeRequest::parse(raw).unwrap();
        assert_eq!(req.protocols, vec!["chat", "superchat"]);
    }

    #[test]
    fn handshake_request_parse_missing_key() {
        let raw = b"GET / HTTP/1.1\r\nHost: h\r\n\r\n";
        assert!(HandshakeRequest::parse(raw).is_err());
    }

    #[test]
    fn handshake_request_parse_not_get() {
        let raw = b"POST / HTTP/1.1\r\n\r\n";
        assert!(HandshakeRequest::parse(raw).is_err());
    }

    // === Handshake response tests ===

    #[test]
    fn handshake_response_from_key() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let resp = HandshakeResponse::from_key(key);
        assert_eq!(resp.accept, "fPgBbBWxQ5p/OQE7IpV6s8+HiTg=");
    }

    #[test]
    fn handshake_response_to_http() {
        let resp = HandshakeResponse::from_key("dGhlIHNhbXBsZSBub25jZQ==");
        let http = resp.to_http();
        assert!(http.contains("HTTP/1.1 101 Switching Protocols\r\n"));
        assert!(http.contains("Upgrade: websocket\r\n"));
        assert!(http.contains("Connection: Upgrade\r\n"));
        assert!(http.contains("Sec-WebSocket-Accept: fPgBbBWxQ5p/OQE7IpV6s8+HiTg=\r\n"));
    }

    #[test]
    fn handshake_response_parse() {
        let raw = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: fPgBbBWxQ5p/OQE7IpV6s8+HiTg=\r\n\r\n";
        let resp = HandshakeResponse::parse(raw).unwrap();
        assert_eq!(resp.accept, "fPgBbBWxQ5p/OQE7IpV6s8+HiTg=");
    }

    #[test]
    fn handshake_response_validate_ok() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let resp = HandshakeResponse::from_key(key);
        assert!(resp.validate(key).is_ok());
    }

    #[test]
    fn handshake_response_validate_fail() {
        let resp = HandshakeResponse {
            accept: "wrong".into(),
            protocol: None,
            extensions: Vec::new(),
            headers: Vec::new(),
        };
        assert_eq!(
            resp.validate("dGhlIHNhbXBsZSBub25jZQ=="),
            Err(WsError::InvalidAccept)
        );
    }

    #[test]
    fn handshake_response_parse_not_101() {
        let raw = b"HTTP/1.1 400 Bad Request\r\n\r\n";
        assert!(HandshakeResponse::parse(raw).is_err());
    }

    #[test]
    fn handshake_response_with_protocol() {
        let mut resp = HandshakeResponse::from_key("k");
        resp.protocol = Some("chat".into());
        let http = resp.to_http();
        assert!(http.contains("Sec-WebSocket-Protocol: chat\r\n"));
    }

    #[test]
    fn handshake_full_roundtrip() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let req = HandshakeRequest::new("example.com", "/chat", key);
        let http_req = req.to_http();
        let parsed_req = HandshakeRequest::parse(http_req.as_bytes()).unwrap();

        let resp = HandshakeResponse::from_key(&parsed_req.key);
        let http_resp = resp.to_http();
        let parsed_resp = HandshakeResponse::parse(http_resp.as_bytes()).unwrap();
        assert!(parsed_resp.validate(key).is_ok());
    }

    // === Extension tests ===

    #[test]
    fn extension_parse_simple() {
        let exts = Extension::parse_list("permessage-deflate");
        assert_eq!(exts.len(), 1);
        assert_eq!(exts[0].name, "permessage-deflate");
        assert!(exts[0].params.is_empty());
    }

    #[test]
    fn extension_parse_with_params() {
        let exts = Extension::parse_list(
            "permessage-deflate; client_max_window_bits; server_no_context_takeover",
        );
        assert_eq!(exts.len(), 1);
        assert_eq!(exts[0].params.len(), 2);
        assert_eq!(exts[0].params[0].key, "client_max_window_bits");
        assert!(exts[0].params[0].value.is_none());
    }

    #[test]
    fn extension_parse_with_value() {
        let exts = Extension::parse_list("permessage-deflate; client_max_window_bits=15");
        assert_eq!(exts[0].params[0].value, Some("15".into()));
    }

    #[test]
    fn extension_parse_multiple() {
        let exts = Extension::parse_list("ext1, ext2; param=val");
        assert_eq!(exts.len(), 2);
        assert_eq!(exts[0].name, "ext1");
        assert_eq!(exts[1].name, "ext2");
    }

    #[test]
    fn extension_parse_empty() {
        let exts = Extension::parse_list("");
        assert!(exts.is_empty());
    }

    #[test]
    fn extension_to_header_value() {
        let exts = vec![
            Extension {
                name: "permessage-deflate".into(),
                params: vec![ExtensionParam {
                    key: "client_max_window_bits".into(),
                    value: Some("15".into()),
                }],
            },
            Extension {
                name: "x-custom".into(),
                params: vec![],
            },
        ];
        let header = Extension::to_header_value(&exts);
        assert_eq!(
            header,
            "permessage-deflate; client_max_window_bits=15, x-custom"
        );
    }

    #[test]
    fn extension_roundtrip() {
        let original = "permessage-deflate; client_max_window_bits=15, x-test; flag";
        let exts = Extension::parse_list(original);
        let header = Extension::to_header_value(&exts);
        let reparsed = Extension::parse_list(&header);
        assert_eq!(exts, reparsed);
    }

    // === Message assembler tests ===

    #[test]
    fn assembler_unfragmented_text() {
        let mut asm = MessageAssembler::new();
        let f = Frame::text("hello");
        let msg = asm.feed(&f).unwrap().unwrap();
        assert_eq!(msg.opcode, Opcode::Text);
        assert_eq!(msg.payload, b"hello");
    }

    #[test]
    fn assembler_unfragmented_binary() {
        let mut asm = MessageAssembler::new();
        let f = Frame::binary(vec![1, 2, 3]);
        let msg = asm.feed(&f).unwrap().unwrap();
        assert_eq!(msg.opcode, Opcode::Binary);
    }

    #[test]
    fn assembler_fragmented_text() {
        let mut asm = MessageAssembler::new();

        let mut f1 = Frame::new(Opcode::Text, b"hel".to_vec());
        f1.fin = false;
        assert!(asm.feed(&f1).unwrap().is_none());
        assert!(asm.in_progress());

        let f2 = Frame::continuation(b"lo".to_vec(), true);
        let msg = asm.feed(&f2).unwrap().unwrap();
        assert_eq!(msg.opcode, Opcode::Text);
        assert_eq!(msg.payload, b"hello");
        assert!(!asm.in_progress());
    }

    #[test]
    fn assembler_fragmented_three_parts() {
        let mut asm = MessageAssembler::new();

        let mut f1 = Frame::new(Opcode::Binary, vec![1]);
        f1.fin = false;
        assert!(asm.feed(&f1).unwrap().is_none());

        let f2 = Frame::continuation(vec![2], false);
        assert!(asm.feed(&f2).unwrap().is_none());

        let f3 = Frame::continuation(vec![3], true);
        let msg = asm.feed(&f3).unwrap().unwrap();
        assert_eq!(msg.payload, vec![1, 2, 3]);
    }

    #[test]
    fn assembler_control_during_fragment() {
        let mut asm = MessageAssembler::new();

        let mut f1 = Frame::new(Opcode::Text, b"hel".to_vec());
        f1.fin = false;
        assert!(asm.feed(&f1).unwrap().is_none());

        // Control frame in the middle should be delivered
        let ping = Frame::ping(vec![0x42]);
        let msg = asm.feed(&ping).unwrap().unwrap();
        assert_eq!(msg.opcode, Opcode::Ping);

        // Continue the fragment
        let f2 = Frame::continuation(b"lo".to_vec(), true);
        let msg = asm.feed(&f2).unwrap().unwrap();
        assert_eq!(msg.payload, b"hello");
    }

    #[test]
    fn assembler_continuation_without_start() {
        let mut asm = MessageAssembler::new();
        let f = Frame::continuation(vec![1], true);
        assert!(asm.feed(&f).is_err());
    }

    #[test]
    fn assembler_new_data_during_fragment() {
        let mut asm = MessageAssembler::new();
        let mut f1 = Frame::new(Opcode::Text, b"x".to_vec());
        f1.fin = false;
        asm.feed(&f1).unwrap();

        let f2 = Frame::text("y");
        assert!(asm.feed(&f2).is_err());
    }

    #[test]
    fn assembler_reset() {
        let mut asm = MessageAssembler::new();
        let mut f = Frame::new(Opcode::Text, b"x".to_vec());
        f.fin = false;
        asm.feed(&f).unwrap();
        assert!(asm.in_progress());

        asm.reset();
        assert!(!asm.in_progress());
    }

    #[test]
    fn assembler_invalid_utf8_text() {
        let mut asm = MessageAssembler::new();
        let f = Frame::new(Opcode::Text, vec![0xFF, 0xFE]);
        assert_eq!(asm.feed(&f), Err(WsError::InvalidUtf8));
    }

    #[test]
    fn assembler_invalid_utf8_fragmented() {
        let mut asm = MessageAssembler::new();
        let mut f1 = Frame::new(Opcode::Text, vec![0xFF]);
        f1.fin = false;
        asm.feed(&f1).unwrap();

        let f2 = Frame::continuation(vec![0xFE], true);
        assert_eq!(asm.feed(&f2), Err(WsError::InvalidUtf8));
    }

    #[test]
    fn assembler_default() {
        let asm = MessageAssembler::default();
        assert!(!asm.in_progress());
    }

    // === Message tests ===

    #[test]
    fn message_as_text() {
        let msg = Message {
            opcode: Opcode::Text,
            payload: b"hello".to_vec(),
        };
        assert_eq!(msg.as_text().unwrap(), "hello");
    }

    #[test]
    fn message_as_text_invalid() {
        let msg = Message {
            opcode: Opcode::Text,
            payload: vec![0xFF],
        };
        assert!(msg.as_text().is_err());
    }

    #[test]
    fn message_fragment_small() {
        let msg = Message {
            opcode: Opcode::Text,
            payload: b"hi".to_vec(),
        };
        let frames = msg.fragment(100);
        assert_eq!(frames.len(), 1);
        assert!(frames[0].fin);
        assert_eq!(frames[0].opcode, Opcode::Text);
    }

    #[test]
    fn message_fragment_split() {
        let msg = Message {
            opcode: Opcode::Binary,
            payload: vec![1, 2, 3, 4, 5],
        };
        let frames = msg.fragment(2);
        assert_eq!(frames.len(), 3);

        assert_eq!(frames[0].opcode, Opcode::Binary);
        assert!(!frames[0].fin);
        assert_eq!(frames[0].payload, vec![1, 2]);

        assert_eq!(frames[1].opcode, Opcode::Continuation);
        assert!(!frames[1].fin);
        assert_eq!(frames[1].payload, vec![3, 4]);

        assert_eq!(frames[2].opcode, Opcode::Continuation);
        assert!(frames[2].fin);
        assert_eq!(frames[2].payload, vec![5]);
    }

    #[test]
    fn message_fragment_zero_size() {
        let msg = Message {
            opcode: Opcode::Text,
            payload: b"ab".to_vec(),
        };
        let frames = msg.fragment(0);
        assert_eq!(frames.len(), 2);
    }

    #[test]
    fn message_fragment_reassemble() {
        let msg = Message {
            opcode: Opcode::Text,
            payload: b"Hello, World!".to_vec(),
        };
        let frames = msg.fragment(5);
        assert!(frames.len() > 1);

        let mut asm = MessageAssembler::new();
        let mut result = None;
        for f in &frames {
            if let Some(m) = asm.feed(f).unwrap() {
                result = Some(m);
            }
        }
        let reassembled = result.unwrap();
        assert_eq!(reassembled, msg);
    }

    // === FrameBuffer tests ===

    #[test]
    fn frame_buffer_empty() {
        let mut fb = FrameBuffer::new();
        assert!(fb.try_parse().unwrap().is_none());
        assert!(fb.is_empty());
        assert_eq!(fb.len(), 0);
    }

    #[test]
    fn frame_buffer_single_frame() {
        let mut fb = FrameBuffer::new();
        let f = Frame::text("test");
        fb.extend(&f.serialize());
        let parsed = fb.try_parse().unwrap().unwrap();
        assert_eq!(parsed.payload, b"test");
        assert!(fb.is_empty());
    }

    #[test]
    fn frame_buffer_partial_data() {
        let mut fb = FrameBuffer::new();
        let f = Frame::text("hello");
        let bytes = f.serialize();

        fb.extend(&bytes[..3]);
        assert!(fb.try_parse().unwrap().is_none());
        assert_eq!(fb.len(), 3);

        fb.extend(&bytes[3..]);
        let parsed = fb.try_parse().unwrap().unwrap();
        assert_eq!(parsed.payload, b"hello");
    }

    #[test]
    fn frame_buffer_multiple_frames() {
        let mut fb = FrameBuffer::new();
        let f1 = Frame::text("one");
        let f2 = Frame::binary(vec![1, 2, 3]);
        let mut bytes = f1.serialize();
        bytes.extend(f2.serialize());

        fb.extend(&bytes);

        let p1 = fb.try_parse().unwrap().unwrap();
        assert_eq!(p1.payload, b"one");

        let p2 = fb.try_parse().unwrap().unwrap();
        assert_eq!(p2.payload, vec![1, 2, 3]);

        assert!(fb.try_parse().unwrap().is_none());
    }

    #[test]
    fn frame_buffer_with_extensions() {
        let mut fb = FrameBuffer::with_extensions();
        let mut f = Frame::text("x");
        f.rsv1 = true;
        fb.extend(&f.serialize());
        let parsed = fb.try_parse().unwrap().unwrap();
        assert!(parsed.rsv1);
    }

    #[test]
    fn frame_buffer_clear() {
        let mut fb = FrameBuffer::new();
        fb.extend(&[0x81, 0x01, 0x41]);
        fb.clear();
        assert!(fb.is_empty());
    }

    #[test]
    fn frame_buffer_default() {
        let fb = FrameBuffer::default();
        assert!(fb.is_empty());
    }

    // === Error display tests ===

    #[test]
    fn error_display() {
        assert_eq!(WsError::Incomplete.to_string(), "incomplete frame data");
        assert_eq!(
            WsError::InvalidOpcode(0x3).to_string(),
            "invalid opcode: 0x3"
        );
        assert_eq!(
            WsError::ControlFrameTooLarge.to_string(),
            "control frame payload > 125 bytes"
        );
        assert_eq!(
            WsError::FragmentedControlFrame.to_string(),
            "control frame must not be fragmented"
        );
        assert_eq!(
            WsError::ReservedBitsSet.to_string(),
            "reserved bits set without extensions"
        );
        assert_eq!(
            WsError::InvalidUtf8.to_string(),
            "invalid UTF-8 in text frame"
        );
        assert_eq!(
            WsError::InvalidCloseCode(9999).to_string(),
            "invalid close code: 9999"
        );
        assert_eq!(
            WsError::HandshakeError("test".into()).to_string(),
            "handshake error: test"
        );
        assert_eq!(
            WsError::InvalidAccept.to_string(),
            "invalid Sec-WebSocket-Accept"
        );
        assert_eq!(
            WsError::FragmentationError("test".into()).to_string(),
            "fragmentation error: test"
        );
        assert_eq!(
            WsError::PayloadTooLarge.to_string(),
            "payload length overflow"
        );
    }

    #[test]
    fn error_is_std_error() {
        let e: Box<dyn std::error::Error> = Box::new(WsError::Incomplete);
        assert!(!e.to_string().is_empty());
    }

    // === Integration-style tests ===

    #[test]
    fn full_client_server_handshake_flow() {
        // Client creates request
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let req = HandshakeRequest::new("example.com", "/ws", key);
        let req_http = req.to_http();

        // Server parses request
        let parsed_req = HandshakeRequest::parse(req_http.as_bytes()).unwrap();
        assert_eq!(parsed_req.key, key);

        // Server creates response
        let resp = HandshakeResponse::from_key(&parsed_req.key);
        let resp_http = resp.to_http();

        // Client parses and validates response
        let parsed_resp = HandshakeResponse::parse(resp_http.as_bytes()).unwrap();
        parsed_resp.validate(key).unwrap();

        // Now exchange frames
        let mut client_buf = FrameBuffer::new();
        let mut server_asm = MessageAssembler::new();

        // Client sends masked text
        let mut f = Frame::text("Hello server!");
        f.set_mask([0x12, 0x34, 0x56, 0x78]);
        let wire = f.serialize_masked();

        // Server receives
        client_buf.extend(&wire);
        let received = client_buf.try_parse().unwrap().unwrap();
        let msg = server_asm.feed(&received).unwrap().unwrap();
        assert_eq!(msg.as_text().unwrap(), "Hello server!");
    }

    #[test]
    fn fragmented_message_with_interleaved_ping() {
        let mut asm = MessageAssembler::new();
        let mut fb = FrameBuffer::new();

        // First fragment
        let mut f1 = Frame::new(Opcode::Text, b"Hel".to_vec());
        f1.fin = false;
        fb.extend(&f1.serialize());

        // Interleaved ping
        let ping = Frame::ping(b"check".to_vec());
        fb.extend(&ping.serialize());

        // Second fragment
        let f2 = Frame::continuation(b"lo!".to_vec(), true);
        fb.extend(&f2.serialize());

        let mut messages = Vec::new();
        while let Some(frame) = fb.try_parse().unwrap() {
            if let Some(msg) = asm.feed(&frame).unwrap() {
                messages.push(msg);
            }
        }

        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].opcode, Opcode::Ping);
        assert_eq!(messages[0].payload, b"check");
        assert_eq!(messages[1].opcode, Opcode::Text);
        assert_eq!(messages[1].as_text().unwrap(), "Hello!");
    }

    #[test]
    fn close_frame_flow() {
        // Client sends close
        let close = Frame::close(Some(CloseCode::Normal), "goodbye");
        let bytes = close.serialize();
        let (parsed, _) = Frame::parse(&bytes).unwrap();

        let cp = ClosePayload::parse(&parsed.payload).unwrap().unwrap();
        assert_eq!(cp.code, CloseCode::Normal);
        assert_eq!(cp.reason, "goodbye");

        // Server echoes close
        let echo = Frame::close(Some(cp.code), &cp.reason);
        let echo_bytes = echo.serialize();
        let (parsed_echo, _) = Frame::parse(&echo_bytes).unwrap();
        let cp2 = ClosePayload::parse(&parsed_echo.payload).unwrap().unwrap();
        assert_eq!(cp2.code, CloseCode::Normal);
    }

    #[test]
    fn ping_pong_flow() {
        let ping_data = b"heartbeat";
        let ping = Frame::ping(ping_data.to_vec());
        let bytes = ping.serialize();
        let (parsed, _) = Frame::parse(&bytes).unwrap();
        assert_eq!(parsed.opcode, Opcode::Ping);

        // Response with pong using same payload
        let pong = Frame::pong(parsed.payload.clone());
        let pong_bytes = pong.serialize();
        let (parsed_pong, _) = Frame::parse(&pong_bytes).unwrap();
        assert_eq!(parsed_pong.opcode, Opcode::Pong);
        assert_eq!(parsed_pong.payload, ping_data);
    }
}
