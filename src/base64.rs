//! Base64 encode / decode.

use crate::errors::WsError;

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
