//! Masking XOR (per RFC 6455 client → server frames).

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
