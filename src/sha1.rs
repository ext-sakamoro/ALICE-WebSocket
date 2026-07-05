//! SHA-1 (minimal implementation, handshake accept key only).

// SHA-1 (minimal, for handshake only)
// ---------------------------------------------------------------------------

/// Minimal SHA-1 implementation for WebSocket handshake.
/// Not for general cryptographic use.
pub struct Sha1 {
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
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finalize()
}
