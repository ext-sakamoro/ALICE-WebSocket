//! Mask and handshake-key sources for the client role.
//!
//! RFC 6455 Section 5.3: every frame a client sends is masked with a fresh 32-bit key that the server (and any
//! intermediary) cannot predict. Section 4.1: the `Sec-WebSocket-Key` is 16 random bytes, base64-encoded.
//! [`MaskSource`] is where those bytes come from; `OsMask` (feature `rng`) reads them from the operating
//! system's random source.

/// A source of mask keys and handshake nonces.
///
/// `fill` must fill the whole buffer with bytes the peer cannot predict. An implementation that cannot do so must
/// panic rather than return a predictable buffer (zeros, a counter, a clock): a client that sends predictable
/// masks defeats the purpose of masking (RFC 6455 Section 10.3).
///
/// A deterministic implementation is for tests only (for example to reproduce the RFC 6455 Section 5.7 example).
pub trait MaskSource {
    /// Fill `buf` entirely with unpredictable bytes.
    fn fill(&mut self, buf: &mut [u8]);
}

impl<M: MaskSource + ?Sized> MaskSource for &mut M {
    fn fill(&mut self, buf: &mut [u8]) {
        (**self).fill(buf);
    }
}

impl<M: MaskSource + ?Sized> MaskSource for Box<M> {
    fn fill(&mut self, buf: &mut [u8]) {
        (**self).fill(buf);
    }
}

/// Mask keys and handshake nonces from the operating system's random source
/// (`alice_crypto::random::fill`, which reads the OS source on every call and keeps no state).
///
/// [`MaskSource::fill`] panics when the OS source fails: the trait cannot report the failure, and there is no
/// safe value to return instead. Use [`OsMask::try_fill`] to handle the failure yourself.
#[cfg(feature = "rng")]
#[derive(Debug, Default, Clone, Copy)]
pub struct OsMask;

#[cfg(feature = "rng")]
impl OsMask {
    /// Create the source (it holds no state).
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Fill `buf` from the OS random source, reporting a failure instead of panicking.
    ///
    /// # Errors
    ///
    /// `alice_crypto::random::RngError` when the OS source is unavailable; `buf` must then not be used.
    pub fn try_fill(&mut self, buf: &mut [u8]) -> Result<(), alice_crypto::random::RngError> {
        alice_crypto::random::fill(buf)
    }
}

#[cfg(feature = "rng")]
impl MaskSource for OsMask {
    fn fill(&mut self, buf: &mut [u8]) {
        if let Err(e) = self.try_fill(buf) {
            panic!("OsMask: no unpredictable mask key can be produced ({e}); refusing to send a predictable one");
        }
    }
}
