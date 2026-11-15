//! Mask and handshake-key sources for the client role.
//!
//! RFC 6455 Section 5.3: every frame a client sends is masked with a fresh 32-bit key that the server (and any
//! intermediary) cannot predict. Section 4.1: the `Sec-WebSocket-Key` is 16 random bytes, base64-encoded.
//! [`MaskSource`] is where those bytes come from; `OsMask` (feature `rng`) reads them from the operating
//! system's random source.

use std::fmt;

/// Why a [`MaskSource`] could not produce unpredictable bytes.
///
/// When a source returns this, the buffer it was given must not be used: no frame and no handshake request
/// is sent with it.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaskError {
    /// The operating system's random source failed (`OsMask`, feature `rng`).
    #[cfg(feature = "rng")]
    Os(alice_crypto::random::RngError),
    /// Another source could not produce unpredictable bytes (its own description).
    Unavailable(String),
}

impl fmt::Display for MaskError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "rng")]
            Self::Os(e) => write!(f, "no unpredictable mask bytes: {e}"),
            Self::Unavailable(s) => write!(f, "no unpredictable mask bytes: {s}"),
        }
    }
}

impl std::error::Error for MaskError {}

#[cfg(feature = "rng")]
impl From<alice_crypto::random::RngError> for MaskError {
    fn from(e: alice_crypto::random::RngError) -> Self {
        Self::Os(e)
    }
}

/// A source of mask keys and handshake nonces.
///
/// `fill` must either fill the whole buffer with bytes the peer cannot predict and return `Ok(())`, or return
/// a [`MaskError`]. It must never return `Ok(())` with a predictable buffer (zeros, a counter, a clock): a
/// client that sends predictable masks defeats the purpose of masking (RFC 6455 Section 10.3). On `Err` the
/// callers in this crate discard the buffer and send nothing.
///
/// A deterministic implementation is for tests only (for example to reproduce the RFC 6455 Section 5.7 example).
pub trait MaskSource {
    /// Fill `buf` entirely with unpredictable bytes.
    ///
    /// # Errors
    ///
    /// [`MaskError`] when unpredictable bytes cannot be produced; `buf` must then not be used.
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), MaskError>;
}

impl<M: MaskSource + ?Sized> MaskSource for &mut M {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), MaskError> {
        (**self).fill(buf)
    }
}

impl<M: MaskSource + ?Sized> MaskSource for Box<M> {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), MaskError> {
        (**self).fill(buf)
    }
}

/// Mask keys and handshake nonces from the operating system's random source
/// (`alice_crypto::random::fill`, which reads the OS source on every call and keeps no state).
///
/// [`MaskSource::fill`] returns [`MaskError::Os`] when the OS source fails.
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
}

#[cfg(feature = "rng")]
impl MaskSource for OsMask {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), MaskError> {
        alice_crypto::random::fill(buf).map_err(MaskError::Os)
    }
}
