//! wss: the client of [`Connection`] over rustls 0.23 (ring provider, TLS 1.2 and 1.3).
//!
//! Consumers name only the types here; rustls stays an implementation detail of this crate.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

use super::Connection;
use crate::errors::WsError;
use crate::mask::MaskSource;

/// Which certificate authorities a TLS client trusts.
///
/// Cheap to clone (the configuration is shared).
#[derive(Debug, Clone)]
pub struct TlsConfig {
    inner: Arc<ClientConfig>,
}

impl TlsConfig {
    /// Trust the Mozilla root program as shipped in the `webpki-roots` crate (the same roots on every platform,
    /// independent of the host's certificate store).
    ///
    /// # Errors
    ///
    /// [`WsError::Tls`] if the TLS configuration cannot be built.
    pub fn webpki_roots() -> Result<Self, WsError> {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Self::from_store(roots)
    }

    /// Trust only the certificates in `pem` (one or more `CERTIFICATE` blocks): a private CA, a pinned root,
    /// or a test certificate.
    ///
    /// # Errors
    ///
    /// [`WsError::Certificate`] when `pem` holds no certificate or one that is not a valid trust anchor,
    /// [`WsError::Tls`] if the configuration cannot be built.
    pub fn from_pem_roots(pem: &[u8]) -> Result<Self, WsError> {
        let mut ders = Vec::new();
        for cert in CertificateDer::pem_slice_iter(pem) {
            ders.push(cert.map_err(|e| WsError::Certificate(format!("root PEM: {e:?}")))?);
        }
        Self::from_der_roots(ders.iter().map(AsRef::as_ref))
    }

    /// Trust only the given DER-encoded certificates.
    ///
    /// # Errors
    ///
    /// [`WsError::Certificate`] when there is no certificate or one is not a valid trust anchor,
    /// [`WsError::Tls`] if the configuration cannot be built.
    pub fn from_der_roots<'a>(ders: impl IntoIterator<Item = &'a [u8]>) -> Result<Self, WsError> {
        let mut roots = RootCertStore::empty();
        for der in ders {
            roots
                .add(CertificateDer::from(der.to_vec()))
                .map_err(|e| WsError::Certificate(format!("root certificate: {e}")))?;
        }
        if roots.is_empty() {
            return Err(WsError::Certificate("no root certificate given".into()));
        }
        Self::from_store(roots)
    }

    fn from_store(roots: RootCertStore) -> Result<Self, WsError> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| WsError::Tls(e.to_string()))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        // The upgrade is an HTTP/1.1 request (RFC 6455 Section 4.1).
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            inner: Arc::new(config),
        })
    }
}

/// A client TLS stream over TCP (the transport of a wss [`Connection`]).
#[derive(Debug)]
pub struct TlsStream {
    inner: StreamOwned<ClientConnection, TcpStream>,
}

impl TlsStream {
    /// The TCP socket under the TLS layer (for timeouts and addresses).
    pub const fn tcp(&self) -> &TcpStream {
        &self.inner.sock
    }
}

impl Read for TlsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Write for TlsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Run the TLS handshake on `tcp` for `server_name` (the name the certificate must carry), then the
/// WebSocket handshake (`GET path`, `Host: host`) over it.
///
/// The TLS handshake completes before any HTTP byte is sent, so a rejected certificate is reported as
/// [`WsError::Certificate`] and never as a WebSocket error.
///
/// # Errors
///
/// [`WsError::Certificate`] when the server's certificate is rejected, [`WsError::Tls`] for other TLS
/// failures or an invalid `server_name`, and the errors of [`Connection::connect`].
pub fn connect_tls<M: MaskSource>(
    mut tcp: TcpStream,
    server_name: &str,
    config: &TlsConfig,
    host: &str,
    path: &str,
    mask: M,
) -> Result<Connection<TlsStream, M>, WsError> {
    let name = ServerName::try_from(server_name.to_owned())
        .map_err(|e| WsError::Tls(format!("server name {server_name:?}: {e}")))?;
    let mut conn =
        ClientConnection::new(Arc::clone(&config.inner), name).map_err(|e| tls_error(&e))?;
    while conn.is_handshaking() {
        conn.complete_io(&mut tcp).map_err(handshake_io_error)?;
    }
    let stream = TlsStream {
        inner: StreamOwned::new(conn, tcp),
    };
    Connection::connect(stream, host, path, mask)
}

fn tls_error(e: &rustls::Error) -> WsError {
    match e {
        rustls::Error::InvalidCertificate(c) => WsError::Certificate(format!("{c:?}")),
        other => WsError::Tls(other.to_string()),
    }
}

/// rustls reports its own errors through `complete_io` as `io::Error`s wrapping a `rustls::Error`.
fn handshake_io_error(e: io::Error) -> WsError {
    let inner = e
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
        .map(tls_error);
    inner.unwrap_or_else(|| e.into())
}
