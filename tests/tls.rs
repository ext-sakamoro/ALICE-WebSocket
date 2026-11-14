//! `client::connect_tls` against a local rustls server whose certificate is generated at test time
//! (rcgen; no key material is stored in the repository).
#![cfg(feature = "tls")]

mod support;

use std::net::TcpStream;
use std::sync::Arc;

use alice_websocket::client::{connect_tls, Connection, Received, TlsConfig, TlsStream};
use alice_websocket::{Frame, WsError};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use support::{counter_mask, dial, spawn_server, ServerConn};

/// A self-signed certificate for `localhost` and its key.
fn test_cert() -> rcgen::CertifiedKey {
    rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("test certificate")
}

fn server_config(cert: &rcgen::CertifiedKey) -> Arc<ServerConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(cert.cert.der().to_vec())], key)
        .unwrap();
    Arc::new(config)
}

/// A TLS WebSocket echo server for one message; returns whether the TLS handshake completed.
fn spawn_tls_echo(config: Arc<ServerConfig>) -> (String, std::thread::JoinHandle<bool>) {
    spawn_server(move |tcp: TcpStream| {
        let mut conn = ServerConnection::new(config).unwrap();
        let mut tcp = tcp;
        while conn.is_handshaking() {
            if conn.complete_io(&mut tcp).is_err() {
                return false; // the client refused the certificate
            }
        }
        let mut s = ServerConn::accept(StreamOwned::new(conn, tcp));
        let f = s.read_frame();
        s.send(&Frame::new(f.opcode, f.payload));
        true
    })
}

#[test]
fn connect_tls_with_the_test_root_round_trips() {
    let cert = test_cert();
    let (addr, server) = spawn_tls_echo(server_config(&cert));
    let roots = TlsConfig::from_pem_roots(cert.cert.pem().as_bytes()).unwrap();
    let mut c = connect_tls(
        dial(&addr),
        "localhost",
        &roots,
        "localhost",
        "/ws",
        counter_mask(),
    )
    .expect("tls + websocket handshake");
    c.send_text("over tls").unwrap();
    assert_eq!(
        c.recv_message(1024).unwrap(),
        Received::Text("over tls".into())
    );
    assert!(server.join().unwrap());
}

#[test]
fn connect_tls_with_default_roots_rejects_the_test_certificate() {
    let cert = test_cert();
    let (addr, server) = spawn_tls_echo(server_config(&cert));
    let roots = TlsConfig::webpki_roots().unwrap();
    let r = connect_tls(
        dial(&addr),
        "localhost",
        &roots,
        "localhost",
        "/ws",
        counter_mask(),
    );
    assert!(matches!(r, Err(WsError::Certificate(_))), "{r:?}");
    assert!(!server.join().unwrap());
}

#[test]
fn connect_tls_with_another_root_rejects_the_certificate() {
    let cert = test_cert();
    let other = test_cert();
    let (addr, server) = spawn_tls_echo(server_config(&cert));
    let roots = TlsConfig::from_pem_roots(other.cert.pem().as_bytes()).unwrap();
    let r = connect_tls(
        dial(&addr),
        "localhost",
        &roots,
        "localhost",
        "/ws",
        counter_mask(),
    );
    assert!(matches!(r, Err(WsError::Certificate(_))), "{r:?}");
    assert!(!server.join().unwrap());
}

#[test]
fn connect_tls_rejects_a_certificate_for_another_name() {
    let cert = test_cert();
    let (addr, server) = spawn_tls_echo(server_config(&cert));
    let roots = TlsConfig::from_pem_roots(cert.cert.pem().as_bytes()).unwrap();
    let r = connect_tls(
        dial(&addr),
        "example.org",
        &roots,
        "example.org",
        "/ws",
        counter_mask(),
    );
    assert!(matches!(r, Err(WsError::Certificate(_))), "{r:?}");
    assert!(!server.join().unwrap());
}

#[test]
fn tls_config_refuses_an_empty_root_set() {
    assert!(matches!(
        TlsConfig::from_pem_roots(b"no certificate here"),
        Err(WsError::Certificate(_))
    ));
    assert!(matches!(
        TlsConfig::from_der_roots(std::iter::empty()),
        Err(WsError::Certificate(_))
    ));
    assert!(TlsConfig::webpki_roots().is_ok());
}

#[test]
fn connect_tls_rejects_an_invalid_server_name() {
    let roots = TlsConfig::webpki_roots().unwrap();
    // nothing listens; the name is checked before any byte is sent
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let tcp = dial(&listener.local_addr().unwrap().to_string());
    let r = connect_tls(tcp, "not a name!", &roots, "h", "/", counter_mask());
    assert!(matches!(r, Err(WsError::Tls(_))), "{r:?}");
}

// TlsStream::connect runs only the TLS handshake: the caller can speak any protocol over the stream,
// and a later Connection::connect over it is the same as connect_tls
#[test]
fn tls_stream_connect_then_websocket_round_trips() {
    let cert = test_cert();
    let (addr, server) = spawn_tls_echo(server_config(&cert));
    let roots = TlsConfig::from_pem_roots(cert.cert.pem().as_bytes()).unwrap();
    let stream = TlsStream::connect(dial(&addr), "localhost", &roots).expect("tls handshake only");
    let mut c =
        Connection::connect(stream, "localhost", "/ws", counter_mask()).expect("ws over tls");
    c.send_binary(b"raw stream").unwrap();
    assert_eq!(
        c.recv_message(1024).unwrap(),
        Received::Binary(b"raw stream".to_vec())
    );
    assert!(server.join().unwrap());
}

#[test]
fn tls_stream_connect_rejects_the_certificate_before_any_application_byte() {
    let cert = test_cert();
    let (addr, server) = spawn_tls_echo(server_config(&cert));
    let err = TlsStream::connect(
        dial(&addr),
        "localhost",
        &TlsConfig::webpki_roots().unwrap(),
    )
    .expect_err("a test certificate is not under the default roots");
    assert!(matches!(err, WsError::Certificate(_)), "{err:?}");
    assert!(!server.join().unwrap());
}
