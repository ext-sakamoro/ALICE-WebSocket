//! A failing [`MaskSource`]: the error reaches the caller and no byte leaves for the stream.
//!
//! RFC 6455 Section 5.3 / 10.3: a client frame without an unpredictable key must not be sent. The
//! connection tests run over a recording stream (no network) and compare the bytes written before and
//! after the failing call.

mod support;

use std::io::{self, Cursor, Read, Write};

use alice_websocket::client::{Connection, Received};
use alice_websocket::{
    client_key, CloseCode, Frame, HandshakeResponse, MaskError, MaskSource, Opcode, WsError,
};
use support::FixedMask;

/// The error every failing source here returns.
fn failure() -> MaskError {
    MaskError::Unavailable("test source refuses".into())
}

/// Succeeds for the first `ok` calls (deterministic bytes), then fails on every call.
#[derive(Debug)]
struct FailAfter {
    ok: usize,
    calls: usize,
    inner: FixedMask,
}

impl FailAfter {
    fn new(ok: usize) -> Self {
        Self {
            ok,
            calls: 0,
            inner: FixedMask::new(b"the sample nonce"),
        }
    }
}

impl MaskSource for FailAfter {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), MaskError> {
        self.calls += 1;
        if self.calls > self.ok {
            return Err(failure());
        }
        self.inner.fill(buf)
    }
}

/// Reads from a fixed script, records every byte written.
#[derive(Debug)]
struct Recording {
    input: Cursor<Vec<u8>>,
    written: Vec<u8>,
}

impl Recording {
    fn new(input: Vec<u8>) -> Self {
        Self {
            input: Cursor::new(input),
            written: Vec::new(),
        }
    }
}

impl Read for Recording {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.input.read(buf)
    }
}

impl Write for Recording {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.written.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The key `FailAfter` produces first ("the sample nonce", RFC 6455 Section 4.1).
const SAMPLE_KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";

/// A connection whose handshake key succeeds and whose every later mask key fails.
fn open_then_fail(rec: &mut Recording) -> Connection<&mut Recording, FailAfter> {
    Connection::connect(rec, "example.com", "/ws", FailAfter::new(1)).expect("handshake")
}

/// The 101 response for [`SAMPLE_KEY`] followed by server frames.
fn script(after: &[Frame]) -> Vec<u8> {
    let mut input = HandshakeResponse::from_key(SAMPLE_KEY)
        .to_http()
        .into_bytes();
    for f in after {
        input.extend_from_slice(&f.serialize());
    }
    input
}

fn is_mask_failure<T: std::fmt::Debug>(r: &Result<T, WsError>) -> bool {
    matches!(r, Err(WsError::Mask(e)) if *e == failure())
}

// --- the sans-I/O functions ----------------------------------------------------------------------

#[test]
fn client_key_returns_the_source_error() {
    assert_eq!(client_key(&mut FailAfter::new(0)), Err(failure()));
}

#[test]
fn serialize_client_returns_the_source_error_for_every_opcode() {
    let frames = [
        Frame::text("t"),
        Frame::binary(vec![1, 2, 3]),
        Frame::ping(vec![4]),
        Frame::pong(vec![5]),
        Frame::close(Some(CloseCode::Normal), "bye"),
        Frame::new(Opcode::Continuation, vec![6]),
    ];
    let mut compared = 0;
    for f in &frames {
        assert_eq!(
            f.serialize_client(&mut FailAfter::new(0)),
            Err(failure()),
            "{f:?}"
        );
        compared += 1;
    }
    assert_eq!(compared, frames.len());
    assert!(compared > 0);
}

#[test]
fn ws_error_carries_the_mask_error_as_its_source() {
    let e = WsError::from(failure());
    assert_eq!(e, WsError::Mask(failure()));
    let source = std::error::Error::source(&e).expect("a source");
    assert_eq!(source.to_string(), failure().to_string());
}

// --- the connection ------------------------------------------------------------------------------

#[test]
fn connect_sends_no_request_when_the_key_fails() {
    let mut rec = Recording::new(script(&[]));
    let r = Connection::connect(&mut rec, "example.com", "/ws", FailAfter::new(0));
    assert!(is_mask_failure(&r), "{r:?}");
    drop(r);
    assert!(
        rec.written.is_empty(),
        "{} bytes written",
        rec.written.len()
    );
}

#[test]
fn every_send_path_returns_the_error_and_writes_nothing() {
    type Send = fn(&mut Connection<&mut Recording, FailAfter>) -> Result<(), WsError>;
    let paths: [(&str, Send); 4] = [
        ("send_text", |c| c.send_text("hello")),
        ("send_binary", |c| c.send_binary(&[1, 2, 3])),
        ("send_ping", |c| c.send_ping(b"p")),
        ("close", |c| c.close(CloseCode::Normal, "bye")),
    ];
    let n0 = request_len();
    assert!(n0 > 0);
    let mut compared = 0;
    for (name, send) in paths {
        let mut rec = Recording::new(script(&[]));
        let mut c = open_then_fail(&mut rec);
        let r = send(&mut c);
        assert!(is_mask_failure(&r), "{name}: {r:?}");
        drop(c);
        // only the upgrade request was written
        assert_eq!(rec.written.len(), n0, "{name}: frame bytes written");
        assert!(rec.written.starts_with(b"GET /ws HTTP/1.1\r\n"), "{name}");
        assert!(rec.written.ends_with(b"\r\n\r\n"), "{name}");
        compared += 1;
    }
    assert_eq!(compared, 4);
}

#[test]
fn a_failed_close_is_not_marked_as_sent() {
    let mut rec = Recording::new(script(&[]));
    let mut c = open_then_fail(&mut rec);
    let first = c.close(CloseCode::Normal, "bye");
    assert!(is_mask_failure(&first), "{first:?}");
    // the close was not sent, so a retry draws a key again (and fails again) instead of reporting Closed
    let second = c.close(CloseCode::Normal, "bye");
    assert!(is_mask_failure(&second), "{second:?}");
    // and data may still be attempted (no close was sent)
    let data = c.send_text("x");
    assert!(is_mask_failure(&data), "{data:?}");
}

/// The handshake writes exactly the request; any frame would follow it.
fn request_len() -> usize {
    let mut rec = Recording::new(script(&[]));
    let c = open_then_fail(&mut rec);
    drop(c);
    rec.written.len()
}

#[test]
fn the_pong_answer_returns_the_error_and_writes_nothing() {
    let n0 = request_len();
    let mut rec = Recording::new(script(&[Frame::ping(b"are you there".to_vec())]));
    let mut c = open_then_fail(&mut rec);
    let r = c.recv_message(1024);
    assert!(is_mask_failure(&r), "{r:?}");
    drop(c);
    assert!(n0 > 0);
    assert_eq!(rec.written.len(), n0, "no pong bytes");
}

#[test]
fn the_close_echo_returns_the_error_and_writes_nothing() {
    let n0 = request_len();
    let mut rec = Recording::new(script(&[Frame::close(Some(CloseCode::GoingAway), "")]));
    let mut c = open_then_fail(&mut rec);
    let r = c.recv_message(1024);
    assert!(is_mask_failure(&r), "{r:?}");
    // the echo was not sent, so the connection is not marked as having sent a close: a close attempt
    // draws a key again (and fails again) instead of reporting Closed
    let retry = c.close(CloseCode::Normal, "");
    assert!(is_mask_failure(&retry), "{retry:?}");
    drop(c);
    assert!(n0 > 0);
    assert_eq!(rec.written.len(), n0, "no close echo bytes");
}

/// Control: with a working source the same script does write the pong (the recording stream observes
/// writes, so the zero-byte assertions above are not vacuous).
#[test]
fn control_a_working_source_writes_the_pong() {
    let n0 = request_len();
    let mut rec = Recording::new(script(&[
        Frame::ping(b"are you there".to_vec()),
        Frame::text("done"),
    ]));
    let mut c = Connection::connect(&mut rec, "example.com", "/ws", FailAfter::new(usize::MAX))
        .expect("handshake");
    assert_eq!(c.recv_message(1024), Ok(Received::Text("done".into())));
    drop(c);
    assert!(rec.written.len() > n0, "the pong was written");
}
