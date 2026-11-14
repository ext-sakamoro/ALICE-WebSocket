//! A blocking WebSocket client over any `Read + Write` stream.
//!
//! [`Connection`] drives the sans-I/O pieces of this crate for the client role (RFC 6455):
//!
//! - the opening handshake with a fresh [`client_key`] and a checked `Sec-WebSocket-Accept`;
//! - every outgoing frame masked with a fresh key from a [`MaskSource`] ([`Frame::serialize_client`]);
//! - incoming frames read with [`Frame::parse_from_server`] (payload limit checked from the header, masked
//!   server frames refused), pings answered with masked pongs, fragments assembled with [`MessageAssembler`],
//!   and a close frame returned as [`Received::Close`] after the close is echoed;
//! - a read buffer that reads never grow past one frame header plus the caller's payload limit (bytes the
//!   server sent together with the handshake response are kept as well; they are at most
//!   [`MAX_RESPONSE_HEAD`]).
//!
//! With feature `tls`, `connect_tls` runs the same client over rustls (wss).
//!
//! ```no_run
//! # #[cfg(feature = "rng")]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use std::net::TcpStream;
//! use alice_websocket::client::{Connection, Received};
//! use alice_websocket::{CloseCode, OsMask};
//!
//! let tcp = TcpStream::connect("127.0.0.1:8080")?;
//! let mut ws = Connection::connect(tcp, "127.0.0.1:8080", "/ws", OsMask::new())?;
//! ws.send_binary(&[1, 2, 3])?;
//! loop {
//!     match ws.recv_message(1 << 20)? {
//!         Received::Binary(b) => println!("{} bytes", b.len()),
//!         Received::Text(t) => println!("{t}"),
//!         Received::Close(c) => {
//!             println!("closed: {c:?}");
//!             break;
//!         }
//!         _ => {}
//!     }
//! }
//! # let _ = CloseCode::Normal;
//! # Ok(())
//! # }
//! # #[cfg(not(feature = "rng"))]
//! # fn main() {}
//! ```

use std::io::{ErrorKind, Read, Write};

use crate::assembler::MessageAssembler;
use crate::close_code::CloseCode;
use crate::close_payload::ClosePayload;
use crate::errors::WsError;
use crate::frame::Frame;
use crate::handshake::{client_key, HandshakeRequest, HandshakeResponse};
use crate::mask::MaskSource;
use crate::opcode::Opcode;

#[cfg(feature = "tls")]
mod tls;
#[cfg(feature = "tls")]
pub use tls::{connect_tls, TlsConfig, TlsStream};

/// The longest HTTP response head [`Connection::connect`] reads before refusing the handshake.
pub const MAX_RESPONSE_HEAD: usize = 16 * 1024;

/// The longest frame header: 2 bytes, an 8-byte extended length and a 4-byte mask key.
pub const MAX_FRAME_HEADER: usize = 14;

/// The size of one `read` call on the stream.
const READ_CHUNK: usize = 16 * 1024;

/// What [`Connection::recv_message`] returns.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Received {
    /// A complete text message (UTF-8 checked).
    Text(String),
    /// A complete binary message.
    Binary(Vec<u8>),
    /// The server closed the connection: its code and reason, or `None` for a close frame without a code
    /// (reported as 1005 by RFC 6455 Section 7.1.5). The close has already been answered.
    Close(Option<ClosePayload>),
}

/// A client WebSocket connection over a blocking stream.
///
/// `S` is the transport (a `TcpStream`, a TLS stream, an in-process pipe in tests); `M` supplies the mask
/// keys and the handshake nonce.
#[derive(Debug)]
pub struct Connection<S, M> {
    stream: S,
    mask: M,
    buf: Vec<u8>,
    assembler: MessageAssembler,
    /// Bytes of the fragmented message being assembled.
    pending: usize,
    close_sent: bool,
    close_received: bool,
}

impl<S: Read + Write, M: MaskSource> Connection<S, M> {
    /// Run the opening handshake on `stream` (`GET path` with `Host: host`).
    ///
    /// Sends a fresh `Sec-WebSocket-Key` from `mask`, reads the response head (at most
    /// [`MAX_RESPONSE_HEAD`] bytes), and checks the status, `Upgrade` / `Connection` and the accept key.
    /// Bytes the server sent after the head (an early frame) are kept for [`Connection::recv_message`].
    ///
    /// # Errors
    ///
    /// [`WsError::HandshakeStatus`] for a non-101 status, [`WsError::InvalidAccept`] for a wrong accept key,
    /// [`WsError::HandshakeError`] for a malformed or over-long response or a missing upgrade header,
    /// [`WsError::Io`] when the stream fails or ends.
    pub fn connect(mut stream: S, host: &str, path: &str, mut mask: M) -> Result<Self, WsError> {
        let key = client_key(&mut mask);
        let request = HandshakeRequest::new(host, path, &key).to_http();
        stream.write_all(request.as_bytes())?;
        stream.flush()?;

        let mut buf = Vec::new();
        let head_end = loop {
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
            if buf.len() >= MAX_RESPONSE_HEAD {
                return Err(WsError::HandshakeError(format!(
                    "response head longer than {MAX_RESPONSE_HEAD} bytes"
                )));
            }
            let mut chunk = [0u8; 4096];
            let room = (MAX_RESPONSE_HEAD - buf.len()).min(chunk.len());
            let n = read_some(&mut stream, &mut chunk[..room])?;
            buf.extend_from_slice(&chunk[..n]);
        };

        let response = HandshakeResponse::parse(&buf[..head_end])?;
        response.validate(&key)?;
        let header = |name: &str| {
            response
                .headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case(name))
                .map(|h| h.value.as_str())
        };
        if !header("upgrade").is_some_and(|v| v.trim().eq_ignore_ascii_case("websocket")) {
            return Err(WsError::HandshakeError(
                "response lacks Upgrade: websocket".into(),
            ));
        }
        if !header("connection").is_some_and(|v| {
            v.split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
        }) {
            return Err(WsError::HandshakeError(
                "response lacks Connection: Upgrade".into(),
            ));
        }
        // RFC 6455 Section 4.1: no subprotocol or extension was requested, so none may be selected.
        if response.protocol.is_some() || !response.extensions.is_empty() {
            return Err(WsError::HandshakeError(
                "server selected a subprotocol or extension that was not requested".into(),
            ));
        }

        buf.drain(..head_end);
        Ok(Self {
            stream,
            mask,
            buf,
            assembler: MessageAssembler::new(),
            pending: 0,
            close_sent: false,
            close_received: false,
        })
    }

    /// Send one binary message (a single masked frame).
    ///
    /// # Errors
    ///
    /// [`WsError::Closed`] after a close was sent or received, [`WsError::Io`] when the write fails.
    pub fn send_binary(&mut self, data: &[u8]) -> Result<(), WsError> {
        self.send_data(&Frame::binary(data.to_vec()))
    }

    /// Send one text message (a single masked frame).
    ///
    /// # Errors
    ///
    /// As [`Connection::send_binary`].
    pub fn send_text(&mut self, text: &str) -> Result<(), WsError> {
        self.send_data(&Frame::text(text))
    }

    /// Send a ping (payload at most 125 bytes).
    ///
    /// # Errors
    ///
    /// [`WsError::ControlFrameTooLarge`] for a payload over 125 bytes, otherwise as
    /// [`Connection::send_binary`].
    pub fn send_ping(&mut self, payload: &[u8]) -> Result<(), WsError> {
        if payload.len() > 125 {
            return Err(WsError::ControlFrameTooLarge);
        }
        self.send_data(&Frame::ping(payload.to_vec()))
    }

    /// Start the closing handshake: send a close frame with `code` and `reason`.
    ///
    /// Read on with [`Connection::recv_message`] until it returns [`Received::Close`] (the server's answer).
    ///
    /// # Errors
    ///
    /// [`WsError::InvalidCloseCode`] for a code that must not be sent (1005, 1006, 1015, unassigned ranges),
    /// [`WsError::ControlFrameTooLarge`] for a reason over 123 bytes, [`WsError::Closed`] when a close was
    /// already sent, [`WsError::Io`] when the write fails.
    pub fn close(&mut self, code: CloseCode, reason: &str) -> Result<(), WsError> {
        if !code.is_sendable() {
            return Err(WsError::InvalidCloseCode(code.to_u16()));
        }
        if reason.len() > 123 {
            return Err(WsError::ControlFrameTooLarge);
        }
        if self.close_sent {
            return Err(WsError::Closed);
        }
        self.close_sent = true;
        self.write_frame(&Frame::close(Some(code), reason))
    }

    /// Read the next complete message; no payload (frame or assembled message) may exceed `max_payload` bytes.
    ///
    /// Pings are answered with masked pongs and pongs are dropped, both without returning. A close frame is
    /// echoed (unless this side closed first) and returned as [`Received::Close`]; later calls return
    /// [`WsError::Closed`].
    ///
    /// # Errors
    ///
    /// [`WsError::PayloadTooLarge`] when a frame header or the assembled message exceeds `max_payload`,
    /// [`WsError::MaskedServerFrame`] for a masked frame, protocol errors from the frame parser, the
    /// assembler and the close payload, [`WsError::Io`] when the stream fails or ends
    /// (`ErrorKind::UnexpectedEof`), [`WsError::Closed`] after the close was received.
    pub fn recv_message(&mut self, max_payload: usize) -> Result<Received, WsError> {
        if self.close_received {
            return Err(WsError::Closed);
        }
        loop {
            match Frame::parse_from_server(&self.buf, max_payload) {
                Ok((frame, used)) => {
                    self.buf.drain(..used);
                    if let Some(received) = self.handle(frame, max_payload)? {
                        return Ok(received);
                    }
                }
                Err(WsError::Incomplete) => self.fill_buffer(max_payload)?,
                Err(e) => return Err(e),
            }
        }
    }

    /// The underlying stream.
    pub const fn get_ref(&self) -> &S {
        &self.stream
    }

    /// The underlying stream, mutably (for timeouts; reading or writing it directly breaks the framing).
    pub const fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Bytes read from the stream but not yet parsed.
    pub const fn buffered(&self) -> usize {
        self.buf.len()
    }

    fn handle(&mut self, frame: Frame, max_payload: usize) -> Result<Option<Received>, WsError> {
        match frame.opcode {
            Opcode::Ping => {
                if !self.close_sent {
                    self.write_frame(&Frame::pong(frame.payload))?;
                }
                Ok(None)
            }
            Opcode::Pong => Ok(None),
            Opcode::Close => {
                let payload = ClosePayload::parse(&frame.payload)?;
                self.close_received = true;
                if !self.close_sent {
                    self.close_sent = true;
                    // RFC 6455 Section 5.5.1: echo the status code received.
                    let echo = Frame::close(payload.as_ref().map(|p| p.code), "");
                    self.write_frame(&echo)?;
                }
                Ok(Some(Received::Close(payload)))
            }
            Opcode::Text | Opcode::Binary | Opcode::Continuation => {
                let total = self.pending.saturating_add(frame.payload.len());
                if total > max_payload {
                    self.assembler.reset();
                    self.pending = 0;
                    return Err(WsError::PayloadTooLarge);
                }
                let message = self.assembler.feed(&frame)?;
                self.pending = if message.is_some() { 0 } else { total };
                match message {
                    None => Ok(None),
                    Some(m) if m.opcode == Opcode::Text => String::from_utf8(m.payload)
                        .map(|t| Some(Received::Text(t)))
                        .map_err(|_| WsError::InvalidUtf8),
                    Some(m) => Ok(Some(Received::Binary(m.payload))),
                }
            }
        }
    }

    /// Read more bytes, never letting the buffer exceed one frame header plus `max_payload`.
    fn fill_buffer(&mut self, max_payload: usize) -> Result<(), WsError> {
        let cap = MAX_FRAME_HEADER.saturating_add(max_payload);
        let room = cap.saturating_sub(self.buf.len()).min(READ_CHUNK);
        if room == 0 {
            // `parse_from_server` refuses any frame longer than `cap`, so a full buffer that still does not
            // hold a whole frame cannot happen; refuse rather than grow.
            return Err(WsError::PayloadTooLarge);
        }
        let start = self.buf.len();
        self.buf.resize(start + room, 0);
        match read_some(&mut self.stream, &mut self.buf[start..]) {
            Ok(n) => {
                self.buf.truncate(start + n);
                Ok(())
            }
            Err(e) => {
                self.buf.truncate(start);
                Err(e)
            }
        }
    }

    fn send_data(&mut self, frame: &Frame) -> Result<(), WsError> {
        if self.close_sent || self.close_received {
            return Err(WsError::Closed);
        }
        self.write_frame(frame)
    }

    fn write_frame(&mut self, frame: &Frame) -> Result<(), WsError> {
        let bytes = frame.serialize_client(&mut self.mask);
        self.stream.write_all(&bytes)?;
        self.stream.flush()?;
        Ok(())
    }
}

/// One `read` into `buf` (non-empty), retrying `Interrupted`; end of stream is an `UnexpectedEof` error.
fn read_some<S: Read>(stream: &mut S, buf: &mut [u8]) -> Result<usize, WsError> {
    loop {
        match stream.read(buf) {
            Ok(0) => {
                return Err(WsError::Io {
                    kind: ErrorKind::UnexpectedEof,
                    message: "the stream ended".into(),
                })
            }
            Ok(n) => return Ok(n),
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
}
