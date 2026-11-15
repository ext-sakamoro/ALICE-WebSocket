//! A test server built from this crate's server-side pieces, and a deterministic mask source.
#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::JoinHandle;
use std::time::Duration;

use alice_websocket::{
    Frame, FrameBuffer, HandshakeRequest, HandshakeResponse, MaskError, MaskSource,
};

/// Bytes handed out in order, wrapping around (tests only: a real client needs unpredictable bytes).
#[derive(Debug)]
pub struct FixedMask {
    bytes: Vec<u8>,
    at: usize,
}

impl FixedMask {
    pub fn new(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
            at: 0,
        }
    }
}

impl MaskSource for FixedMask {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), MaskError> {
        for b in buf {
            *b = self.bytes[self.at % self.bytes.len()];
            self.at += 1;
        }
        Ok(())
    }
}

/// A source that always fails (tests the paths that must send nothing without a key).
#[derive(Debug, Clone, Copy, Default)]
pub struct FailingMask;

impl MaskSource for FailingMask {
    fn fill(&mut self, _buf: &mut [u8]) -> Result<(), MaskError> {
        Err(MaskError::Unavailable("test source refuses".into()))
    }
}

/// A counter mask that differs on every call (tests only).
pub fn counter_mask() -> FixedMask {
    FixedMask::new(&(1..=251).collect::<Vec<u8>>())
}

/// The server side of one connection.
pub struct ServerConn<S> {
    pub stream: S,
    frames: FrameBuffer,
}

impl<S: Read + Write> ServerConn<S> {
    /// Read the upgrade request and answer it with 101.
    pub fn accept(stream: S) -> Self {
        Self::accept_with(stream, |req| {
            HandshakeResponse::from_key(&req.key).to_http().into_bytes()
        })
    }

    /// Read the upgrade request and answer with `respond(request)`.
    pub fn accept_with(mut stream: S, respond: impl FnOnce(&HandshakeRequest) -> Vec<u8>) -> Self {
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            let n = stream.read(&mut byte).expect("read the request");
            assert!(n > 0, "the client closed during the upgrade");
            head.push(byte[0]);
        }
        let req = HandshakeRequest::parse(&head).expect("a valid upgrade request");
        stream.write_all(&respond(&req)).expect("send the response");
        stream.flush().expect("flush");
        Self {
            stream,
            frames: FrameBuffer::new(),
        }
    }

    /// The next frame from the client (it must be masked: RFC 6455 Section 5.1).
    pub fn read_frame(&mut self) -> Frame {
        loop {
            if let Some(frame) = self.frames.try_parse().expect("a valid client frame") {
                assert!(frame.masked, "client frame not masked: {frame:?}");
                return frame;
            }
            let mut chunk = [0u8; 4096];
            let n = self.stream.read(&mut chunk).expect("read a frame");
            assert!(n > 0, "the client closed the stream");
            self.frames.extend(&chunk[..n]);
        }
    }

    /// Send a frame as a server does (unmasked unless the frame says otherwise).
    pub fn send(&mut self, frame: &Frame) {
        self.send_raw(&frame.serialize_masked());
    }

    pub fn send_raw(&mut self, bytes: &[u8]) {
        self.stream.write_all(bytes).expect("send");
        self.stream.flush().expect("flush");
    }
}

/// A listener on 127.0.0.1 and a thread that runs `serve` on the first connection.
pub fn spawn_server<T: Send + 'static>(
    serve: impl FnOnce(TcpStream) -> T + Send + 'static,
) -> (String, JoinHandle<T>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();
    let handle = std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("timeout");
        serve(stream)
    });
    (addr, handle)
}

pub fn dial(addr: &str) -> TcpStream {
    let s = TcpStream::connect(addr).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");
    s
}
