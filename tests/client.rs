//! The client role: masking, bounded parsing, the server-mask check, handshake status, and
//! `client::Connection` against an in-process server on 127.0.0.1.

mod support;

use alice_websocket::client::{Connection, Received, MAX_FRAME_HEADER};
use alice_websocket::{
    client_key, CloseCode, ClosePayload, Frame, HandshakeResponse, Opcode, WsError,
};
use support::{counter_mask, dial, spawn_server, FixedMask, ServerConn};

// --- masking -------------------------------------------------------------------------------------

/// oracle: RFC 6455 Section 5.7, "A single-frame masked text message":
/// `0x81 0x85 0x37 0xfa 0x21 0x3d 0x7f 0x9f 0x4d 0x51 0x58` (contains "Hello").
#[test]
fn serialize_client_reproduces_rfc6455_masked_hello() {
    let mut mask = FixedMask::new(&[0x37, 0xfa, 0x21, 0x3d]);
    let bytes = Frame::text("Hello").serialize_client(&mut mask).unwrap();
    assert_eq!(
        bytes,
        [0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58]
    );
}

#[test]
fn serialize_client_draws_a_fresh_key_per_frame() {
    let mut mask = counter_mask();
    let frame = Frame::binary(vec![0; 8]);
    let a = frame.serialize_client(&mut mask).unwrap();
    let b = frame.serialize_client(&mut mask).unwrap();
    assert_eq!(a[1] & 0x80, 0x80, "mask bit set");
    assert_ne!(a[2..6], b[2..6], "a new key for each frame");
    // the payload on the wire is the masked one, and it decodes back
    let (parsed, _) = Frame::parse(&a).unwrap();
    assert_eq!(parsed.payload, vec![0; 8]);
    assert_ne!(a[6..], [0u8; 8], "payload bytes are masked on the wire");
}

/// oracle: RFC 6455 Section 4.1 — the nonce "the sample nonce" is sent as `dGhlIHNhbXBsZSBub25jZQ==`.
#[test]
fn client_key_is_base64_of_16_source_bytes() {
    let mut src = FixedMask::new(b"the sample nonce");
    assert_eq!(client_key(&mut src).unwrap(), "dGhlIHNhbXBsZSBub25jZQ==");
}

// --- bounded parse -------------------------------------------------------------------------------

#[test]
fn parse_limited_refuses_over_limit_length_from_the_header_alone() {
    // 64-bit length 1_000_000, header only (no payload byte present)
    let mut header = vec![0x82, 0x7f];
    header.extend_from_slice(&1_000_000u64.to_be_bytes());
    assert_eq!(
        Frame::parse_limited(&header, 1024),
        Err(WsError::PayloadTooLarge)
    );
    // 16-bit length 1025 with a 1024 limit, header only
    assert_eq!(
        Frame::parse_limited(&[0x82, 0x7e, 0x04, 0x01], 1024),
        Err(WsError::PayloadTooLarge)
    );
    // masked: refused before the mask key arrives
    assert_eq!(
        Frame::parse_limited(&[0x82, 0xfe, 0x04, 0x01], 1024),
        Err(WsError::PayloadTooLarge)
    );
}

#[test]
fn parse_limited_incomplete_rules() {
    // the length field itself is incomplete
    assert_eq!(
        Frame::parse_limited(&[0x82, 0x7f, 0x00], 10),
        Err(WsError::Incomplete)
    );
    // exactly at the limit, payload missing
    assert_eq!(
        Frame::parse_limited(&[0x82, 0x0a], 10),
        Err(WsError::Incomplete)
    );
    // exactly at the limit, complete
    let mut f = vec![0x82, 0x0a];
    f.extend_from_slice(&[7; 10]);
    let (frame, used) = Frame::parse_limited(&f, 10).unwrap();
    assert_eq!((frame.payload.len(), used), (10, 12));
    // one over
    assert_eq!(
        Frame::parse_limited(&[0x82, 0x0b], 10),
        Err(WsError::PayloadTooLarge)
    );
}

// --- client role ---------------------------------------------------------------------------------

const RFC_MASKED_HELLO: [u8; 11] = [
    0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58,
];
/// oracle: RFC 6455 Section 5.7, "A single-frame unmasked text message".
const RFC_UNMASKED_HELLO: [u8; 7] = [0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f];

#[test]
fn client_refuses_a_masked_server_frame() {
    assert_eq!(
        Frame::parse_from_server(&RFC_MASKED_HELLO, 1024),
        Err(WsError::MaskedServerFrame)
    );
    // refused from the first two bytes
    assert_eq!(
        Frame::parse_from_server(&RFC_MASKED_HELLO[..2], 1024),
        Err(WsError::MaskedServerFrame)
    );
    let (f, _) = Frame::parse_from_server(&RFC_UNMASKED_HELLO, 1024).unwrap();
    assert_eq!(f.payload, b"Hello");
}

#[test]
fn server_side_parse_still_accepts_masked_frames() {
    let (f, used) = Frame::parse(&RFC_MASKED_HELLO).unwrap();
    assert_eq!((f.payload.as_slice(), used), (&b"Hello"[..], 11));
    let (f, _) = Frame::parse_limited(&RFC_MASKED_HELLO, 5).unwrap();
    assert_eq!(f.payload, b"Hello");
}

// --- handshake status ----------------------------------------------------------------------------

#[test]
fn non_101_response_reports_the_status() {
    let raw = b"HTTP/1.1 503 Service Unavailable\r\nRetry-After: 5\r\n\r\n";
    assert!(matches!(
        HandshakeResponse::parse(raw),
        Err(WsError::HandshakeStatus(503))
    ));
    // "101" elsewhere in the line does not make it a 101
    let raw = b"HTTP/1.1 404 No route 101\r\n\r\n";
    assert!(matches!(
        HandshakeResponse::parse(raw),
        Err(WsError::HandshakeStatus(404))
    ));
    // not a status line
    assert!(matches!(
        HandshakeResponse::parse(b"garbage\r\n\r\n"),
        Err(WsError::HandshakeError(_))
    ));
}

// --- Connection over TCP -------------------------------------------------------------------------

fn connect(addr: &str) -> Connection<std::net::TcpStream, FixedMask> {
    Connection::connect(dial(addr), "127.0.0.1", "/ws", counter_mask()).expect("handshake")
}

#[test]
fn connection_round_trips_binary_and_text() {
    let (addr, server) = spawn_server(|tcp| {
        let mut s = ServerConn::accept(tcp);
        let mut keys = Vec::new();
        for _ in 0..2 {
            let f = s.read_frame();
            keys.push(f.mask_key);
            s.send(&Frame::new(f.opcode, f.payload));
        }
        keys
    });
    let mut c = connect(&addr);
    c.send_binary(&[1, 2, 3, 250]).unwrap();
    assert_eq!(
        c.recv_message(1024).unwrap(),
        Received::Binary(vec![1, 2, 3, 250])
    );
    c.send_text("héllo").unwrap();
    assert_eq!(
        c.recv_message(1024).unwrap(),
        Received::Text("héllo".into())
    );
    let keys = server.join().unwrap();
    assert_ne!(keys[0], keys[1], "each frame has its own mask key");
}

#[test]
fn connection_answers_ping_with_masked_pong() {
    let (addr, server) = spawn_server(|tcp| {
        let mut s = ServerConn::accept(tcp);
        s.send(&Frame::ping(b"are you there".to_vec()));
        let pong = s.read_frame(); // read_frame asserts the mask
        s.send(&Frame::binary(b"after".to_vec()));
        pong
    });
    let mut c = connect(&addr);
    assert_eq!(
        c.recv_message(1024).unwrap(),
        Received::Binary(b"after".to_vec())
    );
    let pong = server.join().unwrap();
    assert_eq!(pong.opcode, Opcode::Pong);
    assert_eq!(pong.payload, b"are you there");
}

#[test]
fn connection_assembles_fragments_around_a_ping() {
    let (addr, server) = spawn_server(|tcp| {
        let mut s = ServerConn::accept(tcp);
        let mut first = Frame::text("Hel");
        first.fin = false;
        s.send(&first);
        s.send(&Frame::continuation(b"lo ".to_vec(), false));
        s.send(&Frame::ping(vec![]));
        s.send(&Frame::continuation(b"world".to_vec(), true));
        s.read_frame()
    });
    let mut c = connect(&addr);
    assert_eq!(
        c.recv_message(1024).unwrap(),
        Received::Text("Hello world".into())
    );
    assert_eq!(server.join().unwrap().opcode, Opcode::Pong);
}

#[test]
fn connection_reports_server_close_code_and_echoes_it() {
    let (addr, server) = spawn_server(|tcp| {
        let mut s = ServerConn::accept(tcp);
        s.send(&Frame::close(Some(CloseCode::Other(4001)), "bye"));
        s.read_frame()
    });
    let mut c = connect(&addr);
    assert_eq!(
        c.recv_message(1024).unwrap(),
        Received::Close(Some(ClosePayload {
            code: CloseCode::Other(4001),
            reason: "bye".into()
        }))
    );
    let echo = server.join().unwrap();
    assert_eq!(echo.opcode, Opcode::Close);
    assert_eq!(
        ClosePayload::parse(&echo.payload).unwrap().unwrap().code,
        CloseCode::Other(4001)
    );
    assert_eq!(c.recv_message(1024), Err(WsError::Closed));
    assert_eq!(c.send_binary(b"x"), Err(WsError::Closed));
}

#[test]
fn connection_client_initiated_close() {
    let (addr, server) = spawn_server(|tcp| {
        let mut s = ServerConn::accept(tcp);
        let f = s.read_frame();
        s.send(&Frame::close(Some(CloseCode::Normal), ""));
        f
    });
    let mut c = connect(&addr);
    assert!(matches!(
        c.close(CloseCode::NoStatus, ""),
        Err(WsError::InvalidCloseCode(1005))
    ));
    c.close(CloseCode::Normal, "done").unwrap();
    assert_eq!(c.send_text("late"), Err(WsError::Closed));
    let got = c.recv_message(1024).unwrap();
    assert!(matches!(got, Received::Close(Some(ref p)) if p.code == CloseCode::Normal));
    let sent = server.join().unwrap();
    let p = ClosePayload::parse(&sent.payload).unwrap().unwrap();
    assert_eq!((p.code, p.reason.as_str()), (CloseCode::Normal, "done"));
}

#[test]
fn connection_buffer_bound_refuses_an_oversized_frame() {
    let (addr, server) = spawn_server(|tcp| {
        let mut s = ServerConn::accept(tcp);
        // wait for the client so no frame byte arrives together with the handshake response
        s.read_frame();
        // the client stops reading after the header, so the write may fail; that is expected
        let big = Frame::binary(vec![9; 100_000]).serialize();
        let _ = std::io::Write::write_all(&mut s.stream, &big);
    });
    let mut c = connect(&addr);
    assert_eq!(c.buffered(), 0);
    c.send_text("go").unwrap();
    assert_eq!(c.recv_message(1024), Err(WsError::PayloadTooLarge));
    assert!(
        c.buffered() <= MAX_FRAME_HEADER + 1024,
        "buffered {} bytes",
        c.buffered()
    );
    drop(c);
    server.join().unwrap();
}

#[test]
fn connection_bounds_the_assembled_message() {
    let (addr, server) = spawn_server(|tcp| {
        let mut s = ServerConn::accept(tcp);
        let mut first = Frame::binary(vec![1; 600]);
        first.fin = false;
        s.send(&first);
        s.send(&Frame::continuation(vec![2; 600], true));
    });
    let mut c = connect(&addr);
    assert_eq!(c.recv_message(1024), Err(WsError::PayloadTooLarge));
    server.join().unwrap();
}

#[test]
fn connection_refuses_a_masked_server_frame() {
    let (addr, server) = spawn_server(|tcp| {
        let mut s = ServerConn::accept(tcp);
        s.send_raw(&RFC_MASKED_HELLO);
    });
    let mut c = connect(&addr);
    assert_eq!(c.recv_message(1024), Err(WsError::MaskedServerFrame));
    server.join().unwrap();
}

#[test]
fn connection_keeps_bytes_sent_with_the_handshake() {
    let (addr, server) = spawn_server(|tcp| {
        // the response head and the first frame in one write
        ServerConn::accept_with(tcp, |req| {
            let mut out = HandshakeResponse::from_key(&req.key).to_http().into_bytes();
            out.extend_from_slice(&RFC_UNMASKED_HELLO);
            out
        });
    });
    let mut c = connect(&addr);
    assert_eq!(
        c.recv_message(1024).unwrap(),
        Received::Text("Hello".into())
    );
    server.join().unwrap();
}

#[test]
fn connection_reports_a_refused_upgrade() {
    let (addr, server) = spawn_server(|tcp| {
        ServerConn::accept_with(tcp, |_| {
            b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n".to_vec()
        });
    });
    let r = Connection::connect(dial(&addr), "127.0.0.1", "/ws", counter_mask());
    assert!(matches!(r, Err(WsError::HandshakeStatus(503))));
    server.join().unwrap();
}

#[test]
fn connection_refuses_a_wrong_accept_key() {
    let (addr, server) = spawn_server(|tcp| {
        ServerConn::accept_with(tcp, |_| {
            HandshakeResponse::from_key("not the client's key")
                .to_http()
                .into_bytes()
        });
    });
    let r = Connection::connect(dial(&addr), "127.0.0.1", "/ws", counter_mask());
    assert!(matches!(r, Err(WsError::InvalidAccept)));
    server.join().unwrap();
}

#[test]
fn connection_reports_end_of_stream() {
    let (addr, server) = spawn_server(|tcp| {
        ServerConn::accept(tcp);
    });
    let mut c = connect(&addr);
    server.join().unwrap();
    assert!(matches!(
        c.recv_message(1024),
        Err(WsError::Io {
            kind: std::io::ErrorKind::UnexpectedEof,
            ..
        })
    ));
}
