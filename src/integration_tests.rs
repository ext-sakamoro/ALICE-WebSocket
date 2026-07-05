//! Integration tests spanning multiple modules.

#![allow(
    clippy::float_cmp,
    clippy::unreadable_literal,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::cast_possible_wrap,
    clippy::too_many_lines,
    clippy::needless_range_loop,
    clippy::explicit_iter_loop,
    clippy::bool_to_int_with_if,
    clippy::approx_constant,
    clippy::cast_lossless,
    clippy::redundant_clone,
    clippy::format_collect,
    clippy::similar_names
)]

use crate::assembler::*;
use crate::base64::*;
use crate::buffer::*;
use crate::close_code::*;
use crate::close_payload::*;
use crate::errors::*;
use crate::extensions::*;
use crate::frame::*;
use crate::handshake::*;
use crate::masking::*;
use crate::opcode::*;
use crate::sha1::sha1;

// === Opcode tests ===

#[test]
fn opcode_from_u8_valid() {
    assert_eq!(Opcode::from_u8(0x0).unwrap(), Opcode::Continuation);
    assert_eq!(Opcode::from_u8(0x1).unwrap(), Opcode::Text);
    assert_eq!(Opcode::from_u8(0x2).unwrap(), Opcode::Binary);
    assert_eq!(Opcode::from_u8(0x8).unwrap(), Opcode::Close);
    assert_eq!(Opcode::from_u8(0x9).unwrap(), Opcode::Ping);
    assert_eq!(Opcode::from_u8(0xA).unwrap(), Opcode::Pong);
}

#[test]
fn opcode_from_u8_invalid() {
    assert_eq!(Opcode::from_u8(0x3), Err(WsError::InvalidOpcode(0x3)));
    assert_eq!(Opcode::from_u8(0x7), Err(WsError::InvalidOpcode(0x7)));
    assert_eq!(Opcode::from_u8(0xB), Err(WsError::InvalidOpcode(0xB)));
    assert_eq!(Opcode::from_u8(0xF), Err(WsError::InvalidOpcode(0xF)));
}

#[test]
fn opcode_is_control() {
    assert!(Opcode::Close.is_control());
    assert!(Opcode::Ping.is_control());
    assert!(Opcode::Pong.is_control());
    assert!(!Opcode::Text.is_control());
    assert!(!Opcode::Binary.is_control());
    assert!(!Opcode::Continuation.is_control());
}

#[test]
fn opcode_is_data() {
    assert!(Opcode::Text.is_data());
    assert!(Opcode::Binary.is_data());
    assert!(Opcode::Continuation.is_data());
    assert!(!Opcode::Close.is_data());
    assert!(!Opcode::Ping.is_data());
    assert!(!Opcode::Pong.is_data());
}

// === Close code tests ===

#[test]
fn close_code_roundtrip() {
    let codes = [
        (1000, CloseCode::Normal),
        (1001, CloseCode::GoingAway),
        (1002, CloseCode::ProtocolError),
        (1003, CloseCode::Unsupported),
        (1005, CloseCode::NoStatus),
        (1006, CloseCode::Abnormal),
        (1007, CloseCode::InvalidPayload),
        (1008, CloseCode::PolicyViolation),
        (1009, CloseCode::TooLarge),
        (1010, CloseCode::MandatoryExtension),
        (1011, CloseCode::InternalError),
        (1015, CloseCode::TlsHandshake),
    ];
    for (num, code) in codes {
        assert_eq!(CloseCode::from_u16(num), code);
        assert_eq!(code.to_u16(), num);
    }
}

#[test]
fn close_code_other() {
    let code = CloseCode::from_u16(4000);
    assert_eq!(code, CloseCode::Other(4000));
    assert_eq!(code.to_u16(), 4000);
}

#[test]
fn close_code_sendable() {
    assert!(CloseCode::Normal.is_sendable());
    assert!(CloseCode::GoingAway.is_sendable());
    assert!(CloseCode::ProtocolError.is_sendable());
    assert!(!CloseCode::NoStatus.is_sendable());
    assert!(!CloseCode::Abnormal.is_sendable());
    assert!(!CloseCode::TlsHandshake.is_sendable());
    assert!(CloseCode::Other(3000).is_sendable());
    assert!(CloseCode::Other(4999).is_sendable());
    assert!(!CloseCode::Other(2999).is_sendable());
}

#[test]
fn validate_close_code_valid() {
    assert!(validate_close_code(1000).is_ok());
    assert!(validate_close_code(1007).is_ok());
    assert!(validate_close_code(3000).is_ok());
    assert!(validate_close_code(4999).is_ok());
}

#[test]
fn validate_close_code_invalid() {
    assert!(validate_close_code(1004).is_err());
    assert!(validate_close_code(1005).is_err());
    assert!(validate_close_code(1006).is_err());
    assert!(validate_close_code(999).is_err());
    assert!(validate_close_code(5000).is_err());
}

// === Close payload tests ===

#[test]
fn close_payload_parse_empty() {
    assert_eq!(ClosePayload::parse(&[]).unwrap(), None);
}

#[test]
fn close_payload_parse_single_byte() {
    assert!(ClosePayload::parse(&[0x00]).is_err());
}

#[test]
fn close_payload_parse_code_only() {
    let data = 1000u16.to_be_bytes();
    let cp = ClosePayload::parse(&data).unwrap().unwrap();
    assert_eq!(cp.code, CloseCode::Normal);
    assert_eq!(cp.reason, "");
}

#[test]
fn close_payload_parse_code_and_reason() {
    let mut data = vec![0x03, 0xE8]; // 1000
    data.extend_from_slice(b"goodbye");
    let cp = ClosePayload::parse(&data).unwrap().unwrap();
    assert_eq!(cp.code, CloseCode::Normal);
    assert_eq!(cp.reason, "goodbye");
}

#[test]
fn close_payload_parse_invalid_utf8() {
    let mut data = vec![0x03, 0xE8]; // 1000
    data.extend_from_slice(&[0xFF, 0xFE]);
    assert_eq!(ClosePayload::parse(&data), Err(WsError::InvalidUtf8));
}

#[test]
fn close_payload_roundtrip() {
    let cp = ClosePayload {
        code: CloseCode::GoingAway,
        reason: "server shutdown".into(),
    };
    let bytes = cp.to_bytes();
    let parsed = ClosePayload::parse(&bytes).unwrap().unwrap();
    assert_eq!(parsed, cp);
}

// === Masking tests ===

#[test]
fn mask_unmask_roundtrip() {
    let key = [0x37, 0xFA, 0x21, 0x3D];
    let original = b"Hello, WebSocket!";
    let masked = apply_mask(original, key);
    assert_ne!(&masked, original);
    let unmasked = apply_mask(&masked, key);
    assert_eq!(&unmasked, original);
}

#[test]
fn mask_empty_data() {
    let key = [1, 2, 3, 4];
    let result = apply_mask(&[], key);
    assert!(result.is_empty());
}

#[test]
fn mask_in_place_single_byte() {
    let key = [0xAB, 0, 0, 0];
    let mut data = vec![0x00];
    apply_mask_in_place(&mut data, key);
    assert_eq!(data, vec![0xAB]);
}

#[test]
fn mask_wraps_around_key() {
    let key = [1, 2, 3, 4];
    let data = vec![0, 0, 0, 0, 0, 0, 0, 0];
    let masked = apply_mask(&data, key);
    assert_eq!(masked, vec![1, 2, 3, 4, 1, 2, 3, 4]);
}

// === Frame construction tests ===

#[test]
fn frame_text() {
    let f = Frame::text("hello");
    assert!(f.fin);
    assert_eq!(f.opcode, Opcode::Text);
    assert_eq!(f.payload, b"hello");
    assert!(!f.masked);
}

#[test]
fn frame_binary() {
    let f = Frame::binary(vec![1, 2, 3]);
    assert_eq!(f.opcode, Opcode::Binary);
    assert_eq!(f.payload, vec![1, 2, 3]);
}

#[test]
fn frame_ping() {
    let f = Frame::ping(vec![]);
    assert_eq!(f.opcode, Opcode::Ping);
    assert!(f.fin);
}

#[test]
fn frame_pong() {
    let f = Frame::pong(vec![0xAA]);
    assert_eq!(f.opcode, Opcode::Pong);
    assert_eq!(f.payload, vec![0xAA]);
}

#[test]
fn frame_close_no_code() {
    let f = Frame::close(None, "");
    assert_eq!(f.opcode, Opcode::Close);
    assert!(f.payload.is_empty());
}

#[test]
fn frame_close_with_code() {
    let f = Frame::close(Some(CloseCode::Normal), "bye");
    assert_eq!(f.opcode, Opcode::Close);
    let cp = ClosePayload::parse(&f.payload).unwrap().unwrap();
    assert_eq!(cp.code, CloseCode::Normal);
    assert_eq!(cp.reason, "bye");
}

#[test]
fn frame_continuation() {
    let f = Frame::continuation(vec![1, 2], false);
    assert!(!f.fin);
    assert_eq!(f.opcode, Opcode::Continuation);
}

#[test]
fn frame_set_mask() {
    let mut f = Frame::text("x");
    f.set_mask([1, 2, 3, 4]);
    assert!(f.masked);
    assert_eq!(f.mask_key, [1, 2, 3, 4]);
}

// === Frame serialization tests ===

#[test]
fn serialize_small_frame() {
    let f = Frame::text("Hi");
    let bytes = f.serialize();
    assert_eq!(bytes[0], 0x81); // FIN + TEXT
    assert_eq!(bytes[1], 2); // payload length
    assert_eq!(&bytes[2..], b"Hi");
}

#[test]
fn serialize_medium_frame() {
    let payload = vec![0x42; 200];
    let f = Frame::binary(payload.clone());
    let bytes = f.serialize();
    assert_eq!(bytes[0], 0x82); // FIN + BINARY
    assert_eq!(bytes[1], 126); // extended 16-bit length
    let len = u16::from_be_bytes([bytes[2], bytes[3]]);
    assert_eq!(len, 200);
    assert_eq!(&bytes[4..], payload.as_slice());
}

#[test]
fn serialize_large_frame() {
    let payload = vec![0x00; 70000];
    let f = Frame::binary(payload.clone());
    let bytes = f.serialize();
    assert_eq!(bytes[1], 127); // extended 64-bit length
    let len = u64::from_be_bytes([
        bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9],
    ]);
    assert_eq!(len, 70000);
}

#[test]
fn serialize_masked_frame() {
    let mut f = Frame::text("AB");
    f.set_mask([0x01, 0x02, 0x03, 0x04]);
    let bytes = f.serialize_masked();
    assert_eq!(bytes[1] & 0x80, 0x80); // mask bit
    assert_eq!(&bytes[2..6], &[0x01, 0x02, 0x03, 0x04]);
    // payload is masked
    assert_eq!(bytes[6], b'A' ^ 0x01);
    assert_eq!(bytes[7], b'B' ^ 0x02);
}

#[test]
fn serialize_rsv_bits() {
    let mut f = Frame::ping(vec![]);
    f.rsv1 = true;
    f.rsv2 = true;
    f.rsv3 = true;
    let bytes = f.serialize();
    assert_eq!(bytes[0] & 0x70, 0x70);
}

// === Frame parsing tests ===

#[test]
fn parse_simple_text() {
    let f = Frame::text("test");
    let bytes = f.serialize();
    let (parsed, consumed) = Frame::parse(&bytes).unwrap();
    assert_eq!(consumed, bytes.len());
    assert_eq!(parsed.opcode, Opcode::Text);
    assert_eq!(parsed.payload, b"test");
    assert!(parsed.fin);
}

#[test]
fn parse_binary_frame() {
    let f = Frame::binary(vec![0xDE, 0xAD, 0xBE, 0xEF]);
    let bytes = f.serialize();
    let (parsed, _) = Frame::parse(&bytes).unwrap();
    assert_eq!(parsed.opcode, Opcode::Binary);
    assert_eq!(parsed.payload, vec![0xDE, 0xAD, 0xBE, 0xEF]);
}

#[test]
fn parse_masked_frame() {
    let mut f = Frame::text("hi");
    f.set_mask([0x37, 0xFA, 0x21, 0x3D]);
    let bytes = f.serialize_masked();
    let (parsed, _) = Frame::parse(&bytes).unwrap();
    assert_eq!(parsed.payload, b"hi"); // unmasked
    assert!(parsed.masked);
}

#[test]
fn parse_incomplete() {
    assert_eq!(Frame::parse(&[0x81]), Err(WsError::Incomplete));
}

#[test]
fn parse_incomplete_payload() {
    let bytes = vec![0x81, 0x05, 0x41]; // says 5 bytes but only 1
    assert_eq!(Frame::parse(&bytes), Err(WsError::Incomplete));
}

#[test]
fn parse_incomplete_extended16() {
    let bytes = vec![0x81, 126, 0x00]; // missing second byte of length
    assert_eq!(Frame::parse(&bytes), Err(WsError::Incomplete));
}

#[test]
fn parse_incomplete_extended64() {
    let bytes = vec![0x81, 127, 0, 0, 0]; // missing most of length
    assert_eq!(Frame::parse(&bytes), Err(WsError::Incomplete));
}

#[test]
fn parse_reserved_bits_rejected() {
    let bytes = vec![0xC1, 0x00]; // RSV1 set
    assert_eq!(Frame::parse(&bytes), Err(WsError::ReservedBitsSet));
}

#[test]
fn parse_reserved_bits_allowed_with_extensions() {
    let bytes = vec![0xC1, 0x00]; // RSV1 set, FIN+Text
    let (frame, _) = Frame::parse_with_extensions(&bytes, true).unwrap();
    assert!(frame.rsv1);
}

#[test]
fn parse_invalid_opcode() {
    let bytes = vec![0x83, 0x00]; // opcode 3 is reserved
    assert_eq!(Frame::parse(&bytes), Err(WsError::InvalidOpcode(3)));
}

#[test]
fn parse_control_frame_too_large() {
    let mut bytes = vec![0x89, 126, 0x00, 0x80]; // ping with 128 byte payload
    bytes.extend(vec![0; 128]);
    assert_eq!(Frame::parse(&bytes), Err(WsError::ControlFrameTooLarge));
}

#[test]
fn parse_fragmented_control_frame() {
    let bytes = vec![0x09, 0x00]; // ping without FIN
    assert_eq!(Frame::parse(&bytes), Err(WsError::FragmentedControlFrame));
}

#[test]
fn parse_medium_payload() {
    let payload = vec![0xAB; 300];
    let f = Frame::binary(payload.clone());
    let bytes = f.serialize();
    let (parsed, consumed) = Frame::parse(&bytes).unwrap();
    assert_eq!(consumed, bytes.len());
    assert_eq!(parsed.payload, payload);
}

#[test]
fn parse_large_payload() {
    let payload = vec![0xCD; 70000];
    let f = Frame::binary(payload.clone());
    let bytes = f.serialize();
    let (parsed, consumed) = Frame::parse(&bytes).unwrap();
    assert_eq!(consumed, bytes.len());
    assert_eq!(parsed.payload, payload);
}

#[test]
fn parse_roundtrip_all_opcodes() {
    let opcodes = [
        Opcode::Text,
        Opcode::Binary,
        Opcode::Close,
        Opcode::Ping,
        Opcode::Pong,
    ];
    for op in opcodes {
        let f = Frame::new(op, vec![0x01, 0x02]);
        let bytes = f.serialize();
        let (parsed, _) = Frame::parse(&bytes).unwrap();
        assert_eq!(parsed.opcode, op);
        assert_eq!(parsed.payload, vec![0x01, 0x02]);
    }
}

#[test]
fn parse_empty_payload() {
    let f = Frame::binary(vec![]);
    let bytes = f.serialize();
    let (parsed, _) = Frame::parse(&bytes).unwrap();
    assert!(parsed.payload.is_empty());
}

#[test]
fn parse_exactly_125_byte_control() {
    let f = Frame::ping(vec![0x42; 125]);
    let bytes = f.serialize();
    let (parsed, _) = Frame::parse(&bytes).unwrap();
    assert_eq!(parsed.payload.len(), 125);
}

#[test]
fn parse_multiple_frames_in_buffer() {
    let f1 = Frame::text("one");
    let f2 = Frame::text("two");
    let mut bytes = f1.serialize();
    bytes.extend(f2.serialize());

    let (p1, consumed1) = Frame::parse(&bytes).unwrap();
    assert_eq!(p1.payload, b"one");

    let (p2, _) = Frame::parse(&bytes[consumed1..]).unwrap();
    assert_eq!(p2.payload, b"two");
}

#[test]
fn header_size_small() {
    let f = Frame::text("hi");
    assert_eq!(f.header_size(), 2);
}

#[test]
fn header_size_medium() {
    let f = Frame::binary(vec![0; 200]);
    assert_eq!(f.header_size(), 4);
}

#[test]
fn header_size_large() {
    let f = Frame::binary(vec![0; 70000]);
    assert_eq!(f.header_size(), 10);
}

#[test]
fn header_size_masked() {
    let mut f = Frame::text("hi");
    f.set_mask([1, 2, 3, 4]);
    assert_eq!(f.header_size(), 6); // 2 + 4
}

// === Base64 tests ===

#[test]
fn base64_encode_empty() {
    assert_eq!(base64_encode(&[]), "");
}

#[test]
fn base64_encode_hello() {
    assert_eq!(base64_encode(b"Hello"), "SGVsbG8=");
}

#[test]
fn base64_encode_padding() {
    assert_eq!(base64_encode(b"a"), "YQ==");
    assert_eq!(base64_encode(b"ab"), "YWI=");
    assert_eq!(base64_encode(b"abc"), "YWJj");
}

#[test]
fn base64_roundtrip() {
    let data = b"WebSocket protocol test data 1234567890!@#";
    let encoded = base64_encode(data);
    let decoded = base64_decode(&encoded).unwrap();
    assert_eq!(decoded, data);
}

#[test]
fn base64_decode_invalid() {
    assert!(base64_decode("!!!").is_err());
}

// === SHA-1 / handshake key tests ===

#[test]
fn sha1_empty() {
    let result = sha1(b"");
    let hex: String = result.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
}

#[test]
fn sha1_abc() {
    let result = sha1(b"abc");
    let hex: String = result.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, "a9993e364706816aba3e25717850c26c9cd0d89d");
}

#[test]
fn compute_accept_key_rfc_example() {
    // RFC 6455 Section 4.2.2 example
    let key = "dGhlIHNhbXBsZSBub25jZQ==";
    let accept = compute_accept_key(key);
    assert_eq!(accept, "fPgBbBWxQ5p/OQE7IpV6s8+HiTg=");
}

// === Handshake request tests ===

#[test]
fn handshake_request_to_http() {
    let req = HandshakeRequest::new("example.com", "/chat", "dGhlIHNhbXBsZSBub25jZQ==");
    let http = req.to_http();
    assert!(http.contains("GET /chat HTTP/1.1\r\n"));
    assert!(http.contains("Host: example.com\r\n"));
    assert!(http.contains("Upgrade: websocket\r\n"));
    assert!(http.contains("Connection: Upgrade\r\n"));
    assert!(http.contains("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"));
    assert!(http.contains("Sec-WebSocket-Version: 13\r\n"));
}

#[test]
fn handshake_request_with_protocols() {
    let mut req = HandshakeRequest::new("host", "/", "key123");
    req.protocols = vec!["chat".into(), "superchat".into()];
    let http = req.to_http();
    assert!(http.contains("Sec-WebSocket-Protocol: chat, superchat\r\n"));
}

#[test]
fn handshake_request_with_extensions() {
    let mut req = HandshakeRequest::new("host", "/", "key123");
    req.extensions = vec!["permessage-deflate".into()];
    let http = req.to_http();
    assert!(http.contains("Sec-WebSocket-Extensions: permessage-deflate\r\n"));
}

#[test]
fn handshake_request_parse() {
    let raw = b"GET /ws HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: testkey\r\nSec-WebSocket-Version: 13\r\n\r\n";
    let req = HandshakeRequest::parse(raw).unwrap();
    assert_eq!(req.path, "/ws");
    assert_eq!(req.host, "example.com");
    assert_eq!(req.key, "testkey");
    assert_eq!(req.version, "13");
}

#[test]
fn handshake_request_parse_with_protocols() {
    let raw = b"GET / HTTP/1.1\r\nHost: h\r\nSec-WebSocket-Key: k\r\nSec-WebSocket-Protocol: chat, superchat\r\n\r\n";
    let req = HandshakeRequest::parse(raw).unwrap();
    assert_eq!(req.protocols, vec!["chat", "superchat"]);
}

#[test]
fn handshake_request_parse_missing_key() {
    let raw = b"GET / HTTP/1.1\r\nHost: h\r\n\r\n";
    assert!(HandshakeRequest::parse(raw).is_err());
}

#[test]
fn handshake_request_parse_not_get() {
    let raw = b"POST / HTTP/1.1\r\n\r\n";
    assert!(HandshakeRequest::parse(raw).is_err());
}

// === Handshake response tests ===

#[test]
fn handshake_response_from_key() {
    let key = "dGhlIHNhbXBsZSBub25jZQ==";
    let resp = HandshakeResponse::from_key(key);
    assert_eq!(resp.accept, "fPgBbBWxQ5p/OQE7IpV6s8+HiTg=");
}

#[test]
fn handshake_response_to_http() {
    let resp = HandshakeResponse::from_key("dGhlIHNhbXBsZSBub25jZQ==");
    let http = resp.to_http();
    assert!(http.contains("HTTP/1.1 101 Switching Protocols\r\n"));
    assert!(http.contains("Upgrade: websocket\r\n"));
    assert!(http.contains("Connection: Upgrade\r\n"));
    assert!(http.contains("Sec-WebSocket-Accept: fPgBbBWxQ5p/OQE7IpV6s8+HiTg=\r\n"));
}

#[test]
fn handshake_response_parse() {
    let raw = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: fPgBbBWxQ5p/OQE7IpV6s8+HiTg=\r\n\r\n";
    let resp = HandshakeResponse::parse(raw).unwrap();
    assert_eq!(resp.accept, "fPgBbBWxQ5p/OQE7IpV6s8+HiTg=");
}

#[test]
fn handshake_response_validate_ok() {
    let key = "dGhlIHNhbXBsZSBub25jZQ==";
    let resp = HandshakeResponse::from_key(key);
    assert!(resp.validate(key).is_ok());
}

#[test]
fn handshake_response_validate_fail() {
    let resp = HandshakeResponse {
        accept: "wrong".into(),
        protocol: None,
        extensions: Vec::new(),
        headers: Vec::new(),
    };
    assert_eq!(
        resp.validate("dGhlIHNhbXBsZSBub25jZQ=="),
        Err(WsError::InvalidAccept)
    );
}

#[test]
fn handshake_response_parse_not_101() {
    let raw = b"HTTP/1.1 400 Bad Request\r\n\r\n";
    assert!(HandshakeResponse::parse(raw).is_err());
}

#[test]
fn handshake_response_with_protocol() {
    let mut resp = HandshakeResponse::from_key("k");
    resp.protocol = Some("chat".into());
    let http = resp.to_http();
    assert!(http.contains("Sec-WebSocket-Protocol: chat\r\n"));
}

#[test]
fn handshake_full_roundtrip() {
    let key = "dGhlIHNhbXBsZSBub25jZQ==";
    let req = HandshakeRequest::new("example.com", "/chat", key);
    let http_req = req.to_http();
    let parsed_req = HandshakeRequest::parse(http_req.as_bytes()).unwrap();

    let resp = HandshakeResponse::from_key(&parsed_req.key);
    let http_resp = resp.to_http();
    let parsed_resp = HandshakeResponse::parse(http_resp.as_bytes()).unwrap();
    assert!(parsed_resp.validate(key).is_ok());
}

// === Extension tests ===

#[test]
fn extension_parse_simple() {
    let exts = Extension::parse_list("permessage-deflate");
    assert_eq!(exts.len(), 1);
    assert_eq!(exts[0].name, "permessage-deflate");
    assert!(exts[0].params.is_empty());
}

#[test]
fn extension_parse_with_params() {
    let exts = Extension::parse_list(
        "permessage-deflate; client_max_window_bits; server_no_context_takeover",
    );
    assert_eq!(exts.len(), 1);
    assert_eq!(exts[0].params.len(), 2);
    assert_eq!(exts[0].params[0].key, "client_max_window_bits");
    assert!(exts[0].params[0].value.is_none());
}

#[test]
fn extension_parse_with_value() {
    let exts = Extension::parse_list("permessage-deflate; client_max_window_bits=15");
    assert_eq!(exts[0].params[0].value, Some("15".into()));
}

#[test]
fn extension_parse_multiple() {
    let exts = Extension::parse_list("ext1, ext2; param=val");
    assert_eq!(exts.len(), 2);
    assert_eq!(exts[0].name, "ext1");
    assert_eq!(exts[1].name, "ext2");
}

#[test]
fn extension_parse_empty() {
    let exts = Extension::parse_list("");
    assert!(exts.is_empty());
}

#[test]
fn extension_to_header_value() {
    let exts = vec![
        Extension {
            name: "permessage-deflate".into(),
            params: vec![ExtensionParam {
                key: "client_max_window_bits".into(),
                value: Some("15".into()),
            }],
        },
        Extension {
            name: "x-custom".into(),
            params: vec![],
        },
    ];
    let header = Extension::to_header_value(&exts);
    assert_eq!(
        header,
        "permessage-deflate; client_max_window_bits=15, x-custom"
    );
}

#[test]
fn extension_roundtrip() {
    let original = "permessage-deflate; client_max_window_bits=15, x-test; flag";
    let exts = Extension::parse_list(original);
    let header = Extension::to_header_value(&exts);
    let reparsed = Extension::parse_list(&header);
    assert_eq!(exts, reparsed);
}

// === Message assembler tests ===

#[test]
fn assembler_unfragmented_text() {
    let mut asm = MessageAssembler::new();
    let f = Frame::text("hello");
    let msg = asm.feed(&f).unwrap().unwrap();
    assert_eq!(msg.opcode, Opcode::Text);
    assert_eq!(msg.payload, b"hello");
}

#[test]
fn assembler_unfragmented_binary() {
    let mut asm = MessageAssembler::new();
    let f = Frame::binary(vec![1, 2, 3]);
    let msg = asm.feed(&f).unwrap().unwrap();
    assert_eq!(msg.opcode, Opcode::Binary);
}

#[test]
fn assembler_fragmented_text() {
    let mut asm = MessageAssembler::new();

    let mut f1 = Frame::new(Opcode::Text, b"hel".to_vec());
    f1.fin = false;
    assert!(asm.feed(&f1).unwrap().is_none());
    assert!(asm.in_progress());

    let f2 = Frame::continuation(b"lo".to_vec(), true);
    let msg = asm.feed(&f2).unwrap().unwrap();
    assert_eq!(msg.opcode, Opcode::Text);
    assert_eq!(msg.payload, b"hello");
    assert!(!asm.in_progress());
}

#[test]
fn assembler_fragmented_three_parts() {
    let mut asm = MessageAssembler::new();

    let mut f1 = Frame::new(Opcode::Binary, vec![1]);
    f1.fin = false;
    assert!(asm.feed(&f1).unwrap().is_none());

    let f2 = Frame::continuation(vec![2], false);
    assert!(asm.feed(&f2).unwrap().is_none());

    let f3 = Frame::continuation(vec![3], true);
    let msg = asm.feed(&f3).unwrap().unwrap();
    assert_eq!(msg.payload, vec![1, 2, 3]);
}

#[test]
fn assembler_control_during_fragment() {
    let mut asm = MessageAssembler::new();

    let mut f1 = Frame::new(Opcode::Text, b"hel".to_vec());
    f1.fin = false;
    assert!(asm.feed(&f1).unwrap().is_none());

    // Control frame in the middle should be delivered
    let ping = Frame::ping(vec![0x42]);
    let msg = asm.feed(&ping).unwrap().unwrap();
    assert_eq!(msg.opcode, Opcode::Ping);

    // Continue the fragment
    let f2 = Frame::continuation(b"lo".to_vec(), true);
    let msg = asm.feed(&f2).unwrap().unwrap();
    assert_eq!(msg.payload, b"hello");
}

#[test]
fn assembler_continuation_without_start() {
    let mut asm = MessageAssembler::new();
    let f = Frame::continuation(vec![1], true);
    assert!(asm.feed(&f).is_err());
}

#[test]
fn assembler_new_data_during_fragment() {
    let mut asm = MessageAssembler::new();
    let mut f1 = Frame::new(Opcode::Text, b"x".to_vec());
    f1.fin = false;
    asm.feed(&f1).unwrap();

    let f2 = Frame::text("y");
    assert!(asm.feed(&f2).is_err());
}

#[test]
fn assembler_reset() {
    let mut asm = MessageAssembler::new();
    let mut f = Frame::new(Opcode::Text, b"x".to_vec());
    f.fin = false;
    asm.feed(&f).unwrap();
    assert!(asm.in_progress());

    asm.reset();
    assert!(!asm.in_progress());
}

#[test]
fn assembler_invalid_utf8_text() {
    let mut asm = MessageAssembler::new();
    let f = Frame::new(Opcode::Text, vec![0xFF, 0xFE]);
    assert_eq!(asm.feed(&f), Err(WsError::InvalidUtf8));
}

#[test]
fn assembler_invalid_utf8_fragmented() {
    let mut asm = MessageAssembler::new();
    let mut f1 = Frame::new(Opcode::Text, vec![0xFF]);
    f1.fin = false;
    asm.feed(&f1).unwrap();

    let f2 = Frame::continuation(vec![0xFE], true);
    assert_eq!(asm.feed(&f2), Err(WsError::InvalidUtf8));
}

#[test]
fn assembler_default() {
    let asm = MessageAssembler::default();
    assert!(!asm.in_progress());
}

// === Message tests ===

#[test]
fn message_as_text() {
    let msg = Message {
        opcode: Opcode::Text,
        payload: b"hello".to_vec(),
    };
    assert_eq!(msg.as_text().unwrap(), "hello");
}

#[test]
fn message_as_text_invalid() {
    let msg = Message {
        opcode: Opcode::Text,
        payload: vec![0xFF],
    };
    assert!(msg.as_text().is_err());
}

#[test]
fn message_fragment_small() {
    let msg = Message {
        opcode: Opcode::Text,
        payload: b"hi".to_vec(),
    };
    let frames = msg.fragment(100);
    assert_eq!(frames.len(), 1);
    assert!(frames[0].fin);
    assert_eq!(frames[0].opcode, Opcode::Text);
}

#[test]
fn message_fragment_split() {
    let msg = Message {
        opcode: Opcode::Binary,
        payload: vec![1, 2, 3, 4, 5],
    };
    let frames = msg.fragment(2);
    assert_eq!(frames.len(), 3);

    assert_eq!(frames[0].opcode, Opcode::Binary);
    assert!(!frames[0].fin);
    assert_eq!(frames[0].payload, vec![1, 2]);

    assert_eq!(frames[1].opcode, Opcode::Continuation);
    assert!(!frames[1].fin);
    assert_eq!(frames[1].payload, vec![3, 4]);

    assert_eq!(frames[2].opcode, Opcode::Continuation);
    assert!(frames[2].fin);
    assert_eq!(frames[2].payload, vec![5]);
}

#[test]
fn message_fragment_zero_size() {
    let msg = Message {
        opcode: Opcode::Text,
        payload: b"ab".to_vec(),
    };
    let frames = msg.fragment(0);
    assert_eq!(frames.len(), 2);
}

#[test]
fn message_fragment_reassemble() {
    let msg = Message {
        opcode: Opcode::Text,
        payload: b"Hello, World!".to_vec(),
    };
    let frames = msg.fragment(5);
    assert!(frames.len() > 1);

    let mut asm = MessageAssembler::new();
    let mut result = None;
    for f in &frames {
        if let Some(m) = asm.feed(f).unwrap() {
            result = Some(m);
        }
    }
    let reassembled = result.unwrap();
    assert_eq!(reassembled, msg);
}

// === FrameBuffer tests ===

#[test]
fn frame_buffer_empty() {
    let mut fb = FrameBuffer::new();
    assert!(fb.try_parse().unwrap().is_none());
    assert!(fb.is_empty());
    assert_eq!(fb.len(), 0);
}

#[test]
fn frame_buffer_single_frame() {
    let mut fb = FrameBuffer::new();
    let f = Frame::text("test");
    fb.extend(&f.serialize());
    let parsed = fb.try_parse().unwrap().unwrap();
    assert_eq!(parsed.payload, b"test");
    assert!(fb.is_empty());
}

#[test]
fn frame_buffer_partial_data() {
    let mut fb = FrameBuffer::new();
    let f = Frame::text("hello");
    let bytes = f.serialize();

    fb.extend(&bytes[..3]);
    assert!(fb.try_parse().unwrap().is_none());
    assert_eq!(fb.len(), 3);

    fb.extend(&bytes[3..]);
    let parsed = fb.try_parse().unwrap().unwrap();
    assert_eq!(parsed.payload, b"hello");
}

#[test]
fn frame_buffer_multiple_frames() {
    let mut fb = FrameBuffer::new();
    let f1 = Frame::text("one");
    let f2 = Frame::binary(vec![1, 2, 3]);
    let mut bytes = f1.serialize();
    bytes.extend(f2.serialize());

    fb.extend(&bytes);

    let p1 = fb.try_parse().unwrap().unwrap();
    assert_eq!(p1.payload, b"one");

    let p2 = fb.try_parse().unwrap().unwrap();
    assert_eq!(p2.payload, vec![1, 2, 3]);

    assert!(fb.try_parse().unwrap().is_none());
}

#[test]
fn frame_buffer_with_extensions() {
    let mut fb = FrameBuffer::with_extensions();
    let mut f = Frame::text("x");
    f.rsv1 = true;
    fb.extend(&f.serialize());
    let parsed = fb.try_parse().unwrap().unwrap();
    assert!(parsed.rsv1);
}

#[test]
fn frame_buffer_clear() {
    let mut fb = FrameBuffer::new();
    fb.extend(&[0x81, 0x01, 0x41]);
    fb.clear();
    assert!(fb.is_empty());
}

#[test]
fn frame_buffer_default() {
    let fb = FrameBuffer::default();
    assert!(fb.is_empty());
}

// === Error display tests ===

#[test]
fn error_display() {
    assert_eq!(WsError::Incomplete.to_string(), "incomplete frame data");
    assert_eq!(
        WsError::InvalidOpcode(0x3).to_string(),
        "invalid opcode: 0x3"
    );
    assert_eq!(
        WsError::ControlFrameTooLarge.to_string(),
        "control frame payload > 125 bytes"
    );
    assert_eq!(
        WsError::FragmentedControlFrame.to_string(),
        "control frame must not be fragmented"
    );
    assert_eq!(
        WsError::ReservedBitsSet.to_string(),
        "reserved bits set without extensions"
    );
    assert_eq!(
        WsError::InvalidUtf8.to_string(),
        "invalid UTF-8 in text frame"
    );
    assert_eq!(
        WsError::InvalidCloseCode(9999).to_string(),
        "invalid close code: 9999"
    );
    assert_eq!(
        WsError::HandshakeError("test".into()).to_string(),
        "handshake error: test"
    );
    assert_eq!(
        WsError::InvalidAccept.to_string(),
        "invalid Sec-WebSocket-Accept"
    );
    assert_eq!(
        WsError::FragmentationError("test".into()).to_string(),
        "fragmentation error: test"
    );
    assert_eq!(
        WsError::PayloadTooLarge.to_string(),
        "payload length overflow"
    );
}

#[test]
fn error_is_std_error() {
    let e: Box<dyn std::error::Error> = Box::new(WsError::Incomplete);
    assert!(!e.to_string().is_empty());
}

// === Integration-style tests ===

#[test]
fn full_client_server_handshake_flow() {
    // Client creates request
    let key = "dGhlIHNhbXBsZSBub25jZQ==";
    let req = HandshakeRequest::new("example.com", "/ws", key);
    let req_http = req.to_http();

    // Server parses request
    let parsed_req = HandshakeRequest::parse(req_http.as_bytes()).unwrap();
    assert_eq!(parsed_req.key, key);

    // Server creates response
    let resp = HandshakeResponse::from_key(&parsed_req.key);
    let resp_http = resp.to_http();

    // Client parses and validates response
    let parsed_resp = HandshakeResponse::parse(resp_http.as_bytes()).unwrap();
    parsed_resp.validate(key).unwrap();

    // Now exchange frames
    let mut client_buf = FrameBuffer::new();
    let mut server_asm = MessageAssembler::new();

    // Client sends masked text
    let mut f = Frame::text("Hello server!");
    f.set_mask([0x12, 0x34, 0x56, 0x78]);
    let wire = f.serialize_masked();

    // Server receives
    client_buf.extend(&wire);
    let received = client_buf.try_parse().unwrap().unwrap();
    let msg = server_asm.feed(&received).unwrap().unwrap();
    assert_eq!(msg.as_text().unwrap(), "Hello server!");
}

#[test]
fn fragmented_message_with_interleaved_ping() {
    let mut asm = MessageAssembler::new();
    let mut fb = FrameBuffer::new();

    // First fragment
    let mut f1 = Frame::new(Opcode::Text, b"Hel".to_vec());
    f1.fin = false;
    fb.extend(&f1.serialize());

    // Interleaved ping
    let ping = Frame::ping(b"check".to_vec());
    fb.extend(&ping.serialize());

    // Second fragment
    let f2 = Frame::continuation(b"lo!".to_vec(), true);
    fb.extend(&f2.serialize());

    let mut messages = Vec::new();
    while let Some(frame) = fb.try_parse().unwrap() {
        if let Some(msg) = asm.feed(&frame).unwrap() {
            messages.push(msg);
        }
    }

    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0].opcode, Opcode::Ping);
    assert_eq!(messages[0].payload, b"check");
    assert_eq!(messages[1].opcode, Opcode::Text);
    assert_eq!(messages[1].as_text().unwrap(), "Hello!");
}

#[test]
fn close_frame_flow() {
    // Client sends close
    let close = Frame::close(Some(CloseCode::Normal), "goodbye");
    let bytes = close.serialize();
    let (parsed, _) = Frame::parse(&bytes).unwrap();

    let cp = ClosePayload::parse(&parsed.payload).unwrap().unwrap();
    assert_eq!(cp.code, CloseCode::Normal);
    assert_eq!(cp.reason, "goodbye");

    // Server echoes close
    let echo = Frame::close(Some(cp.code), &cp.reason);
    let echo_bytes = echo.serialize();
    let (parsed_echo, _) = Frame::parse(&echo_bytes).unwrap();
    let cp2 = ClosePayload::parse(&parsed_echo.payload).unwrap().unwrap();
    assert_eq!(cp2.code, CloseCode::Normal);
}

#[test]
fn ping_pong_flow() {
    let ping_data = b"heartbeat";
    let ping = Frame::ping(ping_data.to_vec());
    let bytes = ping.serialize();
    let (parsed, _) = Frame::parse(&bytes).unwrap();
    assert_eq!(parsed.opcode, Opcode::Ping);

    // Response with pong using same payload
    let pong = Frame::pong(parsed.payload.clone());
    let pong_bytes = pong.serialize();
    let (parsed_pong, _) = Frame::parse(&pong_bytes).unwrap();
    assert_eq!(parsed_pong.opcode, Opcode::Pong);
    assert_eq!(parsed_pong.payload, ping_data);
}
