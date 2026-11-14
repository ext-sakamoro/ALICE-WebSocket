**English** | [日本語](README_JP.md)

# ALICE-WebSocket

Pure Rust WebSocket protocol implementation for the A.L.I.C.E. ecosystem. RFC 6455 compliant frame parsing, handshake, and message handling.

## Features

- **Frame Parsing** — Binary frame decoding with opcode, mask, and payload extraction
- **Masking** — XOR masking/unmasking per RFC 6455 Section 5.3
- **Handshake** — Client/server HTTP Upgrade handshake with `Sec-WebSocket-Key` validation
- **Ping/Pong** — Keep-alive frame generation and response
- **Close Frames** — Graceful close with status codes and reason phrases
- **Fragmentation** — Multi-frame message assembly (continuation frames)
- **Text & Binary** — Both text (UTF-8 validated) and binary message types
- **Extensions** — Reserved bit awareness for extension negotiation
- **Bounded parsing** — `Frame::parse_limited` refuses an over-limit payload from the header alone
- **Client role** — `client::Connection` over any blocking `Read + Write` stream: masked frames with a fresh key each, masked server frames refused, pings answered, fragments assembled, close codes reported, a bounded read buffer
- **Mask sources** — `MaskSource` trait; `OsMask` (feature `rng`) reads the operating system's random source
- **wss** — `client::connect_tls` (feature `tls`, rustls 0.23 with the ring provider), Mozilla roots or caller-supplied roots

## Architecture

```
Byte Stream
  │
  ├── WsError      — Error types (Incomplete, InvalidOpcode, etc.)
  ├── Opcode       — Frame opcodes (Text, Binary, Close, Ping, Pong)
  ├── Frame        — Wire-level frame parsing and construction
  ├── Handshake    — HTTP Upgrade request/response generation
  ├── Masking      — XOR mask application
  ├── Defragmenter — Continuation frame assembly
  └── Message      — High-level text/binary message API
```

## Features (Cargo)

| feature | adds | dependencies |
|---|---|---|
| (none) | protocol pieces, `client::Connection` | none |
| `rng` | `OsMask` | alice-crypto (OS random source) |
| `tls` | `client::connect_tls`, `TlsConfig`, `TlsStream` | rustls 0.23 (ring), webpki-roots |

```rust,ignore
use std::net::TcpStream;
use alice_websocket::client::{connect_tls, Received, TlsConfig};
use alice_websocket::OsMask;

let tcp = TcpStream::connect("example.com:443")?;
let roots = TlsConfig::webpki_roots()?;
let mut ws = connect_tls(tcp, "example.com", &roots, "example.com", "/ws", OsMask::new())?;
ws.send_text("hello")?;
match ws.recv_message(1 << 20)? {
    Received::Text(t) => println!("{t}"),
    Received::Binary(b) => println!("{} bytes", b.len()),
    Received::Close(c) => println!("closed: {c:?}"),
    _ => {}
}
```

## Usage

```rust
use alice_websocket::Opcode;

let op = Opcode::from_u8(0x1).unwrap();
assert_eq!(op, Opcode::Text);
```

## License

`LicenseRef-Proprietary`. The text is [LICENSE-Proprietary](LICENSE-Proprietary).

Enquiries: https://extoria.co.jp/
