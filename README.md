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

## Usage

```rust
use alice_websocket::Opcode;

let op = Opcode::from_u8(0x1).unwrap();
assert_eq!(op, Opcode::Text);
```

## License

AGPL-3.0
