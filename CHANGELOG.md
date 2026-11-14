# Changelog

この crate の変更の記録 形式は [Keep a Changelog](https://keepachangelog.com/ja/1.1.0/)、版は [Semantic Versioning](https://semver.org/lang/ja/) に従う

## [Unreleased]

## [2.0.0]

### Changed (破壊的)

- `WsError` を `#[non_exhaustive]` にした 外部の crate で `WsError` を網羅的に `match` している箇所には `_ =>` の腕が要る
- 追加した variant: `MaskedServerFrame` (client が server から mask つきの frame を受けた、RFC 6455 §5.1) / `HandshakeStatus(u16)` (101 以外の応答) / `Io { kind, message }` (`From<std::io::Error>`) / `Closed` (close の後の送受信) / `Tls(String)` / `Certificate(String)` TLS の variant は feature に関わらず常にある (どの feature で build しても enum の形が同じ)
- `HandshakeResponse::parse` は status code を数値で読む 以前は status line に `101` を含めば通していた (`404 ... 101` も通った)

### Added

- `mask::MaskSource` (mask と handshake key の乱数の源) と、feature `rng` の `OsMask` (OS の乱数、取れなければ panic、`try_fill` で `Result`)
- `handshake::client_key`、`Frame::serialize_client` (frame ごとに新しい mask key)
- `Frame::parse_limited` (header で長さが分かった時点で上限を超えれば `PayloadTooLarge`) と `Frame::parse_from_server` (client 側、mask つきの frame を拒む)
- `client::Connection` (blocking の client: handshake の検証、ping への pong、断片の組立と上限、close の往復、読みの buffer の上限)
- feature `tls`: `client::connect_tls` / `TlsConfig` (webpki-roots か呼び出し側の root) / `TlsStream`、rustls を利用側に見せない

## [1.0.2]

### Fixed

- `WEBSOCKET_GUID` を RFC 6455 §1.3 の値にした (以前の値ではどの準拠した相手とも handshake が成立しなかった)
