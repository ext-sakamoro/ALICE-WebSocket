# Changelog

この crate の変更の記録 形式は [Keep a Changelog](https://keepachangelog.com/ja/1.1.0/)、版は [Semantic Versioning](https://semver.org/lang/ja/) に従う

## [Unreleased]

## [3.0.0]

### Changed (破壊的)

- `MaskSource::fill` は `Result<(), MaskError>` を返す 乱数が取れない時に panic せず呼び出し側へ返す 外部の `MaskSource` 実装は戻り値を `Ok(())` / `Err(MaskError)` に変える必要がある
- `OsMask` の `fill` は OS の乱数源が失敗すると `MaskError::Os` を返す (以前は panic) `OsMask::try_fill` は削除した (`MaskSource::fill` と同じ処理で、失敗を返す経路が 2 本になるため)
- `handshake::client_key` は `Result<String, MaskError>`、`Frame::serialize_client` は `Result<Vec<u8>, MaskError>` を返す
- `client::Connection` の `connect` / `send_text` / `send_binary` / `send_ping` / `close` / `recv_message` (ping への pong、close の echo) と `client::connect_tls` は、mask の源が失敗すると `WsError::Mask` を返す この時 stream には 1 byte も書かない (key は書き込みの前に取る)
- `Connection::close` と close の echo は、mask の key が取れてから close を送った状態にする 失敗した close は送っていない扱いで、再度 `close` を呼べる

### Added

- `mask::MaskError` (`#[non_exhaustive]`、`Display` / `Error`): `Os(RngError)` (feature `rng`) と `Unavailable(String)` (独自の源の失敗)
- `WsError::Mask(MaskError)` と `From<MaskError> for WsError` (`Error::source` は `MaskError` を返す)
- `clippy.toml`: ALICE-Law G1 の禁止 method (f32 / f64 の libm 依存の method) の一覧 CI の clippy (`-D warnings`) が `clippy::disallowed_methods` を拒む

## [2.1.0]

### Added

- `client::TlsStream::connect(tcp, server_name, &TlsConfig)` (feature `tls`): TLS の handshake だけを行い暗号化した stream を返す 利用側はその上で HTTPS の要求や `Connection::connect` を自分で行える `connect_tls` はこの上に組み直した (挙動は同じ)

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
