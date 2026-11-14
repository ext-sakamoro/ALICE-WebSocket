[English](README.md) | **日本語**

# ALICE-WebSocket

A.L.I.C.E. エコシステム向け純Rust WebSocketプロトコル実装。RFC 6455準拠のフレーム解析、ハンドシェイク、メッセージ処理。

## 機能

- **フレーム解析** — オペコード、マスク、ペイロード抽出によるバイナリフレームデコード
- **マスキング** — RFC 6455 Section 5.3準拠のXORマスク/アンマスク
- **ハンドシェイク** — `Sec-WebSocket-Key`検証付きクライアント/サーバーHTTP Upgradeハンドシェイク
- **Ping/Pong** — キープアライブフレームの生成と応答
- **Closeフレーム** — ステータスコードと理由フレーズによるグレースフルクローズ
- **フラグメンテーション** — マルチフレームメッセージの組み立て（継続フレーム）
- **テキスト & バイナリ** — テキスト（UTF-8検証済み）とバイナリの両メッセージタイプ
- **拡張機能** — 拡張ネゴシエーション用の予約ビット対応
- **上限付き解析** — `Frame::parse_limited` はヘッダーの長さだけで上限超過のペイロードを拒否
- **クライアント** — 任意のブロッキング `Read + Write` 上の `client::Connection`: フレームごとに新しいキーでマスク、マスク付きサーバーフレームの拒否、ping 応答、フラグメント組み立て、close コードの通知、上限付き読み込みバッファ
- **マスク源** — `MaskSource` トレイト、`OsMask` (feature `rng`) は OS の乱数源から読む
- **wss** — `client::connect_tls` (feature `tls`、rustls 0.23 + ring)、Mozilla のルートまたは呼び出し側のルート

## アーキテクチャ

```
バイトストリーム
  │
  ├── WsError      — エラー型（Incomplete, InvalidOpcode 等）
  ├── Opcode       — フレームオペコード（Text, Binary, Close, Ping, Pong）
  ├── Frame        — ワイヤレベルのフレーム解析・構築
  ├── Handshake    — HTTP Upgradeリクエスト/レスポンス生成
  ├── Masking      — XORマスク適用
  ├── Defragmenter — 継続フレーム組み立て
  └── Message      — 高レベルテキスト/バイナリメッセージAPI
```

## Cargo feature

| feature | 追加されるもの | 依存 |
|---|---|---|
| (なし) | プロトコル部品、`client::Connection` | なし |
| `rng` | `OsMask` | alice-crypto (OS の乱数源) |
| `tls` | `client::connect_tls`、`TlsConfig`、`TlsStream` | rustls 0.23 (ring)、webpki-roots |

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

## 使用例

```rust
use alice_websocket::Opcode;

let op = Opcode::from_u8(0x1).unwrap();
assert_eq!(op, Opcode::Text);
```

## ライセンス

`LicenseRef-Proprietary` 条文は [LICENSE-Proprietary](LICENSE-Proprietary)

Enquiries: https://extoria.co.jp/
