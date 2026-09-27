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

## 使用例

```rust
use alice_websocket::Opcode;

let op = Opcode::from_u8(0x1).unwrap();
assert_eq!(op, Opcode::Text);
```

## ライセンス

`AGPL-3.0-or-later OR LicenseRef-Commercial` — デュアルライセンス どちらかを選べる

| 選択肢 | 条文 | こういう時 |
|--------|------|-----------|
| **AGPL-3.0-or-later** | [LICENSE-AGPL](LICENSE-AGPL) — 無償、報告義務なし | 自分の project も AGPL 互換の OSS、または社内利用のみ |
| **商用ライセンス** | [LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md) — 有償、コピーレフト義務を解除 | クローズドソース製品 / 商用 SaaS / エッジ・ファームウェア配布 / plugin 再配布 / ソース開示を禁じるプラットフォーム NDA |

AGPL は強いコピーレフト: `alice-websocket` を link して配布 / 提供する製品・ファームウェア・
サービスは AGPL で公開する義務がある これはオープンなエコシステムのための意図的な
選択で、それが実行できない場合のために商用ライセンスを用意している

商用ライセンスの問い合わせ: <contact@extoria.co.jp>
