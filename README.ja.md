# mcp-yoshi

> MCPの通信、ちゃんと見てヨシッ！

**[English README](README.md)**

MCP (Model Context Protocol) ツール通信のリアルタイムセキュリティフィルター。
Claude Code の hook として動作し、MCPツールの送受信データを検査して安全性を判定します。

## なぜ必要か

- MCPツールの説明文は97%が不十分、13%が実装と不一致（[研究論文](https://arxiv.org/abs/2602.14878)）
- 既存ツール（mcp-scan, mcp-drift-detector）は静的チェック・事前検査のみ
- **リアルタイムの通信フィルター**が存在しなかった

mcp-yoshi は通信の瞬間にデータを検査し、問題があれば即座にブロックまたは警告します。

## 機能

### アウトバウンドチェック（送信データ → MCPサーバー）

| ID | チェック | 検出対象 |
|----|---------|---------|
| OUT-001 | APIキーパターン | AWS, OpenAI, GitHub, Slack, Google, Stripe 等のAPIキー |
| OUT-002 | 秘密鍵 | RSA/EC/DSA/OPENSSH秘密鍵 |
| OUT-003 | 高エントロピー文字列 | 32文字以上の高ランダム文字列 |
| OUT-004 | 環境変数値パターン | PASSWORD, SECRET, TOKEN 等の環境変数値 |
| OUT-005 | PIIパターン | メールアドレス、電話番号、クレジットカード番号 |
| OUT-006 | 大きなペイロード | リクエストペイロードが50KB超（大量データ送信） |
| OUT-007 | パストラバーサル | /etc/passwd, ~/.ssh/, C:\Windows\ 等のセンシティブパス |

### インバウンドチェック（MCPサーバー → 受信データ）

| ID | チェック | 検出対象 |
|----|---------|---------|
| IN-001 | プロンプトインジェクション | "ignore previous instructions" 等の指示上書き |
| IN-002 | シェルコマンド埋め込み | `$(...)`, `; rm`, `\| bash` 等のコマンド注入 |
| IN-003 | 不審なURL / SSRF | javascript:, 短縮URL, 内部ネットワーク, クラウドメタデータ(169.254.169.254等) |
| IN-004 | スクリプト注入 | `<script>`, `eval()`, `document.cookie` 等 |
| IN-005 | ツール定義改竄 | ツール説明文に埋め込まれた隠し指示（12パターン） |
| IN-006 | ASCII密輸 | 不可視Unicode文字（U+E0000台Tags Block, Zero-Width文字） |
| IN-007 | Base64エンコードペイロード | Base64デコード後に既存パターンで再検出 |
| IN-008 | レスポンスサイズ制限 | レスポンスが512KB超（コンテキストウィンドウ毒盛対策） |
| IN-009 | 隠しフィールド | `_hidden`, `$meta` 等の未宣言フィールド |
| IN-010 | Elicitation悪用 | 認証情報要求・コマンド実行誘導をBLOCK |
| IN-011 | サンプリングインジェクション | LLMトークナイザマーカー（`[INST]`, `<<SYS>>`, `<\|im_start\|>` 等）の埋め込み |
| IN-012 | ログ経由漏洩 | データ窃取指示（「send this data to...」「call the logging tool」等） |
| IN-013 | 会話マーカー | 会話マーカー（`Human:`, `Assistant:`）の行頭埋め込み |

### レート制限（通信パターン）

| ID | チェック | 検出対象 |
|----|---------|---------|
| RATE-001 | 高速連続呼び出し検出 | 同一ツールが60秒以内に10回以上呼び出された場合にWARN |

### Rug Pull検出（ツール定義の改竄検知）

| ID | チェック | 検出対象 |
|----|---------|---------|
| RUG-001 | ツール定義変更 | ツール定義のSHA-256ハッシュ変更を検知 |
| SHADOW-001 | ツールシャドウイング | 異なるサーバーからの同名ツール登録を検知 |

初回呼び出し時にツール定義のハッシュを記録し、以降の呼び出しで変更があればWARNを発生させます。ハッシュは `~/.mcp-yoshi/tool-hashes.json` に永続化されるため、セッションを跨いだ検出が可能です。

### NFKC正規化（難読化対策）

全てのインバウンド/アウトバウンドチェックの前段で[NFKC正規化](https://unicode.org/reports/tr15/)を適用します。全角文字（ｉｇｎｏｒｅ → ignore）やUnicode互換文字による難読化を透過的に検出します。

### 3段階判定

| 判定 | 動作 |
|------|------|
| **PASS** | 問題なし。そのまま実行 |
| **WARN** | 警告をClaudeのコンテキストに追加。実行は継続 |
| **BLOCK** | ツール実行を阻止（送信時）/ 警告表示（受信時） |

## インストール

```bash
npm install -g mcp-yoshi
```

## セットアップ

```bash
# Claude Code の settings.json に hook 設定を自動追加
mcp-yoshi init

# プロジェクト単位で設定する場合
mcp-yoshi init --project
```

これにより、以下の hook が自動設定されます：

- `PreToolUse`: `mcp__.*` にマッチ → アウトバウンドチェック
- `PostToolUse`: `mcp__.*` にマッチ → インバウンドチェック

## 使い方

セットアップ後は自動的に動作します。MCPツールが呼ばれるたびにチェックが実行されます。

### ログ確認

```bash
# 直近20件のログを表示
mcp-yoshi logs

# 直近50件のWARN以上のみ表示
mcp-yoshi logs --tail 50 --level warn

# BLOCK のみ表示
mcp-yoshi logs --level block
```

### 統計レポート

```bash
# 過去7日間の検出統計を表示
mcp-yoshi stats

# 過去30日間
mcp-yoshi stats --days 30
```

### 設定確認

```bash
mcp-yoshi config
```

## Allowlist（信頼済みサーバー）

特定のMCPサーバーを信頼済みとして登録し、チェックをスキップできます。
**ユーザー責任**での運用となりますが、ログ記録は継続されます（severity: SKIPPED）。

```bash
# サーバーを allowlist に追加（理由必須推奨）
mcp-yoshi allow memory --reason "社内ナレッジグラフ、信頼済み"

# allowlist 一覧
mcp-yoshi allow --list

# allowlist から削除
mcp-yoshi allow --remove memory
```

`~/.mcp-yoshi/config.json` で直接設定することもできます：

```json
{
  "allowlist": [
    { "server": "memory", "reason": "社内ナレッジグラフ", "addedAt": "2026-03-12T00:00:00.000Z" }
  ]
}
```

## 設定カスタマイズ

`~/.mcp-yoshi/config.json` を作成して設定を上書きできます。

```json
{
  "logLevel": "warn",
  "checks": {
    "outbound": {
      "highEntropy": false
    }
  },
  "servers": {
    "*": { "enabled": true },
    "memory": { "enabled": true },
    "trusted-server": { "enabled": false }
  },
  "severity": {
    "WARN": ["highEntropy", "pii", "suspiciousUrls", "base64Payload", "largePayload", "responseSizeLimit", "hiddenFields", "rapidFire"],
    "BLOCK": ["apiKeys", "privateKeys", "promptInjection", "shellCommands", "scriptInjection", "toolTampering", "envValues", "asciiSmuggling", "pathTraversal", "elicitationAbuse"]
  }
}
```

### MCPサーバー別の設定

`servers` セクションでMCPサーバーごとにフィルターのON/OFFとチェック項目を制御できます。

```json
{
  "servers": {
    "*": { "enabled": true },
    "trusted-internal": { "enabled": false },
    "external-api": {
      "enabled": true,
      "checks": {
        "outbound": { "pii": false },
        "inbound": { "promptInjection": true }
      }
    }
  }
}
```

| キー | 説明 |
|------|------|
| `"*"` | デフォルト設定（未定義のサーバーに適用） |
| `"<server名>"` | `mcp__<server名>__*` のツールに適用 |

- `enabled: false` → そのサーバーのチェックを完全スキップ
- `checks` → グローバル設定をサーバー単位でオーバーライド

### 設定項目

| 項目 | デフォルト | 説明 |
|------|-----------|------|
| `logDir` | `~/.mcp-yoshi/logs` | ログ出力先 |
| `logLevel` | `info` | `info`: 全記録, `warn`: WARN以上, `none`: 記録なし |
| `checks.outbound.*` | `true` | 各アウトバウンドチェックの有効/無効 |
| `checks.inbound.*` | `true` | 各インバウンドチェックの有効/無効 |
| `servers` | `{"*": {"enabled": true}}` | サーバー別ON/OFF |
| `severity.WARN` | `["highEntropy", "pii", "suspiciousUrls", ...]` | WARN判定するチェックID |
| `severity.BLOCK` | `["apiKeys", "privateKeys", "promptInjection", ...]` | BLOCK判定するチェックID |

## アンインストール

```bash
# hook 設定を削除
mcp-yoshi uninstall

# パッケージ削除
npm uninstall -g mcp-yoshi
```

## 既存ツールとの違い

| ツール | タイミング | 対象 |
|--------|----------|------|
| [mcp-scan](https://github.com/invariantlabs-ai/mcp-scan) | 事前（静的チェック） | ツール定義の安全性 |
| [mcp-drift-detector](https://github.com/AshishKumar-ops/mcp-drift-detector) | 定期（変更検出） | ツール定義の改竄 |
| **mcp-yoshi** | **リアルタイム（通信時）** | **送受信データの安全性** |

## セキュリティ推奨事項

### 外部リポジトリの `.mcp.json` について

外部リポジトリをクローンした際、そのリポジトリの `.mcp.json` に定義されたMCPサーバーは**低信頼**として扱うことを推奨します。悪意ある `.mcp.json` によりツールが自動登録される攻撃が報告されています。

- 外部リポの `.mcp.json` 由来のサーバーは **allowlist に追加しない**
- mcp-yoshi のチェックが有効な状態で利用する
- 不審なツール呼び出しがないかログを確認する

## 注意事項

- **パフォーマンス**: 全てのMCPツール呼び出しでhookが実行されるため、MCP操作に若干の遅延（数十ms程度）が発生します。気になる場合は `logLevel: "warn"` に変更するか、信頼済みサーバーを `enabled: false` に設定してください
- **誤検出（False Positive）**: 高エントロピー文字列やPIIパターンは正規のデータにもマッチすることがあります。頻繁に誤検出する場合は該当チェックを無効にするか、severity設定でWARNに下げてください
- **検出限界**: 正規表現ベースのパターンマッチとNFKC正規化による検出です。高度に難読化された攻撃や未知のパターンは検出できない場合があります。他のセキュリティツール（mcp-scan等）との併用を推奨します
- **Rug Pull検出**: ツール定義ハッシュは `~/.mcp-yoshi/tool-hashes.json` に永続化されます。ファイルが破損した場合は自動的に空の状態から再開します

## ライセンス

MIT
