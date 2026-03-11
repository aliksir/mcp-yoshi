# mcp-yoshi

> MCPの通信、ちゃんと見てヨシッ！

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
| OUT-001 | API Key Pattern | AWS, OpenAI, GitHub, Slack, Google, Stripe 等のAPIキー |
| OUT-002 | Private Key | RSA/EC/DSA/OPENSSH秘密鍵 |
| OUT-003 | High Entropy String | 32文字以上の高ランダム文字列 |
| OUT-004 | Env Value Pattern | PASSWORD, SECRET, TOKEN 等の環境変数値 |
| OUT-005 | PII Pattern | メールアドレス、電話番号、クレジットカード番号 |

### インバウンドチェック（MCPサーバー → 受信データ）

| ID | チェック | 検出対象 |
|----|---------|---------|
| IN-001 | Prompt Injection | "ignore previous instructions" 等の指示上書き |
| IN-002 | Shell Command Embedding | `$(...)`, `; rm`, `\| bash` 等のコマンド注入 |
| IN-003 | Suspicious URL | javascript:, 短縮URL, 内部ネットワーク直接アクセス |
| IN-004 | Script Injection | `<script>`, `eval()`, `document.cookie` 等 |
| IN-005 | Tool Definition Tampering | ツール説明文に埋め込まれた隠し指示 |

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

### 設定確認

```bash
mcp-yoshi config
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
    "WARN": ["highEntropy", "pii", "suspiciousUrls"],
    "BLOCK": ["apiKeys", "privateKeys", "promptInjection", "shellCommands", "scriptInjection", "toolTampering", "envValues"]
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
| `severity.WARN` | `["highEntropy", "pii"]` | WARN判定するチェックID |
| `severity.BLOCK` | `["apiKeys", ...]` | BLOCK判定するチェックID |

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

## ライセンス

MIT
