---
description: Check MCP communication security filter status and configuration
---

# mcp-yoshi — MCP通信セキュリティフィルター

MCPツールのアウトバウンド/インバウンド通信をリアルタイムで検査するセキュリティフィルターです。

## コマンド一覧

### ステータス確認

```bash
mcp-yoshi status
```

現在の動作状態・設定ファイルのパス・有効なルール数を表示します。

### 通信チェック実行

```bash
# アウトバウンド（MCPツール呼び出し前）の検査
mcp-yoshi check --direction outbound

# インバウンド（MCPツール応答後）の検査
mcp-yoshi check --direction inbound
```

### 設定初期化

```bash
mcp-yoshi init
```

デフォルト設定ファイルを `~/.mcp-yoshi/config.json` に生成します。
既存の設定がある場合は上書きされません（`--force` オプションで強制上書き）。

## 設定ファイル

設定ファイルの場所: `~/.mcp-yoshi/config.json`

プロジェクト固有の設定を使いたい場合は、プロジェクトルートに `config.json` を置くと優先されます。

デフォルト設定のテンプレートは `config.default.json` を参照してください。

## フック統合

`hooks/hooks.json` に定義されたフック設定を Claude Code の設定に追加することで、
MCPツール呼び出しのたびに自動的にセキュリティチェックが実行されます。

詳細は [README](../README.md) を参照してください。
