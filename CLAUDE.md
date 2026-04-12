# mcp-yoshi

MCPツール通信のリアルタイムセキュリティフィルター。Claude Code hookとして動作し、MCPツールの送受信データを検査して安全性を判定する。

## 技術スタック
- Node.js 18+
- Claude Code Hooks API（PreToolCall / PostToolCall）
- 依存パッケージなし（Node.js built-insのみ）

## セットアップ
```bash
npm install -g mcp-yoshi
```

## ビルド
該当なし（ビルドステップなし）

## テスト
```bash
node test/run.js
```

## 開発規約
- BLOCKレベルの検出時は処理を必ず中断し、ユーザーに判断を委ねる
- フィルター結果は常にログに記録する（事後確認可能にする）
- ログに機密情報を平文で残さない（マスキング必須）
- チェックパターンはユーザーがカスタマイズ可能な状態を維持する
- エントリポイント: `bin/mcp-yoshi.js`、コアロジック: `src/checker.js`
