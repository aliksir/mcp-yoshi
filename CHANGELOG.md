# Changelog

## v1.1.0 (2026-03-13)

- **Rug Pullハッシュ永続化**: ツール定義SHA-256ハッシュを `~/.mcp-yoshi/tool-hashes.json` に保存。セッション跨ぎでの定義改竄検出が可能に
- **`mcp-yoshi stats` コマンド**: ログから検出統計を集計・表示（severity別、チェックID別、サーバー別、期間指定対応）
- **npm公開**: `npm install -g mcp-yoshi` でインストール可能に
- README更新: stats使い方、Rug Pull永続化の説明追加

## v1.0.0 (2026-03-12)

- 初回リリース
- アウトバウンドチェック5種（OUT-001〜005）
- インバウンドチェック7種（IN-001〜007）
- Rug Pull検出（RUG-001）
- NFKC正規化による難読化対策
- Allowlist機能
- 偽陽性低減（SHA-256/UUID/ファイルパス除外、コンテキスト依存マッチ）
- アップデート確認機能
