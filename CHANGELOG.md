# Changelog

## v1.4.0 (2026-04-17) — Supply Chain Defense

CVE-2026-40933 (Flowise Authenticated RCE Via MCP Adapters) と同型攻撃クラスへの防御強化、および Flowise 59件アドバイザリ（2026-04-16一斉公開、Anthropic researcher igor-magun-wd 起点の "Anthropic MCP Supply Chain Vulnerability" series）由来の防御パターン群を追加。

### IN-002 拡張: Node.js エコシステム + NODE_OPTIONS

既存 Shell Command Embedding チェックに以下パターンを追加:
- `npx -c <cmd>`, `npx --call <cmd>` — CVE-2026-40933 同型
- `npm exec -- <pkg>`, `npm exec -c <cmd>` — npm v7+ セパレータ形式対応
- `pnpm exec -c`, `pnpm dlx -c`, `yarn dlx -c`, `bun x -c`, `bun -e`, `bun exec -c`
- `deno eval`, `deno repl`, `deno -e`, `deno -p`
- `NODE_OPTIONS` 経由の `--experimental-loader` / `--import` / `--require` / `--inspect-brk`
- `--experimental-loader=data:text/javascript,...` (= 区切り版、GHSA-cvrr-qhgw-2mm6 主要 PoC 形式)

### 新規 6 ルール追加

- `IN-015` Parameter Override / OverrideConfig (BLOCK): `overrideConfig` キー + 値内に `mcpServerConfig`/`NODE_OPTIONS`/`executablePath` を含む組み合わせ攻撃 (GHSA-cvrr-qhgw-2mm6, GHSA-5cph-wvm9-45gj)
- `IN-017` Path Traversal (BLOCK): `../`/`..\\` ディレクトリ移動 + `basePath`/`filePath`/`filename`/`filepath` への機密パス指定 (`/etc/`, `/root/`, `C:\Windows\`, `/proc/`) (GHSA-w6v6-49gh-mc9w 他5件)
- `IN-018` Query Injection — **BLOCK + WARN 分離設計**:
  - BLOCK: `MATCH ... DETACH DELETE`, `DROP TABLE`, `UNION SELECT`, `;--`
  - WARN: `' OR/AND '...'`, `sleep(...)` (time-based) — 偽陽性リスク考慮
  - (GHSA-28g4-38q8-3cwc Cypher, GHSA-9c4c-g95m-c8cp SQL)
- `IN-019` Sandbox Escape (BLOCK): `globalThis.process.mainModule.require`, `process.binding()`, `constructor.constructor()` (vm2 escape), `__proto__.constructor` (GHSA-435c-mg9p-fv22, GHSA-xhmj-rg95-44hv)
- `IN-020` Header Spoofing (WARN): `x-request-from: internal`, `x-forwarded-for: 127.0.0.1`, `x-real-ip: localhost` (GHSA-wvhq-wp8g-c7vq)
- `IN-021` Browser Launch RCE (BLOCK): Puppeteer/Playwright `executablePath` にシェルバイナリ (`/bin/sh`, `/bin/bash`, `/usr/bin/nc` 等) または `ignoreDefaultArgs: true` + 危険 args (GHSA-5w3r-f6gm-c25w)

### CHECK メタデータ拡張（v1.4 新仕様）

各 CHECK に以下フィールドを追加:
- `severity`: 'BLOCK' | 'WARN' (コード側メタ、config.default.json と併存)
- `references`: ['GHSA-XXXX-XXXX-XXXX', ...] (出典 GHSA 配列)

### テストフィクスチャ新設

`test/fixtures/ghsa-payloads/` ディレクトリを新設、8件の GHSA PoC を JSON 形式で配置。トレーサビリティ向上。

### テスト

184件全 PASS（既存テストの劣化ゼロ）。新規テスト 152件追加。

### 検出統計（v1.3.1 → v1.4.0）

- Inbound: 14 → 21 チェック (+7、IN-018 split含む)
- IN-002 検出パターン: +9 種
- Flowise 59件アドバイザリのうち 約40件 (68%) を mcp-yoshi で防御範囲化

### v1.5 Backlog (本リリースから DROP)

- IN-016 Mass Assignment / IDOR — `runInboundChecks` インターフェース拡張と併せて再検討
- IN-022 Function constructor — 既存 IN-004 (`Function(`) で既にカバー済（重複回避）

### 出典

- CVE-2026-40933 / GHSA-c9gw-hvqq-f33r — https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-c9gw-hvqq-f33r
- Flowise 59件 Security Advisories (2026-04-16) — https://github.com/FlowiseAI/Flowise/security/advisories
- 起点 X 投稿 (Moshe Siman Tov Bustan / MosesOX) — https://x.com/moshetov/status/2044835423730741680

## v1.3.1 (2026-03-22)

- **package.json files配列修正**: `commands/`, `hooks/`, `README.ja.md` をnpm publishパッケージに追加
- **README.ja.md新規作成**: README.mdの完全日本語版を追加
- **CI強化**: Node.js構文チェック（`node --check`）をGitHub Actions CIに追加
- **統合テスト追加**: `test/integration.js`（hook JSON入出力の結合テスト）をリポジトリに追加

## v1.3.0 (2026-03-18)

- **4つのセキュリティチェック追加** — MCP通信防御強化（20 → 24チェック）
  - `IN-011` Sampling Injection (BLOCK): LLMトークナイザマーカー（`[INST]`, `<<SYS>>`, `<|im_start|>` 等）の埋め込み検出
  - `IN-012` Log-To-Leak (WARN): ツールレスポンス内のデータ窃取指示（「send this data to...」「call the logging tool」等）
  - `IN-013` Conversation Marker (WARN): 会話マーカー（`Human:`, `Assistant:`）の行頭埋め込み
  - `SHADOW-001` Tool Shadowing (BLOCK): 異なるサーバーからの同名ツール登録を検知
- **設定バグ修正**: v1.2.0で追加したIN-008/009/010, OUT-006/007が `config.default.json` に未登録で実質無効だった問題を修正
- **IN-008レスポンスサイズ上限変更**: 200KB → 512KB（MCP Discussion #2211コミュニティ推奨値）

## v1.2.0 (2026-03-16)

- **6 new checks** — MCP通信路特化の検出強化（12 → 18チェック）
  - `OUT-006` Large Payload: リクエストペイロードサイズ制限（50KB超でWARN）
  - `OUT-007` Path Traversal: センシティブパス（/etc/, ~/.ssh/, C:\Windows\等）へのアクセスをBLOCK
  - `IN-008` Response Size Limit: 異常に大きなレスポンス検出（200KB超でWARN、コンテキスト毒盛対策）
  - `IN-009` Hidden Fields: MCPレスポンス内の未宣言フィールド（_hidden, $meta等）検出
  - `IN-010` Elicitation Abuse: 認証情報要求・コマンド実行誘導をBLOCK
  - `RATE-001` Rapid Fire Detection: 同一ツールの短時間連続呼び出し（60秒10回超でWARN）

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
