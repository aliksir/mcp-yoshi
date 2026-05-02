// メインチェックロジック: stdin からhookデータを受け取り、判定結果を出力

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { loadConfig, getServerConfig, parseServerName, parseToolBaseName, getAllowlistEntry } = require('./config');
const { runOutboundChecks, CHECKS: OUTBOUND_CHECKS } = require('./checks/outbound');
const { runInboundChecks, CHECKS: INBOUND_CHECKS } = require('./checks/inbound');
const { log } = require('./logger');
const { stashWrite, shouldStash, flattenRaw, flatten } = require('./stash');
const { maskSensitiveText } = require('./masker');

// RATE-001: Rapid Fire Detection — ツール名ごとの呼び出し履歴（セッション内）
const RATE_WINDOW_MS = 60000;
const RATE_LIMIT = 10;
const CALL_HISTORY_MAX_ENTRIES = 1000;
const callHistory = new Map();

// SHADOW-001: Tool Shadowing Detection — ツール名→サーバー名のマッピング（セッション内）
const toolServerMap = new Map();

function checkRateLimit(toolName) {
  if (!toolName) return null;

  const now = Date.now();
  const cutoff = now - RATE_WINDOW_MS;

  // 古いタイムスタンプを除去しつつ、現在のツールのタイムスタンプ一覧を取得
  let timestamps = (callHistory.get(toolName) || []).filter((ts) => ts >= cutoff);
  timestamps.push(now);
  callHistory.set(toolName, timestamps);

  // Map全体の肥大化防止: エントリ数が上限を超えたら最古エントリを削除
  if (callHistory.size > CALL_HISTORY_MAX_ENTRIES) {
    const oldestKey = callHistory.keys().next().value;
    callHistory.delete(oldestKey);
  }

  const count = timestamps.length;
  if (count >= RATE_LIMIT) {
    return {
      id: 'RATE-001',
      name: 'Rapid Fire Detection',
      severity: 'WARN',
      message: `Tool '${toolName}' called ${count} times in ${RATE_WINDOW_MS / 1000}s (limit: ${RATE_LIMIT})`,
    };
  }

  return null;
}

function checkToolShadowing(toolName) {
  const baseName = parseToolBaseName(toolName);
  const serverName = parseServerName(toolName);
  if (!baseName || !serverName) return null;

  const existingServer = toolServerMap.get(baseName);
  if (!existingServer) {
    toolServerMap.set(baseName, serverName);
    return null;
  }

  if (existingServer !== serverName) {
    return {
      id: 'SHADOW-001',
      name: 'Tool Shadowing',
      matched: `Tool '${baseName}' registered by '${existingServer}', now called from '${serverName}'`,
    };
  }

  return null;
}

// P5: Rug Pull検出 — ツール定義ハッシュ（ディスク永続化対応）
const HASH_FILE_PATH = path.join(os.homedir(), '.mcp-yoshi', 'tool-hashes.json');
const toolDefinitionHashes = new Map();
let hashesLoaded = false;

function loadHashes() {
  if (hashesLoaded) return;
  hashesLoaded = true;
  try {
    const data = JSON.parse(fs.readFileSync(HASH_FILE_PATH, 'utf8'));
    for (const [key, value] of Object.entries(data)) {
      toolDefinitionHashes.set(key, value);
    }
  } catch {
    // ファイルなし or 破損 → 空Mapで開始（フェイルセーフ）
  }
}

function saveHashes() {
  try {
    const dir = path.dirname(HASH_FILE_PATH);
    fs.mkdirSync(dir, { recursive: true });
    const obj = Object.fromEntries(toolDefinitionHashes);
    fs.writeFileSync(HASH_FILE_PATH, JSON.stringify(obj, null, 2), 'utf8');
  } catch {
    // 書き込み失敗は無視（フィルター動作を止めない）
  }
}

function resetHashState() {
  toolDefinitionHashes.clear();
  hashesLoaded = false;
  toolServerMap.clear();
}

// CHECK_ID_MAP を CHECKS 定義から自動構築（二重管理の排除）
const CHECK_ID_MAP = {};
for (const [name, def] of Object.entries({ ...OUTBOUND_CHECKS, ...INBOUND_CHECKS })) {
  CHECK_ID_MAP[def.id] = name;
}

function determineSeverity(config, findings) {
  if (findings.length === 0) return 'PASS';

  const blockChecks = new Set(config.severity.BLOCK || []);
  const warnChecks = new Set(config.severity.WARN || []);

  let maxSeverity = 'PASS';

  for (const finding of findings) {
    const checkName = CHECK_ID_MAP[finding.id] || 'unknown';
    if (blockChecks.has(checkName)) {
      return 'BLOCK';
    }
    if (warnChecks.has(checkName)) {
      maxSeverity = 'WARN';
    }
  }

  // severity に明示されていない finding がある場合は WARN 扱い
  if (maxSeverity === 'PASS') {
    maxSeverity = 'WARN';
  }

  return maxSeverity;
}

const MAX_TEXT_LENGTH = 100000; // 100KB上限

// M2: stash.flatten を利用（near-duplicate 統合、既存 export は維持）
function flattenToString(obj) {
  return flatten(obj, { maxLength: MAX_TEXT_LENGTH });
}

// P5: Rug Pull検出 — ツール定義のSHA-256ハッシュを比較（ディスク永続化）
function checkRugPull(hookData) {
  const toolName = hookData.tool_name || '';
  const toolDef = hookData.tool_description || hookData.tool_input_schema;
  if (!toolName || !toolDef) return null;

  loadHashes(); // 初回のみディスクからロード

  const defStr = typeof toolDef === 'string' ? toolDef : JSON.stringify(toolDef);
  const hash = crypto.createHash('sha256').update(defStr).digest('hex');

  if (!toolDefinitionHashes.has(toolName)) {
    // 初回: ハッシュを記録して永続化
    toolDefinitionHashes.set(toolName, hash);
    saveHashes();
    return null;
  }

  const previousHash = toolDefinitionHashes.get(toolName);
  if (hash !== previousHash) {
    // ツール定義が変更された → Rug Pull疑い
    // NOTE: 検出後は新しいハッシュをそのまま更新して保存する。
    // これにより同じ変更内容での2回目以降の呼び出しではRUG-001は発火しない（1回警告のみ）。
    // 意図的な設計: 毎回アラートを出すと攻撃者にハッシュ更新のタイミングを悪用される可能性があるため、
    // 変更発生時に1回警告してハッシュを新しい値に更新する。継続的な監視はログで行うこと。
    toolDefinitionHashes.set(toolName, hash); // 新しいハッシュに更新（以降は新定義として扱う）
    saveHashes();
    return {
      id: 'RUG-001',
      name: 'Tool Definition Changed (Rug Pull)',
      matched: `${toolName}: hash changed ${previousHash.slice(0, 8)}→${hash.slice(0, 8)}`,
    };
  }

  return null;
}

function checkOutbound(hookData, config) {
  const toolName = hookData.tool_name || '';
  const serverName = parseServerName(toolName);

  if (!serverName) return { severity: 'PASS', findings: [] };

  // allowlistチェック: チェックをスキップするがログは記録する
  const allowEntry = getAllowlistEntry(config, serverName);
  if (allowEntry) {
    return { severity: 'SKIPPED', findings: [], skipped: true, server: serverName, reason: allowEntry.reason };
  }

  const serverConfig = getServerConfig(config, serverName);
  if (!serverConfig.enabled) return { severity: 'PASS', findings: [], skipped: true, server: serverName };

  const text = flattenToString(hookData.tool_input);
  const findings = runOutboundChecks(text, serverConfig.checks.outbound, hookData.tool_input);

  // P5: Rug Pull検出（outbound時にツール定義をチェック）
  const rugPullFinding = checkRugPull(hookData);
  if (rugPullFinding) {
    findings.push(rugPullFinding);
  }

  // SHADOW-001: Tool Shadowing検出
  const shadowFinding = checkToolShadowing(toolName);
  if (shadowFinding) {
    findings.push(shadowFinding);
  }

  const severity = determineSeverity(config, findings);

  return { severity, findings, server: serverName, direction: 'outbound' };
}

function checkInbound(hookData, config) {
  const toolName = hookData.tool_name || '';
  const serverName = parseServerName(toolName);

  if (!serverName) return { severity: 'PASS', findings: [] };

  // allowlistチェック: チェックをスキップするがログは記録する
  const allowEntry = getAllowlistEntry(config, serverName);
  if (allowEntry) {
    return { severity: 'SKIPPED', findings: [], skipped: true, server: serverName, reason: allowEntry.reason };
  }

  const serverConfig = getServerConfig(config, serverName);
  if (!serverConfig.enabled) return { severity: 'PASS', findings: [], skipped: true, server: serverName };

  const text = flattenToString(hookData.tool_response);
  const findings = runInboundChecks(text, serverConfig.checks.inbound);
  const severity = determineSeverity(config, findings);

  return { severity, findings, server: serverName, direction: 'inbound' };
}

function formatOutput(result, direction) {
  if (result.severity === 'PASS') return null;

  const summary = result.findings
    .map((f) => `[${f.id}] ${f.name}: ${f.matched || JSON.stringify(f.detail)}`)
    .join('; ');

  if (result.severity === 'BLOCK' && direction === 'outbound') {
    // PreToolUse: permissionDecision: deny でブロック
    return {
      json: {
        hookSpecificOutput: {
          hookEventName: 'PreToolUse',
          permissionDecision: 'deny',
          permissionDecisionReason: `[mcp-yoshi] BLOCKED: ${summary}`,
        },
      },
      exitCode: 0,
    };
  }

  if (result.severity === 'BLOCK' && direction === 'inbound') {
    // PostToolUse: exit 2 + stderr でブロック
    return {
      stderr: `[mcp-yoshi] BLOCKED: ${summary}`,
      exitCode: 2,
    };
  }

  // WARN: additionalContext で警告
  return {
    json: {
      hookSpecificOutput: {
        hookEventName: direction === 'outbound' ? 'PreToolUse' : 'PostToolUse',
        additionalContext: `[mcp-yoshi] WARNING: ${summary}`,
      },
    },
    exitCode: 0,
  };
}

async function run(direction) {
  const config = loadConfig();
  const chunks = [];

  for await (const chunk of process.stdin) {
    chunks.push(chunk);
  }

  const input = Buffer.concat(chunks).toString('utf8');
  let hookData;
  try {
    hookData = JSON.parse(input);
  } catch {
    process.stderr.write('[mcp-yoshi] Failed to parse hook input\n');
    process.exit(1);
  }

  // RATE-001: レートチェック（outbound/inbound チェックより先に実行）
  const rateFinding = checkRateLimit(hookData.tool_name);

  const result =
    direction === 'outbound'
      ? checkOutbound(hookData, config)
      : checkInbound(hookData, config);

  // レート超過 finding を結果に追加（WARN のみなので severity は上書きしない）
  if (rateFinding) {
    result.findings = result.findings || [];
    result.findings.push(rateFinding);
    // findings が追加されたので severity を再評価（PASS → WARN へ昇格し得る）
    if (result.severity === 'PASS') {
      result.severity = 'WARN';
    }
  }

  // ログ記録
  log(config, {
    timestamp: new Date().toISOString(),
    direction,
    tool: hookData.tool_name,
    server: result.server,
    severity: result.severity,
    skipped: result.skipped || false,
    findings: result.findings,
  });

  // ⚠️ FIX-D1 変更1: const → let（stash 通知発生時に output を null から昇格させるため）
  let output = formatOutput(result, direction);

  // ⚠️ FIX-D1 変更2: if (!output) { process.exit(0); return; } ブロックを削除
  // （stash 判定ブロック後の process.exit で一元管理）

  // ──────────────────────────────────────────────────────────────────
  // ⚠️ FIX-D1 変更3: context-stash 判定ブロック（process.exit の直前）
  // inbound 応答を閾値超過時に退避（AC-1, AC-7, AC-10, AC-11）
  // ──────────────────────────────────────────────────────────────────
  if (direction === 'inbound') {
    const stashConfig = config.stash;
    if (stashConfig && stashConfig.enabled !== false) {
      // BLOCK 応答は stash しない（AC-7: Claude に渡らないため）
      // allowlist 早期リターン（SKIPPED）は stash しない（AC-10）
      const skipStash = (result.severity === 'BLOCK') || (result.skipped === true);
      if (!skipStash && shouldStash(hookData.tool_response, stashConfig)) {
        // flattenToString 経由しない（FIX-001: 100KB 切り詰めを避ける）
        const rawText = flattenRaw(hookData.tool_response);
        // findings の matched をマスク（不変条件 I4 厳守）
        const maskedText = maskSensitiveText(rawText, result.findings || []);
        let stashNotice = '';
        try {
          const sr = stashWrite(maskedText, {
            server: result.server || parseServerName(hookData.tool_name),
            tool: hookData.tool_name,
            timestamp: Date.now(),
          }, stashConfig);
          const summary = maskedText.slice(0, 200).replace(/\n/g, ' ');
          stashNotice = `[mcp-yoshi] stashed: key=${sr.key} size=${sr.size}B\n  summary: ${summary}...\n  restore: mcp-yoshi stash get ${sr.key}`;
        } catch (err) {
          // フェイルセーフ: 書込失敗でも既存 severity は維持（AC-8）
          stashNotice = `[mcp-yoshi] stash failed: ${String(err.message || err).slice(0, 100)}`;
        }
        // additionalContext に stash 通知を追記
        if (stashNotice) {
          if (!output) {
            // PASS（output=null）の場合: output を新規昇格
            output = {
              json: { hookSpecificOutput: { hookEventName: 'PostToolUse', additionalContext: stashNotice } },
              exitCode: 0,
            };
          } else if (output.json && output.json.hookSpecificOutput) {
            // WARN の場合: 既存 additionalContext に追記
            const existing = output.json.hookSpecificOutput.additionalContext || '';
            output.json.hookSpecificOutput.additionalContext = existing
              ? `${existing}\n${stashNotice}`
              : stashNotice;
          }
        }
      }
    }
  }
  // ──────────────────────────────────────────────────────────────────

  // 出力 + 終了（stash 判定ブロック後に一元化）
  // output が null（PASS かつ stash なし）→ exit(0)
  // output が stash 通知で昇格 → exitCode: 0 で additionalContext 出力
  if (output && output.json) {
    process.stdout.write(JSON.stringify(output.json));
  }
  if (output && output.stderr) {
    process.stderr.write(output.stderr);
  }

  process.exit(output ? output.exitCode : 0);
}

module.exports = { run, checkOutbound, checkInbound, determineSeverity, flattenToString, checkRugPull, toolDefinitionHashes, loadHashes, saveHashes, resetHashState, HASH_FILE_PATH, checkRateLimit, callHistory, RATE_WINDOW_MS, RATE_LIMIT, toolServerMap, checkToolShadowing };
