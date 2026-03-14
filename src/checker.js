// メインチェックロジック: stdin からhookデータを受け取り、判定結果を出力

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { loadConfig, getServerConfig, parseServerName, getAllowlistEntry } = require('./config');
const { runOutboundChecks, CHECKS: OUTBOUND_CHECKS } = require('./checks/outbound');
const { runInboundChecks, CHECKS: INBOUND_CHECKS } = require('./checks/inbound');
const { log } = require('./logger');

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

function flattenToString(obj) {
  try {
    const str = typeof obj === 'string' ? obj : JSON.stringify(obj) || '';
    return str.length > MAX_TEXT_LENGTH ? str.slice(0, MAX_TEXT_LENGTH) : str;
  } catch {
    return String(obj);
  }
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
    toolDefinitionHashes.set(toolName, hash); // 新しいハッシュに更新
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
  const findings = runOutboundChecks(text, serverConfig.checks.outbound);

  // P5: Rug Pull検出（outbound時にツール定義をチェック）
  const rugPullFinding = checkRugPull(hookData);
  if (rugPullFinding) {
    findings.push(rugPullFinding);
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

  const result =
    direction === 'outbound'
      ? checkOutbound(hookData, config)
      : checkInbound(hookData, config);

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

  const output = formatOutput(result, direction);

  if (!output) {
    process.exit(0);
    return;
  }

  if (output.json) {
    process.stdout.write(JSON.stringify(output.json));
  }
  if (output.stderr) {
    process.stderr.write(output.stderr);
  }

  process.exit(output.exitCode);
}

module.exports = { run, checkOutbound, checkInbound, determineSeverity, flattenToString, checkRugPull, toolDefinitionHashes, loadHashes, saveHashes, resetHashState, HASH_FILE_PATH };
