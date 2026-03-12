// メインチェックロジック: stdin からhookデータを受け取り、判定結果を出力

const { loadConfig, getServerConfig, parseServerName, getAllowlistEntry } = require('./config');
const { runOutboundChecks, CHECKS: OUTBOUND_CHECKS } = require('./checks/outbound');
const { runInboundChecks, CHECKS: INBOUND_CHECKS } = require('./checks/inbound');
const { log } = require('./logger');

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

module.exports = { run, checkOutbound, checkInbound, determineSeverity, flattenToString };
