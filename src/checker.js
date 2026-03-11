// メインチェックロジック: stdin からhookデータを受け取り、判定結果を出力

const { loadConfig, getServerConfig, parseServerName } = require('./config');
const { runOutboundChecks } = require('./checks/outbound');
const { runInboundChecks } = require('./checks/inbound');
const { log } = require('./logger');

function determineSeverity(config, findings) {
  const blockChecks = new Set(config.severity.BLOCK || []);
  const warnChecks = new Set(config.severity.WARN || []);

  let maxSeverity = 'PASS';

  for (const finding of findings) {
    // finding.id から checkName を逆引き
    const checkName = findCheckName(finding.id);
    if (blockChecks.has(checkName)) {
      return 'BLOCK'; // 即座にBLOCK
    }
    if (warnChecks.has(checkName)) {
      maxSeverity = 'WARN';
    }
  }

  // severity に明示されていない finding がある場合は WARN 扱い
  if (maxSeverity === 'PASS' && findings.length > 0) {
    maxSeverity = 'WARN';
  }

  return maxSeverity;
}

const CHECK_ID_MAP = {
  'OUT-001': 'apiKeys',
  'OUT-002': 'privateKeys',
  'OUT-003': 'highEntropy',
  'OUT-004': 'envValues',
  'OUT-005': 'pii',
  'IN-001': 'promptInjection',
  'IN-002': 'shellCommands',
  'IN-003': 'suspiciousUrls',
  'IN-004': 'scriptInjection',
  'IN-005': 'toolTampering',
};

function findCheckName(id) {
  return CHECK_ID_MAP[id] || 'unknown';
}

function flattenToString(obj) {
  if (typeof obj === 'string') return obj;
  if (obj === null || obj === undefined) return '';
  if (Array.isArray(obj)) return obj.map(flattenToString).join(' ');
  if (typeof obj === 'object') return Object.values(obj).map(flattenToString).join(' ');
  return String(obj);
}

function checkOutbound(hookData, config) {
  const toolName = hookData.tool_name || '';
  const serverName = parseServerName(toolName);

  if (!serverName) return { severity: 'PASS', findings: [] };

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
