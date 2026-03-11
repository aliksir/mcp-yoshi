// ログ記録: フィルター結果をファイルに記録（マスキング付き）

const fs = require('fs');
const path = require('path');
const { resolveLogDir } = require('./config');

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

function getLogFilePath(logDir) {
  const date = new Date().toISOString().slice(0, 10);
  return path.join(logDir, `mcp-yoshi-${date}.log`);
}

function log(config, entry) {
  if (config.logLevel === 'none') return;
  if (config.logLevel === 'warn' && entry.severity === 'PASS') return;

  const logDir = resolveLogDir(config);
  ensureDir(logDir);

  const logFile = getLogFilePath(logDir);
  const line = JSON.stringify(entry) + '\n';

  try {
    fs.appendFileSync(logFile, line, 'utf8');
  } catch {
    // ログ書き込み失敗は無視（フィルター自体を止めない）
  }
}

function readLogs(config, options = {}) {
  const logDir = resolveLogDir(config);
  const { tail = 50, level } = options;

  if (!fs.existsSync(logDir)) return [];

  const files = fs.readdirSync(logDir)
    .filter((f) => f.startsWith('mcp-yoshi-') && f.endsWith('.log'))
    .sort()
    .reverse();

  const entries = [];

  for (const file of files) {
    const lines = fs.readFileSync(path.join(logDir, file), 'utf8')
      .split('\n')
      .filter(Boolean);

    for (const line of lines.reverse()) {
      try {
        const entry = JSON.parse(line);
        if (level && entry.severity !== level.toUpperCase()) continue;
        entries.push(entry);
        if (entries.length >= tail) return entries;
      } catch {
        // 壊れた行はスキップ
      }
    }

    if (entries.length >= tail) break;
  }

  return entries;
}

module.exports = { log, readLogs };
