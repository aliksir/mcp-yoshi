#!/usr/bin/env node

const { run } = require('../src/checker');
const { init, uninstall } = require('../src/setup');
const { loadConfig } = require('../src/config');
const { readLogs } = require('../src/logger');

const args = process.argv.slice(2);
const command = args[0];

function parseFlag(flag) {
  const idx = args.indexOf(flag);
  if (idx === -1 || idx + 1 >= args.length) return null;
  return args[idx + 1];
}

function hasFlag(flag) {
  return args.includes(flag);
}

function showHelp() {
  console.log(`mcp-yoshi — MCPの通信、ちゃんと見てヨシッ！

Usage:
  mcp-yoshi check --direction <outbound|inbound>   hookから呼ばれるチェック実行
  mcp-yoshi init [--global|--project]               settings.jsonにhook設定を追加
  mcp-yoshi uninstall [--global|--project]           hook設定を削除
  mcp-yoshi config                                   現在の設定を表示
  mcp-yoshi logs [--tail N] [--level warn|block]     ログを表示
  mcp-yoshi --version                                バージョン表示
  mcp-yoshi --help                                   このヘルプ
`);
}

function showVersion() {
  const pkg = require('../package.json');
  console.log(`mcp-yoshi v${pkg.version}`);
}

function showConfig() {
  const config = loadConfig();
  console.log(JSON.stringify(config, null, 2));
}

function showLogs() {
  const config = loadConfig();
  const tail = parseInt(parseFlag('--tail') || '20', 10);
  const level = parseFlag('--level');
  const entries = readLogs(config, { tail, level });

  if (entries.length === 0) {
    console.log('ログがありません');
    return;
  }

  for (const entry of entries.reverse()) {
    const icon = entry.severity === 'BLOCK' ? '🚫' : entry.severity === 'WARN' ? '⚠️' : '✅';
    const skip = entry.skipped ? ' [SKIP]' : '';
    const findingStr = entry.findings.length > 0
      ? ` — ${entry.findings.map((f) => `[${f.id}] ${f.name}`).join(', ')}`
      : '';
    console.log(`${entry.timestamp} ${icon} ${entry.severity}${skip} ${entry.direction} ${entry.tool}${findingStr}`);
  }
}

// メイン
switch (command) {
  case 'check': {
    const direction = parseFlag('--direction');
    if (!direction || !['outbound', 'inbound'].includes(direction)) {
      console.error('Error: --direction outbound|inbound を指定してください');
      process.exit(1);
    }
    run(direction);
    break;
  }
  case 'init': {
    const scope = hasFlag('--project') ? 'project' : 'global';
    init(scope);
    break;
  }
  case 'uninstall': {
    const scope = hasFlag('--project') ? 'project' : 'global';
    uninstall(scope);
    break;
  }
  case 'config':
    showConfig();
    break;
  case 'logs':
    showLogs();
    break;
  case '--version':
  case '-v':
    showVersion();
    break;
  case '--help':
  case '-h':
  case undefined:
    showHelp();
    break;
  default:
    console.error(`Unknown command: ${command}`);
    showHelp();
    process.exit(1);
}
