#!/usr/bin/env node

const { run } = require('../src/checker');
const { init, uninstall } = require('../src/setup');
const { loadConfig, addToAllowlist, removeFromAllowlist, listAllowlist } = require('../src/config');
const { readLogs } = require('../src/logger');
const { checkUpdate, runUpdate } = require('../src/updater');

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
  mcp-yoshi allow <server> --reason "理由"          allowlistにサーバーを追加
  mcp-yoshi allow --list                            allowlist一覧を表示
  mcp-yoshi allow --remove <server>                 allowlistからサーバーを削除
  mcp-yoshi update [--check]                         アップデート確認・実行
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
  case 'allow': {
    if (hasFlag('--list')) {
      const config = loadConfig();
      const list = listAllowlist(config);
      if (list.length === 0) {
        console.log('allowlistは空です');
      } else {
        for (const entry of list) {
          console.log(`  ${entry.server} — ${entry.reason || '(理由なし)'} (${entry.addedAt || ''})`);
        }
      }
    } else if (hasFlag('--remove')) {
      const server = parseFlag('--remove');
      if (!server) {
        console.error('Error: --remove <server> を指定してください');
        process.exit(1);
      }
      const removed = removeFromAllowlist(server);
      if (removed) {
        console.log(`${server} をallowlistから削除しました`);
      } else {
        console.log(`${server} はallowlistに存在しません`);
      }
    } else {
      const server = args[1];
      if (!server) {
        console.error('Error: mcp-yoshi allow <server> --reason "理由" を指定してください');
        process.exit(1);
      }
      const reason = parseFlag('--reason') || '';
      const entry = addToAllowlist(server, reason);
      console.log(`${server} をallowlistに追加しました（理由: ${entry.reason || 'なし'}）`);
    }
    break;
  }
  case 'update': {
    const checkOnly = hasFlag('--check');
    checkUpdate().then((result) => {
      if (result.status === 'not-published') {
        console.log(`現在のバージョン: v${result.current}`);
        console.log('npm に未公開のため、アップデート確認ができません');
        console.log('GitHub からの手動更新: git pull origin master');
      } else if (result.status === 'up-to-date') {
        console.log(`✅ 最新です (v${result.current})`);
      } else if (result.status === 'update-available') {
        console.log(`🆕 アップデートがあります: v${result.current} → v${result.latest}`);
        if (checkOnly) {
          console.log('実行するには: mcp-yoshi update');
        } else {
          console.log('アップデートを実行します...');
          try {
            runUpdate();
            console.log(`✅ v${result.latest} にアップデートしました`);
          } catch (e) {
            console.error('アップデートに失敗しました。手動で実行してください:');
            console.error('  npm install -g mcp-yoshi@latest');
            process.exit(1);
          }
        }
      } else if (result.status === 'ahead') {
        console.log(`現在のバージョン (v${result.current}) はnpm公開版 (v${result.latest}) より新しいです`);
      }
    }).catch((err) => {
      console.error(`アップデート確認に失敗しました: ${err.message}`);
      process.exit(1);
    });
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
