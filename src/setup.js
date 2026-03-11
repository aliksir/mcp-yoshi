// init コマンド: settings.json に hook 設定を自動追加

const fs = require('fs');
const path = require('path');
const os = require('os');

const HOOK_CONFIG = {
  PreToolUse: [
    {
      matcher: 'mcp__.*',
      hooks: [
        {
          type: 'command',
          command: 'mcp-yoshi check --direction outbound',
          timeout: 10,
          statusMessage: 'mcp-yoshi: checking outbound...',
        },
      ],
    },
  ],
  PostToolUse: [
    {
      matcher: 'mcp__.*',
      hooks: [
        {
          type: 'command',
          command: 'mcp-yoshi check --direction inbound',
          timeout: 10,
          statusMessage: 'mcp-yoshi: checking inbound...',
        },
      ],
    },
  ],
};

function getSettingsPath(scope) {
  if (scope === 'global') {
    return path.join(os.homedir(), '.claude', 'settings.json');
  }
  // project scope
  return path.join(process.cwd(), '.claude', 'settings.json');
}

function init(scope = 'global') {
  const settingsPath = getSettingsPath(scope);
  const settingsDir = path.dirname(settingsPath);

  // ディレクトリ確認
  if (!fs.existsSync(settingsDir)) {
    fs.mkdirSync(settingsDir, { recursive: true });
  }

  // 既存 settings.json 読み込み
  let settings = {};
  if (fs.existsSync(settingsPath)) {
    try {
      settings = JSON.parse(fs.readFileSync(settingsPath, 'utf8'));
    } catch {
      console.error(`Error: ${settingsPath} の読み込みに失敗しました`);
      process.exit(1);
    }
  }

  // hooks セクションがなければ作成
  if (!settings.hooks) {
    settings.hooks = {};
  }

  // 既存のmcp-yoshi hookがあるか確認
  let alreadyExists = false;
  for (const eventName of ['PreToolUse', 'PostToolUse']) {
    const existing = settings.hooks[eventName] || [];
    for (const entry of existing) {
      if (entry.hooks && entry.hooks.some((h) => h.command && h.command.includes('mcp-yoshi'))) {
        alreadyExists = true;
        break;
      }
    }
  }

  if (alreadyExists) {
    console.log('mcp-yoshi hooks は既に設定済みです');
    console.log(`設定ファイル: ${settingsPath}`);
    return;
  }

  // hook 追加
  for (const [eventName, hookEntries] of Object.entries(HOOK_CONFIG)) {
    if (!settings.hooks[eventName]) {
      settings.hooks[eventName] = [];
    }
    settings.hooks[eventName].push(...hookEntries);
  }

  // 書き込み
  fs.writeFileSync(settingsPath, JSON.stringify(settings, null, 2) + '\n', 'utf8');

  console.log('mcp-yoshi hooks を設定しました');
  console.log(`設定ファイル: ${settingsPath}`);
  console.log('');
  console.log('追加された hooks:');
  console.log('  PreToolUse:  mcp__.*  → outbound チェック');
  console.log('  PostToolUse: mcp__.*  → inbound チェック');

  // config ディレクトリ作成
  const configDir = path.join(os.homedir(), '.mcp-yoshi');
  if (!fs.existsSync(configDir)) {
    fs.mkdirSync(configDir, { recursive: true });
    console.log('');
    console.log(`設定ディレクトリを作成しました: ${configDir}`);
    console.log('カスタム設定: config.json をこのディレクトリに配置してください');
  }
}

function uninstall(scope = 'global') {
  const settingsPath = getSettingsPath(scope);

  if (!fs.existsSync(settingsPath)) {
    console.log('settings.json が見つかりません');
    return;
  }

  let settings;
  try {
    settings = JSON.parse(fs.readFileSync(settingsPath, 'utf8'));
  } catch {
    console.error(`Error: ${settingsPath} の読み込みに失敗しました`);
    process.exit(1);
  }

  if (!settings.hooks) {
    console.log('hooks 設定がありません');
    return;
  }

  let removed = false;
  for (const eventName of ['PreToolUse', 'PostToolUse']) {
    if (!settings.hooks[eventName]) continue;
    const before = settings.hooks[eventName].length;
    settings.hooks[eventName] = settings.hooks[eventName].filter(
      (entry) => !entry.hooks || !entry.hooks.some((h) => h.command && h.command.includes('mcp-yoshi'))
    );
    if (settings.hooks[eventName].length < before) removed = true;
    if (settings.hooks[eventName].length === 0) delete settings.hooks[eventName];
  }

  if (Object.keys(settings.hooks).length === 0) delete settings.hooks;

  if (removed) {
    fs.writeFileSync(settingsPath, JSON.stringify(settings, null, 2) + '\n', 'utf8');
    console.log('mcp-yoshi hooks を削除しました');
  } else {
    console.log('mcp-yoshi hooks は見つかりませんでした');
  }
}

module.exports = { init, uninstall, HOOK_CONFIG };
