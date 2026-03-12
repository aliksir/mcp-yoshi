const fs = require('fs');
const path = require('path');
const os = require('os');

const DEFAULT_CONFIG_PATH = path.join(__dirname, '..', 'config.default.json');
const USER_CONFIG_PATH = path.join(os.homedir(), '.mcp-yoshi', 'config.json');

function loadConfig() {
  const defaults = JSON.parse(fs.readFileSync(DEFAULT_CONFIG_PATH, 'utf8'));
  let userConfig = {};

  try {
    userConfig = JSON.parse(fs.readFileSync(USER_CONFIG_PATH, 'utf8'));
  } catch (e) {
    if (e.code !== 'ENOENT') {
      process.stderr.write(`[mcp-yoshi] Warning: ${USER_CONFIG_PATH} の読み込みに失敗しました。デフォルト設定を使用します\n`);
    }
  }

  return deepMerge(defaults, userConfig);
}

function deepMerge(target, source) {
  const result = { ...target };
  for (const key of Object.keys(source)) {
    if (
      source[key] &&
      typeof source[key] === 'object' &&
      !Array.isArray(source[key]) &&
      target[key] &&
      typeof target[key] === 'object' &&
      !Array.isArray(target[key])
    ) {
      result[key] = deepMerge(target[key], source[key]);
    } else {
      result[key] = source[key];
    }
  }
  return result;
}

function getServerConfig(config, serverName) {
  const globalChecks = config.checks;
  const defaultServer = config.servers['*'] || { enabled: true };
  const serverOverride = config.servers[serverName];

  if (!serverOverride) {
    return { enabled: defaultServer.enabled !== false, checks: globalChecks };
  }

  if (serverOverride.enabled === false) {
    return { enabled: false, checks: globalChecks };
  }

  const mergedChecks = serverOverride.checks
    ? deepMerge(globalChecks, serverOverride.checks)
    : globalChecks;

  return { enabled: true, checks: mergedChecks };
}

function parseServerName(toolName) {
  // mcp__<server>__<tool> → server
  const match = toolName.match(/^mcp__([^_]+)__/);
  return match ? match[1] : null;
}

function resolveLogDir(config) {
  const logDir = config.logDir.replace(/^~/, os.homedir());
  return logDir;
}

function isAllowlisted(config, serverName) {
  const list = config.allowlist || [];
  return list.some((entry) => entry.server === serverName);
}

function getAllowlistEntry(config, serverName) {
  const list = config.allowlist || [];
  return list.find((entry) => entry.server === serverName) || null;
}

function listAllowlist(config) {
  return config.allowlist || [];
}

function addToAllowlist(serverName, reason) {
  const userConfig = loadUserConfig();
  if (!userConfig.allowlist) userConfig.allowlist = [];

  // 既存エントリがあれば更新
  const idx = userConfig.allowlist.findIndex((e) => e.server === serverName);
  const entry = { server: serverName, reason: reason || '', addedAt: new Date().toISOString() };
  if (idx >= 0) {
    userConfig.allowlist[idx] = entry;
  } else {
    userConfig.allowlist.push(entry);
  }

  saveUserConfig(userConfig);
  return entry;
}

function removeFromAllowlist(serverName) {
  const userConfig = loadUserConfig();
  if (!userConfig.allowlist) return false;

  const before = userConfig.allowlist.length;
  userConfig.allowlist = userConfig.allowlist.filter((e) => e.server !== serverName);
  if (userConfig.allowlist.length === before) return false;

  saveUserConfig(userConfig);
  return true;
}

function loadUserConfig() {
  try {
    return JSON.parse(fs.readFileSync(USER_CONFIG_PATH, 'utf8'));
  } catch (e) {
    if (e.code === 'ENOENT') return {};
    throw e;
  }
}

function saveUserConfig(userConfig) {
  const dir = path.dirname(USER_CONFIG_PATH);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(USER_CONFIG_PATH, JSON.stringify(userConfig, null, 2), 'utf8');
}

module.exports = {
  loadConfig, getServerConfig, parseServerName, resolveLogDir, deepMerge,
  isAllowlisted, getAllowlistEntry, listAllowlist, addToAllowlist, removeFromAllowlist,
  USER_CONFIG_PATH,
};
