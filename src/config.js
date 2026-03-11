const fs = require('fs');
const path = require('path');
const os = require('os');

const DEFAULT_CONFIG_PATH = path.join(__dirname, '..', 'config.default.json');
const USER_CONFIG_PATH = path.join(os.homedir(), '.mcp-yoshi', 'config.json');

function loadConfig() {
  const defaults = JSON.parse(fs.readFileSync(DEFAULT_CONFIG_PATH, 'utf8'));
  let userConfig = {};

  if (fs.existsSync(USER_CONFIG_PATH)) {
    try {
      userConfig = JSON.parse(fs.readFileSync(USER_CONFIG_PATH, 'utf8'));
    } catch {
      // ユーザー設定が壊れている場合はデフォルトにフォールバック
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

module.exports = { loadConfig, getServerConfig, parseServerName, resolveLogDir, deepMerge };
