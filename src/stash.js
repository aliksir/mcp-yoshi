// context-stash: MCP ツール応答の JSONL 退避モジュール
// 依存: Node.js built-ins のみ（fs / path / os / crypto）
'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

const DEFAULT_STASH_DIR = path.join(os.homedir(), '.mcp-yoshi', 'stash');

// stash ディレクトリを返す（~ 展開対応）
function getStashDir(stashConfig) {
  const dir = (stashConfig && stashConfig.dir)
    ? stashConfig.dir.replace(/^~/, os.homedir())
    : DEFAULT_STASH_DIR;
  return dir;
}

// stash key を生成する
// フォーマット: {server}__{tool}__{ts13}_{rand4hex}
// NEW-02: 連続アンダースコアを単一化
function generateKey(server, tool, timestamp) {
  const safeServer = (server || 'unknown').replace(/[^\w-]/g, '_').replace(/__+/g, '_').slice(0, 30);
  const safeTool   = (tool   || 'unknown').replace(/[^\w-]/g, '_').replace(/__+/g, '_').slice(0, 30);
  const rand = crypto.randomBytes(2).toString('hex'); // 4 hex chars
  return `${safeServer}__${safeTool}__${timestamp}_${rand}`;
}

// 日付ディレクトリパスを返す（YYYYMMDD 形式）
function getDateDir(stashDir, timestamp) {
  const d = new Date(timestamp);
  const dateStr = `${d.getFullYear()}${String(d.getMonth() + 1).padStart(2, '0')}${String(d.getDate()).padStart(2, '0')}`;
  return path.join(stashDir, dateStr);
}

// stash 書込
// @param maskedText  string  マスク済みテキスト
// @param meta        {server, tool, timestamp}
// @param stashConfig config.stash オブジェクト
// @returns {key: string, path: string, size: number}
// @throws 書込失敗時（呼び出し元でキャッチ必須）
function stashWrite(maskedText, meta, stashConfig) {
  const stashDir = getStashDir(stashConfig);
  const ts = meta.timestamp || Date.now();
  const dateDir = getDateDir(stashDir, ts);
  fs.mkdirSync(dateDir, { recursive: true });

  let key, filePath, attempts = 0;
  do {
    key = generateKey(meta.server, meta.tool, ts);
    filePath = path.join(dateDir, `${key}.jsonl`);
    attempts++;
    if (attempts > 3) throw new Error('key collision after 3 retries');
  } while (fs.existsSync(filePath));

  const line = JSON.stringify({
    key,
    server: meta.server,
    tool: meta.tool,
    ts,
    text: maskedText,
  }) + '\n';

  fs.writeFileSync(filePath, line, { encoding: 'utf8', flag: 'wx' });

  // Unix: owner-only パーミッション設定（AC-9）
  // Windows: chmod は no-op のため README で明記
  try {
    fs.chmodSync(filePath, 0o600);
  } catch {
    // Windows 等で chmod 失敗しても継続（no-op 扱い）
  }

  return { key, path: filePath, size: Buffer.byteLength(line, 'utf8') };
}

// stash 読出
// @param key         string  stash key
// @param stashConfig config.stash オブジェクト
// @returns string | null（key 不在時 null）
// IMPROVE-D1: ts13 逆算で日付ディレクトリを1つに絞り込み、なければ全スキャンにフォールバック
function stashGet(key, stashConfig) {
  const stashDir = getStashDir(stashConfig);
  if (!fs.existsSync(stashDir)) return null;

  // key フォーマット: {server}__{tool}__{ts13}_{rand4}
  // ts13 部分から日付を逆算して対象ディレクトリを絞り込む
  let primaryDateDir = null;
  const tsMatch = key.match(/__(\d{13})_[0-9a-f]{4}$/);
  if (tsMatch) {
    const ts = parseInt(tsMatch[1], 10);
    if (!isNaN(ts)) {
      const d = new Date(ts);
      const dateStr = `${d.getFullYear()}${String(d.getMonth() + 1).padStart(2, '0')}${String(d.getDate()).padStart(2, '0')}`;
      primaryDateDir = dateStr;
      // まず逆算した日付ディレクトリを優先確認
      const priorityPath = path.join(stashDir, dateStr, `${key}.jsonl`);
      if (fs.existsSync(priorityPath)) {
        try {
          return JSON.parse(fs.readFileSync(priorityPath, 'utf8').trim()).text || null;
        } catch {
          return null;
        }
      }
    }
  }

  // フォールバック: 逆算に失敗した場合、または優先ディレクトリに存在しない場合は全スキャン
  let dateDirs;
  try {
    dateDirs = fs.readdirSync(stashDir).filter(d => /^\d{8}$/.test(d) && d !== primaryDateDir);
  } catch {
    return null;
  }

  for (const dateDir of dateDirs) {
    const filePath = path.join(stashDir, dateDir, `${key}.jsonl`);
    if (fs.existsSync(filePath)) {
      try {
        const line = fs.readFileSync(filePath, 'utf8').trim();
        return JSON.parse(line).text || null;
      } catch {
        return null;
      }
    }
  }
  return null;
}

// stash 一覧
// @param filter      { days: N } — 直近 N 日のみ（省略時は全件）
// @param stashConfig config.stash オブジェクト
// @returns [{key, date, size, server, tool}]
function stashList(filter, stashConfig) {
  const stashDir = getStashDir(stashConfig);
  if (!fs.existsSync(stashDir)) return [];

  const results = [];
  const cutoffDate = filter && filter.days
    ? new Date(Date.now() - filter.days * 86400000)
    : null;

  let dateDirs;
  try {
    dateDirs = fs.readdirSync(stashDir).sort().reverse();
  } catch {
    return [];
  }

  for (const dateDir of dateDirs) {
    if (!/^\d{8}$/.test(dateDir)) continue;
    const dirPath = path.join(stashDir, dateDir);
    let files;
    try {
      files = fs.readdirSync(dirPath);
    } catch {
      continue;
    }
    for (const file of files) {
      if (!file.endsWith('.jsonl')) continue;
      const filePath = path.join(dirPath, file);
      let stat;
      try {
        stat = fs.statSync(filePath);
      } catch {
        continue;
      }
      if (cutoffDate && stat.mtime < cutoffDate) continue;
      const key = file.replace(/\.jsonl$/, '');
      // key から server, tool を逆算（フォーマット: server__tool__ts_rand）
      const parts = key.split('__');
      results.push({
        key,
        date: dateDir,
        size: stat.size,
        server: parts[0] || '',
        tool: parts[1] || '',
      });
    }
  }
  return results;
}

// stash 削除（日付ベース）
// @param olderThanDays  number
// @param stashConfig    config.stash オブジェクト
// @returns {count: number}（削除件数）
function stashPurge(olderThanDays, stashConfig) {
  const stashDir = getStashDir(stashConfig);
  if (!fs.existsSync(stashDir)) return { count: 0 };

  const cutoff = Date.now() - olderThanDays * 86400000;
  let count = 0;

  let dateDirs;
  try {
    dateDirs = fs.readdirSync(stashDir);
  } catch {
    return { count: 0 };
  }

  for (const dateDir of dateDirs) {
    if (!/^\d{8}$/.test(dateDir)) continue;
    const dirPath = path.join(stashDir, dateDir);
    let files;
    try {
      files = fs.readdirSync(dirPath);
    } catch {
      continue;
    }
    for (const file of files) {
      if (!file.endsWith('.jsonl')) continue;
      const filePath = path.join(dirPath, file);
      try {
        const stat = fs.statSync(filePath);
        if (stat.mtimeMs < cutoff) {
          fs.unlinkSync(filePath);
          count++;
        }
      } catch {
        // 削除失敗は無視
      }
    }
    // 空になったディレクトリを削除
    try {
      if (fs.readdirSync(dirPath).length === 0) fs.rmdirSync(dirPath);
    } catch {
      // ディレクトリ削除失敗は無視
    }
  }
  return { count };
}

// stash 対象判定
// @param toolResponse  any  フック hookData.tool_response
// @param stashConfig   config.stash オブジェクト
// @returns boolean
function shouldStash(toolResponse, stashConfig) {
  // R-5: null/undefined はスタッシュ対象外
  if (toolResponse === null || toolResponse === undefined) return false;
  // AC-11: enabled === false ならスキップ
  if (!stashConfig || stashConfig.enabled === false) return false;

  const threshold = stashConfig.threshold || 50000;
  const maxSize   = stashConfig.max_size   || 5242880; // 5MB

  let str;
  try {
    str = typeof toolResponse === 'string' ? toolResponse : JSON.stringify(toolResponse);
  } catch {
    return false;
  }
  if (!str) return false;

  const len = str.length;
  if (len < threshold) return false;
  if (len > maxSize)   return false; // 5MB 超はスキップ（R-2）
  return true;
}

// raw 変換（切り詰めなし JSON.stringify）
// flattenToString と異なり 100KB 切り詰めを行わない
// @param obj  any
// @returns string
function flattenRaw(obj) {
  try {
    return typeof obj === 'string' ? obj : JSON.stringify(obj) || '';
  } catch {
    return String(obj);
  }
}

module.exports = { stashWrite, stashGet, stashList, stashPurge, shouldStash, flattenRaw, generateKey };
