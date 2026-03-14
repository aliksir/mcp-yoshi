// 統計集計: ログファイルからチェック検出統計を生成

const fs = require('fs');
const path = require('path');
const { resolveLogDir } = require('./config');

function collectStats(config, options = {}) {
  const logDir = resolveLogDir(config);
  const days = options.days || 7;

  if (!fs.existsSync(logDir)) return null;

  const cutoff = new Date();
  cutoff.setDate(cutoff.getDate() - days);
  const cutoffStr = cutoff.toISOString().slice(0, 10);

  const files = fs.readdirSync(logDir)
    .filter((f) => f.startsWith('mcp-yoshi-') && f.endsWith('.log'))
    .filter((f) => {
      const date = f.replace('mcp-yoshi-', '').replace('.log', '');
      return date >= cutoffStr;
    })
    .sort();

  if (files.length === 0) return null;

  const stats = {
    total: 0,
    bySeverity: { PASS: 0, WARN: 0, BLOCK: 0, SKIPPED: 0 },
    byCheck: {},
    byServer: {},
    byDirection: { outbound: 0, inbound: 0 },
    period: { from: null, to: null, days },
  };

  for (const file of files) {
    const lines = fs.readFileSync(path.join(logDir, file), 'utf8')
      .split('\n')
      .filter(Boolean);

    for (const line of lines) {
      let entry;
      try {
        entry = JSON.parse(line);
      } catch {
        continue;
      }

      stats.total++;

      // severity
      const sev = entry.severity || 'PASS';
      stats.bySeverity[sev] = (stats.bySeverity[sev] || 0) + 1;

      // direction
      if (entry.direction) {
        stats.byDirection[entry.direction] = (stats.byDirection[entry.direction] || 0) + 1;
      }

      // server
      const server = entry.server || 'unknown';
      if (!stats.byServer[server]) {
        stats.byServer[server] = { total: 0, PASS: 0, WARN: 0, BLOCK: 0, SKIPPED: 0 };
      }
      stats.byServer[server].total++;
      stats.byServer[server][sev] = (stats.byServer[server][sev] || 0) + 1;

      // findings
      if (entry.findings && entry.findings.length > 0) {
        for (const f of entry.findings) {
          const id = f.id || 'unknown';
          if (!stats.byCheck[id]) {
            stats.byCheck[id] = { count: 0, name: f.name || id };
          }
          stats.byCheck[id].count++;
        }
      }

      // period
      if (entry.timestamp) {
        if (!stats.period.from || entry.timestamp < stats.period.from) {
          stats.period.from = entry.timestamp;
        }
        if (!stats.period.to || entry.timestamp > stats.period.to) {
          stats.period.to = entry.timestamp;
        }
      }
    }
  }

  return stats;
}

function formatStats(stats) {
  if (!stats || stats.total === 0) {
    return 'ログデータがありません';
  }

  const lines = [];
  const blockRate = ((stats.bySeverity.BLOCK / stats.total) * 100).toFixed(1);

  lines.push(`📊 mcp-yoshi 統計レポート（過去${stats.period.days}日間）`);
  lines.push(`   期間: ${(stats.period.from || '').slice(0, 10)} 〜 ${(stats.period.to || '').slice(0, 10)}`);
  lines.push('');

  // サマリー
  lines.push(`── サマリー ──────────────────`);
  lines.push(`  総チェック数: ${stats.total}`);
  lines.push(`  ✅ PASS: ${stats.bySeverity.PASS}  ⚠️ WARN: ${stats.bySeverity.WARN}  🚫 BLOCK: ${stats.bySeverity.BLOCK}  ⏭️ SKIP: ${stats.bySeverity.SKIPPED}`);
  lines.push(`  ブロック率: ${blockRate}%`);
  lines.push(`  方向: outbound ${stats.byDirection.outbound} / inbound ${stats.byDirection.inbound}`);
  lines.push('');

  // チェック別
  const checks = Object.entries(stats.byCheck).sort((a, b) => b[1].count - a[1].count);
  if (checks.length > 0) {
    lines.push(`── 検出ルール別 ─────────────────`);
    for (const [id, data] of checks) {
      lines.push(`  [${id}] ${data.name}: ${data.count}件`);
    }
    lines.push('');
  }

  // サーバー別
  const servers = Object.entries(stats.byServer).sort((a, b) => b[1].total - a[1].total);
  if (servers.length > 0) {
    lines.push(`── サーバー別 ──────────────────`);
    for (const [name, data] of servers) {
      const detail = [];
      if (data.BLOCK > 0) detail.push(`🚫${data.BLOCK}`);
      if (data.WARN > 0) detail.push(`⚠️${data.WARN}`);
      if (data.SKIPPED > 0) detail.push(`⏭️${data.SKIPPED}`);
      const detailStr = detail.length > 0 ? ` (${detail.join(' ')})` : '';
      lines.push(`  ${name}: ${data.total}件${detailStr}`);
    }
  }

  return lines.join('\n');
}

module.exports = { collectStats, formatStats };
