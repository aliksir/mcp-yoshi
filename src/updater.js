// アップデート確認・実行: npm registry から最新バージョンを取得し、比較・更新する

const https = require('https');
const { execSync } = require('child_process');
const pkg = require('../package.json');

function fetchLatestVersion() {
  return new Promise((resolve, reject) => {
    const url = `https://registry.npmjs.org/${pkg.name}/latest`;
    https.get(url, { headers: { 'Accept': 'application/json' } }, (res) => {
      if (res.statusCode === 404) {
        res.resume(); // ソケット解放のためボディをドレイン
        return resolve(null); // npmに未公開
      }
      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error(`npm registry responded with ${res.statusCode}`));
      }

      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          resolve(json.version || null);
        } catch {
          reject(new Error('npm registry の応答を解析できませんでした'));
        }
      });
    }).on('error', (err) => {
      reject(new Error(`npm registry への接続に失敗しました: ${err.message}`));
    });
  });
}

function compareVersions(current, latest) {
  const parse = (v) => v.replace(/^v/, '').split('.').map(Number);
  const c = parse(current);
  const l = parse(latest);
  for (let i = 0; i < 3; i++) {
    if ((l[i] || 0) > (c[i] || 0)) return 1;  // latest is newer
    if ((l[i] || 0) < (c[i] || 0)) return -1; // current is newer
  }
  return 0; // same
}

async function checkUpdate() {
  const current = pkg.version;
  const latest = await fetchLatestVersion();

  if (latest === null) {
    return { current, latest: null, status: 'not-published' };
  }

  const cmp = compareVersions(current, latest);
  if (cmp > 0) {
    return { current, latest, status: 'update-available' };
  }
  if (cmp < 0) {
    return { current, latest, status: 'ahead' };
  }
  return { current, latest, status: 'up-to-date' };
}

function runUpdate() {
  execSync('npm install -g mcp-yoshi@latest', { stdio: 'inherit' });
}

module.exports = { fetchLatestVersion, compareVersions, checkUpdate, runUpdate };
