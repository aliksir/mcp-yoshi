// アウトバウンドチェック: 送信データから機密情報漏洩を検出

const CHECKS = {
  apiKeys: {
    id: 'OUT-001',
    name: 'API Key Pattern',
    patterns: [
      // AWS
      /AKIA[0-9A-Z]{16}/,
      // OpenAI / Anthropic
      /sk-[a-zA-Z0-9_-]{20,}/,
      // GitHub
      /gh[ps]_[A-Za-z0-9_]{36,}/,
      /gho_[A-Za-z0-9_]{36,}/,
      // GitLab
      /glpat-[A-Za-z0-9_-]{20,}/,
      // Slack
      /xox[bpas]-[0-9a-zA-Z-]{10,}/,
      // Google
      /AIza[0-9A-Za-z_-]{35}/,
      // Stripe
      /[sr]k_(live|test)_[0-9a-zA-Z]{24,}/,
      // Generic bearer/token
      /Bearer\s+[A-Za-z0-9_\-.]{20,}/,
    ],
  },

  privateKeys: {
    id: 'OUT-002',
    name: 'Private Key',
    patterns: [
      /-----BEGIN\s+(RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE KEY-----/,
      /-----BEGIN\s+ENCRYPTED\s+PRIVATE KEY-----/,
    ],
  },

  highEntropy: {
    id: 'OUT-003',
    name: 'High Entropy String',
    check: (text) => {
      // 32文字以上の高ランダム文字列（Base64/Hex）を検出（最大50件で打ち切り）
      const matches = text.match(/[A-Za-z0-9+/=_-]{32,}/g) || [];
      const findings = [];
      for (const m of matches.slice(0, 50)) {
        if (isKnownHarmlessPattern(m)) continue;
        const entropy = calcEntropy(m);
        if (entropy > 4.5 && m.length >= 32) {
          findings.push({ matched: mask(m), entropy: entropy.toFixed(2) });
          break; // 1件見つかれば十分
        }
      }
      return findings;
    },
  },

  envValues: {
    id: 'OUT-004',
    name: 'Environment Variable Value',
    patterns: [
      // KEY=value パターン（コメントや設定ファイルの値）
      /(?:PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|DATABASE_URL|CONNECTION_STRING)\s*[=:]\s*\S+/i,
    ],
  },

  pii: {
    id: 'OUT-005',
    name: 'PII Pattern',
    patterns: [
      // メールアドレス
      /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/,
      // 日本の電話番号
      /0[0-9]{1,4}-?[0-9]{1,4}-?[0-9]{4}/,
      // クレジットカード（16桁）
      /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b/,
      // マイナンバー（12桁数字）— コンテキスト必須 or 区切りなしの連続12桁のみ
      // ハイフン・ドット区切り（日付・バージョン番号）は除外
      /(?:マイナンバー|個人番号|my\s*number)\s*[:：]?\s*[0-9]{4}\s?[0-9]{4}\s?[0-9]{4}/i,
    ],
  },
};

// OUT-003: 既知の無害パターンを除外（calcEntropy前にスキップ）
function isKnownHarmlessPattern(str) {
  // SHA-256ハッシュ（64文字hex）
  if (/^[0-9a-f]{64}$/i.test(str)) return true;
  // SHA-512ハッシュ（128文字hex）
  if (/^[0-9a-f]{128}$/i.test(str)) return true;
  // UUID
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(str)) return true;
  // 短いBase64（32文字ちょうど、末尾==パディング）
  if (str.length === 32 && /==$/i.test(str)) return true;
  // ファイルパスっぽい（/ or \ を3つ以上含む）
  if ((str.match(/[/\\]/g) || []).length >= 3) return true;
  return false;
}

function calcEntropy(str) {
  const freq = {};
  for (const c of str) {
    freq[c] = (freq[c] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function mask(str) {
  if (str.length <= 8) return '****';
  return str.slice(0, 4) + '****' + str.slice(-4);
}

function runOutboundChecks(text, enabledChecks) {
  const findings = [];

  for (const [checkName, check] of Object.entries(CHECKS)) {
    if (!enabledChecks[checkName]) continue;

    if (check.check) {
      // カスタムチェック関数
      const results = check.check(text);
      for (const result of results) {
        findings.push({
          id: check.id,
          name: check.name,
          detail: result,
        });
      }
    } else if (check.patterns) {
      // パターンマッチ
      for (const pattern of check.patterns) {
        const match = text.match(pattern);
        if (match) {
          findings.push({
            id: check.id,
            name: check.name,
            matched: mask(match[0]),
          });
          break; // 同一チェックで複数マッチは1件にまとめる
        }
      }
    }
  }

  return findings;
}

module.exports = { runOutboundChecks, CHECKS, mask };
