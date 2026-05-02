// sensitive text masker: stash 入力前のマスキングモジュール
// 依存: Node.js built-ins のみ
'use strict';

// IN-014 credentialsInResponse と同一パターン（グローバルフラグ追加）
// NOTE: IN-014 パターン（src/checks/inbound.js）を更新する場合、このファイルも同時に更新すること（DRY 許容、§3.7）
const CREDENTIAL_PATTERNS = [
  /AKIA[0-9A-Z]{16}/g,
  /sk-[a-zA-Z0-9_-]{20,}/g,
  /gh[pos]_[A-Za-z0-9_]{36,}/g,
  /glpat-[a-zA-Z0-9_-]{20,}/g,
  /xox[bpas]-[0-9a-zA-Z-]{10,}/g,
  /AIza[0-9A-Za-z_-]{35}/g,
  /[sr]k_(?:live|test)_[0-9a-zA-Z]{24,}/g,
  /Bearer\s+[A-Za-z0-9_\-.]{20,}/g,
  /-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE KEY-----/g,
  /(?:password|passwd)\s*[=:]\s*['"]?\S{8,}/gi,
  /(?:API_KEY|SECRET_KEY|AUTH_TOKEN|ACCESS_TOKEN|CREDENTIAL)\s*[=:]\s*['"]?\S{8,}/gi,
];

// IN-014 / IN-010 専用: credential パターンで全件マスク
// グローバルフラグの lastIndex をリセットして再利用安全にする
function maskCredentials(text, placeholder) {
  let result = text;
  for (const pattern of CREDENTIAL_PATTERNS) {
    pattern.lastIndex = 0; // グローバルフラグのリセット（再利用安全）
    result = result.replace(pattern, placeholder);
  }
  return result;
}

// finding.matched から実際の平文部分を抽出する
// 省略（***）・説明文が混入している場合は null を返す
function extractLiteralFromMatched(matched) {
  if (!matched || typeof matched !== 'string') return null;
  // "***" が含まれる場合は省略済み → 平文不在
  if (matched.includes('***')) return null;
  // 説明文パターン（detected, abuse, injection 等の末尾説明句）が含まれる場合はスキップ
  if (/\b(detected|abuse|injection|embedding|limit|marker|changed|override|field|traversal)\b/i.test(matched)) return null;
  // 空文字列・空白のみはスキップ
  if (matched.trim().length === 0) return null;
  return matched;
}

// findings の matched を基に text をマスクする
// @param text     string  マスク対象テキスト（flattenRaw 後）
// @param findings Array   runInboundChecks が返す findings 配列
// @returns        string  マスク済みテキスト
function maskSensitiveText(text, findings) {
  if (!text || typeof text !== 'string') return text;
  if (!findings || findings.length === 0) return text;

  let masked = text;
  for (const finding of findings) {
    if (!finding || !finding.id) continue;
    const placeholder = `[REDACTED:${finding.id}]`;

    if (finding.id === 'IN-014') {
      // IN-014: credentialsInResponse パターンで全件マスク
      masked = maskCredentials(masked, placeholder);
    } else if (finding.id === 'IN-010') {
      // FIX-D2: IN-010（elicitationAbuse）専用マスキング
      // matched に 'detected' キーワードが含まれるため extractLiteralFromMatched がスキップする。
      // IN-010 firing 条件上 snippet に credential 関連語が含まれ得るため、
      // IN-014 と同じ maskCredentials を適用して I4 を遵守する（案A採用）。
      masked = maskCredentials(masked, '[REDACTED:IN-010]');
    } else {
      // 汎用: finding.matched を substring として検索し置換
      const literal = extractLiteralFromMatched(finding.matched);
      if (literal) {
        masked = masked.split(literal).join(placeholder);
      }
    }
  }
  return masked;
}

module.exports = { maskSensitiveText };
