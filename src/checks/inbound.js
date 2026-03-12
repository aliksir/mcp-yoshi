// インバウンドチェック: 受信データから攻撃パターンを検出

const CHECKS = {
  promptInjection: {
    id: 'IN-001',
    name: 'Prompt Injection',
    patterns: [
      /ignore\s+(all\s+)?(previous|above|prior)\s+(instructions?|prompts?|rules?)/i,
      /disregard\s+(all\s+)?(previous|above|prior)/i,
      /you\s+are\s+now\s+(a|an|acting\s+as)/i,
      /new\s+instructions?:\s/i,
      /system\s*prompt\s*:/i,
      /\bdo\s+not\s+follow\s+(the\s+)?(previous|above|original)/i,
      /\bforget\s+(all|everything)\s+(about|you)/i,
      /\boverride\s+(all\s+)?(safety|security|restrictions?)/i,
      /\bact\s+as\s+(if\s+)?(you\s+are|a|an)\b/i,
      // role: system — 攻撃的文脈がある場合のみ検出（YAML/JSON設定は除外）
      /\b(?:ignore|override|new|inject|fake)\b[^.]{0,40}\brole\s*:\s*(system|assistant|user)\b/i,
      /<\/?system>/i,
    ],
  },

  shellCommands: {
    id: 'IN-002',
    name: 'Shell Command Embedding',
    patterns: [
      /\$\([^)]{2,}\)/,                          // $(command)
      // バックティック — 中身に危険コマンドがある場合のみ検出（Markdownコードスパン除外）
      /`[^`]*\b(?:rm|curl|wget|sudo|chmod|dd|mkfs|kill)\b[^`]*`/,
      /;\s*(rm|curl|wget|chmod|chown|sudo|kill|dd|mkfs)\s/i,
      /\|\s*(bash|sh|zsh|cmd|powershell)\b/i,     // | bash
      /&&\s*(rm|curl|wget|sudo)\s/i,
      />\s*\/etc\//,                              // > /etc/...
      // eval/exec — 攻撃的コンテキストがある場合のみ（コード例は除外）
      /;\s*eval\s*\(/,
      /\bchild_process\b[^;]*\bexec\s*\(/,
    ],
  },

  suspiciousUrls: {
    id: 'IN-003',
    name: 'Suspicious URL',
    patterns: [
      /javascript\s*:/i,
      /data\s*:\s*text\/html/i,
      /vbscript\s*:/i,
      // 短縮URL
      /https?:\/\/(bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly)\//i,
      // IPアドレス直接アクセス（内部ネットワーク）
      /https?:\/\/(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)/,
    ],
  },

  scriptInjection: {
    id: 'IN-004',
    name: 'Script Injection',
    patterns: [
      /<script[\s>]/i,
      /<\/script>/i,
      /\bon\w+\s*=\s*["']/i,    // onload="...", onclick="..."
      /\bFunction\s*\(/,
      /\bsetTimeout\s*\(\s*["']/,
      /\bsetInterval\s*\(\s*["']/,
      /document\.(cookie|write|location)/i,
      /window\.(location|open)\s*[=(]/i,
    ],
  },

  toolTampering: {
    id: 'IN-005',
    name: 'Tool Definition Tampering',
    patterns: [
      // ツール説明文に埋め込まれた隠し指示
      /\b(always|must|never|required)\s+(send|post|upload|transmit|forward)\s+(to|all|data|information)/i,
      /\bhidden\s+(instruction|command|action)/i,
      /\bsecretly\s+(send|post|log|store|transmit)/i,
      /\bdo\s+not\s+(tell|inform|notify|alert)\s+(the\s+)?(user|human|operator)/i,
      /\bwithout\s+(the\s+)?(user|human)'?s?\s+(knowledge|consent|awareness)/i,
      /\bexfiltrate\b/i,
      /\bphone\s*home\b/i,
    ],
  },
};

function runInboundChecks(text, enabledChecks) {
  const findings = [];

  for (const [checkName, check] of Object.entries(CHECKS)) {
    if (!enabledChecks[checkName]) continue;

    for (const pattern of check.patterns) {
      const match = text.match(pattern);
      if (match) {
        findings.push({
          id: check.id,
          name: check.name,
          matched: match[0].slice(0, 80),
        });
        break; // 同一チェックで複数マッチは1件にまとめる
      }
    }
  }

  return findings;
}

module.exports = { runInboundChecks, CHECKS };
