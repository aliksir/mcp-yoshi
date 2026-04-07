// インバウンドチェック: 受信データから攻撃パターンを検出

// P1: ASCII Smuggling — U+E0000台不可視文字 + Zero-Width文字の検出
const ASCII_SMUGGLING_PATTERN = /[\u{E0000}-\u{E007F}]/u;
const ZERO_WIDTH_PATTERN = /[\u200B\u200C\u200D\uFEFF\u2060]/;

// IN-008: Response Size Limit
const MAX_RESPONSE_BYTES = 512000;

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
      // PowerShell固有構文
      /\b(?:Invoke-Expression|IEX)\s*[\s(]/i,
      /\bStart-Process\b/i,
      /\b(?:Invoke-WebRequest|iwr|Invoke-RestMethod|irm)\s/i,
      // スクリプト言語の直接実行
      /\b(?:python3?|node|ruby|perl)\s+-[ec]\s/i,
      // 環境変数展開攻撃（シェル変数の悪用）
      /\$\{IFS\}/,
      /\$\{(?:PATH|HOME|USER)\}[^a-zA-Z]*(?:rm|curl|wget|sudo|chmod)\b/i,
      // Windows固有の危険コマンド
      /\bcmd\s*\/[ck]\s/i,
      /\b(?:certutil|bitsadmin|mshta|regsvr32|rundll32|msiexec)\b[^.]/i,
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
      // P6: クラウドメタデータURL（SSRF拡張）
      /169\.254\.169\.254/,
      /metadata\.google\.internal/i,
      /100\.100\.100\.200/,  // Alibaba Cloud metadata
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
      // P4: Tool Poisoning追加パターン（5件）
      /\bbefore\s+(executing|running|calling)\s+any\s+(tool|function|action)/i,
      /\bread\s+~?\/?\.ssh\//i,
      /\boverride\s+(all\s+)?instructions?\b/i,
      /\bforget\s+(all\s+)?previous\b/i,
      /\bIMPORTANT\s*:\s*Before\s+any\s+action/i,
    ],
  },

  // P1: ASCII Smuggling検出
  asciiSmuggling: {
    id: 'IN-006',
    name: 'ASCII Smuggling',
    check: (text) => {
      const findings = [];
      if (ASCII_SMUGGLING_PATTERN.test(text)) {
        findings.push({ matched: 'Unicode Tags Block (U+E0000-E007F)' });
      }
      if (ZERO_WIDTH_PATTERN.test(text)) {
        findings.push({ matched: 'Zero-Width characters detected' });
      }
      return findings;
    },
  },

  // P3: Base64ペイロード検出
  base64Payload: {
    id: 'IN-007',
    name: 'Base64 Encoded Payload',
    check: (text, enabledChecks) => {
      // 40文字以上のBase64文字列を抽出
      const b64Matches = text.match(/[A-Za-z0-9+/]{40,}={0,2}/g) || [];
      const findings = [];
      for (const b64 of b64Matches.slice(0, 10)) {
        let decoded;
        try {
          decoded = Buffer.from(b64, 'base64').toString('utf8');
        } catch {
          continue;
        }
        // デコード結果が有効なテキストでない場合スキップ
        if (!/^[\x20-\x7E\s]{10,}$/.test(decoded)) continue;
        // デコード結果をIN-001〜005のパターンで再チェック（enabledChecks設定を尊重）
        for (const [checkNameInner, check] of Object.entries(CHECKS)) {
          if (!check.patterns) continue;
          // enabledChecks が渡された場合のみ有効/無効を考慮（未渡しなら全チェック実施）
          if (enabledChecks && !enabledChecks[checkNameInner]) continue;
          for (const pattern of check.patterns) {
            if (pattern.test(decoded)) {
              findings.push({
                matched: `Base64 decoded → [${check.id}] ${decoded.slice(0, 60)}`,
              });
              return findings; // 1件見つかれば十分
            }
          }
        }
      }
      return findings;
    },
  },

  // IN-008: Response Size Limit — コンテキストウィンドウポイズニング対策
  responseSizeLimit: {
    id: 'IN-008',
    name: 'Response Size Limit',
    severity: 'WARN',
    check: (text) => {
      const size = Buffer.byteLength(text, 'utf8');
      const limit = MAX_RESPONSE_BYTES;
      if (size > limit) {
        return [{ matched: `Response size ${size}B exceeds limit ${limit}B — potential context window poisoning` }];
      }
      return [];
    },
  },

  // IN-009: Hidden Fields — MCPレスポンス内の未申告内部フィールド検出
  hiddenFields: {
    id: 'IN-009',
    name: 'Hidden Fields',
    severity: 'WARN',
    check: (text) => {
      let parsed;
      try {
        parsed = JSON.parse(text);
      } catch {
        return [];
      }
      // 除外リスト: 一般的なフレームワークで使われる標準フィールド
      const ALLOWED_HIDDEN = new Set(['_type', '_id']);
      const findings = [];

      function scanObject(obj) {
        if (!obj || typeof obj !== 'object') return;
        if (Array.isArray(obj)) {
          for (const item of obj) scanObject(item);
          return;
        }
        for (const key of Object.keys(obj)) {
          if ((key.startsWith('_') || key.startsWith('$')) && !ALLOWED_HIDDEN.has(key)) {
            findings.push({ matched: `Hidden field detected: '${key}' — undeclared internal field in MCP response` });
          }
          scanObject(obj[key]);
        }
      }

      scanObject(parsed);
      return findings;
    },
  },

  // IN-010: Elicitation Abuse — Elicitation経由の攻撃パターン検出
  elicitationAbuse: {
    id: 'IN-010',
    name: 'Elicitation Abuse',
    severity: 'BLOCK',
    check: (text) => {
      const findings = [];

      // パターン1: 認証情報要求（認証情報ワードと入力要求ワードの共存）
      if (/password|api.?key|secret|token|credential/i.test(text) &&
          /enter|input|provide|type|submit/i.test(text)) {
        const snippet = text.slice(0, 80).replace(/\n/g, ' ');
        findings.push({ matched: `Elicitation abuse detected: credential_request — ${snippet}` });
      }

      // パターン2: コマンド実行誘導（承認ワードとコマンド実行ワードの共存）
      if (/confirm|approve|authorize/i.test(text) &&
          /exec|bash|eval|system|spawn|child_process/i.test(text)) {
        const snippet = text.slice(0, 80).replace(/\n/g, ' ');
        findings.push({ matched: `Elicitation abuse detected: command_execution — ${snippet}` });
      }

      // パターン3: 隠しコマンド（シェル構文がUIテキストに埋め込まれている）
      const hiddenCmdPattern = /\$\(|`[^`]+`|\bsh\s+-c\b|\bbash\s+-c\b/;
      const hiddenMatch = text.match(hiddenCmdPattern);
      if (hiddenMatch) {
        const snippet = hiddenMatch[0].slice(0, 80);
        findings.push({ matched: `Elicitation abuse detected: hidden_command — ${snippet}` });
      }

      return findings;
    },
  },

  // IN-011: Sampling Injection — LLMトークナイザマーカー検出
  samplingInjection: {
    id: 'IN-011',
    name: 'Sampling Injection',
    patterns: [
      /\[INST\]/i,
      /\[\/INST\]/i,
      /<<SYS>>/,
      /<<\/SYS>>/,
      /<\|im_start\|>\s*system/i,
      /<\|im_end\|>/,
      /<\|system\|>/i,
      /<\|user\|>/i,
      /<\|assistant\|>/i,
      /\[SYSTEM_PROMPT\]/i,
      /<start_of_turn>\s*(?:user|model)/i,
      /<\|endoftext\|>/,
    ],
  },

  // IN-012: Log-To-Leak — データ窃取指示検出
  logToLeak: {
    id: 'IN-012',
    name: 'Log-To-Leak',
    patterns: [
      /\b(?:send|post|forward|transmit|upload|log|report)\s+(?:this|the|all|these|that)\s+(?:data|information|content|result|output|response)\s+(?:to|via|through|using)\b/i,
      /\b(?:call|invoke|use|execute)\s+(?:the\s+)?(?:logging|analytics|telemetry|monitoring|webhook)\s+(?:tool|service|api|endpoint)\b/i,
      /\bcurl\s+.*?-d\s+.*?\b(?:log|analytics|telemetry)\b/i,
      /\bfetch\s*\(\s*['"]https?:\/\/[^'"]*(?:log|analytics|telemetry|webhook)\b/i,
    ],
  },

  // IN-013: Conversation Marker — 会話マーカー検出（行頭限定）
  conversationMarker: {
    id: 'IN-013',
    name: 'Conversation Marker',
    patterns: [
      /^Human:\s/m,
      /^Assistant:\s/m,
    ],
  },
  // IN-014: Credentials in Response — stdout/stderr内の認証情報検出
  // 研究根拠: 17,022件AIスキル監査で漏洩の73.5%がprint/console.log残留が原因
  credentialsInResponse: {
    id: 'IN-014',
    name: 'Credentials in Response',
    check: (text) => {
      const findings = [];
      const patterns = {
        'AWS Access Key': /AKIA[0-9A-Z]{16}/,
        'OpenAI/Anthropic API Key': /sk-[a-zA-Z0-9_-]{20,}/,
        'GitHub Token': /gh[pos]_[A-Za-z0-9_]{36,}/,
        'GitLab Token': /glpat-[a-zA-Z0-9_-]{20,}/,
        'Slack Token': /xox[bpas]-[0-9a-zA-Z-]{10,}/,
        'Google API Key': /AIza[0-9A-Za-z_-]{35}/,
        'Stripe Key': /[sr]k_(?:live|test)_[0-9a-zA-Z]{24,}/,
        'Bearer Token': /Bearer\s+[A-Za-z0-9_\-.]{20,}/,
        'Private Key Block': /-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE KEY-----/,
        'Password Assignment': /(?:password|passwd)\s*[=:]\s*['"]?\S{8,}/i,
        'Credential Env Exposure': /(?:API_KEY|SECRET_KEY|AUTH_TOKEN|ACCESS_TOKEN|CREDENTIAL)\s*[=:]\s*['"]?\S{8,}/i,
      };

      for (const [name, pattern] of Object.entries(patterns)) {
        const match = text.match(pattern);
        if (match) {
          // マスク処理: 先頭8文字 + *** で秘匿
          const masked = match[0].length > 8
            ? match[0].slice(0, 8) + '***'
            : match[0];
          findings.push({ matched: `${name}: ${masked}` });
          break;
        }
      }
      return findings;
    },
  },
};

function runInboundChecks(text, enabledChecks) {
  const findings = [];

  // P2: NFKC正規化（難読化回避対策）— パターンマッチ前に適用
  const normalizedText = text.normalize('NFKC');

  for (const [checkName, check] of Object.entries(CHECKS)) {
    if (!enabledChecks[checkName]) continue;

    if (check.check) {
      // カスタムチェック関数（IN-006 ASCII Smuggling, IN-007 Base64）
      // ASCII Smugglingは正規化前のテキストでチェック（正規化で消える文字を検出するため）
      // IN-007 Base64は内部で他チェックを再実行するため enabledChecks を第2引数で渡す
      const targetText = checkName === 'asciiSmuggling' ? text : normalizedText;
      const results = check.check(targetText, enabledChecks);
      for (const result of results) {
        findings.push({
          id: check.id,
          name: check.name,
          matched: result.matched || JSON.stringify(result),
        });
      }
    } else if (check.patterns) {
      for (const pattern of check.patterns) {
        const match = normalizedText.match(pattern);
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
  }

  return findings;
}

module.exports = { runInboundChecks, CHECKS };
