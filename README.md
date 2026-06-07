> Japanese version: [README.ja.md](README.ja.md)

# mcp-yoshi

A real-time security filter for MCP (Model Context Protocol) tool communication. Runs as a Claude Code hook, inspecting data sent to and received from MCP tools to assess safety.

## Why

- 97% of MCP tool descriptions are inadequate, and 13% are inconsistent with the actual implementation ([research paper](https://arxiv.org/abs/2602.14878))
- Existing tools (mcp-scan, mcp-drift-detector) only provide static or pre-run checks
- **No real-time communication filter existed**

mcp-yoshi inspects data at the moment of communication and immediately blocks or warns when issues are detected.

## Features

### Outbound Checks (data sent to MCP servers)

| ID | Check | Detection Target |
|----|-------|-----------------|
| OUT-001 | API Key Pattern | API keys for AWS, OpenAI, GitHub, Slack, Google, Stripe, etc. |
| OUT-002 | Private Key | RSA/EC/DSA/OPENSSH private keys |
| OUT-003 | High Entropy String | Random strings of 32+ characters |
| OUT-004 | Env Value Pattern | Environment variable values for PASSWORD, SECRET, TOKEN, etc. |
| OUT-005 | PII Pattern | Email addresses, phone numbers, credit card numbers |
| OUT-006 | Large Payload | Request payloads exceeding 50KB (bulk data exfiltration) |
| OUT-007 | Path Traversal | Sensitive paths such as /etc/passwd, ~/.ssh/, C:\Windows\ |

### Inbound Checks (data received from MCP servers)

| ID | Check | Detection Target |
|----|-------|-----------------|
| IN-001 | Prompt Injection | Instruction overrides like "ignore previous instructions" |
| IN-002 | Shell Command Embedding | Command injection via `$(...)`, `; rm`, `\| bash`, etc. |
| IN-003 | Suspicious URL / SSRF | javascript: URIs, URL shorteners, internal networks, cloud metadata (169.254.169.254, etc.) |
| IN-004 | Script Injection | `<script>`, `eval()`, `document.cookie`, etc. |
| IN-005 | Tool Definition Tampering | Hidden instructions embedded in tool descriptions (12 patterns) |
| IN-006 | ASCII Smuggling | Invisible Unicode characters (U+E0000 Tags Block, Zero-Width characters) |
| IN-007 | Base64 Encoded Payload | Re-inspects decoded Base64 content against existing patterns |
| IN-008 | Response Size Limit | Responses exceeding 512KB (context window poisoning prevention) |
| IN-009 | Hidden Fields | Undeclared fields such as `_hidden`, `$meta` |
| IN-010 | Elicitation Abuse | BLOCKs credential requests and command execution prompts |
| IN-011 | Sampling Injection | Embedded LLM tokenizer markers (`[INST]`, `<<SYS>>`, `<\|im_start\|>`, etc.) |
| IN-012 | Log-To-Leak | Data exfiltration instructions ("send this data to...", "call the logging tool", etc.) |
| IN-013 | Conversation Marker | Conversation markers (`Human:`, `Assistant:`) injected at the beginning of lines |
| IN-014 | Credentials in Response | Residual credentials in stdout/stderr (AWS/OpenAI/GitHub keys, Bearer Tokens, private keys) |
| IN-015 | Parameter Override | `overrideConfig` key co-occurring with `mcpServerConfig`/`NODE_OPTIONS`/`executablePath` for Allowlist Bypass attacks (CVE-2026-40933 related) |
| IN-017 | Path Traversal | `../` directory traversal + sensitive path references in `basePath`/`filePath`/`filename` (`/etc/`, `/root/`, `C:\Windows\`, `/proc/`) |
| IN-018 | Query Injection | SQL/Cypher/NoSQL injection -- BLOCK: `UNION SELECT`, `DROP TABLE`, `MATCH...DELETE`, `;--` / WARN: `' OR '`, `sleep()` |
| IN-019 | Sandbox Escape | vm/Function/global access (`globalThis.process.mainModule.require`, `constructor.constructor()` vm2 escape, etc.) |
| IN-020 | Header Spoofing | Trust boundary bypass (`x-request-from: internal`, `x-forwarded-for: 127.0.0.1`, etc.) |
| IN-021 | Browser Launch RCE | Puppeteer/Playwright `executablePath` pointing to shell binaries (`/bin/sh`, `/usr/bin/nc`, etc.) |

### Rate Limiting (communication patterns)

| ID | Check | Detection Target |
|----|-------|-----------------|
| RATE-001 | Rapid Fire Detection | WARNs when the same tool is called 10+ times within 60 seconds |

### Rug Pull Detection (tool definition tampering)

| ID | Check | Detection Target |
|----|-------|-----------------|
| RUG-001 | Tool Definition Changed | Detects SHA-256 hash changes in tool definitions |
| SHADOW-001 | Tool Shadowing | Detects same-name tool registrations from different servers |

On the first call, tool definition hashes are recorded. Subsequent calls that detect changes will trigger a WARN. Hashes are persisted in `~/.mcp-yoshi/tool-hashes.json`, enabling cross-session detection.

### NFKC Normalization (anti-obfuscation)

[NFKC normalization](https://unicode.org/reports/tr15/) is applied before all inbound/outbound checks. This transparently detects obfuscation via fullwidth characters (e.g., `ignore` encoded as fullwidth) and Unicode compatibility characters.

### Three-Level Verdicts

| Verdict | Behavior |
|---------|----------|
| **PASS** | No issues found. Execution proceeds normally |
| **WARN** | Warning is added to Claude's context. Execution continues |
| **BLOCK** | Tool execution is blocked (outbound) / warning is displayed (inbound) |

## Requirements

- Node.js 18+

## Installation

```bash
npm install -g mcp-yoshi
```

## Setup

```bash
# Automatically add hook configuration to Claude Code's settings.json
mcp-yoshi init

# For project-level configuration
mcp-yoshi init --project
```

This automatically configures the following hooks:

- `PreToolUse`: matches `mcp__.*` -> outbound checks
- `PostToolUse`: matches `mcp__.*` -> inbound checks

## Usage

After setup, mcp-yoshi operates automatically. Checks run every time an MCP tool is invoked.

### Viewing Logs

```bash
# Show the last 20 log entries
mcp-yoshi logs

# Show the last 50 entries at WARN level or above
mcp-yoshi logs --tail 50 --level warn

# Show BLOCK entries only
mcp-yoshi logs --level block
```

### Statistics Report

```bash
# Show detection statistics for the past 7 days
mcp-yoshi stats

# Past 30 days
mcp-yoshi stats --days 30
```

### View Configuration

```bash
mcp-yoshi config
```

## Allowlist (Trusted Servers)

You can register specific MCP servers as trusted to skip checks.
This operates under **your own responsibility**, but logging continues (severity: SKIPPED).

```bash
# Add a server to the allowlist (reason recommended)
mcp-yoshi allow memory --reason "Internal knowledge graph, trusted"

# List the allowlist
mcp-yoshi allow --list

# Remove from the allowlist
mcp-yoshi allow --remove memory
```

You can also configure it directly in `~/.mcp-yoshi/config.json`:

```json
{
  "allowlist": [
    { "server": "memory", "reason": "Internal knowledge graph", "addedAt": "2026-03-12T00:00:00.000Z" }
  ]
}
```

## Configuration

Create `~/.mcp-yoshi/config.json` to override default settings.

```json
{
  "logLevel": "warn",
  "checks": {
    "outbound": {
      "highEntropy": false
    }
  },
  "servers": {
    "*": { "enabled": true },
    "memory": { "enabled": true },
    "trusted-server": { "enabled": false }
  },
  "severity": {
    "WARN": ["highEntropy", "pii", "suspiciousUrls", "base64Payload", "largePayload", "responseSizeLimit", "hiddenFields", "rapidFire"],
    "BLOCK": ["apiKeys", "privateKeys", "promptInjection", "shellCommands", "scriptInjection", "toolTampering", "envValues", "asciiSmuggling", "pathTraversal", "elicitationAbuse"]
  }
}
```

### Per-Server Configuration

Use the `servers` section to control filter on/off and check items per MCP server.

```json
{
  "servers": {
    "*": { "enabled": true },
    "trusted-internal": { "enabled": false },
    "external-api": {
      "enabled": true,
      "checks": {
        "outbound": { "pii": false },
        "inbound": { "promptInjection": true }
      }
    }
  }
}
```

| Key | Description |
|-----|-------------|
| `"*"` | Default settings (applied to undefined servers) |
| `"<server-name>"` | Applied to tools matching `mcp__<server-name>__*` |

- `enabled: false` -> completely skips checks for that server
- `checks` -> overrides global settings on a per-server basis

### Configuration Reference

| Option | Default | Description |
|--------|---------|-------------|
| `logDir` | `~/.mcp-yoshi/logs` | Log output directory |
| `logLevel` | `info` | `info`: log everything, `warn`: WARN and above, `none`: no logging |
| `checks.outbound.*` | `true` | Enable/disable individual outbound checks |
| `checks.inbound.*` | `true` | Enable/disable individual inbound checks |
| `servers` | `{"*": {"enabled": true}}` | Per-server on/off |
| `severity.WARN` | `["highEntropy", "pii", "suspiciousUrls", ...]` | Check IDs classified as WARN |
| `severity.BLOCK` | `["apiKeys", "privateKeys", "promptInjection", ...]` | Check IDs classified as BLOCK |

## Uninstall

```bash
# Remove hook configuration
mcp-yoshi uninstall

# Remove the package
npm uninstall -g mcp-yoshi
```

## Comparison with Existing Tools

| Tool | Timing | Scope |
|------|--------|-------|
| [mcp-scan](https://github.com/invariantlabs-ai/mcp-scan) | Pre-run (static check) | Tool definition safety |
| [mcp-drift-detector](https://github.com/AshishKumar-ops/mcp-drift-detector) | Periodic (change detection) | Tool definition tampering |
| **mcp-yoshi** | **Real-time (during communication)** | **Safety of transmitted/received data** |

## Security Recommendations

### Regarding `.mcp.json` in External Repositories

When cloning external repositories, MCP servers defined in their `.mcp.json` should be treated as **untrusted**. Attacks via malicious `.mcp.json` files that auto-register tools have been reported.

- Do **not** add servers originating from external `.mcp.json` to the allowlist
- Use them with mcp-yoshi checks enabled
- Review logs for suspicious tool invocations

## Notes

- **Performance**: Hooks run on every MCP tool call, adding slight latency (around tens of milliseconds). If this is a concern, change `logLevel` to `"warn"` or set trusted servers to `enabled: false`
- **False Positives**: High entropy strings and PII patterns may match legitimate data. If false positives are frequent, disable the relevant check or downgrade its severity to WARN
- **Detection Limits**: Detection is based on regex pattern matching with NFKC normalization. Highly obfuscated attacks or unknown patterns may not be caught. We recommend using mcp-yoshi alongside other security tools (such as mcp-scan)
- **Rug Pull Detection**: Tool definition hashes are persisted in `~/.mcp-yoshi/tool-hashes.json`. If the file is corrupted, it automatically restarts from an empty state

## License

MIT
