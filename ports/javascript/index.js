#!/usr/bin/env node
// keyhunt — Node/JavaScript port of the core scan surface.
//
// Mirrors the Python CLI: recursively scans a file or directory for hardcoded
// secrets using the same detector families and emits the same JSON shape:
//   {tool, version, count, findings:[{detector,description,severity,path,line,column,secret}]}
//
// Secrets are redacted by default; pass --show-secrets to reveal. Passive and
// offline by design — it only reads local files, never the network. Exit code
// 1 when secrets are found (CI gate), 0 when clean, 2 on usage error.
import { readdirSync, statSync, readFileSync } from "fs";
import { join, extname } from "path";
import { pathToFileURL } from "url";

export const TOOL_VERSION = "1.2.9";

// detector: [id, description, severity, regex, secretGroup, minEntropy]
export const DETECTORS = [
  ["private-key", "PEM private key block", "critical",
    /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g, 0, 0],
  ["aws-access-key", "AWS access key id", "critical",
    /\b((?:AKIA|ASIA|AGPA|AIDA)[A-Z0-9]{16})\b/g, 1, 0],
  ["aws-secret-key", "AWS secret access key", "critical",
    /aws_?secret_?(?:access_?)?key\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})/gi, 1, 0],
  ["gcp-api-key", "Google API key", "high",
    /\b(AIza[0-9A-Za-z\-_]{35})\b/g, 1, 0],
  ["github-token", "GitHub personal access / app token", "critical",
    /\b((?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,255})\b/g, 1, 0],
  ["slack-token", "Slack token", "high",
    /\b(xox[baprs]-[A-Za-z0-9-]{10,})\b/g, 1, 0],
  ["jwt", "JSON Web Token", "medium",
    /\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b/g, 1, 0],
  ["connection-uri-password", "Credentials embedded in a connection URI", "high",
    /\b[a-z][a-z0-9+.\-]*:\/\/[^\s:/@]+:([^\s:/@]+)@[^\s/]+/gi, 1, 0],
  ["hardcoded-password", "Hardcoded password assignment", "high",
    /(?:passwd|password|pwd|pass)\s*[:=]\s*['"]([^'"\n]{3,64})['"]/gi, 1, 0],
  ["api-key-assignment", "Generic api/secret/token assignment", "medium",
    /(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\s*[:=]\s*['"]([A-Za-z0-9_\-./+=]{12,128})['"]/gi, 1, 3.0],
];

const PLACEHOLDERS = new Set([
  "", "changeme", "password", "passwd", "example", "your_password",
  "xxxxxxxx", "none", "null", "undefined", "redacted", "********",
  "<password>", "yourpasswordhere", "placeholder",
]);

const SKIP_EXT = new Set([
  ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".svg", ".mp3", ".mp4",
  ".avi", ".mov", ".wav", ".ogg", ".woff", ".woff2", ".ttf", ".eot", ".gz",
  ".xz", ".bz2", ".zip", ".7z", ".lz4",
]);

const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3 };

function shannon(s) {
  if (!s) return 0;
  const counts = {};
  for (const ch of s) counts[ch] = (counts[ch] || 0) + 1;
  const n = s.length;
  let h = 0;
  for (const c of Object.values(counts)) {
    const p = c / n;
    h -= p * Math.log2(p);
  }
  return h;
}

function lineCol(text, pos) {
  let line = 1;
  for (let i = 0; i < pos; i++) if (text[i] === "\n") line++;
  const lastNL = text.lastIndexOf("\n", pos - 1);
  return [line, pos - lastNL];
}

export function redact(s) {
  if (s.length <= 8) return s ? s[0] + "*".repeat(s.length - 1) : "";
  return s.slice(0, 4) + "*".repeat(s.length - 8) + s.slice(-4);
}

export function scanText(text, path = "<bytes>") {
  const findings = [];
  const seen = new Set();
  for (const [id, desc, sev, re, group, minEntropy] of DETECTORS) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(text)) !== null) {
      if (m[0].length === 0) { re.lastIndex++; continue; }
      const secret = (group ? m[group] : m[0]).trim();
      if (PLACEHOLDERS.has(secret.toLowerCase())) continue;
      if (minEntropy && shannon(secret) < minEntropy) continue;
      const start = group ? m.index + m[0].indexOf(m[group]) : m.index;
      const [line, col] = lineCol(text, start);
      const key = `${id}|${path}|${line}|${secret}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push({ detector: id, description: desc, severity: sev, path, line, column: col, secret });
    }
  }
  return findings;
}

function walk(p) {
  try {
    if (statSync(p).isDirectory()) {
      return readdirSync(p).flatMap((f) => walk(join(p, f)));
    }
    if (SKIP_EXT.has(extname(p).toLowerCase())) return [];
    return [p];
  } catch {
    return [];
  }
}

export function scan(target) {
  let findings = [];
  for (const f of walk(target)) {
    let t = "";
    try { t = readFileSync(f, "latin1"); } catch { continue; }
    findings = findings.concat(scanText(t, f.split("\\").join("/")));
  }
  findings.sort((a, b) =>
    (SEV_RANK[a.severity] - SEV_RANK[b.severity]) ||
    a.path.localeCompare(b.path) || (a.line - b.line));
  return { tool: "keyhunt", version: TOOL_VERSION, count: findings.length, findings };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const argv = process.argv.slice(2);
  const show = argv.includes("--show-secrets");
  if (argv.includes("--version")) { console.log("keyhunt", TOOL_VERSION); process.exit(0); }
  const target = argv.find((a) => !a.startsWith("-"));
  if (!target) { console.error("usage: keyhunt-js [--show-secrets] <path>"); process.exit(2); }
  const res = scan(target);
  if (!show) res.findings = res.findings.map((f) => ({ ...f, secret: redact(f.secret) }));
  console.log(JSON.stringify(res, null, 2));
  process.exit(res.count > 0 ? 1 : 0);
}
