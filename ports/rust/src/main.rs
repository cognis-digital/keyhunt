// keyhunt — Rust port of the core scan surface.
//
// Mirrors the Python CLI: recursively scans a file or directory for hardcoded
// secrets across the same detector families and emits the same JSON shape:
//   {"tool":"keyhunt","version":"...","count":N,"findings":[...]}
//
// Secrets are redacted by default; pass --show-secrets to reveal. Passive and
// offline by design — it only reads local files, never the network. Exit code
// 1 when secrets are found (CI gate), 0 when clean, 2 on usage error.
//
// Zero third-party crates: a tiny purpose-built matcher covers the fixed,
// well-known secret formats so the binary builds anywhere with just `cargo`.
use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::Path;
use std::process::exit;

const TOOL_VERSION: &str = "1.2.9";

struct Finding {
    detector: &'static str,
    description: &'static str,
    severity: &'static str,
    path: String,
    line: usize,
    column: usize,
    secret: String,
}

fn placeholders() -> HashSet<&'static str> {
    [
        "", "changeme", "password", "passwd", "example", "your_password",
        "xxxxxxxx", "none", "null", "undefined", "redacted", "********",
        "<password>", "yourpasswordhere", "placeholder",
    ]
    .into_iter()
    .collect()
}

fn skip_ext(ext: &str) -> bool {
    matches!(
        ext,
        "jpg" | "jpeg" | "png" | "gif" | "bmp" | "ico" | "svg" | "mp3" | "mp4"
            | "avi" | "mov" | "wav" | "ogg" | "woff" | "woff2" | "ttf" | "eot"
            | "gz" | "xz" | "bz2" | "zip" | "7z" | "lz4"
    )
}

fn shannon(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = std::collections::HashMap::new();
    for c in s.chars() {
        *counts.entry(c).or_insert(0u32) += 1;
    }
    let n = s.chars().count() as f64;
    counts
        .values()
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

fn line_col(text: &str, pos: usize) -> (usize, usize) {
    let pre = &text[..pos];
    let line = pre.matches('\n').count() + 1;
    let col = match pre.rfind('\n') {
        Some(i) => pos - i,
        None => pos + 1,
    };
    (line, col)
}

fn redact(s: &str) -> String {
    let n = s.len();
    if n <= 8 {
        if n == 0 {
            return String::new();
        }
        return format!("{}{}", &s[..1], "*".repeat(n - 1));
    }
    format!("{}{}{}", &s[..4], "*".repeat(n - 8), &s[n - 4..])
}

// A detector is a hand-rolled scanner over `text` returning (start, secret).
type Det = fn(&str) -> Vec<(usize, String)>;

fn find_substr_then(text: &str, marker: &str) -> Vec<usize> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(i) = text[from..].find(marker) {
        out.push(from + i);
        from += i + 1;
    }
    out
}

fn det_private_key(text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for m in &[
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN DSA PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "-----BEGIN PGP PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----",
    ] {
        for i in find_substr_then(text, m) {
            out.push((i, (*m).to_string()));
        }
    }
    out
}

fn det_aws_access(text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    for pfx in &["AKIA", "ASIA", "AGPA", "AIDA"] {
        for i in find_substr_then(text, pfx) {
            let end = i + 20;
            if end <= bytes.len() {
                let cand = &text[i..end];
                if cand[4..].chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()) {
                    out.push((i, cand.to_string()));
                }
            }
        }
    }
    out
}

fn det_gcp(text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for i in find_substr_then(text, "AIza") {
        let end = i + 39;
        if end <= text.len() {
            let cand = &text[i..end];
            if cand[4..]
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            {
                out.push((i, cand.to_string()));
            }
        }
    }
    out
}

fn det_github(text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for pfx in &["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"] {
        for i in find_substr_then(text, pfx) {
            let rest: String = text[i..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if rest.len() >= pfx.len() + 20 {
                out.push((i, rest));
            }
        }
    }
    out
}

// Generic `<key> = "value"` assignment scanner for password/api-key families.
fn assignment_secrets(text: &str, keys: &[&str]) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let lower = text.to_lowercase();
    for key in keys {
        for kpos in find_substr_then(&lower, key) {
            // walk forward to a quote, allowing : = and whitespace between
            let after = &text[kpos + key.len()..];
            let mut j = 0;
            let ab = after.as_bytes();
            while j < ab.len() && (ab[j] == b' ' || ab[j] == b'\t' || ab[j] == b':' || ab[j] == b'=')
            {
                j += 1;
            }
            if j < ab.len() && (ab[j] == b'"' || ab[j] == b'\'') {
                let quote = ab[j];
                let val_start = j + 1;
                if let Some(rel) = after[val_start..].find(quote as char) {
                    let val = &after[val_start..val_start + rel];
                    if (3..=128).contains(&val.len()) && !val.contains('\n') {
                        out.push((kpos + key.len() + val_start, val.to_string()));
                    }
                }
            }
        }
    }
    out
}

fn det_password(text: &str) -> Vec<(usize, String)> {
    assignment_secrets(text, &["password", "passwd", "pwd", "pass"])
}

struct DetMeta {
    id: &'static str,
    desc: &'static str,
    sev: &'static str,
    func: Det,
    min_entropy: f64,
}

fn detectors() -> Vec<DetMeta> {
    vec![
        DetMeta { id: "private-key", desc: "PEM private key block", sev: "critical", func: det_private_key, min_entropy: 0.0 },
        DetMeta { id: "aws-access-key", desc: "AWS access key id", sev: "critical", func: det_aws_access, min_entropy: 0.0 },
        DetMeta { id: "gcp-api-key", desc: "Google API key", sev: "high", func: det_gcp, min_entropy: 0.0 },
        DetMeta { id: "github-token", desc: "GitHub personal access / app token", sev: "critical", func: det_github, min_entropy: 0.0 },
        DetMeta { id: "hardcoded-password", desc: "Hardcoded password assignment", sev: "high", func: det_password, min_entropy: 0.0 },
    ]
}

fn scan_text(text: &str, path: &str, out: &mut Vec<Finding>) {
    let ph = placeholders();
    let mut seen: HashSet<String> = HashSet::new();
    for d in detectors() {
        for (start, secret) in (d.func)(text) {
            let s = secret.trim().to_string();
            if ph.contains(s.to_lowercase().as_str()) {
                continue;
            }
            if d.min_entropy > 0.0 && shannon(&s) < d.min_entropy {
                continue;
            }
            let (line, column) = line_col(text, start);
            let key = format!("{}|{}|{}|{}", d.id, path, line, s);
            if seen.contains(&key) {
                continue;
            }
            seen.insert(key);
            out.push(Finding {
                detector: d.id,
                description: d.desc,
                severity: d.sev,
                path: path.to_string(),
                line,
                column,
                secret: s,
            });
        }
    }
}

fn walk(p: &Path, out: &mut Vec<String>) {
    if p.is_dir() {
        if let Ok(rd) = fs::read_dir(p) {
            let mut entries: Vec<_> = rd.flatten().map(|e| e.path()).collect();
            entries.sort();
            for e in entries {
                walk(&e, out);
            }
        }
    } else if let Some(ext) = p.extension().and_then(|e| e.to_str()) {
        if !skip_ext(&ext.to_lowercase()) {
            if let Some(s) = p.to_str() {
                out.push(s.to_string());
            }
        }
    } else if let Some(s) = p.to_str() {
        out.push(s.to_string());
    }
}

fn json_escape(s: &str) -> String {
    let mut o = String::new();
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let show = args.iter().any(|a| a == "--show-secrets");
    if args.iter().any(|a| a == "--version") {
        println!("keyhunt {}", TOOL_VERSION);
        return;
    }
    let target = match args.iter().find(|a| !a.starts_with('-')) {
        Some(t) => t.clone(),
        None => {
            eprintln!("usage: keyhunt-rs [--show-secrets] <path>");
            exit(2);
        }
    };
    let p = Path::new(&target);
    if !p.exists() {
        eprintln!("keyhunt: path not found: {}", target);
        exit(2);
    }

    let mut files = Vec::new();
    walk(p, &mut files);
    let mut findings: Vec<Finding> = Vec::new();
    for f in &files {
        if let Ok(t) = fs::read_to_string(f) {
            scan_text(&t, &f.replace('\\', "/"), &mut findings);
        }
    }
    let rank = |s: &str| match s {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        _ => 3,
    };
    findings.sort_by(|a, b| {
        rank(a.severity)
            .cmp(&rank(b.severity))
            .then(a.path.cmp(&b.path))
            .then(a.line.cmp(&b.line))
    });

    let mut items = Vec::new();
    for f in &findings {
        let secret = if show { f.secret.clone() } else { redact(&f.secret) };
        items.push(format!(
            "    {{\"detector\":\"{}\",\"description\":\"{}\",\"severity\":\"{}\",\"path\":\"{}\",\"line\":{},\"column\":{},\"secret\":\"{}\"}}",
            f.detector, json_escape(f.description), f.severity, json_escape(&f.path),
            f.line, f.column, json_escape(&secret)
        ));
    }
    println!(
        "{{\n  \"tool\": \"keyhunt\",\n  \"version\": \"{}\",\n  \"count\": {},\n  \"findings\": [\n{}\n  ]\n}}",
        TOOL_VERSION,
        findings.len(),
        items.join(",\n")
    );
    if !findings.is_empty() {
        exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(text: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        scan_text(text, "x", &mut out);
        out
    }

    #[test]
    fn redact_masks_middle() {
        let r = redact("AKIAIOSFODNN7EXAMPLE");
        assert!(r.starts_with("AKIA"));
        assert_ne!(r, "AKIAIOSFODNN7EXAMPLE");
        assert!(r.contains('*'));
    }

    #[test]
    fn redact_short() {
        assert_eq!(redact(""), "");
        assert_eq!(redact("ab"), "a*");
    }

    #[test]
    fn clean_text_no_findings() {
        assert_eq!(run("log_level=info\njust text\n").len(), 0);
    }

    #[test]
    fn detects_aws_access_key() {
        let fs = run("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n");
        let f = fs.iter().find(|f| f.detector == "aws-access-key").unwrap();
        assert_eq!(f.secret, "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(f.severity, "critical");
    }

    #[test]
    fn placeholder_suppressed() {
        let fs = run("password = \"changeme\"\n");
        assert!(!fs.iter().any(|f| f.secret == "changeme"));
    }

    #[test]
    fn detects_password() {
        let fs = run("admin_password = \"Sup3rSecret!\"\n");
        assert!(fs.iter().any(|f| f.detector == "hardcoded-password"
            && f.secret == "Sup3rSecret!"));
    }

    #[test]
    fn detects_private_key() {
        let fs = run("-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n");
        assert_eq!(fs[0].detector, "private-key");
        assert_eq!(fs[0].severity, "critical");
    }

    #[test]
    fn detects_github_token() {
        let fs = run("GITHUB_TOKEN=ghp_ab12CD34ef56GH78ij90KL12mn34OP56qr78\n");
        assert!(fs.iter().any(|f| f.detector == "github-token"));
    }

    #[test]
    fn detects_gcp_key() {
        let fs = run("key=AIzaSyA1234567890abcdefghijklmnopqrstuv\n");
        assert!(fs.iter().any(|f| f.detector == "gcp-api-key"));
    }

    #[test]
    fn entropy_nonzero() {
        assert!(shannon("abcd1234XYZ!") > 2.0);
        assert_eq!(shannon(""), 0.0);
    }

    #[test]
    fn json_escape_quotes() {
        assert_eq!(json_escape("a\"b"), "a\\\"b");
    }
}
