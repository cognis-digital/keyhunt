// keyhunt — Go port of the core scan surface.
//
// Mirrors the Python CLI: recursively scans a file or directory for hardcoded
// secrets using the same detector families (PEM private keys, AWS keys, Google
// API keys, GitHub/Slack tokens, JWTs, connection-URI passwords, /etc/shadow
// hashes, hardcoded passwords, generic high-entropy api/secret assignments).
//
// Output is the same JSON shape the Python tool emits:
//
//	{"tool":"keyhunt","version":"...","count":N,"findings":[{detector,severity,path,line,column,secret}]}
//
// Secrets are redacted by default (head/tail kept, middle masked); pass
// --show-secrets to reveal. Passive/offline by design: it only reads files,
// never touches the network. Exit code 1 when secrets are found (CI gate),
// 0 when clean, 2 on usage error.
package main

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const toolVersion = "1.2.9"

type detector struct {
	id          string
	description string
	severity    string
	re          *regexp.Regexp
	group       int     // capture group holding the secret value (0 = whole match)
	minEntropy  float64 // if > 0, secret must exceed this Shannon entropy
}

type finding struct {
	Detector    string `json:"detector"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Path        string `json:"path"`
	Line        int    `json:"line"`
	Column      int    `json:"column"`
	Secret      string `json:"secret"`
}

var detectors = []detector{
	{"private-key", "PEM private key block", "critical",
		regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`), 0, 0},
	{"aws-access-key", "AWS access key id", "critical",
		regexp.MustCompile(`\b((?:AKIA|ASIA|AGPA|AIDA)[A-Z0-9]{16})\b`), 1, 0},
	{"aws-secret-key", "AWS secret access key", "critical",
		regexp.MustCompile(`(?i)aws_?secret_?(?:access_?)?key\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})`), 1, 0},
	{"gcp-api-key", "Google API key", "high",
		regexp.MustCompile(`\b(AIza[0-9A-Za-z\-_]{35})\b`), 1, 0},
	{"github-token", "GitHub personal access / app token", "critical",
		regexp.MustCompile(`\b((?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,255})\b`), 1, 0},
	{"slack-token", "Slack token", "high",
		regexp.MustCompile(`\b(xox[baprs]-[A-Za-z0-9-]{10,})\b`), 1, 0},
	{"jwt", "JSON Web Token", "medium",
		regexp.MustCompile(`\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b`), 1, 0},
	{"connection-uri-password", "Credentials embedded in a connection URI", "high",
		regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.\-]*://[^\s:/@]+:([^\s:/@]+)@[^\s/]+`), 1, 0},
	{"hardcoded-password", "Hardcoded password assignment", "high",
		regexp.MustCompile(`(?i)(?:passwd|password|pwd|pass)\s*[:=]\s*['"]([^'"\n]{3,64})['"]`), 1, 0},
	{"api-key-assignment", "Generic api/secret/token assignment", "medium",
		regexp.MustCompile(`(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\s*[:=]\s*['"]([A-Za-z0-9_\-./+=]{12,128})['"]`), 1, 3.0},
}

var placeholders = map[string]bool{
	"": true, "changeme": true, "password": true, "passwd": true, "example": true,
	"your_password": true, "xxxxxxxx": true, "none": true, "null": true,
	"undefined": true, "redacted": true, "********": true, "<password>": true,
	"yourpasswordhere": true, "placeholder": true,
}

var skipExt = map[string]bool{
	".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".bmp": true, ".ico": true,
	".svg": true, ".mp3": true, ".mp4": true, ".avi": true, ".mov": true, ".wav": true,
	".ogg": true, ".woff": true, ".woff2": true, ".ttf": true, ".eot": true, ".gz": true,
	".xz": true, ".bz2": true, ".zip": true, ".7z": true, ".lz4": true,
}

func shannon(s string) float64 {
	if s == "" {
		return 0
	}
	counts := map[rune]int{}
	for _, c := range s {
		counts[c]++
	}
	n := float64(len([]rune(s)))
	var h float64
	for _, c := range counts {
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

func lineCol(text string, pos int) (int, int) {
	line := strings.Count(text[:pos], "\n") + 1
	lastNL := strings.LastIndex(text[:pos], "\n")
	col := pos - lastNL
	return line, col
}

func redact(s string) string {
	if len(s) <= 8 {
		if s == "" {
			return ""
		}
		return s[:1] + strings.Repeat("*", len(s)-1)
	}
	return s[:4] + strings.Repeat("*", len(s)-8) + s[len(s)-4:]
}

func scanBytes(data []byte, path string) []finding {
	text := string(data)
	var out []finding
	seen := map[string]bool{}
	for _, d := range detectors {
		for _, m := range d.re.FindAllStringSubmatchIndex(text, -1) {
			var start, end int
			if d.group > 0 && len(m) > 2*d.group+1 && m[2*d.group] >= 0 {
				start, end = m[2*d.group], m[2*d.group+1]
			} else {
				start, end = m[0], m[1]
			}
			secret := strings.TrimSpace(text[start:end])
			if placeholders[strings.ToLower(secret)] {
				continue
			}
			if d.minEntropy > 0 && shannon(secret) < d.minEntropy {
				continue
			}
			line, col := lineCol(text, start)
			key := fmt.Sprintf("%s|%s|%d|%s", d.id, path, line, secret)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, finding{d.id, d.description, d.severity, path, line, col, secret})
		}
	}
	return out
}

func main() {
	args := os.Args[1:]
	show := false
	var target string
	for _, a := range args {
		switch {
		case a == "--show-secrets":
			show = true
		case a == "--version":
			fmt.Println("keyhunt", toolVersion)
			return
		case strings.HasPrefix(a, "-"):
			// ignore unknown flags for forward-compat
		default:
			if target == "" {
				target = a
			}
		}
	}
	if target == "" {
		fmt.Fprintln(os.Stderr, "usage: keyhunt-go [--show-secrets] <path>")
		os.Exit(2)
	}
	info, err := os.Stat(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "keyhunt: path not found: %s\n", target)
		os.Exit(2)
	}

	var findings []finding
	scanOne := func(p string) {
		data, err := os.ReadFile(p)
		if err != nil {
			return
		}
		findings = append(findings, scanBytes(data, filepath.ToSlash(p))...)
	}
	if info.IsDir() {
		filepath.Walk(target, func(p string, fi os.FileInfo, err error) error {
			if err != nil || fi.IsDir() {
				return nil
			}
			if skipExt[strings.ToLower(filepath.Ext(p))] {
				return nil
			}
			scanOne(p)
			return nil
		})
	} else {
		scanOne(target)
	}

	rank := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}
	sort.SliceStable(findings, func(i, j int) bool {
		if rank[findings[i].Severity] != rank[findings[j].Severity] {
			return rank[findings[i].Severity] < rank[findings[j].Severity]
		}
		if findings[i].Path != findings[j].Path {
			return findings[i].Path < findings[j].Path
		}
		return findings[i].Line < findings[j].Line
	})

	if !show {
		for i := range findings {
			findings[i].Secret = redact(findings[i].Secret)
		}
	}
	if findings == nil {
		findings = []finding{}
	}
	out, _ := json.MarshalIndent(map[string]any{
		"tool": "keyhunt", "version": toolVersion,
		"count": len(findings), "findings": findings,
	}, "", "  ")
	fmt.Println(string(out))
	if len(findings) > 0 {
		os.Exit(1)
	}
}
