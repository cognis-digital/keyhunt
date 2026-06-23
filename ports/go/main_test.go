package main

import "testing"

func TestRedactMasksMiddle(t *testing.T) {
	r := redact("AKIAIOSFODNN7EXAMPLE")
	if r[:4] != "AKIA" {
		t.Fatalf("expected head AKIA, got %q", r)
	}
	if r == "AKIAIOSFODNN7EXAMPLE" {
		t.Fatal("secret was not redacted")
	}
}

func TestRedactShort(t *testing.T) {
	if redact("") != "" {
		t.Fatal("empty should stay empty")
	}
	if redact("ab") != "a*" {
		t.Fatalf("short redact wrong: %q", redact("ab"))
	}
}

func TestScanCleanText(t *testing.T) {
	fs := scanBytes([]byte("log_level=info\njust text\n"), "x")
	if len(fs) != 0 {
		t.Fatalf("expected no findings, got %d", len(fs))
	}
}

func TestScanAWSAccessKey(t *testing.T) {
	fs := scanBytes([]byte("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"), "x")
	var found bool
	for _, f := range fs {
		if f.Detector == "aws-access-key" {
			found = true
			if f.Secret != "AKIAIOSFODNN7EXAMPLE" {
				t.Fatalf("bad secret %q", f.Secret)
			}
		}
	}
	if !found {
		t.Fatal("aws-access-key not detected")
	}
}

func TestPlaceholderSuppressed(t *testing.T) {
	fs := scanBytes([]byte("password = \"changeme\"\n"), "x")
	for _, f := range fs {
		if f.Secret == "changeme" {
			t.Fatal("placeholder should be suppressed")
		}
	}
}

func TestConnectionURIPassword(t *testing.T) {
	fs := scanBytes([]byte("DB=mysql://u:hunter2pass@h:3306/db\n"), "x")
	var ok bool
	for _, f := range fs {
		if f.Detector == "connection-uri-password" && f.Secret == "hunter2pass" {
			ok = true
		}
	}
	if !ok {
		t.Fatal("connection uri password not extracted")
	}
}

func TestLowEntropyFiltered(t *testing.T) {
	fs := scanBytes([]byte("api_key = \"aaaaaaaaaaaaaaaa\"\n"), "x")
	for _, f := range fs {
		if f.Detector == "api-key-assignment" {
			t.Fatal("low-entropy key should be filtered")
		}
	}
}

func TestHighEntropyReported(t *testing.T) {
	fs := scanBytes([]byte("api_key = \"aB3xK9mZ2qR7tW1nP5vL8jH4dF6gS0cY\"\n"), "x")
	var ok bool
	for _, f := range fs {
		if f.Detector == "api-key-assignment" {
			ok = true
		}
	}
	if !ok {
		t.Fatal("high-entropy api key should be reported")
	}
}

func TestGitHubToken(t *testing.T) {
	fs := scanBytes([]byte("GITHUB_TOKEN=ghp_ab12CD34ef56GH78ij90KL12mn34OP56qr78\n"), "x")
	var ok bool
	for _, f := range fs {
		if f.Detector == "github-token" {
			ok = true
		}
	}
	if !ok {
		t.Fatal("github token not detected")
	}
}

func TestPrivateKey(t *testing.T) {
	fs := scanBytes([]byte("-----BEGIN RSA PRIVATE KEY-----\nabc\n"), "x")
	if len(fs) == 0 || fs[0].Detector != "private-key" {
		t.Fatal("private key not detected")
	}
	if fs[0].Severity != "critical" {
		t.Fatal("private key should be critical")
	}
}
