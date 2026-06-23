// Smoke tests for the keyhunt Node port. Uses the built-in node:test runner —
// no third-party deps. Run with: node --test
import { test } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, mkdtempSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { scan, scanText, redact, TOOL_VERSION, DETECTORS } from "./index.js";

const DEMOS = join(import.meta.dirname ?? new URL(".", import.meta.url).pathname, "..", "..", "demos");

test("version is semver-ish", () => {
  assert.equal(TOOL_VERSION.split(".").length, 3);
});

test("detector set covers the core families", () => {
  const ids = new Set(DETECTORS.map((d) => d[0]));
  for (const want of ["private-key", "aws-access-key", "gcp-api-key",
    "github-token", "slack-token", "jwt", "connection-uri-password",
    "hardcoded-password", "api-key-assignment"]) {
    assert.ok(ids.has(want), `missing detector ${want}`);
  }
});

test("redaction keeps head and tail, masks the middle", () => {
  const r = redact("AKIAIOSFODNN7EXAMPLE");
  assert.ok(r.startsWith("AKIA"));
  assert.ok(r.includes("*"));
  assert.ok(!r.includes("OSFODNN7"));
});

test("redaction of short secrets", () => {
  assert.equal(redact(""), "");
  assert.equal(redact("ab"), "a*");
});

test("clean text yields no findings", () => {
  assert.equal(scanText("log_level=info\njust text\n").length, 0);
});

test("aws access key is detected and value extracted", () => {
  const fs = scanText('AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n', "x");
  const aws = fs.find((f) => f.detector === "aws-access-key");
  assert.ok(aws);
  assert.equal(aws.secret, "AKIAIOSFODNN7EXAMPLE");
});

test("placeholder password is suppressed", () => {
  const fs = scanText('password = "changeme"\n', "x");
  assert.equal(fs.filter((f) => f.secret === "changeme").length, 0);
});

test("connection-uri password is extracted", () => {
  const fs = scanText('DB=mysql://u:hunter2pass@h:3306/db\n', "x");
  const uri = fs.find((f) => f.detector === "connection-uri-password");
  assert.ok(uri);
  assert.equal(uri.secret, "hunter2pass");
});

test("low-entropy generic api key is filtered out", () => {
  const fs = scanText('api_key = "aaaaaaaaaaaaaaaa"\n', "x");
  assert.equal(fs.filter((f) => f.detector === "api-key-assignment").length, 0);
});

test("high-entropy generic api key is reported", () => {
  const fs = scanText('api_key = "aB3xK9mZ2qR7tW1nP5vL8jH4dF6gS0cY"\n', "x");
  assert.ok(fs.some((f) => f.detector === "api-key-assignment"));
});

test("scan of the iot-router demo matches the Python port shape", () => {
  const res = scan(join(DEMOS, "06-iot-router"));
  assert.equal(res.tool, "keyhunt");
  assert.ok(res.count >= 3);
  const ids = new Set(res.findings.map((f) => f.detector));
  assert.ok(ids.has("private-key"));
  assert.ok(ids.has("slack-token"));
  assert.ok(ids.has("hardcoded-password"));
});

test("clean-config demo reports nothing", () => {
  const res = scan(join(DEMOS, "10-clean-config"));
  assert.equal(res.count, 0);
});

test("findings are sorted critical-first", () => {
  const dir = mkdtempSync(join(tmpdir(), "kh-"));
  const file = join(dir, "mix.txt");
  writeFileSync(file,
    'password = "Sup3rSecret!"\n' +
    "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n");
  const res = scan(dir);
  assert.equal(res.findings[0].severity, "critical");
});
