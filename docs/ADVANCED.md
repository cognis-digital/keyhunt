# keyhunt — Advanced usage

## CI gate (fail the build on findings)
```yaml
- run: pip install cognis-keyhunt
- run: keyhunt scan . --format sarif --out keyhunt.sarif --fail-on high
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: keyhunt.sarif }
```

## Pipe into a SIEM / webhook
```bash
keyhunt scan . --format json | python integrations/webhook.py --url "$COGNIS_WEBHOOK_URL"
```

## Drive it from an AI agent (MCP)
```jsonc
// claude_desktop_config.json
{ "mcpServers": { "keyhunt": { "command": "keyhunt", "args": ["mcp"] } } }
```

## Run a language port instead of Python
```bash
node ports/javascript/index.js .     # Node
( cd ports/go && go run . .. )        # Go single binary
( cd ports/rust && cargo run -- .. )  # Rust
```

## Query the bundled offline vulnerability DB
```bash
keyhunt vulndb --count                       # 262351 (no network)
keyhunt vulndb CVE-2021-44228                 # Log4Shell record
keyhunt vulndb --package log4j-core           # all vulns for a package
keyhunt vulndb --search "deserialization"     # summary search
```

## Refresh / air-gap the edge data feeds
```bash
keyhunt feeds list --domain vuln              # CISA KEV / EPSS / OSV / NVD ...
keyhunt feeds update cisa-kev epss            # fetch + cache (online)
keyhunt feeds get cisa-kev --offline          # serve cache only, no network
keyhunt feeds snapshot-export feeds.tar.gz    # sneakernet to an air gap
keyhunt feeds snapshot-import feeds.tar.gz    # restore inside the enclave
```

## Ports & services
Default service/forward ports: **8000** (HTTP API), **8080** (alt), **3000** (UI), **9090** (metrics).
