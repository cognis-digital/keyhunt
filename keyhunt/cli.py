"""KEYHUNT command-line interface.

Examples:
  # Scan an extracted firmware tree, human-readable table
  keyhunt scan /tmp/firmware_extracted

  # Emit JSON for CI / piping into jq
  keyhunt scan ./dump --format json | jq '.findings[] | select(.severity=="critical")'

  # Show full (unredacted) secrets - use with care
  keyhunt scan ./dump --show-secrets

Exit codes:
  0  no findings
  1  one or more secrets found (use as a CI gate)
  2  usage / runtime error
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import Finding, scan_path


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Scan firmware / filesystem dumps for hardcoded keys, "
        "tokens, and default credentials.",
        epilog="Point it at a router firmware extraction and get hardcoded "
        "creds. Exit code 1 means secrets were found (CI-friendly).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}"
    )
    parser.add_argument(
        "--format",
        choices=("table", "json", "sarif"),
        default="table",
        help="output format (default: table)",
    )

    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser(
        "scan",
        help="scan a file or directory tree for secrets",
        description="Recursively scan a path for hardcoded secrets.",
    )
    scan.add_argument("path", help="file or directory to scan")
    scan.add_argument(
        "--format",
        choices=("table", "json", "sarif"),
        default=None,
        help="output format (overrides global --format)",
    )
    scan.add_argument(
        "--severity",
        choices=("critical", "high", "medium", "low"),
        default="low",
        help="minimum severity to report (default: low = report everything)",
    )
    scan.add_argument(
        "--fail-on",
        choices=("critical", "high", "medium", "low"),
        default=None,
        help="exit non-zero only when a finding at or above this severity exists "
        "(default: any finding fails)",
    )
    scan.add_argument(
        "--out",
        metavar="FILE",
        default=None,
        help="write output to FILE instead of stdout (e.g. results.sarif)",
    )
    scan.add_argument(
        "--show-secrets",
        action="store_true",
        help="print full secret values instead of redacting them",
    )
    return parser


_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _filter_severity(findings: List[Finding], minimum: str) -> List[Finding]:
    cutoff = _SEV_RANK.get(minimum, 3)
    return [f for f in findings if _SEV_RANK.get(f.severity, 9) <= cutoff]


def _render_table(findings: List[Finding], show_secrets: bool) -> str:
    if not findings:
        return "No secrets found."
    lines = []
    counts: dict = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
        value = f.secret if show_secrets else f.redacted()
        loc = f"{f.path}:{f.line}:{f.column}"
        lines.append(
            f"[{f.severity.upper():8}] {f.detector:24} {loc}\n"
            f"             {f.description}\n"
            f"             secret: {value}"
        )
    summary_parts = [
        f"{counts[s]} {s}" for s in ("critical", "high", "medium", "low") if s in counts
    ]
    header = f"Found {len(findings)} secret(s): " + ", ".join(summary_parts)
    return header + "\n\n" + "\n\n".join(lines)


def _render_json(findings: List[Finding], show_secrets: bool) -> str:
    payload = {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "count": len(findings),
        "findings": [f.to_dict(redact=not show_secrets) for f in findings],
    }
    return json.dumps(payload, indent=2)


# SARIF 2.1.0 maps keyhunt severities onto the spec's "level" enum.
_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}


def _render_sarif(findings: List[Finding], show_secrets: bool) -> str:
    """Render findings as a SARIF 2.1.0 log (github/codeql-action ingestible).

    One SARIF `rule` per detector that fired; one `result` per finding. Secrets
    are redacted in the message unless --show-secrets is set, so the SARIF file
    is safe to upload to code-scanning dashboards.
    """
    rules: dict = {}
    results: List[dict] = []
    for f in findings:
        if f.detector not in rules:
            rules[f.detector] = {
                "id": f.detector,
                "name": f.detector.replace("-", " ").title().replace(" ", ""),
                "shortDescription": {"text": f.description},
                "defaultConfiguration": {
                    "level": _SARIF_LEVEL.get(f.severity, "warning")
                },
                "properties": {"keyhunt-severity": f.severity, "tags": ["security"]},
            }
        value = f.secret if show_secrets else f.redacted()
        results.append(
            {
                "ruleId": f.detector,
                "level": _SARIF_LEVEL.get(f.severity, "warning"),
                "message": {"text": f"{f.description} (secret: {value})"},
                "properties": {"keyhunt-severity": f.severity},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.path.replace("\\", "/")},
                            "region": {
                                "startLine": max(f.line, 1),
                                "startColumn": max(f.column, 1),
                            },
                        }
                    }
                ],
            }
        )
    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": TOOL_VERSION,
                        "informationUri": "https://github.com/cognis-digital/keyhunt",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 2

    if args.command == "scan":
        # subcommand --format overrides global; fall back to global default.
        fmt = args.format or "table"

        if not os.path.exists(args.path):
            print(f"{TOOL_NAME}: error: path not found: {args.path}", file=sys.stderr)
            return 2

        try:
            findings = scan_path(args.path)
        except Exception as exc:  # pragma: no cover - defensive
            print(f"{TOOL_NAME}: error: {exc}", file=sys.stderr)
            return 2

        findings = _filter_severity(findings, args.severity)

        if fmt == "json":
            output = _render_json(findings, args.show_secrets)
        elif fmt == "sarif":
            output = _render_sarif(findings, args.show_secrets)
        else:
            output = _render_table(findings, args.show_secrets)

        if args.out:
            try:
                with open(args.out, "w", encoding="utf-8") as fh:
                    fh.write(output + "\n")
            except OSError as exc:
                print(f"{TOOL_NAME}: error: cannot write {args.out}: {exc}",
                      file=sys.stderr)
                return 2
        else:
            print(output)

        # CI gate: --fail-on raises the bar; by default any finding fails.
        if args.fail_on:
            gating = _filter_severity(findings, args.fail_on)
            return 1 if gating else 0
        return 1 if findings else 0

    parser.print_help()
    return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
