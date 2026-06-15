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
        choices=("table", "json"),
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
        choices=("table", "json"),
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


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        # argparse already printed usage/error; map to exit code 2
        return int(exc.code) if exc.code is not None else 2

    if not args.command:
        parser.print_help(sys.stderr)
        return 2

    if args.command == "scan":
        # subcommand --format overrides global; fall back to "table"
        fmt = args.format or "table"

        if not os.path.exists(args.path):
            print(f"{TOOL_NAME}: error: path not found: {args.path}", file=sys.stderr)
            return 2

        try:
            findings = scan_path(args.path)
        except (OSError, FileNotFoundError) as exc:
            print(f"{TOOL_NAME}: error: {exc}", file=sys.stderr)
            return 2
        except Exception as exc:  # pragma: no cover - last-resort safety net
            print(f"{TOOL_NAME}: unexpected error: {exc}", file=sys.stderr)
            return 2

        findings = _filter_severity(findings, args.severity)

        if fmt == "json":
            print(_render_json(findings, args.show_secrets))
        else:
            print(_render_table(findings, args.show_secrets))

        return 1 if findings else 0

    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
