"""Hardening tests: edge cases, bad input, and error paths."""
from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from keyhunt.core import (  # noqa: E402
    TOOL_NAME,
    TOOL_VERSION,
    Finding,
    scan,
    scan_bytes,
    scan_file,
    scan_path,
    to_json,
    _shannon_entropy,
)
from keyhunt.cli import main  # noqa: E402


# ---------------------------------------------------------------------------
# core.py — edge cases
# ---------------------------------------------------------------------------


def test_scan_bytes_empty():
    """Empty input must return an empty list, not raise."""
    assert scan_bytes(b"") == []


def test_scan_bytes_binary_nul():
    """Null bytes should not crash the decoder."""
    assert scan_bytes(b"\x00\x01\x02\x03") == []


def test_scan_path_missing_root():
    """scan_path must raise FileNotFoundError on a non-existent path."""
    with pytest.raises(FileNotFoundError):
        scan_path("/no/such/path/keyhunt_xyz_missing")


def test_scan_alias_missing_root():
    """scan() alias must also raise FileNotFoundError on a non-existent path."""
    with pytest.raises(FileNotFoundError):
        scan("/no/such/path/keyhunt_xyz_missing")


def test_scan_path_empty_directory(tmp_path):
    """scan_path on an empty directory must return an empty list."""
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    assert scan_path(str(empty_dir)) == []


def test_scan_path_directory_with_skipped_extensions_only(tmp_path):
    """A directory containing only image files returns no findings."""
    img = tmp_path / "photo.jpg"
    img.write_bytes(b"\xff\xd8\xff" + b"A" * 100)
    findings = scan_path(str(tmp_path))
    assert findings == []


def test_scan_file_unreadable(tmp_path):
    """scan_file on an unreadable path returns [] without raising."""
    # Use a path that won't exist
    result = scan_file(str(tmp_path / "nonexistent.txt"))
    assert result == []


def test_shannon_entropy_empty_string():
    """_shannon_entropy on empty string must return 0.0 without ZeroDivisionError."""
    assert _shannon_entropy("") == 0.0


def test_shannon_entropy_single_char():
    """Single repeated character has entropy 0.0."""
    assert _shannon_entropy("aaaa") == 0.0


def test_tool_constants():
    """TOOL_NAME and TOOL_VERSION must be properly set in core."""
    assert TOOL_NAME == "keyhunt"
    assert TOOL_VERSION.count(".") == 2


# ---------------------------------------------------------------------------
# Finding.to_dict — redact flag
# ---------------------------------------------------------------------------


def test_to_dict_redact_false_includes_match():
    """to_dict(redact=False) must include the 'match' field with the real secret."""
    f = Finding(
        detector="aws-access-key",
        description="AWS access key id",
        severity="critical",
        path="test.txt",
        line=1,
        column=1,
        match="AKIAIOSFODNN7EXAMPLE",
        secret="AKIAIOSFODNN7EXAMPLE",
    )
    d = f.to_dict(redact=False)
    assert d["secret"] == "AKIAIOSFODNN7EXAMPLE"
    assert "match" in d


def test_to_dict_redact_true_masks_secret():
    """to_dict(redact=True) must mask the secret and omit 'match'."""
    f = Finding(
        detector="aws-access-key",
        description="AWS access key id",
        severity="critical",
        path="test.txt",
        line=1,
        column=1,
        match="AKIAIOSFODNN7EXAMPLE",
        secret="AKIAIOSFODNN7EXAMPLE",
    )
    d = f.to_dict(redact=True)
    assert d["secret"] != "AKIAIOSFODNN7EXAMPLE"
    assert "*" in d["secret"]
    assert "match" not in d


# ---------------------------------------------------------------------------
# to_json helper
# ---------------------------------------------------------------------------


def test_to_json_empty_findings():
    """to_json on an empty list must produce valid JSON with count=0."""
    result = to_json([])
    data = json.loads(result)
    assert data["count"] == 0
    assert data["findings"] == []
    assert data["tool"] == "keyhunt"


def test_to_json_redact_default():
    """to_json redacts secrets by default."""
    f = Finding(
        detector="aws-access-key",
        description="AWS access key id",
        severity="critical",
        path="x.txt",
        line=1,
        column=1,
        match="AKIAIOSFODNN7EXAMPLE",
        secret="AKIAIOSFODNN7EXAMPLE",
    )
    data = json.loads(to_json([f]))
    assert data["findings"][0]["secret"] != "AKIAIOSFODNN7EXAMPLE"


# ---------------------------------------------------------------------------
# cli.py — error paths
# ---------------------------------------------------------------------------


def test_cli_missing_path_returns_exit_two(capsys):
    """CLI must return exit code 2 and print to stderr when path is missing."""
    rc = main(["scan", "/absolutely/no/such/path/keyhunt_xyz"])
    err = capsys.readouterr().err
    assert rc == 2
    assert "not found" in err


def test_cli_no_subcommand_exits_two(capsys):
    """Calling CLI with no subcommand must return exit code 2."""
    rc = main([])
    assert rc == 2


def test_cli_severity_high_filters_lower(tmp_path, capsys):
    """--severity high must exclude medium/low findings."""
    # inject a medium finding
    code = tmp_path / "config.py"
    code.write_text('api_key = "SomeFakeKeyWith1234567890AbcXyz"\n')
    main(["scan", str(tmp_path), "--format", "json", "--severity", "high"])
    out = capsys.readouterr().out
    data = json.loads(out)
    for finding in data["findings"]:
        assert finding["severity"] in ("critical", "high")


def test_cli_json_empty_dir(tmp_path, capsys):
    """Scanning an empty directory should return exit 0 with count=0 JSON."""
    rc = main(["scan", str(tmp_path), "--format", "json"])
    out = capsys.readouterr().out
    assert rc == 0
    data = json.loads(out)
    assert data["count"] == 0


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
