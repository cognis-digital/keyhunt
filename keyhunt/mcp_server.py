"""KEYHUNT MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations

from keyhunt.core import scan, to_json


def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-keyhunt[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-keyhunt[mcp]'")
        return 1
    app = FastMCP("keyhunt")

    @app.tool()
    def keyhunt_scan(target: str) -> str:
        """Scan firmware blobs and filesystem dumps for hardcoded keys.

        Detects private keys, API tokens, default creds, and weak RSA/ECC
        material.  Returns JSON findings.
        """
        try:
            return to_json(scan(target))
        except FileNotFoundError:
            return to_json([])  # return empty findings on bad path

    app.run()
    return 0
