"""PREFETCHPARSE MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from prefetchparse.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-prefetchparse[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-prefetchparse[mcp]'")
        return 1
    app = FastMCP("prefetchparse")

    @app.tool()
    def prefetchparse_scan(target: str) -> str:
        """Surface program-execution evidence from Windows Prefetch exports. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
