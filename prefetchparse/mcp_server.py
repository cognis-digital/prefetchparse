"""PREFETCHPARSE MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations

import json
from pathlib import Path

from prefetchparse.core import (
    PrefetchParseError,
    parse_prefetch_file,
    scan_directory,
    triage_findings,
)


def _scan_to_json(target: str) -> str:
    """Parse *target* (file or directory) and return findings as a JSON string."""
    p = Path(target)
    if not p.exists():
        return json.dumps({"error": f"path does not exist: {target}"})
    if p.is_dir():
        try:
            parsed, errors = scan_directory(p)
        except ValueError as exc:
            return json.dumps({"error": str(exc)})
    else:
        try:
            parsed = [parse_prefetch_file(p)]
            errors = []
        except (PrefetchParseError, OSError) as exc:
            return json.dumps({"error": str(exc)})
    findings = triage_findings(parsed)
    return json.dumps({
        "parsed": len(parsed),
        "errors": [{"source": n, "message": m} for n, m in errors],
        "findings": [f.to_dict() for f in findings],
    })


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
        """Surface program-execution evidence from Windows Prefetch exports.

        Returns JSON findings.
        """
        if not target or not target.strip():
            return json.dumps({"error": "target path must not be empty"})
        return _scan_to_json(target.strip())

    app.run()
    return 0
