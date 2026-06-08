"""PREFETCHPARSE — surface program-execution evidence from Windows Prefetch.

A defensive forensics/triage tool. It parses Windows Prefetch (.pf) files —
the artifacts Windows writes under C:\\Windows\\Prefetch to speed up program
launches — and surfaces *what ran, when, and how often*. Spirit of PECmd.

Standard library only. Zero install.
"""
from .core import (
    PrefetchFile,
    PrefetchParseError,
    parse_prefetch_bytes,
    parse_prefetch_file,
    scan_directory,
    triage_findings,
    Finding,
)

TOOL_NAME = "prefetchparse"
TOOL_VERSION = "1.0.0"

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "PrefetchFile",
    "PrefetchParseError",
    "Finding",
    "parse_prefetch_bytes",
    "parse_prefetch_file",
    "scan_directory",
    "triage_findings",
]
