"""Core Prefetch parsing + triage engine (standard library only).

Supports the uncompressed Windows Prefetch (.pf) layout for the common
versions:

    17  -> Windows XP / 2003
    23  -> Windows Vista / 7
    26  -> Windows 8 / 8.1
    30  -> Windows 10 (early)
    31  -> Windows 10 (1809+) / 11

Windows 10/11 store prefetch with a "MAM\\x04" prefix (Xpress-Huffman /
LZNT-style compression handled by the kernel API RtlDecompressBufferEx).
Decompressing that without ctypes/Windows APIs is out of scope for a pure
stdlib tool, so we detect it and report a clear, actionable error rather
than silently producing garbage. Feed decompressed exports (e.g. from
PECmd / a forensic suite) for those.

Everything here operates on artifacts the operator already owns. No network,
no execution, no attack surface — read-only analysis.
"""
from __future__ import annotations

import datetime as _dt
import struct
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Iterable

# FILETIME epoch: 1601-01-01 UTC, in 100-ns ticks.
_FILETIME_EPOCH = _dt.datetime(1601, 1, 1, tzinfo=_dt.timezone.utc)
_HUNDRED_NS = 10_000_000

# Per-version offsets into the file information block (relative to start of
# that block, which begins at byte 84 for all supported versions).
_FILEINFO_LAYOUT = {
    17: {"size": 68, "last_run": 36, "last_run_count": 1, "run_count": 60},
    23: {"size": 156, "last_run": 44, "last_run_count": 1, "run_count": 152},
    26: {"size": 224, "last_run": 44, "last_run_count": 8, "run_count": 208},
    30: {"size": 224, "last_run": 44, "last_run_count": 8, "run_count": 208},
    31: {"size": 224, "last_run": 44, "last_run_count": 8, "run_count": 200},
}

_FILEINFO_START = 84

# Directories legitimate first-party software lives in. Anything running from
# outside these is worth a closer look during triage.
_TRUSTED_DIR_HINTS = (
    "\\WINDOWS\\",
    "\\PROGRAM FILES\\",
    "\\PROGRAM FILES (X86)\\",
    "\\PROGRAMDATA\\MICROSOFT\\",
)

# Locations attackers love (living-off-the-land staging spots).
_SUSPECT_DIR_HINTS = (
    "\\TEMP\\",
    "\\APPDATA\\LOCAL\\TEMP\\",
    "\\DOWNLOADS\\",
    "\\RECYCLE",
    "\\PERFLOGS\\",
    "\\USERS\\PUBLIC\\",
    "\\WINDOWS\\TEMP\\",
)

# LOLBins — legitimate signed binaries frequently abused. Execution alone is
# not malicious; surfacing them just speeds analyst triage.
_LOLBINS = {
    "POWERSHELL.EXE", "CMD.EXE", "WSCRIPT.EXE", "CSCRIPT.EXE", "MSHTA.EXE",
    "RUNDLL32.EXE", "REGSVR32.EXE", "CERTUTIL.EXE", "BITSADMIN.EXE",
    "WMIC.EXE", "MSIEXEC.EXE", "INSTALLUTIL.EXE", "REGASM.EXE",
    "SCHTASKS.EXE", "AT.EXE", "PSEXEC.EXE", "MSBUILD.EXE", "CURL.EXE",
}


class PrefetchParseError(Exception):
    """Raised when a buffer is not a parseable (uncompressed) prefetch file."""


@dataclass
class PrefetchFile:
    source_name: str
    version: int
    executable: str
    prefetch_hash: str
    run_count: int
    last_run_times: list[str]  # ISO-8601 UTC strings, most recent first
    volume_count: int
    accessed_files: list[str] = field(default_factory=list)
    accessed_dirs: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Finding:
    source_name: str
    executable: str
    severity: str  # "high" | "medium" | "info"
    reasons: list[str]
    run_count: int
    last_run: str | None

    def to_dict(self) -> dict:
        return asdict(self)


_SEVERITY_ORDER = {"high": 0, "medium": 1, "info": 2}


def _filetime_to_iso(raw: int) -> str | None:
    if raw <= 0 or raw == 0xFFFFFFFFFFFFFFFF:
        return None
    try:
        ts = _FILETIME_EPOCH + _dt.timedelta(microseconds=raw / 10)
    except (OverflowError, OSError):
        return None
    # Reject absurd dates (corruption) — anything beyond a sane window.
    if ts.year < 2000 or ts.year > 2100:
        return None
    return ts.isoformat()


def _read_utf16(buf: bytes, offset: int, char_count: int) -> str:
    end = offset + char_count * 2
    if offset < 0 or end > len(buf):
        return ""
    return buf[offset:end].decode("utf-16-le", errors="replace").rstrip("\x00")


def parse_prefetch_bytes(data: bytes, source_name: str = "<bytes>") -> PrefetchFile:
    """Parse an *uncompressed* prefetch buffer into a PrefetchFile."""
    if len(data) < 84:
        raise PrefetchParseError(f"{source_name}: too small to be a prefetch file")

    if data[:3] == b"MAM":
        raise PrefetchParseError(
            f"{source_name}: MAM-compressed Win10/11 prefetch detected; "
            "decompress it first (e.g. via a forensic suite) and re-run."
        )

    version = struct.unpack_from("<I", data, 0)[0]
    signature = data[4:8]
    if signature != b"SCCA":
        raise PrefetchParseError(
            f"{source_name}: missing 'SCCA' signature (got {signature!r})"
        )
    if version not in _FILEINFO_LAYOUT:
        raise PrefetchParseError(f"{source_name}: unsupported version {version}")

    layout = _FILEINFO_LAYOUT[version]

    # Header: executable name (UTF-16, 60 bytes -> 30 chars) at 0x10, hash at 0x4C.
    executable = _read_utf16(data, 0x10, 30)
    prefetch_hash = "%08X" % struct.unpack_from("<I", data, 0x4C)[0]

    fi = _FILEINFO_START
    run_count = struct.unpack_from("<I", data, fi + layout["run_count"])[0]

    # Last-run times (array of FILETIME)
    last_run_times: list[str] = []
    lr_off = fi + layout["last_run"]
    for i in range(layout["last_run_count"]):
        off = lr_off + i * 8
        if off + 8 > len(data):
            break
        raw = struct.unpack_from("<Q", data, off)[0]
        iso = _filetime_to_iso(raw)
        if iso:
            last_run_times.append(iso)
    last_run_times.sort(reverse=True)

    # Volume information count lives in the header section pointers (0x70).
    try:
        volume_count = struct.unpack_from("<I", data, 0x70)[0]
        if volume_count > 1000:  # sanity guard against corrupt/misaligned reads
            volume_count = 0
    except struct.error:
        volume_count = 0

    # Filename strings section (offset 0x64, length 0x68). Contains the list of
    # files/dirs touched during the traced startup — rich execution evidence.
    accessed_files: list[str] = []
    accessed_dirs: list[str] = []
    try:
        names_off = struct.unpack_from("<I", data, 0x64)[0]
        names_len = struct.unpack_from("<I", data, 0x68)[0]
    except struct.error:
        names_off = names_len = 0
    if names_off and names_len and names_off + names_len <= len(data):
        blob = data[names_off:names_off + names_len].decode(
            "utf-16-le", errors="replace"
        )
        for entry in blob.split("\x00"):
            entry = entry.strip()
            if not entry:
                continue
            upper = entry.upper()
            if upper.endswith("\\") or "." not in entry.rsplit("\\", 1)[-1]:
                accessed_dirs.append(entry)
            else:
                accessed_files.append(entry)

    return PrefetchFile(
        source_name=source_name,
        version=version,
        executable=executable,
        prefetch_hash=prefetch_hash,
        run_count=run_count,
        last_run_times=last_run_times,
        volume_count=volume_count,
        accessed_files=accessed_files,
        accessed_dirs=accessed_dirs,
    )


def parse_prefetch_file(path: str | Path) -> PrefetchFile:
    p = Path(path)
    data = p.read_bytes()
    return parse_prefetch_bytes(data, source_name=p.name)


def scan_directory(path: str | Path) -> tuple[list[PrefetchFile], list[tuple[str, str]]]:
    """Parse every *.pf in a directory.

    Returns (parsed, errors) where errors is a list of (filename, message).
    """
    p = Path(path)
    parsed: list[PrefetchFile] = []
    errors: list[tuple[str, str]] = []
    for pf in sorted(p.glob("*.pf")):
        try:
            parsed.append(parse_prefetch_file(pf))
        except (PrefetchParseError, OSError) as exc:
            errors.append((pf.name, str(exc)))
    return parsed, errors


def _evidence_paths(pf: PrefetchFile) -> list[str]:
    """All path-like strings associated with this execution."""
    return list(pf.accessed_files) + list(pf.accessed_dirs)


def triage_findings(parsed: Iterable[PrefetchFile]) -> list[Finding]:
    """Risk-rank parsed prefetch records for analyst triage."""
    findings: list[Finding] = []
    for pf in parsed:
        reasons: list[str] = []
        severity = "info"
        exe = pf.executable.upper()
        evidence = "\n".join(_evidence_paths(pf)).upper()

        # LOLBin execution.
        if exe in _LOLBINS:
            reasons.append(f"Living-off-the-land binary executed ({pf.executable})")
            severity = "medium"

        # Ran from / loaded files in a suspicious staging directory.
        hit_suspect = [d for d in _SUSPECT_DIR_HINTS if d in evidence]
        if hit_suspect:
            reasons.append(
                "Image/loaded files reference suspicious path(s): "
                + ", ".join(sorted(set(hit_suspect)))
            )
            severity = "high"

        # Path evidence exists but never resolves into a known-good tree.
        if evidence and not any(h in evidence for h in _TRUSTED_DIR_HINTS):
            if not hit_suspect:
                reasons.append("No reference to a standard system/program directory")
                if severity == "info":
                    severity = "medium"

        # Single execution of a LOLBin is often the interesting one.
        if exe in _LOLBINS and pf.run_count <= 1:
            reasons.append("First/only observed execution")
            if severity != "high":
                severity = "high"

        # Hash mismatch heuristic: prefetch filename embeds NAME-HASH.pf. If the
        # parsed exe name doesn't appear in the source filename, flag it.
        base = pf.source_name.upper().rsplit(".PF", 1)[0]
        if exe and "-" in base and not base.startswith(exe.split(".")[0][:8]):
            reasons.append(
                "Prefetch filename does not match embedded executable name "
                "(possible renamed/spoofed binary)"
            )
            severity = "high"

        if not reasons:
            reasons.append("Normal first-party execution")

        findings.append(
            Finding(
                source_name=pf.source_name,
                executable=pf.executable,
                severity=severity,
                reasons=reasons,
                run_count=pf.run_count,
                last_run=pf.last_run_times[0] if pf.last_run_times else None,
            )
        )

    findings.sort(
        key=lambda f: (_SEVERITY_ORDER.get(f.severity, 9), f.source_name)
    )
    return findings
