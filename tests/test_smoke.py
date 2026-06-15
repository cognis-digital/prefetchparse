"""Smoke tests for prefetchparse - no network, no real Windows needed.

We synthesize valid uncompressed v23 prefetch buffers in-memory and assert the
parser + triage engine behave correctly.
"""
import datetime
import json
import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from prefetchparse import (  # noqa: E402
    TOOL_NAME,
    TOOL_VERSION,
    PrefetchParseError,
    parse_prefetch_bytes,
    triage_findings,
)
from prefetchparse.cli import main  # noqa: E402
from prefetchparse.core import (  # noqa: E402
    TOOL_NAME as _CORE_TOOL_NAME,
    TOOL_VERSION as _CORE_TOOL_VERSION,
    scan_directory,
)

_FILETIME_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)


def _to_ft(dt):
    return int((dt - _FILETIME_EPOCH).total_seconds() * 10_000_000)


def build_v23(exe_name, run_count, last_run_dt, names, prefetch_hash):
    FI_START = 84
    FI_SIZE = 156
    blob = ("\x00".join(names) + "\x00").encode("utf-16-le")
    names_off = FI_START + FI_SIZE
    names_len = len(blob)
    buf = bytearray(names_off + names_len)
    struct.pack_into("<I", buf, 0, 23)
    buf[4:8] = b"SCCA"
    struct.pack_into("<I", buf, 12, len(buf))
    exe_u = exe_name.encode("utf-16-le")[:60]
    buf[0x10:0x10 + len(exe_u)] = exe_u
    struct.pack_into("<I", buf, 0x4C, prefetch_hash)
    struct.pack_into("<I", buf, 0x64, names_off)
    struct.pack_into("<I", buf, 0x68, names_len)
    struct.pack_into("<I", buf, 0x70, 1)
    struct.pack_into("<Q", buf, FI_START + 44, _to_ft(last_run_dt))
    struct.pack_into("<I", buf, FI_START + 152, run_count)
    buf[names_off:names_off + names_len] = blob
    return bytes(buf)


@pytest.fixture
def suspicious_pf():
    return build_v23(
        "POWERSHELL.EXE", 1,
        datetime.datetime(2026, 6, 7, 14, 32, 11, tzinfo=datetime.timezone.utc),
        [r"\VOLUME{01}\WINDOWS\SYSTEM32\WINDOWSPOWERSHELL\V1.0\POWERSHELL.EXE",
         r"\VOLUME{01}\USERS\CHRIS\APPDATA\LOCAL\TEMP\STAGE\PAYLOAD.PS1"],
        0xAF1C2D3E,
    )


@pytest.fixture
def benign_pf():
    return build_v23(
        "NOTEPAD.EXE", 42,
        datetime.datetime(2026, 6, 6, 9, 5, 0, tzinfo=datetime.timezone.utc),
        [r"\VOLUME{01}\WINDOWS\SYSTEM32\NOTEPAD.EXE"],
        0x1B2C3D4E,
    )


def test_metadata():
    assert TOOL_NAME == "prefetchparse"
    assert TOOL_VERSION.count(".") == 2


def test_parse_core_fields(benign_pf):
    pf = parse_prefetch_bytes(benign_pf, "NOTEPAD.EXE-1B2C3D4E.pf")
    assert pf.version == 23
    assert pf.executable == "NOTEPAD.EXE"
    assert pf.run_count == 42
    assert pf.prefetch_hash == "1B2C3D4E"
    assert pf.last_run_times[0].startswith("2026-06-06T09:05:00")
    assert any("NOTEPAD.EXE" in f for f in pf.accessed_files)


def test_parse_accessed_paths(suspicious_pf):
    pf = parse_prefetch_bytes(suspicious_pf, "POWERSHELL.EXE-AF1C2D3E.pf")
    assert any("PAYLOAD.PS1" in f for f in pf.accessed_files)


def test_triage_flags_lolbin_and_temp(suspicious_pf):
    pf = parse_prefetch_bytes(suspicious_pf, "POWERSHELL.EXE-AF1C2D3E.pf")
    [finding] = triage_findings([pf])
    assert finding.severity == "high"
    joined = " ".join(finding.reasons).lower()
    assert "living-off-the-land" in joined
    assert "suspicious path" in joined


def test_triage_benign_is_info(benign_pf):
    pf = parse_prefetch_bytes(benign_pf, "NOTEPAD.EXE-1B2C3D4E.pf")
    [finding] = triage_findings([pf])
    assert finding.severity == "info"


def test_rejects_compressed():
    with pytest.raises(PrefetchParseError):
        parse_prefetch_bytes(b"MAM\x04" + b"\x00" * 200, "x.pf")


def test_rejects_bad_signature():
    bad = bytearray(200)
    struct.pack_into("<I", bad, 0, 23)
    bad[4:8] = b"XXXX"
    with pytest.raises(PrefetchParseError):
        parse_prefetch_bytes(bytes(bad), "x.pf")


def test_cli_json_and_exit_code(tmp_path, suspicious_pf, benign_pf, capsys):
    d = tmp_path / "pf"
    d.mkdir()
    (d / "POWERSHELL.EXE-AF1C2D3E.pf").write_bytes(suspicious_pf)
    (d / "NOTEPAD.EXE-1B2C3D4E.pf").write_bytes(benign_pf)
    rc = main(["parse", str(d), "--format", "json"])
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["summary"]["parsed"] == 2
    assert payload["summary"]["high"] == 1
    assert rc == 1


def test_cli_html_output(tmp_path, suspicious_pf):
    d = tmp_path / "pf"
    d.mkdir()
    (d / "POWERSHELL.EXE-AF1C2D3E.pf").write_bytes(suspicious_pf)
    out_html = tmp_path / "report.html"
    rc = main(["parse", str(d), "--format", "html", "-o", str(out_html)])
    assert rc == 1
    html = out_html.read_text(encoding="utf-8")
    assert html.startswith("<!DOCTYPE html>")
    assert "HIGH" in html
    assert "http://" not in html and "https://" not in html


def test_cli_no_parseable_input(tmp_path):
    rc = main(["parse", str(tmp_path / "nope.pf")])
    assert rc == 2


# ---------------------------------------------------------------------------
# Hardening tests: bad input, edge cases, error paths
# ---------------------------------------------------------------------------


def test_tool_constants_exported_from_core():
    """TOOL_NAME and TOOL_VERSION are directly importable from core."""
    assert _CORE_TOOL_NAME == "prefetchparse"
    assert _CORE_TOOL_VERSION.count(".") == 2


def test_rejects_empty_bytes():
    """A zero-length buffer raises PrefetchParseError, not an unhandled exception."""
    with pytest.raises(PrefetchParseError, match="too small"):
        parse_prefetch_bytes(b"", "empty.pf")


def test_rejects_truncated_bytes():
    """A buffer shorter than the 84-byte header minimum is rejected cleanly."""
    with pytest.raises(PrefetchParseError, match="too small"):
        parse_prefetch_bytes(b"\x00" * 83, "short.pf")


def test_rejects_unsupported_version():
    """An unrecognised version field produces a clear error."""
    buf = bytearray(200)
    struct.pack_into("<I", buf, 0, 99)   # version 99 — not supported
    buf[4:8] = b"SCCA"
    with pytest.raises(PrefetchParseError, match="unsupported version"):
        parse_prefetch_bytes(bytes(buf), "v99.pf")


def test_scan_directory_missing_path(tmp_path):
    """scan_directory raises ValueError for a non-existent path."""
    missing = tmp_path / "does_not_exist"
    with pytest.raises(ValueError, match="does not exist"):
        scan_directory(missing)


def test_scan_directory_file_not_dir(tmp_path, benign_pf):
    """scan_directory raises ValueError when given a file path instead of a dir."""
    f = tmp_path / "NOTEPAD.EXE-1B2C3D4E.pf"
    f.write_bytes(benign_pf)
    with pytest.raises(ValueError, match="not a directory"):
        scan_directory(f)


def test_scan_directory_empty_dir(tmp_path):
    """scan_directory on an empty directory returns ([], []) without errors."""
    parsed, errors = scan_directory(tmp_path)
    assert parsed == []
    assert errors == []


def test_cli_no_subcommand_returns_2(capsys):
    """Invoking the CLI with no subcommand prints help and returns exit code 2."""
    rc = main([])
    assert rc == 2


def test_triage_empty_input():
    """triage_findings on an empty list returns an empty list without crashing."""
    assert triage_findings([]) == []
