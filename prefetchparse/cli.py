"""Command-line interface for PREFETCHPARSE.

Subcommands:
    parse  PATH ...   Parse one or more .pf files (or directories of them) and
                      emit an execution-evidence report with triage severity.

Output formats: table (default, human), json (pipelines), html (shareable UI).

Exit codes:
    0  ran cleanly, nothing flagged above "info"
    1  at least one medium/high triage finding (or per-file parse errors)
    2  usage / no parseable input
"""
from __future__ import annotations

import argparse
import html
import json
import sys
from pathlib import Path

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    PrefetchFile,
    PrefetchParseError,
    parse_prefetch_file,
    scan_directory,
    triage_findings,
)

_SEV_COLORS = {
    "high": "#c0392b",
    "medium": "#d68910",
    "info": "#2e86c1",
}


def _collect(paths: list[str]) -> tuple[list[PrefetchFile], list[tuple[str, str]]]:
    parsed: list[PrefetchFile] = []
    errors: list[tuple[str, str]] = []
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            d_parsed, d_errors = scan_directory(p)
            parsed.extend(d_parsed)
            errors.extend(d_errors)
        elif p.is_file():
            try:
                parsed.append(parse_prefetch_file(p))
            except (PrefetchParseError, OSError) as exc:
                errors.append((p.name, str(exc)))
        else:
            errors.append((raw, "no such file or directory"))
    return parsed, errors


def _render_table(parsed, errors, findings) -> str:
    lines: list[str] = []
    lines.append(f"{TOOL_NAME} {TOOL_VERSION} - Prefetch execution evidence")
    lines.append("=" * 64)
    lines.append(f"Parsed {len(parsed)} prefetch file(s), {len(errors)} error(s).")
    lines.append("")

    if parsed:
        lines.append("EXECUTION EVIDENCE")
        lines.append("-" * 64)
        lines.append(f"{'EXECUTABLE':<26}{'RUNS':>5}  {'LAST RUN (UTC)':<26}{'VER':>4}")
        for pf in sorted(parsed, key=lambda x: x.executable.upper()):
            last = pf.last_run_times[0] if pf.last_run_times else "-"
            lines.append(
                f"{pf.executable[:25]:<26}{pf.run_count:>5}  {last[:25]:<26}{pf.version:>4}"
            )
        lines.append("")

    by_sev = {"high": [], "medium": [], "info": []}
    for f in findings:
        by_sev.setdefault(f.severity, []).append(f)

    lines.append("TRIAGE")
    lines.append("-" * 64)
    lines.append(
        f"high={len(by_sev['high'])}  medium={len(by_sev['medium'])}  "
        f"info={len(by_sev['info'])}"
    )
    lines.append("")
    for f in findings:
        if f.severity == "info":
            continue
        lines.append(f"[{f.severity.upper()}] {f.executable}  ({f.source_name})")
        lines.append(f"    runs={f.run_count}  last_run={f.last_run or '-'}")
        for r in f.reasons:
            lines.append(f"    - {r}")
        lines.append("")

    if errors:
        lines.append("ERRORS / SKIPPED")
        lines.append("-" * 64)
        for name, msg in errors:
            lines.append(f"  {name}: {msg}")
        lines.append("")

    return "\n".join(lines)


def _render_json(parsed, errors, findings) -> str:
    payload = {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "summary": {
            "parsed": len(parsed),
            "errors": len(errors),
            "high": sum(1 for f in findings if f.severity == "high"),
            "medium": sum(1 for f in findings if f.severity == "medium"),
            "info": sum(1 for f in findings if f.severity == "info"),
        },
        "prefetch": [pf.to_dict() for pf in parsed],
        "findings": [f.to_dict() for f in findings],
        "errors": [{"source": n, "message": m} for n, m in errors],
    }
    return json.dumps(payload, indent=2)


def _render_html(parsed, errors, findings) -> str:
    e = html.escape
    counts = {
        "high": sum(1 for f in findings if f.severity == "high"),
        "medium": sum(1 for f in findings if f.severity == "medium"),
        "info": sum(1 for f in findings if f.severity == "info"),
    }
    rows = []
    for f in findings:
        color = _SEV_COLORS.get(f.severity, "#555")
        reasons = "<br>".join(e(r) for r in f.reasons)
        rows.append(
            f"<tr>"
            f"<td><span class='badge' style='background:{color}'>{e(f.severity.upper())}</span></td>"
            f"<td class='mono'>{e(f.executable)}</td>"
            f"<td>{f.run_count}</td>"
            f"<td class='mono'>{e(f.last_run or '-')}</td>"
            f"<td>{reasons}</td>"
            f"<td class='mono small'>{e(f.source_name)}</td>"
            f"</tr>"
        )
    err_rows = "".join(
        f"<tr><td class='mono'>{e(n)}</td><td>{e(m)}</td></tr>" for n, m in errors
    )
    err_block = (
        f"<h2>Errors / Skipped ({len(errors)})</h2>"
        f"<table class='grid'><thead><tr><th>Source</th><th>Message</th></tr></thead>"
        f"<tbody>{err_rows}</tbody></table>"
        if errors else ""
    )

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(TOOL_NAME)} report</title>
<style>
  :root {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; }}
  body {{ margin: 0; background: #0f1419; color: #e6e6e6; }}
  header {{ padding: 24px 32px; background: #161b22; border-bottom: 3px solid #2e86c1; }}
  h1 {{ margin: 0; font-size: 20px; }}
  .sub {{ color: #9aa5b1; font-size: 13px; margin-top: 4px; }}
  main {{ padding: 24px 32px; }}
  .cards {{ display: flex; gap: 16px; margin-bottom: 28px; flex-wrap: wrap; }}
  .card {{ background: #161b22; border-radius: 10px; padding: 16px 22px; min-width: 110px; }}
  .card .n {{ font-size: 30px; font-weight: 700; }}
  .card .l {{ font-size: 12px; color: #9aa5b1; text-transform: uppercase; letter-spacing: .06em; }}
  table {{ border-collapse: collapse; width: 100%; margin-bottom: 28px; }}
  th, td {{ text-align: left; padding: 9px 12px; border-bottom: 1px solid #222b35; font-size: 13px; vertical-align: top; }}
  th {{ color: #9aa5b1; text-transform: uppercase; font-size: 11px; letter-spacing: .05em; }}
  tr:hover td {{ background: #11161c; }}
  .mono {{ font-family: ui-monospace, Consolas, monospace; }}
  .small {{ font-size: 11px; color: #7d8896; }}
  .badge {{ color: #fff; padding: 2px 9px; border-radius: 999px; font-size: 11px; font-weight: 700; }}
  footer {{ padding: 16px 32px; color: #5c6773; font-size: 12px; }}
</style></head><body>
<header>
  <h1>{e(TOOL_NAME)} <span style="color:#9aa5b1">{e(TOOL_VERSION)}</span></h1>
  <div class="sub">Windows Prefetch execution-evidence report - defensive triage</div>
</header>
<main>
  <div class="cards">
    <div class="card"><div class="n">{len(parsed)}</div><div class="l">Parsed</div></div>
    <div class="card"><div class="n" style="color:{_SEV_COLORS['high']}">{counts['high']}</div><div class="l">High</div></div>
    <div class="card"><div class="n" style="color:{_SEV_COLORS['medium']}">{counts['medium']}</div><div class="l">Medium</div></div>
    <div class="card"><div class="n" style="color:{_SEV_COLORS['info']}">{counts['info']}</div><div class="l">Info</div></div>
    <div class="card"><div class="n">{len(errors)}</div><div class="l">Errors</div></div>
  </div>

  <h2>Triage findings</h2>
  <table class="grid"><thead><tr>
    <th>Severity</th><th>Executable</th><th>Runs</th><th>Last run (UTC)</th>
    <th>Reasons</th><th>Source</th>
  </tr></thead><tbody>
  {''.join(rows)}
  </tbody></table>

  {err_block}
</main>
<footer>Generated by {e(TOOL_NAME)} {e(TOOL_VERSION)} - read-only analysis of artifacts you own.</footer>
</body></html>
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Surface program-execution evidence from Windows Prefetch (.pf).",
    )
    parser.add_argument(
        "--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}"
    )
    sub = parser.add_subparsers(dest="command")

    p_parse = sub.add_parser(
        "parse", help="Parse .pf files/dirs and report execution evidence."
    )
    p_parse.add_argument("paths", nargs="+", help="One or more .pf files or directories.")
    p_parse.add_argument(
        "--format", choices=["table", "json", "html"], default="table"
    )
    p_parse.add_argument(
        "-o", "--output", help="Write report to this file instead of stdout."
    )

    args = parser.parse_args(argv)

    if args.command != "parse":
        parser.print_help()
        return 2

    parsed, errors = _collect(args.paths)
    if not parsed and errors:
        for name, msg in errors:
            print(f"error: {name}: {msg}", file=sys.stderr)
        return 2

    findings = triage_findings(parsed)

    if args.format == "json":
        report = _render_json(parsed, errors, findings)
    elif args.format == "html":
        report = _render_html(parsed, errors, findings)
    else:
        report = _render_table(parsed, errors, findings)

    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
        print(f"wrote {args.format} report -> {args.output}", file=sys.stderr)
    else:
        print(report)

    flagged = any(f.severity in ("high", "medium") for f in findings)
    return 1 if (flagged or errors) else 0


if __name__ == "__main__":
    raise SystemExit(main())
