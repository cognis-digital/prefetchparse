# Demo 01 - Basic Prefetch triage

Two exported Windows Prefetch (`.pf`) files captured from a workstation under
investigation. Both are **version 23** (Windows 7 layout), which `prefetchparse`
parses directly with the standard library (Windows 10/11 prefetch is
MAM-compressed - decompress those first; the tool reports a clear error if you
feed a compressed file).

## Generate the demo input

The `.pf` files are binary, so a tiny stdlib-only generator reproduces the exact
bytes:

```
python demos/01-basic/make_demo.py
```

This writes `NOTEPAD.EXE-1B2C3D4E.pf` and `POWERSHELL.EXE-AF1C2D3E.pf` next to it.

## Files

| File | What it represents |
|------|--------------------|
| `NOTEPAD.EXE-1B2C3D4E.pf` | A benign baseline - `notepad.exe` run 42 times from `\Windows\System32`. |
| `POWERSHELL.EXE-AF1C2D3E.pf` | The interesting one - `powershell.exe` run **once**, whose traced startup loaded `PAYLOAD.PS1` from `\Users\Chris\AppData\Local\Temp\Stage\`. |

## Run it

```
python -m prefetchparse parse demos/01-basic --format table
```

Expected: NOTEPAD is `info` (normal first-party execution), POWERSHELL is
flagged **HIGH** for three reasons:

- Living-off-the-land binary executed (`POWERSHELL.EXE`)
- Image/loaded files reference a suspicious Temp staging path
- First/only observed execution

The process exits non-zero (1) because medium/high findings are present -
handy for wiring into CI / triage pipelines.

## Shareable report

```
python -m prefetchparse parse demos/01-basic --format html -o report.html
```

Produces a self-contained HTML report (inline CSS, severity-colored badges,
summary cards) you can hand to an analyst or attach to a ticket.

## JSON for pipelines

```
python -m prefetchparse parse demos/01-basic --format json
```

> All analysis is read-only on artifacts you already own. No network access, no
> execution of the parsed binaries.
