#!/usr/bin/env python3
"""Minimal, dependency-free webhook forwarder for Cognis findings.

Reads JSON findings on stdin and POSTs them to a URL (SIEM/Slack/Jira bridge).
Usage:  <tool> scan . --format json | python integrations/webhook.py --url URL
"""
from __future__ import annotations

import argparse
import sys
import urllib.request


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--url", required=True, help="Destination URL (must be http/https)."
    )
    ap.add_argument("--header", action="append", default=[], help="'Key: Value'")
    args = ap.parse_args()

    url = args.url.strip()
    if not url.startswith(("http://", "https://")):
        print(
            f"error: --url must start with http:// or https://, got: {url!r}",
            file=sys.stderr,
        )
        return 2

    payload = sys.stdin.buffer.read()
    if not payload:
        print("error: no data on stdin; pipe JSON findings to this script.",
              file=sys.stderr)
        return 2

    req = urllib.request.Request(url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    for h in args.header:
        if ":" not in h:
            print(
                f"error: --header value must be in 'Key: Value' format, got: {h!r}",
                file=sys.stderr,
            )
            return 2
        k, _, v = h.partition(":")
        req.add_header(k.strip(), v.strip())

    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            print(f"posted {len(payload)} bytes -> {r.status}")
        return 0
    except Exception as e:
        print(f"webhook error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
