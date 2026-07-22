#!/usr/bin/env python3
"""Concatenate static/src/*.js -> static/app.js (ordered). Run from repo or any cwd."""
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
SRC = HERE / "src"
OUT = HERE / "app.js"
ORDER = [
    "01_header_state.js",
    "02_dom_token_utils.js",
    "03_auth_gate.js",
    "04_api_status.js",
    "05_jobstore.js",
    "06_logs_dom.js",
    "07_card_html.js",
    "08_data_loaders.js",
    "09_actions.js",
    "10_sse_boot.js",
]

def build() -> str:
    missing = [n for n in ORDER if not (SRC / n).is_file()]
    if missing:
        raise SystemExit(f"missing src parts: {missing}")
    parts = [(SRC / n).read_text(encoding="utf-8") for n in ORDER]
    # ensure newline between parts if needed
    out = []
    for p in parts:
        if p and not p.endswith("\n"):
            p += "\n"
        out.append(p)
    return "".join(out)

def main():
    data = build()
    if not data.rstrip().endswith("})();"):
        print("WARN: bundle does not end with IIFE close", file=sys.stderr)
    OUT.write_text(data, encoding="utf-8")
    print(f"wrote {OUT} ({len(data.splitlines())} lines, {len(data)} bytes)")

if __name__ == "__main__":
    main()
