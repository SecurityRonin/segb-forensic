#!/usr/bin/env python3
"""Differential validation harness: reconcile `segb-core` against the ccl-segb
reference on one or more SEGB files.

ccl-segb (Alex Caithness / CCL Group, github.com/cclgroupltd/ccl-segb) is the
canonical *independent* open-source reverse-engineering of the SEGB format —
mac_apt does not parse SEGB and iLEAPP vendors ccl-segb verbatim, so it is the
only independent open-source oracle available. This script makes the
reconciliation reproducible (it was previously run ad-hoc).

For every record it compares: count, per-record state, primary timestamp
(Unix seconds), and the CRC-32 verdict (stored == computed). A mismatch on any
exits non-zero.

Usage:
    CCL_SEGB_PATH=~/src/ccl-segb \\
      python3 scripts/diff_vs_ccl_segb.py tests/data/biome/*.segb

`CCL_SEGB_PATH` defaults to ~/src/ccl-segb. `SEGB_CORE_MANIFEST` may point at the
core crate's Cargo.toml (default: ./core/Cargo.toml relative to the repo root).
"""

import os
import re
import subprocess
import sys
import glob
from datetime import timezone

CCL_PATH = os.path.expanduser(os.environ.get("CCL_SEGB_PATH", "~/src/ccl-segb"))
sys.path.insert(0, CCL_PATH)

try:
    from ccl_segb.ccl_segb import read_segb_file
except ImportError as exc:  # pragma: no cover - environment dependent
    sys.exit(
        f"could not import ccl_segb from {CCL_PATH!r}: {exc}\n"
        "clone it: git clone https://github.com/cclgroupltd/ccl-segb "
        "and set CCL_SEGB_PATH"
    )

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST = os.environ.get("SEGB_CORE_MANIFEST", os.path.join(REPO_ROOT, "core", "Cargo.toml"))

LINE = re.compile(
    r"\[(?P<i>\d+)\] state=(?P<state>\w+) "
    r"ts_unix=(?:Some\((?P<ts>[\d.eE+-]+)\)|None) "
    r"crc_ok=(?P<crc>true|false)"
)


def ours(path):
    """Run segb-core's dump_structure example; return list of (state, ts, crc_ok)."""
    out = subprocess.run(
        ["cargo", "run", "-q", "--manifest-path", MANIFEST,
         "--example", "dump_structure", "--", path],
        capture_output=True, text=True, check=True,
    ).stdout
    recs = []
    for m in LINE.finditer(out):
        ts = float(m["ts"]) if m["ts"] else None
        recs.append((m["state"].lower(), ts, m["crc"] == "true"))
    return recs


def theirs(path):
    """Parse with ccl-segb; return list of (state, ts, crc_passed)."""
    recs = []
    for e in read_segb_file(path):
        # ccl-segb's COCOA_EPOCH is a *naive* datetime representing UTC, so the
        # naive result must be pinned to UTC before converting to a Unix epoch;
        # calling .timestamp() directly would reinterpret it in the local zone.
        ts = e.timestamp1.replace(tzinfo=timezone.utc).timestamp() if e.timestamp1 is not None else None
        recs.append((e.state.name.lower(), ts, bool(e.crc_passed)))
    return recs


def reconcile(path):
    a, b = ours(path), theirs(path)
    problems = []
    if len(a) != len(b):
        problems.append(f"count: ours={len(a)} ccl={len(b)}")
    for i, (ra, rb) in enumerate(zip(a, b)):
        if ra[0] != rb[0]:
            problems.append(f"[{i}] state: ours={ra[0]} ccl={rb[0]}")
        if (ra[1] is None) != (rb[1] is None) or (
            ra[1] is not None and abs(ra[1] - rb[1]) > 1e-3
        ):
            problems.append(f"[{i}] ts: ours={ra[1]} ccl={rb[1]}")
        if ra[2] != rb[2]:
            problems.append(f"[{i}] crc_ok: ours={ra[2]} ccl={rb[2]}")
    return len(a), problems


def main():
    files = sys.argv[1:] or sorted(glob.glob(os.path.join(REPO_ROOT, "tests", "data", "biome", "*.segb")))
    if not files:
        sys.exit("no SEGB files given and none found under tests/data/biome/")
    failed = 0
    for path in files:
        n, problems = reconcile(path)
        name = os.path.basename(path)
        if problems:
            failed += 1
            print(f"MISMATCH  {name} ({n} records)")
            for p in problems:
                print(f"    {p}")
        else:
            print(f"PASS      {name} ({n} records reconciled: count/state/timestamp/crc)")
    print(f"\n{len(files) - failed}/{len(files)} files reconciled with ccl-segb")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
