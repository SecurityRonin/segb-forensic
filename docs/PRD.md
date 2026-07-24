# segb-forensic — Design, Purpose & Scope

This is a **library** design/scope document, not a PRD. `segb-forensic` ships no
binary an examiner runs; it is two crates a developer *links*. Per the fleet
PRD & ADR Standard, a library records its "why does this exist" as a Purpose &
Scope doc, not a product-requirements fiction. The load-bearing decisions live in
[`docs/decisions/`](decisions/); this doc frames the whole.

## Purpose

Decode Apple **SEGB** (Biome) container files into forensic records, and grade
those records for the corruption and tamper signals a casual read would miss.

SEGB is the container the **Biome** subsystem uses to log user activity on macOS
and iOS — Safari history events, app launches, micro-location visits, the
`App.MenuItem` selection stream, and more. Each stream is an append-ordered log
of records carrying a state flag, one or two Cocoa timestamps, a CRC-32, and a
raw protobuf payload. The format is undocumented by Apple; the byte layout is
sourced from the community ccl-segb reference (ADR 0002).

## Who links this

- **Fleet ORCHESTRATION (issen, `useract-forensic`)** — consumes `segb-core`
  records and `segb-forensic` findings to place Biome activity on a correlated
  timeline. `segb-core`'s `App.MenuItem` walker feeds user-activity correlation.
- **Rust/DFIR developers** — who want a panic-free, dependency-light Biome reader
  (`segb-core` alone) or graded anomaly findings (`segb-forensic`) without
  building tooling from the raw format.

## What it does

Two crates, one workspace (ADR 0001):

| Crate | Role | Depends on | Emits |
|---|---|---|---|
| `segb-core` (lib `segb`) | reader / decoder | `thiserror` | `SegbRecord` — state, Cocoa→Unix timestamp, payload, stored vs computed CRC-32 |
| `segb-forensic` | anomaly analyzer | `segb-core`, `forensicnomicon` | graded `Finding`s |

- **`segb-core`** auto-detects SEGB **v1** (56-byte header, magic at offset 52,
  8-byte alignment) and **v2** (32-byte header, magic at offset 0, trailer of
  16-byte entries, 4-byte alignment) over any `Read + Seek` source, decodes every
  record, recomputes the CRC-32, converts Cocoa (`CFAbsoluteTime`) timestamps to
  Unix seconds, and ships a minimal protobuf field walker plus an `App.MenuItem`
  decoder. No `unsafe`, no C bindings.
- **`segb-forensic`** walks decoded records once and emits graded
  `forensicnomicon::report::Finding`s (ADR 0006):

  | Code | Severity | Meaning |
  |---|---|---|
  | `SEGB-CRC-MISMATCH` | High | a `Written` record's payload CRC-32 ≠ stored CRC — corruption or post-write edit |
  | `SEGB-TIMESTAMP-OUT-OF-ORDER` | Medium | a `Written` record older than a preceding one — append order broken |
  | `SEGB-TIMESTAMP-MISSING` | Low | a `Written` record with no finite timestamp |

  Findings apply to **`Written`** records only (ADR 0007). Findings are
  observations, never verdicts — the analyst concludes.

## Scope

- Read SEGB v1 and v2 containers to version-neutral records.
- Recompute and expose stored-vs-computed CRC-32 per record.
- Convert Cocoa timestamps to Unix seconds; expose record state and payload.
- Decode the `App.MenuItem` protobuf payload (inferred schema — ADR 0008).
- Grade CRC / timestamp-ordering / missing-timestamp anomalies on live records.

## Non-goals

- **No user-facing binary.** The end-user surface is the fleet CLI (issen); the
  in-repo `core/examples/` (`dump_structure`, `dump_menuitems`) and the `fuzz`
  targets are development aids, not shipped tools.
- **No protobuf runtime.** A hand-rolled field walker decodes the four standard
  protobuf wire types (varint, 64-bit, length-delimited, 32-bit) — of which the
  App.MenuItem payload uses only varint and length-delimited; no `prost`/`protobuf`
  codegen (ADR 0005, 0008).
- **No writing / repair.** The reader is read-only; the analyzer is a pure,
  side-effect-free function of decoded records.
- **No legal conclusions.** Anomalies are graded observations, aggregated via
  `forensicnomicon`; interpretation is the examiner's.
- **No independent RE of the format.** The layout follows ccl-segb; this repo
  does not attempt a second reverse-engineering.

## Validation approach

Correctness is proven against **real Apple data with an independent oracle**, not
only synthetic fixtures (see [`docs/validation.md`](validation.md)):

- **Container**: every SEGB file in Josh Hickman's public iOS 17.3 image (139 v1
  + 262 v2 = **401 files**) reconciles record-for-record with the ccl-segb
  reference — 401 PASS / 0 MISMATCH — plus a private 785-record macOS 15.7 v2
  stream matching exactly on count, states, and timestamps.
- **CRC-32**: byte-exact known-answer tests against Python `zlib.crc32`.
- **Analyzer**: zero false positives on the committed real iOS-17 benign
  fixtures; true-positive detection covered by constructed records. No
  independent *anomaly* oracle exists (ccl-segb is a reader), so the analyzer is
  validated by construction against documented invariants plus the ccl-segb
  `Written`-only CRC rule.
- **Panic-free**: `cargo-fuzz` targets over the v1/v2 containers, the protobuf
  walker, the `App.MenuItem` decoder, and the full `read_segb` → `audit`
  pipeline; invariant "must not panic."
- **Pending**: reconciliation of a real macOS Tahoe 26 `App.MenuItem/local` to
  confirm the inferred protobuf field mapping (ADR 0008).
