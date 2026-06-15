# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crates adhere
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `segb-forensic` `0.1.0` — the anomaly analyzer over `segb-core` records. Walks
  a parsed SEGB stream once and emits graded
  [`forensicnomicon::report`](https://crates.io/crates/forensicnomicon) findings:
  Findings apply to `Written` (live) records only — `Deleted`/`Unknown` records
  are the normal lifecycle of a Biome append-log (wiped payloads, CRC mismatches
  by construction), so auditing them would false-positive on every real stream
  (the ccl-segb reference likewise validates CRC for `Written` records only).
  - `SEGB-CRC-MISMATCH` (High) — a `Written` record's payload CRC-32 ≠ stored CRC
    (corruption or a post-write edit).
  - `SEGB-TIMESTAMP-OUT-OF-ORDER` (Medium) — a `Written` record older than a
    preceding one (append order broken — clock change or reordering).
  - `SEGB-TIMESTAMP-MISSING` (Low) — a `Written` record with no finite timestamp.
  - Validated for zero false positives against the committed real iOS-17 Biome
    fixtures (see `docs/validation.md`).

  Findings are observations, never verdicts. The auditor is a pure function of
  already-decoded records — no I/O — and is exercised against constructed v1/v2
  records covering each anomaly class plus clean and placeholder-state streams.

## [0.1.0] — 2026-06-14

### Added

- `segb-core` `0.1.0` — panic-free reader for Apple SEGB (Biome) container files.
  - Auto-detecting `read_segb()` entry point that decodes both SEGB **v1**
    (56-byte header, magic at offset 52, 8-byte alignment) and SEGB **v2**
    (32-byte header, magic at offset 0, 4-byte alignment) streams.
  - A version-neutral `SegbRecord` exposing state, primary timestamp
    (Cocoa→Unix), raw protobuf payload, stored vs computed CRC-32, and a
    `crc_ok()` check per record.
  - A minimal protobuf field walker (`proto`) and an `App.MenuItem` payload
    decoder (`menuitem`).
  - `#![forbid(unsafe_code)]`, bounds-checked reads, and a typed `SegbError`.
  - Validated against real Apple Biome data: 401/401 SEGB files (139 v1 + 262 v2)
    in Josh Hickman's public iOS 17.3 image reconciled against the `ccl-segb`
    reference oracle. See [`docs/validation.md`](docs/validation.md).

[Unreleased]: https://github.com/SecurityRonin/segb-forensic/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/SecurityRonin/segb-forensic/releases/tag/v0.1.0
