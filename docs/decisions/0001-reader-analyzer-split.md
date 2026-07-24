# 1. Reader/analyzer split — `segb-core` reader, `segb-forensic` analyzer

Date: 2026-07-24
Status: Accepted

## Context

The repo has one job with two halves: decode Apple SEGB (Biome) container files
into records, and judge those records for forensic anomalies. These are
different concerns with different audiences. A Rust developer who only wants to
read a Biome stream (state, timestamp, payload, CRC) should not have to compile
an anomaly engine or pull in the fleet reporting model; an examiner who wants
graded findings needs both. Collapsing them into one crate would couple the
medium-agnostic decoder to the analyzer and force every consumer to take the
whole surface.

The fleet's Crate-structure standard (`ronin-issen/CLAUDE.md` — "reader/analyzer
split (core/ + forensic/)") makes this the default layout for every format:
`core/` = the raw reader, `forensic/` = the anomaly auditor.

## Decision

Ship two crates in one workspace (`Cargo.toml` `members = ["core", "forensic"]`):

1. **`segb-core`** (`core/`) — the reader. Decodes SEGB v1 and v2 over any
   `Read + Seek` source into a version-neutral `SegbRecord` (state, Cocoa→Unix
   timestamp, payload, stored vs computed CRC-32), plus a protobuf field walker
   and an `App.MenuItem` decoder. It makes **no judgments**.
2. **`segb-forensic`** (`forensic/`) — the analyzer. A side-effect-free `audit()`
   over already-decoded records that emits graded anomalies. It depends **down**
   on `segb-core` (`forensic/Cargo.toml`: `segb = { workspace = true }`), never
   the reverse.

The analyzer builds on `segb-core`'s public API rather than re-parsing raw
bytes, because the reader already exposes everything the SEGB audit needs —
per-record `state()`, `data_offset()`, `stored_crc32()`/`computed_crc32()`, and
`timestamp_unix()` (`core/src/lib.rs`). SEGB's simple append-log framing has no
slack, deleted-record residue, or normalized fields hidden behind the reader, so
the "drop below `-core`" escape hatch in the fleet standard is unnecessary here.

## Consequences

- `segb-core` stands alone on crates.io as a general Biome reader with only a
  `thiserror` dependency; `segb-forensic` drops straight into a fleet `Report`
  beside every other analyzer.
- The layering must stay acyclic: forensic meaning lives only in the analyzer,
  domain decoding only in the reader. A future audit that needs sub-record
  structure the reader hides would justify dropping the analyzer to raw bytes,
  per the fleet standard — not the case today.
- Two crates version in lockstep from the workspace (`[workspace.package]
  version = "0.2.0"`), so a reader change and its analyzer consumer release
  together.
