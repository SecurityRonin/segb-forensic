# 6. Emit canonical `forensicnomicon` Findings from the analyzer

Date: 2026-07-24
Status: Accepted

## Context

Every analyzer in the fleet must feed one uniform aggregation so ORCHESTRATION
(issen) and a future GUI render findings the same way, instead of N bespoke
`XxxAnalysis` types (`ronin-issen/CLAUDE.md` — "The Reporting Model —
`forensicnomicon::report`"). `forensicnomicon` is the KNOWLEDGE leaf every
analyzer depends **down** onto; it owns the shared `Finding`/`Severity`/
`Category`/`Observation` vocabulary. The fleet Dependency-Preference rule ("prefer
our own crates") also points at reusing this model rather than inventing a local
one.

The producer pattern the fleet prescribes: each analyzer **keeps** its own typed
anomaly enum (its domain knowledge) and **converts** to canonical Findings via
`impl Observation`, so `forensicnomicon` never enumerates every anomaly kind.

## Decision

`segb-forensic` keeps a typed `AnomalyKind` enum carrying the domain detail
(record index, byte offset, stored/computed CRC, prev/this timestamps) and
implements `forensicnomicon::report::Observation` for `Anomaly` (`forensic/
src/lib.rs`), so each anomaly becomes a canonical `Finding` via
`to_finding(Source)`:

- `severity()` → `Some(High|Medium|Low)` per kind.
- `code()` → published, scheme-prefixed SCREAMING-KEBAB contracts:
  `SEGB-CRC-MISMATCH`, `SEGB-TIMESTAMP-OUT-OF-ORDER`, `SEGB-TIMESTAMP-MISSING`.
- `evidence()` → a `Location::ByteOffset` at the record's payload offset.
- `note()` → a human sentence including the offending values (stored vs computed
  CRC, both timestamps).

The dependency is declared full-featured (`forensicnomicon = { version = "1",
features = ["std"] }` in the root `Cargo.toml`), consistent with the
batteries-included default. `#[non_exhaustive]` on `AnomalyKind` keeps the enum
additively evolvable.

## Consequences

- SEGB anomalies aggregate into a fleet `Report` beside NTFS, registry, EVTX,
  browser, etc., with no adapter — issen renders them uniformly.
- The anomaly `code`s are a **published contract**: a shipped code is never
  changed; new variants get new codes (fleet convention).
- `segb-forensic` tracks `forensicnomicon` major versions (the git log shows the
  0.5 → 0.11 → 1.0 progression, commits `f2c5aa6`, `af9af7f`); a breaking change
  in the reporting model is a coordinated fleet bump, not a local concern.
