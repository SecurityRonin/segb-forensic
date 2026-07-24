# 7. Audit `Written` records only — zero-false-positive design

Date: 2026-07-24
Status: Accepted

## Context

A SEGB/Biome stream is an append-ordered log. Records move through a lifecycle:
`Written` (live), then `Deleted` (logically removed, payload wiped), plus
`Unknown` placeholder slots in v2. The first draft of the analyzer flagged every
`Deleted` record and validated CRC across all states. Run against real iOS-17
Biome fixtures (Doer-Checker: validate against real data, not synthetic
fixtures), this was wrong: `Deleted` is the **normal majority** in a live stream
(12 of 16 records in the `Device.Power.LowPowerMode` v1 fixture), and a deleted
record's payload is wiped, so its stored CRC mismatches **by construction**. The
draft produced a false-positive on essentially every real stream — the exact
failure the fleet's "fail loud, never on the happy path only" and real-data
validation disciplines exist to catch.

The ccl-segb reference resolves this the same way: it prints a CRC verdict only
`if record.state == 1` (`Written`).

## Decision

`audit()` processes **`Written` records exclusively** — any non-`Written` state
is skipped before CRC and timestamp checks (`forensic/src/lib.rs`):

```rust
if record.state() != EntryState::Written { continue; }
```

All three anomaly checks (CRC mismatch, timestamp out-of-order tracked against
the last `Written` timestamp, missing finite timestamp) apply to live records
only. The skip also covers any future `#[non_exhaustive]` `EntryState` variant.

This was landed under strict TDD: a RED test asserting the analyzer stays silent
on real benign Biome streams (commit `0c163e3`), then the GREEN fix (commit
`b0594b3`). True-positive detection (bad CRC / backwards / missing timestamp on a
`Written` record) is covered separately by constructed records in
`forensic/tests/audit.rs`.

## Consequences

- On the committed real iOS-17 fixtures the analyzer emits **0 findings** — the
  correct result for ordinary device telemetry (`forensic/tests/real_fixtures.rs`,
  `docs/validation.md`).
- Deletion is treated as the normal append-log lifecycle, not an anomaly. If
  detecting anomalous *deletion patterns* is ever wanted, it is a new,
  separately-graded check — not a CRC failure on wiped payloads.
- There is no independent anomaly-detection oracle for SEGB (ccl-segb is a
  reader, not an analyzer), so the analyzer is validated by construction against
  the documented invariants plus the ccl-segb `Written`-only CRC rule and a
  zero-false-positive check on real benign data.
