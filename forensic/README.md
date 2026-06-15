# segb-forensic

[![Crates.io](https://img.shields.io/crates/v/segb-forensic.svg)](https://crates.io/crates/segb-forensic)
[![Docs.rs](https://docs.rs/segb-forensic/badge.svg)](https://docs.rs/segb-forensic)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](../LICENSE)

**Anomaly analyzer for Apple SEGB (Biome) streams — graded forensic findings over the records [`segb-core`](https://crates.io/crates/segb-core) decodes.**

`segb-core` reads SEGB v1/v2 records; `segb-forensic` decides what's *suspicious* about them and emits it as the shared [`forensicnomicon::report`](https://crates.io/crates/forensicnomicon) model, so it drops straight into a fleet `Report` next to every other analyzer.

```rust
use std::io::Cursor;

let records = segb::read_segb(&mut Cursor::new(bytes))?;
for anomaly in segb_forensic::audit(&records) {
    // each Anomaly -> a canonical forensicnomicon Finding
    let finding = forensicnomicon::report::Observation::to_finding(
        &anomaly,
        forensicnomicon::report::Source {
            analyzer: "segb-forensic".into(),
            scope: "SEGB".into(),
            version: None,
        },
    );
    println!("{} ({:?}): {}", finding.code, finding.severity, finding.note);
}
# Ok::<(), segb::SegbError>(())
```

## What it detects

SEGB streams are append-ordered logs of state-tagged, CRC-protected records — a structure that makes a small set of tampering / corruption signals precise.

| Code | Severity | Meaning |
|---|---|---|
| `SEGB-CRC-MISMATCH` | High | payload CRC-32 ≠ stored CRC — corruption or a post-write edit |
| `SEGB-RECORD-DELETED` | Medium | a logically-`Deleted` record still present — recoverable deletion residue |
| `SEGB-TIMESTAMP-OUT-OF-ORDER` | Medium | a `Written` record older than a preceding one — append order broken (clock change / reordering) |
| `SEGB-TIMESTAMP-MISSING` | Low | a `Written` record with no finite timestamp |

Findings are **observations, never verdicts** — the analyst concludes.

## Trust but verify

Panic-free and `#![forbid(unsafe_code)]` (inherited from the workspace Paranoid Gatekeeper lints): SEGB files are untrusted, attacker-controllable input. The auditor is a pure function of already-decoded records — no I/O, no allocation surprises — and is exercised against constructed v1/v2 records covering each anomaly class plus clean and placeholder-state streams.

[Privacy Policy](https://securityronin.github.io/segb-core/privacy/) · [Terms of Service](https://securityronin.github.io/segb-core/terms/) · © 2026 Security Ronin Ltd
