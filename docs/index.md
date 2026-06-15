# segb-forensic

**Apple SEGB (Biome) forensics for Rust — a panic-free reader (`segb-core`) plus
a graded anomaly analyzer (`segb-forensic`).**

SEGB is Apple's container format used by the **Biome** subsystem on macOS and
iOS to store user-activity streams. Each Biome stream carries a sequence of
state-tagged, CRC-protected records with one or two timestamps and a raw
protobuf payload. This workspace ships two crates:

- **`segb-core`** — the reader. Auto-detects SEGB **v1** and **v2**, decodes
  every record (state, Cocoa→Unix timestamp, payload, stored vs computed CRC-32),
  and provides a minimal protobuf field walker and an `App.MenuItem` decoder. No
  judgments — just bytes faithfully decoded.
- **`segb-forensic`** — the analyzer. Walks the decoded records once and emits
  graded [`forensicnomicon::report`](https://crates.io/crates/forensicnomicon)
  findings for CRC mismatch and timestamp-ordering anomalies (on `Written`
  records only).

```rust
use std::io::Cursor;

let records = segb::read_segb(&mut Cursor::new(bytes))?;
for anomaly in segb_forensic::audit(&records) {
    println!("{} ({:?})", anomaly.code(), anomaly.severity());
}
# Ok::<(), segb::SegbError>(())
```

## Anomaly codes

| Code | Severity | Meaning |
|---|---|---|
| `SEGB-CRC-MISMATCH` | High | a `Written` record's payload CRC-32 ≠ stored CRC — corruption or a post-write edit |
| `SEGB-TIMESTAMP-OUT-OF-ORDER` | Medium | a `Written` record older than a preceding one — append order broken |
| `SEGB-TIMESTAMP-MISSING` | Low | a `Written` record with no finite timestamp |

Findings are observations, never verdicts — the analyst concludes.

## Trust but verify

Both crates are `#![forbid(unsafe_code)]`, panic-free against
attacker-controllable input, fuzzed with `cargo-fuzz`, and validated against
real Apple Biome data. See [Validation](validation.md) for the 401/401
reconciliation against the `ccl-segb` reference oracle on Josh Hickman's public
iOS 17.3 image.

---

[Privacy Policy](https://securityronin.github.io/segb-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/segb-forensic/terms/) · © 2026 Security Ronin Ltd
