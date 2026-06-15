# segb-forensic

[![segb-core](https://img.shields.io/crates/v/segb-core.svg?label=segb-core)](https://crates.io/crates/segb-core)
[![segb-forensic](https://img.shields.io/crates/v/segb-forensic.svg?label=segb-forensic)](https://crates.io/crates/segb-forensic)
[![Docs.rs](https://img.shields.io/docsrs/segb-core?label=docs.rs)](https://docs.rs/segb-core)
[![Rust 1.81+](https://img.shields.io/badge/rust-1.81%2B-orange.svg)](https://www.rust-lang.org)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

[![CI](https://github.com/SecurityRonin/segb-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/segb-forensic/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-100%25%20lines-brightgreen.svg)](https://github.com/SecurityRonin/segb-forensic/actions/workflows/ci.yml)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)
[![Security advisories](https://img.shields.io/badge/security-cargo--deny-informational.svg)](deny.toml)

**Apple SEGB (Biome) forensics for Rust — a panic-free reader that decodes the state-tagged, CRC-protected records of macOS/iOS user-activity streams, and a graded anomaly analyzer that flags the CRC mismatches, deletion residue, and out-of-order timestamps a casual read would miss.**

SEGB is the container the **Biome** subsystem uses to log user activity on macOS and iOS — Safari history events, app launches, micro-location visits, the `App.MenuItem` selection stream, and more. Each stream is an append-ordered log of records carrying a state flag, one or two timestamps, and a raw protobuf payload. Two crates, one workspace:

- **[`segb-core`](https://crates.io/crates/segb-core)** — the reader: auto-detects SEGB **v1** and **v2**, decodes every record (state, Cocoa→Unix timestamp, payload, stored vs computed CRC-32), and ships a minimal protobuf field walker plus an `App.MenuItem` decoder, over any `Read + Seek` source. No `unsafe`, no C bindings.
- **[`segb-forensic`](https://crates.io/crates/segb-forensic)** — the analyzer: turns those records into severity-graded [`forensicnomicon::report::Finding`](https://crates.io/crates/forensicnomicon)s, so a Biome stream's anomalies aggregate uniformly with every other artifact layer.

## Audit a SEGB stream in 30 seconds

```toml
[dependencies]
segb-forensic = "0.1"   # pulls in segb-core
```

```rust
use std::io::Cursor;
use forensicnomicon::report::{Observation, Source};

let records = segb::read_segb(&mut Cursor::new(bytes))?;
let src = Source { analyzer: "segb-forensic".into(), scope: "SEGB".into(), version: None };

for anomaly in segb_forensic::audit(&records) {
    // each Anomaly -> a canonical forensicnomicon Finding
    let finding = anomaly.to_finding(src.clone());
    println!("{} ({:?}): {}", finding.code, finding.severity, finding.note);
}
# Ok::<(), segb::SegbError>(())
```

### Anomaly codes

SEGB streams are append-ordered logs of state-tagged, CRC-protected records — a structure that makes a small set of tampering / corruption signals precise.

| Code | Severity | Meaning |
|---|---|---|
| `SEGB-CRC-MISMATCH` | High | payload CRC-32 ≠ stored CRC — corruption or a post-write edit |
| `SEGB-RECORD-DELETED` | Medium | a logically-`Deleted` record still present — recoverable deletion residue |
| `SEGB-TIMESTAMP-OUT-OF-ORDER` | Medium | a `Written` record older than a preceding one — append order broken (clock change / reordering) |
| `SEGB-TIMESTAMP-MISSING` | Low | a `Written` record with no finite timestamp |

Findings are **observations, never verdicts** — the analyst concludes.

## Just need the reader?

`segb-core` stands alone. Decode every record and walk the `App.MenuItem` payload without pulling in the analyzer:

```toml
[dependencies]
segb-core = "0.1"
```

```rust
use std::fs::File;
use std::io::BufReader;
use segb::{read_segb, menuitem::decode_app_menu_item};

let f = File::open("/path/to/App.MenuItem/local")?;
let mut r = BufReader::new(f);
for record in read_segb(&mut r)? {
    let item = decode_app_menu_item(record.payload(), record.timestamp_unix())?;
    println!("{:?} selected {:?}", item.application, item.menu_item);
}
# Ok::<(), segb::SegbError>(())
```

`read_segb()` rewinds the stream and detects the variant automatically:

| Variant | Magic location | Header | Alignment |
|---------|----------------|--------|-----------|
| SEGB v1 | last 4 bytes of the 56-byte header | 56 bytes | 8 bytes |
| SEGB v2 | first 4 bytes of the 32-byte header | 32 bytes | 4 bytes |

## The two-crate split

| Crate | Role | Depends on | Emits |
|---|---|---|---|
| [`segb-core`](https://crates.io/crates/segb-core) | reader / decoder | `thiserror` | `SegbRecord` (state, timestamp, payload, CRC) |
| [`segb-forensic`](https://crates.io/crates/segb-forensic) | anomaly analyzer | `segb-core`, `forensicnomicon` | graded `Finding`s |

The reader stays pure — it decodes bytes and makes no judgments. All *forensic meaning* lives in the analyzer, which is a side-effect-free function of already-decoded records. That separation is why `segb-core` is useful on its own and why `segb-forensic` drops straight into a fleet `Report` next to every other analyzer.

## Trust but verify

SEGB files are untrusted, attacker-controllable input, so the crates are hardened by construction:

- **`#![forbid(unsafe_code)]`** across the whole workspace — no `unsafe`, anywhere.
- **Panic-free** — every length, offset, trailer entry, and protobuf varint is bounds-checked before use; a crafted length field cannot drive an out-of-bounds read or an allocation bomb. Malformed input surfaces as a typed `SegbError`, never a silent default.
- **Fuzzed** — `cargo-fuzz` targets cover the v1 and v2 containers, the protobuf walker, the `App.MenuItem` decoder, and the full `read_segb` → `audit` pipeline; the invariant is "must not panic."
- **Validated against real Apple data** — every SEGB file in Josh Hickman's public iOS 17.3 image (139 v1 + 262 v2 = **401 files**) reconciles record-for-record with the [`ccl-segb`](https://github.com/cclgroupltd/ccl-segb) reference oracle: **401 PASS / 0 MISMATCH**. See [`docs/validation.md`](docs/validation.md).

## References

- **ccl-segb** (Alex Caithness / CCL Solutions) — the byte-layout reference: <https://github.com/cclgroupltd/ccl-segb>
- **Unit 42 research** (Palo Alto Networks, 2026): <https://unit42.paloaltonetworks.com/new-macos-artifact-discovered/>

---

[Privacy Policy](https://securityronin.github.io/segb-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/segb-forensic/terms/) · © 2026 Security Ronin Ltd
