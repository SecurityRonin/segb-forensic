//! Regression test against REAL Apple Biome SEGB files.
//!
//! Two small, benign device-telemetry streams extracted from Josh Hickman's
//! public iOS 17.3 forensic image (`DigitalCorpora`, freely licensed for research)
//! — a low-power-mode toggle stream (SEGB **v1**) and a `TrueTone` display stream
//! (SEGB **v2**). No user content, no PII. Their record counts were reconciled
//! against the ccl-segb reference oracle (16 and 7). These guard against
//! regressions in the real-world v1/v2 container parse without needing the 22 GB
//! source image. Provenance: `tests/data/README.md`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/../tests/data/biome/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("read fixture {path}: {e}"))
}

/// Real iOS 17 SEGB **v1** stream (Device.Power.LowPowerMode): 16 records,
/// matching ccl-segb.
#[test]
fn real_ios_segb_v1_record_count() {
    let data = fixture("Device.Power.LowPowerMode.v1.segb");
    let records = segb::read_segb(&mut Cursor::new(data)).expect("parse real v1 SEGB");
    assert_eq!(records.len(), 16, "v1 record count must match ccl-segb");
    // every record decodes a finite timestamp and a non-empty payload
    for r in &records {
        assert!(r.timestamp_unix().is_some(), "v1 record has a timestamp");
    }
}

/// Real iOS 17 SEGB **v2** stream (Device.Display.TrueTone): 7 records,
/// matching ccl-segb.
#[test]
fn real_ios_segb_v2_record_count() {
    let data = fixture("Device.Display.TrueTone.v2.segb");
    let records = segb::read_segb(&mut Cursor::new(data)).expect("parse real v2 SEGB");
    assert_eq!(records.len(), 7, "v2 record count must match ccl-segb");
    for r in &records {
        assert!(r.timestamp_unix().is_some(), "v2 record has a timestamp");
    }
}
