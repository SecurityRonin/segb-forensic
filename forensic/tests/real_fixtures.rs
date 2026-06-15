//! Real-data false-positive check: the auditor must stay silent on genuine,
//! benign Apple Biome streams. Uses the two committed iOS-17 regression fixtures
//! (a low-power-mode SEGB v1 stream and a `TrueTone` SEGB v2 stream) — both are
//! ordinary device telemetry with all-`Written` records, valid CRCs, and
//! monotonic timestamps, so a correct auditor reports nothing.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;

use segb_forensic::audit;

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/../tests/data/biome/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("read fixture {path}: {e}"))
}

fn audit_fixture(name: &str) -> Vec<String> {
    let records = segb::read_segb(&mut Cursor::new(fixture(name))).expect("parse real SEGB");
    audit(&records)
        .into_iter()
        .map(|a| a.code().to_string())
        .collect()
}

#[test]
fn real_ios17_v1_stream_has_no_anomalies() {
    let codes = audit_fixture("Device.Power.LowPowerMode.v1.segb");
    assert!(
        codes.is_empty(),
        "benign real v1 stream must produce no findings, got: {codes:?}"
    );
}

#[test]
fn real_ios17_v2_stream_has_no_anomalies() {
    let codes = audit_fixture("Device.Display.TrueTone.v2.segb");
    assert!(
        codes.is_empty(),
        "benign real v2 stream must produce no findings, got: {codes:?}"
    );
}
