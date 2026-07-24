//! Behavioral tests for the SEGB anomaly auditor.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use forensicnomicon::report::{Observation, Severity, Source};
use segb::{EntryState, SegbRecord, SegbV1Record};
use segb_forensic::{audit, Anomaly, AnomalyKind};

/// Build a v1 record with explicit fields; CRC is consistent unless overridden.
fn rec(state: EntryState, ts: Option<f64>, stored_crc: u32, computed_crc: u32) -> SegbRecord {
    SegbRecord::V1(SegbV1Record {
        data_offset: 0x100,
        state,
        timestamp1_unix: ts,
        timestamp2_unix: ts,
        stored_crc32: stored_crc,
        computed_crc32: computed_crc,
        payload: vec![1, 2, 3],
    })
}

fn written(ts: f64) -> SegbRecord {
    rec(EntryState::Written, Some(ts), 0xAABB_CCDD, 0xAABB_CCDD)
}

#[test]
fn clean_stream_yields_no_anomalies() {
    let records = vec![written(1000.0), written(2000.0), written(3000.0)];
    assert!(
        audit(&records).is_empty(),
        "a clean append-ordered stream has no anomalies"
    );
}

#[test]
fn crc_mismatch_is_high_severity() {
    let records = vec![rec(
        EntryState::Written,
        Some(1000.0),
        0x1111_1111,
        0x2222_2222,
    )];
    let a = audit(&records);
    assert_eq!(a.len(), 1);
    assert_eq!(a[0].code(), "SEGB-CRC-MISMATCH");
    assert_eq!(a[0].severity(), Severity::High);
    assert!(matches!(
        a[0].kind,
        AnomalyKind::CrcMismatch {
            stored: 0x1111_1111,
            computed: 0x2222_2222,
            ..
        }
    ));
}

#[test]
fn deleted_record_is_not_an_anomaly() {
    // Deleted is the normal lifecycle state of a Biome append-log — never a
    // finding, even though its wiped payload makes its stored CRC mismatch.
    let records = vec![rec(
        EntryState::Deleted,
        Some(1000.0),
        0x1111_1111,
        0x2222_2222,
    )];
    assert!(
        audit(&records).is_empty(),
        "a Deleted record is normal, not an anomaly"
    );
}

#[test]
fn unknown_state_record_with_bad_crc_is_not_flagged() {
    // CRC is only validated for Written records; a non-Written record's CRC
    // mismatch must not produce a finding.
    let records = vec![rec(EntryState::Unknown, None, 0xAAAA_AAAA, 0xBBBB_BBBB)];
    assert!(audit(&records).is_empty());
}

#[test]
fn backwards_timestamp_breaks_append_order() {
    // second written record is older than the first
    let records = vec![written(5000.0), written(1000.0)];
    let a = audit(&records);
    assert_eq!(a.len(), 1, "exactly one out-of-order finding");
    assert_eq!(a[0].code(), "SEGB-TIMESTAMP-OUT-OF-ORDER");
    assert_eq!(a[0].kind.index(), 1);
}

#[test]
fn deleted_record_does_not_set_the_append_order_baseline() {
    // A deleted record between two written ones must not be treated as the
    // monotonic baseline (only Written records define append order).
    let records = vec![
        written(5000.0),
        rec(EntryState::Deleted, Some(9000.0), 0, 0),
        written(6000.0),
    ];
    // The Deleted record is skipped (no finding) and its 9000 timestamp must not
    // become the baseline; 6000 > 5000, so there is no out-of-order finding.
    let found = audit(&records);
    assert!(
        found.is_empty(),
        "{:?}",
        found.iter().map(Anomaly::code).collect::<Vec<_>>()
    );
}

#[test]
fn written_record_without_timestamp_is_flagged() {
    let records = vec![rec(EntryState::Written, None, 0xDEAD_BEEF, 0xDEAD_BEEF)];
    let a = audit(&records);
    assert_eq!(a.len(), 1);
    assert_eq!(a[0].code(), "SEGB-TIMESTAMP-MISSING");
    assert_eq!(a[0].severity(), Severity::Low);
}

#[test]
fn unknown_state_record_is_not_flagged_on_its_own() {
    // Unknown (v2 placeholder slot) with a good CRC is structurally normal.
    let records = vec![rec(EntryState::Unknown, None, 7, 7)];
    assert!(audit(&records).is_empty());
}

#[test]
fn anomaly_converts_to_canonical_finding() {
    let records = vec![rec(EntryState::Written, Some(1.0), 1, 2)];
    let a = audit(&records);
    let f = a[0].to_finding(Source {
        analyzer: "segb-forensic".to_string(),
        scope: "SEGB".to_string(),
        version: None,
    });
    assert!(f.code.starts_with("SEGB-"));
    assert_eq!(f.severity, Some(Severity::High));
    assert!(f.evidence.iter().any(|e| matches!(
        e.location,
        Some(forensicnomicon::report::Location::ByteOffset(_))
    )));
}

#[test]
fn timestamp_out_of_order_metadata_and_note() {
    // A backwards-stepping written record produces an out-of-order anomaly;
    // exercise its severity, index/offset accessors and canonical note.
    let records = vec![written(5000.0), written(1000.0)];
    let a = audit(&records);
    assert_eq!(a.len(), 1);
    let anomaly = &a[0];
    assert_eq!(anomaly.severity(), Severity::Medium);
    assert_eq!(anomaly.kind.index(), 1);
    assert_eq!(anomaly.kind.offset(), 0x100);
    let f = anomaly.to_finding(Source {
        analyzer: "segb-forensic".to_string(),
        scope: "SEGB".to_string(),
        version: None,
    });
    assert!(f.note.contains("append order"), "note: {}", f.note);
}

#[test]
fn missing_timestamp_metadata_and_note() {
    let records = vec![rec(EntryState::Written, None, 7, 7)];
    let a = audit(&records);
    assert_eq!(a.len(), 1);
    let anomaly = &a[0];
    assert_eq!(anomaly.kind.index(), 0);
    assert_eq!(anomaly.kind.offset(), 0x100);
    let f = anomaly.to_finding(Source {
        analyzer: "segb-forensic".to_string(),
        scope: "SEGB".to_string(),
        version: None,
    });
    assert!(f.note.contains("no finite timestamp"), "note: {}", f.note);
}

#[test]
fn crc_mismatch_index_and_offset_accessors() {
    let records = vec![rec(EntryState::Written, Some(1.0), 1, 2)];
    let a = audit(&records);
    assert_eq!(a[0].kind.index(), 0);
    assert_eq!(a[0].kind.offset(), 0x100);
}
