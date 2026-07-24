//! Integration tests for segb-core.
//!
//! These tests build synthetic SEGB v1 and v2 fixtures byte-by-byte following
//! the ccl-segb-documented layout, then verify that the reader recovers the
//! expected records exactly.
//!
//! # Fixture construction references
//!
//! All byte offsets and struct formats are sourced from:
//! - `ccl_segb/ccl_segb1.py` (version 0.3) by Alex Caithness / CCL Solutions
//! - `ccl_segb/ccl_segb2.py` (version 0.4) by Alex Caithness / CCL Solutions
//! - `ccl_segb/ccl_segb_common.py` — EntryState values, Cocoa epoch
//!
//! <https://github.com/cclgroupltd/ccl-segb>

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::doc_markdown,
    unused_imports
)]

use std::io::Cursor;

use segb::{
    common::{cocoa_to_unix_secs, EntryState, COCOA_EPOCH_UNIX_SECS},
    read_segb,
    segb1::{is_segb_v1, read_v1, HEADER_LENGTH as V1_HEADER_LEN},
    segb2::{is_segb_v2, read_v2},
    SegbRecord,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Produce the CRC-32 (zlib / IEEE polynomial) of `data`.
/// This mirrors Python's `zlib.crc32()`.
fn crc32(data: &[u8]) -> u32 {
    let mut c: u32 = 0xFFFF_FFFF;
    for &b in data {
        c ^= u32::from(b);
        for _ in 0..8 {
            if c & 1 == 1 {
                c = (c >> 1) ^ 0xEDB8_8320;
            } else {
                c >>= 1;
            }
        }
    }
    !c
}

/// Encode a little-endian i32.
fn le_i32(v: i32) -> [u8; 4] {
    v.to_le_bytes()
}

/// Encode a little-endian u32.
fn le_u32(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}

/// Encode a little-endian f64.
fn le_f64(v: f64) -> [u8; 8] {
    v.to_le_bytes()
}

/// Pad `buf` with zero bytes to the next multiple of `align`.
fn pad_to(buf: &mut Vec<u8>, align: usize) {
    let rem = buf.len() % align;
    if rem != 0 {
        buf.extend(std::iter::repeat(0u8).take(align - rem));
    }
}

// ---------------------------------------------------------------------------
// SEGB v1 fixture builder
// ---------------------------------------------------------------------------

/// Build a minimal valid SEGB v1 file with the given records.
///
/// Layout per ccl_segb1.py:
///
/// ```text
/// [56-byte header]
///   offset 0:  end_of_data_offset (u32 LE)
///   offset 4:  48 bytes of zeros (unknown)
///   offset 52: b"SEGB" (magic)
///
/// [records, each 8-byte aligned]
///   [32-byte record header]
///     offset 0: record_length (i32 LE)
///     offset 4: entry_state   (i32 LE)
///     offset 8: timestamp1    (f64 LE, Cocoa seconds)
///    offset 16: timestamp2    (f64 LE, Cocoa seconds)
///    offset 24: crc32         (u32 LE)
///    offset 28: unknown       (i32 LE)
///   [record_length bytes of payload]
///   [0–7 bytes of zero padding to 8-byte boundary]
/// ```
struct V1Record {
    state: i32,
    ts1_cocoa: f64,
    ts2_cocoa: f64,
    payload: Vec<u8>,
}

fn build_segb_v1(records: &[V1Record]) -> Vec<u8> {
    // Build record area first so we know end_of_data_offset.
    let mut body: Vec<u8> = Vec::new();
    for rec in records {
        let payload_len = rec.payload.len() as i32;
        let crc = crc32(&rec.payload);

        // 32-byte record header: "<iiddIi"
        body.extend_from_slice(&le_i32(payload_len));
        body.extend_from_slice(&le_i32(rec.state));
        body.extend_from_slice(&le_f64(rec.ts1_cocoa));
        body.extend_from_slice(&le_f64(rec.ts2_cocoa));
        body.extend_from_slice(&le_u32(crc));
        body.extend_from_slice(&le_i32(0)); // unknown
                                            // payload
        body.extend_from_slice(&rec.payload);
        // align to 8 bytes
        pad_to(&mut body, 8);
    }

    // end_of_data_offset = header_len + body_len
    let end_of_data = V1_HEADER_LEN as u32 + body.len() as u32;

    // Build full file: 56-byte header then body.
    let mut file: Vec<u8> = Vec::with_capacity(V1_HEADER_LEN + body.len());
    file.extend_from_slice(&le_u32(end_of_data)); // offset 0
    file.extend(std::iter::repeat(0u8).take(48)); // offset 4..52: unknown
    file.extend_from_slice(b"SEGB"); // offset 52: magic
    file.extend(body);
    file
}

// ---------------------------------------------------------------------------
// SEGB v2 fixture builder
// ---------------------------------------------------------------------------

struct V2Record {
    state: i32,
    ts_cocoa: f64,
    payload: Vec<u8>,
}

/// Build a minimal valid SEGB v2 file with the given records.
///
/// Layout per ccl_segb2.py:
///
/// ```text
/// [32-byte header]
///   offset 0: b"SEGB" (magic)
///   offset 4: entries_count (i32 LE)
///   offset 8: creation_timestamp (f64 LE, Cocoa seconds)
///  offset 16: 16 bytes of zeros (unknown padding)
///
/// [entry area] — each entry:
///   [8-byte entry sub-header]
///     offset 0: crc32   (u32 LE)
///     offset 4: unknown (i32 LE)
///   [payload bytes]
///   [0–3 bytes of zero padding to 4-byte alignment of end_offset]
///
/// [trailer] — entries_count × 16-byte trailer entries:
///   offset 0: end_offset  (i32 LE, relative to start of entry area = HEADER_LENGTH)
///   offset 4: entry_state (i32 LE)
///   offset 8: timestamp   (f64 LE, Cocoa seconds)
/// ```
fn build_segb_v2(records: &[V2Record]) -> Vec<u8> {
    let creation_ts: f64 = 800_000_000.0; // arbitrary Cocoa timestamp

    // Build entry area: sub-header + payload + 4-byte alignment per entry.
    let mut entry_area: Vec<u8> = Vec::new();
    // Collect end_offsets (relative to HEADER_LENGTH = start of entry area).
    let mut end_offsets: Vec<i32> = Vec::new();

    for rec in records {
        let crc = crc32(&rec.payload);
        // 8-byte sub-header
        entry_area.extend_from_slice(&le_u32(crc));
        entry_area.extend_from_slice(&le_i32(0)); // unknown
        entry_area.extend_from_slice(&rec.payload);
        // align to 4 bytes relative to current position in entry area
        let cur_end = entry_area.len() as i32;
        end_offsets.push(cur_end);
        let rem = cur_end as usize % 4;
        if rem != 0 {
            entry_area.extend(std::iter::repeat(0u8).take(4 - rem));
        }
    }

    // Build trailer entries.
    let mut trailer: Vec<u8> = Vec::new();
    for (i, rec) in records.iter().enumerate() {
        trailer.extend_from_slice(&le_i32(end_offsets[i])); // end_offset
        trailer.extend_from_slice(&le_i32(rec.state)); // state
        trailer.extend_from_slice(&le_f64(rec.ts_cocoa)); // timestamp
    }

    // Assemble the full file.
    let mut file: Vec<u8> = Vec::new();
    // 32-byte header
    file.extend_from_slice(b"SEGB"); // offset 0
    file.extend_from_slice(&le_i32(records.len() as i32)); // offset 4
    file.extend_from_slice(&le_f64(creation_ts)); // offset 8
    file.extend(std::iter::repeat(0u8).take(16)); // offset 16..32
                                                  // entry area
    file.extend(entry_area);
    // trailer
    file.extend(trailer);
    file
}

// ---------------------------------------------------------------------------
// SEGB v1 tests (RED stage: tests written before verifying implementation)
// ---------------------------------------------------------------------------

#[test]
fn test_v1_detect_magic() {
    // A valid v1 fixture must be detected as v1.
    let fixture = build_segb_v1(&[V1Record {
        state: 1,
        ts1_cocoa: 700_000_000.0,
        ts2_cocoa: 700_000_001.0,
        payload: b"hello".to_vec(),
    }]);
    let mut cur = Cursor::new(&fixture);
    assert!(
        is_segb_v1(&mut cur),
        "valid v1 fixture must be detected as v1"
    );
    assert!(
        !is_segb_v2(&mut cur),
        "v1 fixture must not be detected as v2"
    );
}

#[test]
fn test_v1_read_single_written_record() {
    let payload = b"test payload";
    let ts1: f64 = 700_000_000.0;
    let ts2: f64 = 700_000_001.5;

    let fixture = build_segb_v1(&[V1Record {
        state: 1, // Written
        ts1_cocoa: ts1,
        ts2_cocoa: ts2,
        payload: payload.to_vec(),
    }]);

    let mut cur = Cursor::new(&fixture);
    let records = read_v1(&mut cur).unwrap();

    assert_eq!(records.len(), 1, "must decode exactly one record");
    let rec = &records[0];

    assert_eq!(rec.state, EntryState::Written);
    assert_eq!(rec.payload, payload);
    assert!(rec.crc_ok(), "CRC must match");

    // Timestamps: Cocoa → Unix
    let expected_ts1 = ts1 + COCOA_EPOCH_UNIX_SECS;
    let expected_ts2 = ts2 + COCOA_EPOCH_UNIX_SECS;
    let got_ts1 = rec.timestamp1_unix.unwrap();
    let got_ts2 = rec.timestamp2_unix.unwrap();
    assert!(
        (got_ts1 - expected_ts1).abs() < 1e-6,
        "timestamp1 mismatch: got {got_ts1}, expected {expected_ts1}"
    );
    assert!(
        (got_ts2 - expected_ts2).abs() < 1e-6,
        "timestamp2 mismatch: got {got_ts2}, expected {expected_ts2}"
    );
}

#[test]
fn test_v1_read_multiple_records() {
    let payloads: &[&[u8]] = &[b"first", b"second record body", b"third!"];
    let records_in: Vec<V1Record> = payloads
        .iter()
        .enumerate()
        .map(|(i, p)| V1Record {
            state: if i == 1 { 3 } else { 1 }, // second record is Deleted
            ts1_cocoa: 700_000_000.0 + i as f64 * 60.0,
            ts2_cocoa: 700_000_000.0 + i as f64 * 60.0 + 1.0,
            payload: p.to_vec(),
        })
        .collect();

    let fixture = build_segb_v1(&records_in);
    let mut cur = Cursor::new(&fixture);
    let records = read_v1(&mut cur).unwrap();

    assert_eq!(records.len(), 3);
    assert_eq!(records[0].state, EntryState::Written);
    assert_eq!(records[1].state, EntryState::Deleted);
    assert_eq!(records[2].state, EntryState::Written);

    for (i, rec) in records.iter().enumerate() {
        assert_eq!(rec.payload, payloads[i], "payload mismatch at index {i}");
        assert!(rec.crc_ok(), "CRC must match for record {i}");
    }
}

#[test]
fn test_v1_empty_payload() {
    // Zero-length payload is valid per the format.
    let fixture = build_segb_v1(&[V1Record {
        state: 1,
        ts1_cocoa: 0.0,
        ts2_cocoa: 0.0,
        payload: vec![],
    }]);
    let mut cur = Cursor::new(&fixture);
    let records = read_v1(&mut cur).unwrap();
    assert_eq!(records.len(), 1);
    assert!(records[0].payload.is_empty());
    assert!(records[0].crc_ok());
}

#[test]
fn test_v1_bad_magic_returns_error() {
    let mut fixture = build_segb_v1(&[V1Record {
        state: 1,
        ts1_cocoa: 0.0,
        ts2_cocoa: 0.0,
        payload: b"x".to_vec(),
    }]);
    // Corrupt the magic at offset 52.
    fixture[52] = 0xFF;
    let mut cur = Cursor::new(&fixture);
    let result = read_v1(&mut cur);
    assert!(result.is_err(), "bad magic must return an error");
}

#[test]
fn test_v1_truncated_header_returns_error() {
    // Only provide 10 bytes — truncated before the full 56-byte header.
    let mut cur = Cursor::new(b"SEGB\x00\x00\x00\x00\x00\x00".as_ref());
    let result = read_v1(&mut cur);
    assert!(result.is_err(), "truncated header must return an error");
}

#[test]
fn test_v1_truncated_payload_returns_error() {
    // Build a valid fixture then truncate the file to the middle of the payload.
    let fixture = build_segb_v1(&[V1Record {
        state: 1,
        ts1_cocoa: 0.0,
        ts2_cocoa: 0.0,
        payload: b"hello world".to_vec(),
    }]);
    // Truncate at: header(56) + record_header(32) + 5 bytes (half the payload).
    let truncated = &fixture[..56 + 32 + 5];
    let mut cur = Cursor::new(truncated);
    let result = read_v1(&mut cur);
    assert!(result.is_err(), "truncated payload must return an error");
}

#[test]
fn test_v1_alignment_correctness() {
    // Two records whose combined length tests 8-byte alignment:
    // payload 3 bytes → padded to 8; payload 5 bytes → padded to 8.
    let fixture = build_segb_v1(&[
        V1Record {
            state: 1,
            ts1_cocoa: 0.0,
            ts2_cocoa: 0.0,
            payload: b"abc".to_vec(),
        },
        V1Record {
            state: 1,
            ts1_cocoa: 1.0,
            ts2_cocoa: 2.0,
            payload: b"12345".to_vec(),
        },
    ]);
    let mut cur = Cursor::new(&fixture);
    let records = read_v1(&mut cur).unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].payload, b"abc");
    assert_eq!(records[1].payload, b"12345");
}

// ---------------------------------------------------------------------------
// SEGB v2 tests
// ---------------------------------------------------------------------------

#[test]
fn test_v2_detect_magic() {
    let fixture = build_segb_v2(&[V2Record {
        state: 1,
        ts_cocoa: 700_000_000.0,
        payload: b"hello v2".to_vec(),
    }]);
    let mut cur = Cursor::new(&fixture);
    assert!(
        is_segb_v2(&mut cur),
        "valid v2 fixture must be detected as v2"
    );
    assert!(
        !is_segb_v1(&mut cur),
        "v2 fixture must not be detected as v1"
    );
}

#[test]
fn test_v2_read_single_written_record() {
    let payload = b"v2 test payload bytes";
    let ts_cocoa: f64 = 750_000_000.0;

    let fixture = build_segb_v2(&[V2Record {
        state: 1,
        ts_cocoa,
        payload: payload.to_vec(),
    }]);

    let mut cur = Cursor::new(&fixture);
    let records = read_v2(&mut cur).unwrap();

    assert_eq!(records.len(), 1);
    let rec = &records[0];
    assert_eq!(rec.state, EntryState::Written);
    assert_eq!(rec.payload, payload);
    assert!(rec.crc_ok(), "CRC must match");

    let expected_unix = ts_cocoa + COCOA_EPOCH_UNIX_SECS;
    let got_unix = rec.timestamp_unix.unwrap();
    assert!(
        (got_unix - expected_unix).abs() < 1e-6,
        "timestamp mismatch: got {got_unix}, expected {expected_unix}"
    );
}

#[test]
fn test_v2_read_multiple_records() {
    let payloads: &[&[u8]] = &[b"alpha", b"beta payload here", b"gamma!!"];
    let records_in: Vec<V2Record> = payloads
        .iter()
        .enumerate()
        .map(|(i, p)| V2Record {
            state: if i == 2 { 3 } else { 1 }, // third is Deleted
            ts_cocoa: 750_000_000.0 + i as f64 * 30.0,
            payload: p.to_vec(),
        })
        .collect();

    let fixture = build_segb_v2(&records_in);
    let mut cur = Cursor::new(&fixture);
    let records = read_v2(&mut cur).unwrap();

    assert_eq!(records.len(), 3);
    for (i, rec) in records.iter().enumerate() {
        assert_eq!(rec.payload, payloads[i], "payload mismatch at index {i}");
        assert!(rec.crc_ok(), "CRC must match for record {i}");
    }
    assert_eq!(records[2].state, EntryState::Deleted);
}

#[test]
fn test_v2_empty_payload() {
    let fixture = build_segb_v2(&[V2Record {
        state: 1,
        ts_cocoa: 0.0,
        payload: vec![],
    }]);
    let mut cur = Cursor::new(&fixture);
    let records = read_v2(&mut cur).unwrap();
    assert_eq!(records.len(), 1);
    assert!(records[0].payload.is_empty());
    assert!(records[0].crc_ok());
}

#[test]
fn test_v2_bad_magic_returns_error() {
    let mut fixture = build_segb_v2(&[V2Record {
        state: 1,
        ts_cocoa: 0.0,
        payload: b"x".to_vec(),
    }]);
    // Corrupt the magic at offset 0.
    fixture[0] = 0xFF;
    let mut cur = Cursor::new(&fixture);
    let result = read_v2(&mut cur);
    assert!(result.is_err(), "bad magic must return an error");
}

#[test]
fn test_v2_negative_entry_count_returns_error() {
    let mut fixture = build_segb_v2(&[V2Record {
        state: 1,
        ts_cocoa: 0.0,
        payload: b"x".to_vec(),
    }]);
    // entries_count is at offset 4 as i32 LE. Set to -1.
    fixture[4..8].copy_from_slice(&(-1i32).to_le_bytes());
    let mut cur = Cursor::new(&fixture);
    let result = read_v2(&mut cur);
    assert!(
        result.is_err(),
        "negative entries_count must return an error"
    );
}

#[test]
fn test_v2_truncated_header_returns_error() {
    let mut cur = Cursor::new(b"SEGB\x01\x00\x00".as_ref()); // only 7 bytes
    let result = read_v2(&mut cur);
    assert!(result.is_err(), "truncated header must return an error");
}

// ---------------------------------------------------------------------------
// Auto-detect dispatch via read_segb
// ---------------------------------------------------------------------------

#[test]
fn test_auto_detect_v1() {
    let fixture = build_segb_v1(&[V1Record {
        state: 1,
        ts1_cocoa: 700_000_000.0,
        ts2_cocoa: 700_000_001.0,
        payload: b"dispatch v1".to_vec(),
    }]);
    let mut cur = Cursor::new(&fixture);
    let records = read_segb(&mut cur).unwrap();
    assert_eq!(records.len(), 1);
    assert!(matches!(records[0], SegbRecord::V1(_)));
    assert_eq!(records[0].payload(), b"dispatch v1");
}

#[test]
fn test_auto_detect_v2() {
    let fixture = build_segb_v2(&[V2Record {
        state: 1,
        ts_cocoa: 750_000_000.0,
        payload: b"dispatch v2".to_vec(),
    }]);
    let mut cur = Cursor::new(&fixture);
    let records = read_segb(&mut cur).unwrap();
    assert_eq!(records.len(), 1);
    assert!(matches!(records[0], SegbRecord::V2(_)));
    assert_eq!(records[0].payload(), b"dispatch v2");
}

#[test]
fn test_auto_detect_not_segb_returns_error() {
    let mut cur = Cursor::new(b"NOT_SEGB_FILE\x00\x00\x00\x00\x00".as_ref());
    let result = read_segb(&mut cur);
    assert!(result.is_err(), "non-SEGB input must return an error");
}

// ---------------------------------------------------------------------------
// Protobuf field walker tests
// ---------------------------------------------------------------------------

mod proto_tests {
    use segb::proto::{as_str, iter_fields, WireType};

    /// Encode a protobuf tag: (field_number << 3) | wire_type.
    fn encode_varint(mut v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (v & 0x7F) as u8;
            v >>= 7;
            if v == 0 {
                out.push(byte);
                break;
            }
            out.push(byte | 0x80);
        }
        out
    }

    fn encode_tag(field: u32, wire: u64) -> Vec<u8> {
        encode_varint((u64::from(field) << 3) | wire)
    }

    fn encode_length_delimited(field: u32, data: &[u8]) -> Vec<u8> {
        let mut out = encode_tag(field, 2);
        out.extend(encode_varint(data.len() as u64));
        out.extend_from_slice(data);
        out
    }

    #[test]
    fn test_decode_two_string_fields() {
        let mut buf = Vec::new();
        buf.extend(encode_length_delimited(1, b"Finder"));
        buf.extend(encode_length_delimited(2, b"Move to Trash"));

        let fields: Vec<_> = iter_fields(&buf).collect::<Result<_, _>>().unwrap();
        assert_eq!(fields.len(), 2);

        assert_eq!(fields[0].field_number, 1);
        assert_eq!(fields[0].wire_type, WireType::LengthDelimited);
        assert_eq!(as_str(fields[0].raw), Some("Finder"));

        assert_eq!(fields[1].field_number, 2);
        assert_eq!(fields[1].wire_type, WireType::LengthDelimited);
        assert_eq!(as_str(fields[1].raw), Some("Move to Trash"));
    }

    #[test]
    fn test_decode_varint_field() {
        // Field 3, wire type 0 (varint), value = 42.
        let mut buf = encode_tag(3, 0);
        buf.extend(encode_varint(42));

        let fields: Vec<_> = iter_fields(&buf).collect::<Result<_, _>>().unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].field_number, 3);
        assert_eq!(fields[0].wire_type, WireType::Varint);
    }

    #[test]
    fn test_empty_buffer_yields_no_fields() {
        let fields: Vec<_> = iter_fields(&[]).collect::<Result<_, _>>().unwrap();
        assert!(fields.is_empty());
    }

    #[test]
    fn test_truncated_length_delimited_returns_error() {
        // Tag for field 1, wire 2, then length=100, but no data follows.
        let mut buf = encode_tag(1, 2);
        buf.extend(encode_varint(100)); // claims 100 bytes but buffer ends here
        let result: Result<Vec<_>, _> = iter_fields(&buf).collect();
        assert!(result.is_err(), "truncated LD field must error");
    }

    #[test]
    fn test_utf8_invalid_bytes_returns_none_from_as_str() {
        // Encode a field containing invalid UTF-8.
        let invalid = [0xFF, 0xFE, 0x00];
        let buf = encode_length_delimited(1, &invalid);
        let fields: Vec<_> = iter_fields(&buf).collect::<Result<_, _>>().unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(
            as_str(fields[0].raw),
            None,
            "invalid UTF-8 must return None"
        );
    }
}

// ---------------------------------------------------------------------------
// App.MenuItem decoder tests
// ---------------------------------------------------------------------------

mod menuitem_tests {
    use segb::menuitem::decode_app_menu_item;
    use segb::proto::{as_str, iter_fields, WireType};

    fn encode_varint(mut v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (v & 0x7F) as u8;
            v >>= 7;
            if v == 0 {
                out.push(byte);
                break;
            }
            out.push(byte | 0x80);
        }
        out
    }

    fn encode_length_delimited(field: u32, data: &[u8]) -> Vec<u8> {
        let tag = ((u64::from(field) << 3) | 2) as u8; // wire type 2, field ≤ 15
        let mut out = vec![tag];
        out.extend(encode_varint(data.len() as u64));
        out.extend_from_slice(data);
        out
    }

    fn make_app_menu_item_payload(application: &str, menu_item: &str) -> Vec<u8> {
        let mut buf = encode_length_delimited(1, application.as_bytes());
        buf.extend(encode_length_delimited(2, menu_item.as_bytes()));
        buf
    }

    #[test]
    fn test_decode_application_and_menu_item() {
        let payload = make_app_menu_item_payload("Finder", "Move to Trash");
        let ts_unix = Some(1_700_000_000.0f64);
        let rec = decode_app_menu_item(&payload, ts_unix).unwrap();
        assert_eq!(rec.application.as_deref(), Some("Finder"));
        assert_eq!(rec.menu_item.as_deref(), Some("Move to Trash"));
        assert_eq!(rec.timestamp_unix, ts_unix);
    }

    #[test]
    fn test_decode_missing_application_field() {
        // Only field 2, no field 1.
        let payload = encode_length_delimited(2, b"Empty Trash");
        let rec = decode_app_menu_item(&payload, None).unwrap();
        assert_eq!(rec.application, None);
        assert_eq!(rec.menu_item.as_deref(), Some("Empty Trash"));
    }

    #[test]
    fn test_decode_missing_menu_item_field() {
        // Only field 1, no field 2.
        let payload = encode_length_delimited(1, b"TextEdit");
        let rec = decode_app_menu_item(&payload, None).unwrap();
        assert_eq!(rec.application.as_deref(), Some("TextEdit"));
        assert_eq!(rec.menu_item, None);
    }

    #[test]
    fn test_decode_empty_payload() {
        // Empty protobuf → both fields absent; not an error.
        let rec = decode_app_menu_item(&[], None).unwrap();
        assert_eq!(rec.application, None);
        assert_eq!(rec.menu_item, None);
    }

    #[test]
    fn test_decode_unknown_fields_ignored() {
        // Field 1 + field 3 (unknown) + field 2 — field 3 must be skipped.
        let mut payload = encode_length_delimited(1, b"Safari");
        // Field 3, wire type 2, length 5, content "extra"
        payload.extend(encode_length_delimited(3, b"extra data"));
        payload.extend(encode_length_delimited(2, b"New Tab"));
        let rec = decode_app_menu_item(&payload, None).unwrap();
        assert_eq!(rec.application.as_deref(), Some("Safari"));
        assert_eq!(rec.menu_item.as_deref(), Some("New Tab"));
    }

    #[test]
    fn test_decode_timestamp_forwarded() {
        let payload = make_app_menu_item_payload("Finder", "Compress \"stolendata\"");
        let ts = Some(1_750_000_000.0f64);
        let rec = decode_app_menu_item(&payload, ts).unwrap();
        assert_eq!(rec.timestamp_unix, ts);
        assert_eq!(rec.menu_item.as_deref(), Some("Compress \"stolendata\""));
    }
}

// ---------------------------------------------------------------------------
// EntryState tests
// ---------------------------------------------------------------------------

#[test]
fn test_entry_state_from_raw() {
    use segb::common::EntryState;
    assert_eq!(EntryState::from_raw(1).unwrap(), EntryState::Written);
    assert_eq!(EntryState::from_raw(3).unwrap(), EntryState::Deleted);
    assert_eq!(EntryState::from_raw(4).unwrap(), EntryState::Unknown);
    assert!(EntryState::from_raw(0).is_err());
    assert!(EntryState::from_raw(2).is_err());
    assert!(EntryState::from_raw(99).is_err());
}

#[test]
fn test_cocoa_to_unix() {
    // 0.0 Cocoa seconds → 2001-01-01T00:00:00Z → Unix 978307200.
    let unix = cocoa_to_unix_secs(0.0).unwrap();
    assert!((unix - 978_307_200.0).abs() < 1e-6);
    // NaN / Inf → None.
    assert!(cocoa_to_unix_secs(f64::NAN).is_none());
    assert!(cocoa_to_unix_secs(f64::INFINITY).is_none());
}

// ---------------------------------------------------------------------------
// EntryState::is_live
// ---------------------------------------------------------------------------

#[test]
fn test_entry_state_is_live() {
    assert!(EntryState::Written.is_live());
    assert!(!EntryState::Deleted.is_live());
    assert!(!EntryState::Unknown.is_live());
}

// ---------------------------------------------------------------------------
// is_segb_* on a reader whose seek fails (I/O-error defensive path)
// ---------------------------------------------------------------------------

/// A reader whose every seek fails — models a non-seekable stream so the
/// signature probes exercise their `stream_position()` error branch.
struct FailingSeek;

impl std::io::Read for FailingSeek {
    fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
        Ok(0)
    }
}

impl std::io::Seek for FailingSeek {
    fn seek(&mut self, _pos: std::io::SeekFrom) -> std::io::Result<u64> {
        Err(std::io::Error::other("seek unsupported"))
    }
}

#[test]
fn test_is_segb_returns_false_on_seek_error() {
    let mut r1 = FailingSeek;
    assert!(!is_segb_v1(&mut r1), "v1 probe must be false on seek error");
    let mut r2 = FailingSeek;
    assert!(!is_segb_v2(&mut r2), "v2 probe must be false on seek error");
}

// ---------------------------------------------------------------------------
// SEGB v1 error paths
// ---------------------------------------------------------------------------

/// Build a bare v1 header (56 bytes) with the given `end_of_data_offset`.
fn v1_header(end_of_data: u32) -> Vec<u8> {
    let mut file = Vec::new();
    file.extend_from_slice(&le_u32(end_of_data)); // offset 0
    file.extend(std::iter::repeat(0u8).take(48)); // offset 4..52
    file.extend_from_slice(b"SEGB"); // offset 52
    file
}

#[test]
fn test_v1_negative_record_length_returns_error() {
    // A record header whose record_length is negative is structurally invalid.
    let mut file = v1_header((V1_HEADER_LEN + 32) as u32);
    file.extend_from_slice(&le_i32(-1)); // record_length < 0
    file.extend_from_slice(&le_i32(1)); // state Written
    file.extend_from_slice(&le_f64(0.0)); // ts1
    file.extend_from_slice(&le_f64(0.0)); // ts2
    file.extend_from_slice(&le_u32(0)); // crc
    file.extend_from_slice(&le_i32(0)); // unknown
    let mut cur = Cursor::new(&file);
    assert!(
        matches!(
            read_v1(&mut cur),
            Err(segb::SegbError::InvalidLength { .. })
        ),
        "negative record length must be InvalidLength"
    );
}

#[test]
fn test_v1_truncated_record_header_returns_error() {
    // end_of_data claims a record, but only a partial record header follows.
    let mut file = v1_header(200);
    file.extend(std::iter::repeat(0u8).take(10)); // 10 < 32-byte record header
    let mut cur = Cursor::new(&file);
    assert!(
        matches!(
            read_v1(&mut cur),
            Err(segb::SegbError::TruncatedRecordHeader { .. })
        ),
        "partial record header must be TruncatedRecordHeader"
    );
}

#[test]
fn test_v1_eof_at_record_boundary_stops_gracefully() {
    // end_of_data points past EOF, but EOF falls exactly on a record boundary
    // (zero bytes left) — the reader stops gracefully with no records.
    let file = v1_header(200); // header only, no body
    let mut cur = Cursor::new(&file);
    let recs = read_v1(&mut cur).unwrap();
    assert!(recs.is_empty(), "clean EOF at a boundary yields no records");
}

// ---------------------------------------------------------------------------
// SEGB v2 error / skip paths
// ---------------------------------------------------------------------------

/// Assemble a v2 file from a raw entry area and explicit trailer entries
/// `(end_offset, state, ts_cocoa)`, so tests control end_offset directly.
fn build_v2_raw(entry_area: &[u8], trailer: &[(i32, i32, f64)]) -> Vec<u8> {
    let mut file = Vec::new();
    file.extend_from_slice(b"SEGB"); // magic
    file.extend_from_slice(&le_i32(trailer.len() as i32)); // entries_count
    file.extend_from_slice(&le_f64(0.0)); // creation ts
    file.extend(std::iter::repeat(0u8).take(16)); // padding → 32-byte header
    file.extend_from_slice(entry_area);
    for &(end_offset, state, ts) in trailer {
        file.extend_from_slice(&le_i32(end_offset));
        file.extend_from_slice(&le_i32(state));
        file.extend_from_slice(&le_f64(ts));
    }
    file
}

#[test]
fn test_v2_trailer_overflow_returns_error() {
    // entries_count huge → trailer_bytes far exceeds the file size.
    let mut file = Vec::new();
    file.extend_from_slice(b"SEGB");
    file.extend_from_slice(&le_i32(1000)); // entries_count
    file.extend_from_slice(&le_f64(0.0));
    file.extend(std::iter::repeat(0u8).take(16)); // 32-byte header only
    let mut cur = Cursor::new(&file);
    assert!(
        matches!(
            read_v2(&mut cur),
            Err(segb::SegbError::TrailerOverflow { .. })
        ),
        "oversized entries_count must be TrailerOverflow"
    );
}

#[test]
fn test_v2_unknown_state_entry_is_skipped() {
    // state 4 (Unknown) entries are skipped without reading a body.
    let entry_area = vec![0u8; 16];
    let file = build_v2_raw(&entry_area, &[(8, 4, 0.0)]);
    let mut cur = Cursor::new(&file);
    assert!(read_v2(&mut cur).unwrap().is_empty());
}

#[test]
fn test_v2_negative_end_offset_entry_is_skipped() {
    // A negative end_offset resolves behind the read cursor — skipped, no panic.
    let entry_area = vec![0u8; 16];
    let file = build_v2_raw(&entry_area, &[(-100, 1, 0.0)]);
    let mut cur = Cursor::new(&file);
    assert!(read_v2(&mut cur).unwrap().is_empty());
}

#[test]
fn test_v2_end_offset_past_eof_is_skipped() {
    // An end_offset pointing past EOF is malformed — skipped, no huge alloc.
    let entry_area = vec![0u8; 16];
    let file = build_v2_raw(&entry_area, &[(100_000, 1, 0.0)]);
    let mut cur = Cursor::new(&file);
    assert!(read_v2(&mut cur).unwrap().is_empty());
}

#[test]
fn test_v2_entry_too_small_for_subheader_is_skipped() {
    // entry_total < ENTRY_HEADER_LENGTH (8) — not enough for a sub-header.
    let entry_area = vec![0u8; 16];
    let file = build_v2_raw(&entry_area, &[(4, 1, 0.0)]);
    let mut cur = Cursor::new(&file);
    assert!(read_v2(&mut cur).unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// protobuf walker — wire types and malformed-input paths
// ---------------------------------------------------------------------------

mod proto_wire_type_tests {
    use segb::proto::{iter_fields, WireType};
    use segb::SegbError;

    fn encode_varint(mut v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let b = (v & 0x7F) as u8;
            v >>= 7;
            if v == 0 {
                out.push(b);
                break;
            }
            out.push(b | 0x80);
        }
        out
    }

    fn tag(field: u32, wire: u64) -> Vec<u8> {
        encode_varint((u64::from(field) << 3) | wire)
    }

    #[test]
    fn bit64_field_is_decoded() {
        let mut buf = tag(1, 1); // wire type 1 = 64-bit
        buf.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let fields: Vec<_> = iter_fields(&buf).collect::<Result<_, _>>().unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].wire_type, WireType::Bit64);
        assert_eq!(fields[0].raw.len(), 8);
    }

    #[test]
    fn bit64_truncated_errors() {
        let mut buf = tag(1, 1);
        buf.extend_from_slice(&[1, 2, 3]); // only 3 of 8 bytes
        let r: Result<Vec<_>, _> = iter_fields(&buf).collect();
        assert!(matches!(r, Err(SegbError::ProtobufOverflow { .. })));
    }

    #[test]
    fn bit32_field_is_decoded() {
        let mut buf = tag(2, 5); // wire type 5 = 32-bit
        buf.extend_from_slice(&[9, 8, 7, 6]);
        let fields: Vec<_> = iter_fields(&buf).collect::<Result<_, _>>().unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].wire_type, WireType::Bit32);
        assert_eq!(fields[0].raw.len(), 4);
    }

    #[test]
    fn bit32_truncated_errors() {
        let mut buf = tag(2, 5);
        buf.extend_from_slice(&[9, 8]); // only 2 of 4 bytes
        let r: Result<Vec<_>, _> = iter_fields(&buf).collect();
        assert!(matches!(r, Err(SegbError::ProtobufOverflow { .. })));
    }

    #[test]
    fn unknown_wire_type_stops_iteration() {
        // wire type 3 (group start) is not one of {0,1,2,5} → iterator ends.
        let mut buf = tag(1, 3);
        buf.extend_from_slice(&[0, 0, 0]);
        let fields: Vec<_> = iter_fields(&buf).collect::<Result<_, _>>().unwrap();
        assert!(fields.is_empty());
    }

    #[test]
    fn multibyte_varint_value_is_decoded() {
        // value ≥ 128 → a 2-byte varint, exercising the continuation branch.
        let mut buf = tag(3, 0);
        buf.extend(encode_varint(300));
        let fields: Vec<_> = iter_fields(&buf).collect::<Result<_, _>>().unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].wire_type, WireType::Varint);
    }

    #[test]
    fn truncated_tag_varint_errors() {
        // a lone continuation byte: the varint never terminates before EOF.
        let buf = [0x80u8];
        let r: Result<Vec<_>, _> = iter_fields(&buf).collect();
        assert!(matches!(r, Err(SegbError::MalformedVarint { .. })));
    }

    #[test]
    fn overlong_varint_errors() {
        // 10+ continuation bytes with no terminator → malformed (shift ≥ 70).
        let buf = [0x80u8; 11];
        let r: Result<Vec<_>, _> = iter_fields(&buf).collect();
        assert!(matches!(r, Err(SegbError::MalformedVarint { .. })));
    }

    #[test]
    fn truncated_varint_value_errors() {
        // valid varint tag then a value varint truncated at EOF.
        let mut buf = tag(1, 0);
        buf.push(0x80);
        let r: Result<Vec<_>, _> = iter_fields(&buf).collect();
        assert!(matches!(r, Err(SegbError::MalformedVarint { .. })));
    }

    #[test]
    fn truncated_length_delimited_length_varint_errors() {
        // valid length-delimited tag then a length varint truncated at EOF.
        let mut buf = tag(1, 2);
        buf.push(0x80);
        let r: Result<Vec<_>, _> = iter_fields(&buf).collect();
        assert!(matches!(r, Err(SegbError::MalformedVarint { .. })));
    }
}

// ---------------------------------------------------------------------------
// App.MenuItem — decode_all / is_valid_app_menu_item_payload
// ---------------------------------------------------------------------------

mod menuitem_extra_tests {
    use segb::menuitem::{decode_all, is_valid_app_menu_item_payload};

    fn ld(field: u8, data: &[u8]) -> Vec<u8> {
        let mut out = vec![(field << 3) | 2, data.len() as u8]; // wire type 2
        out.extend_from_slice(data);
        out
    }

    #[test]
    fn decode_all_maps_each_payload() {
        let p1 = ld(1, b"Finder");
        let p2 = ld(2, b"Empty Trash");
        let recs = decode_all(vec![(p1.as_slice(), Some(1.0f64)), (p2.as_slice(), None)]).unwrap();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].application.as_deref(), Some("Finder"));
        assert_eq!(recs[1].menu_item.as_deref(), Some("Empty Trash"));
    }

    #[test]
    fn decode_all_propagates_error() {
        // A malformed payload (length-delimited claiming 100 bytes) fails fast.
        let bad = [0x0Au8, 100u8];
        assert!(decode_all(vec![(bad.as_slice(), None)]).is_err());
    }

    #[test]
    fn is_valid_true_for_wellformed() {
        let p = ld(1, b"Safari");
        assert!(is_valid_app_menu_item_payload(&p));
    }

    #[test]
    fn is_valid_false_for_malformed() {
        let bad = [0x0Au8, 100u8]; // length-delimited claiming 100 bytes
        assert!(!is_valid_app_menu_item_payload(&bad));
    }
}
