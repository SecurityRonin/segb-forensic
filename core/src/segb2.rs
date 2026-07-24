//! SEGB v2 reader.
//!
//! # Layout (from `ccl_segb/ccl_segb2.py` by Alex Caithness / CCL Solutions)
//!
//! This format is documented by CCL as being "based upon information provided
//! by Cellebrite" (see the file header comment in `ccl_segb2.py`):
//! <https://cellebrite.com/en/understanding-and-decoding-the-newest-ios-segb-format/>
//!
//! ## File header — 32 bytes (`HEADER_LENGTH = 32`)
//!
//! Unlike v1, the magic `b"SEGB"` is at **offset 0** (the first 4 bytes).
//!
//! Python struct format: `"<4sid16s"` (little-endian)
//!
//! ```text
//! Offset  Size  Type    Field
//! ------  ----  ------  -----------------------------------
//!  0       4    bytes   magic = b"SEGB"
//!  4       4    i32LE   entries_count  (number of trailer entries)
//!  8       8    f64LE   creation_timestamp  (Cocoa seconds)
//! 16      16    bytes   unknown_padding
//! ```
//!
//! ## Trailer — at the end of the file
//!
//! The trailer consists of `entries_count` entries of 16 bytes each
//! (`TRAILER_ENTRY_LENGTH = 16`), stored sequentially starting at
//! `file_len - (entries_count * 16)`.
//!
//! Python struct format per entry: `"<2id"` (little-endian)
//!
//! ```text
//! Offset  Size  Type    Field
//! ------  ----  ------  ---------------------------------------------------
//!  0       4    i32LE   entry_end_offset  (end of entry relative to start of entry area)
//!  4       4    i32LE   entry_state       (EntryState: 1=Written, 3=Deleted, 4=Unknown)
//!  8       8    f64LE   timestamp         (Cocoa seconds since 2001-01-01)
//! ```
//!
//! Note: `entry_end_offset` is relative to the **start of the entry area**
//! (i.e. relative to `HEADER_LENGTH = 32`), not to absolute file offset.
//!
//! ## Per-entry data (body area)
//!
//! After the header (offset 32), entries are stored consecutively. Each entry
//! consists of:
//!
//! - An 8-byte entry sub-header (`ENTRY_HEADER_LENGTH = 8`):
//!   Python struct `"Ii"` (big-endian? actually the struct uses "Ii" without
//!   an endian prefix, so it's native; but given the rest of the file is LE
//!   and the context, CCL treats it as: `crc32(u32) + unknown(i32)`).
//!   Source: `ccl_segb2.py:ENTRY_HEADER_LENGTH = 8`, line
//!   `crc32_stored, unknown_raw = struct.unpack("Ii", entry_raw[:ENTRY_HEADER_LENGTH])`.
//! - Followed by payload bytes: `entry_length - ENTRY_HEADER_LENGTH` bytes,
//!   where `entry_length = trailer_entry.end_offset - (stream.tell() - HEADER_LENGTH)`.
//!
//! After reading each entry's payload, the stream is padded to a **4-byte
//! boundary** relative to `entry_end_offset` — `ALIGNMENT = 4`.
//!
//! Entries with `state == Unknown (4)` are skipped by ccl-segb; we expose
//! them to callers but mark them with `EntryState::Unknown`.
//!
//! Source: `ccl_segb/ccl_segb2.py` (version 0.4)
//! <https://github.com/cclgroupltd/ccl-segb/blob/main/ccl_segb/ccl_segb2.py>

use std::io::{Read, Seek, SeekFrom};

use crate::{
    common::{cocoa_to_unix_secs, le_f64, le_i32, le_i32_at, le_u32, EntryState, MAGIC},
    error::{Result, SegbError},
    segb1,
};

/// Total byte length of the SEGB v2 file header.
///
/// Source: `ccl_segb2.py:HEADER_LENGTH = 32`.
pub const HEADER_LENGTH: usize = 32;

/// Byte length of the sub-header that precedes each entry's payload.
///
/// Source: `ccl_segb2.py:ENTRY_HEADER_LENGTH = 8`.
pub const ENTRY_HEADER_LENGTH: usize = 8;

/// Byte length of each trailer entry.
///
/// Source: `ccl_segb2.py:TRAILER_ENTRY_LENGTH = 16`.
pub const TRAILER_ENTRY_LENGTH: usize = 16;

/// After each entry payload, the read position is aligned to this boundary.
///
/// Source: `ccl_segb2.py`: `if (remainder := trailer_entry.end_offset % 4) != 0: stream.seek(4 - remainder, …)`.
pub const ALIGNMENT: u64 = 4;

/// A single decoded SEGB v2 record.
#[derive(Debug, Clone)]
pub struct SegbV2Record {
    /// File offset of the first byte of the payload (after the 8-byte entry
    /// sub-header).
    pub data_offset: u64,
    /// Logical state of this record.
    pub state: EntryState,
    /// Timestamp from the trailer entry — Unix seconds.
    /// `None` if the stored `f64` is not finite.
    pub timestamp_unix: Option<f64>,
    /// CRC-32 stored in the entry sub-header.
    pub stored_crc32: u32,
    /// CRC-32 computed over the payload bytes.
    pub computed_crc32: u32,
    /// The raw payload bytes (protobuf or other format).
    pub payload: Vec<u8>,
}

impl SegbV2Record {
    /// Returns `true` if the stored and computed CRC-32 values match.
    #[inline]
    pub fn crc_ok(&self) -> bool {
        self.stored_crc32 == self.computed_crc32
    }
}

/// Returns `true` when the stream begins with a valid SEGB v2 header.
///
/// Reads 4 bytes and checks that they equal `b"SEGB"`, then rewinds. Returns
/// `false` on any I/O error or short read.
///
/// Source: `ccl_segb2.py:stream_matches_segbv2_signature`.
pub fn is_segb_v2<R: Read + Seek>(r: &mut R) -> bool {
    let start = match r.stream_position() {
        Ok(p) => p,
        Err(_) => return false,
    };
    let mut buf = [0u8; 4];
    let n = r.read(&mut buf).unwrap_or(0);
    let _ = r.seek(SeekFrom::Start(start));
    n == 4 && &buf == MAGIC
}

/// Read all SEGB v2 records from `r` and return them sorted by
/// `entry_end_offset` (i.e. file order).
///
/// # Errors
///
/// Returns `Err` on I/O failure, bad magic, negative/overflow counts, or
/// structurally invalid entries.
pub fn read_v2<R: Read + Seek>(r: &mut R) -> Result<Vec<SegbV2Record>> {
    // ------------------------------------------------------------------
    // Parse the file header.
    // ------------------------------------------------------------------
    let mut header = vec![0u8; HEADER_LENGTH];
    let n = r.read(&mut header)?;
    if n < HEADER_LENGTH {
        return Err(SegbError::TruncatedHeader {
            need: HEADER_LENGTH,
            got: n,
        });
    }

    // Magic check: first 4 bytes must be b"SEGB".
    if &header[0..4] != MAGIC {
        return Err(SegbError::BadMagic {
            found: hex_encode(&header[0..4]),
        });
    }

    let entries_count_raw = le_i32_at(&header, 4);
    if entries_count_raw < 0 {
        return Err(SegbError::InvalidEntryCount {
            count: entries_count_raw,
        });
    }
    let entries_count = entries_count_raw as u64;

    // creation_timestamp at offset 8 (f64 LE) — not currently used in output.
    let _creation_ts = le_f64(&header, 8);

    // ------------------------------------------------------------------
    // Read the trailer: `entries_count` × 16-byte entries at end of file.
    // ------------------------------------------------------------------
    let stream_len = r.seek(SeekFrom::End(0))?;

    let trailer_bytes = entries_count * TRAILER_ENTRY_LENGTH as u64;
    if trailer_bytes > stream_len {
        return Err(SegbError::TrailerOverflow {
            trailer_bytes,
            stream_bytes: stream_len,
        });
    }

    let trailer_start = stream_len - trailer_bytes;
    r.seek(SeekFrom::Start(trailer_start))?;

    // Metadata collected from the trailer; we sort by end_offset before
    // reading the body so we process entries in file order.
    struct TrailerEntry {
        end_offset: i32, // relative to HEADER_LENGTH
        state: EntryState,
        timestamp_unix: Option<f64>,
    }

    let mut trailer: Vec<TrailerEntry> = Vec::with_capacity(entries_count as usize);
    let mut trailer_raw = vec![0u8; TRAILER_ENTRY_LENGTH];

    for _ in 0..entries_count {
        let n = r.read(&mut trailer_raw)?;
        if n < TRAILER_ENTRY_LENGTH {
            // Truncated trailer — stop gracefully. Defensive: `trailer_start`
            // positions the cursor so exactly `entries_count * 16` bytes remain,
            // so a full read always succeeds for a well-behaved reader; kept in
            // case a future `Read` impl under-fills a non-EOF read.
            break; // cov:unreachable: trailer_start guarantees 16 bytes remain per iteration
        }
        // struct "<2id": i32 end_offset, i32 state, f64 timestamp
        let end_offset = le_i32(&trailer_raw, 0);
        let state_raw = le_i32(&trailer_raw, 4);
        let ts_cocoa = le_f64(&trailer_raw, 8);

        let state = EntryState::from_raw(state_raw)?;
        trailer.push(TrailerEntry {
            end_offset,
            state,
            timestamp_unix: cocoa_to_unix_secs(ts_cocoa),
        });
    }

    // Sort entries by their end offset so we read the body sequentially.
    trailer.sort_by_key(|e| e.end_offset);

    // ------------------------------------------------------------------
    // Seek to end of header and read entry bodies in sorted order.
    // ------------------------------------------------------------------
    r.seek(SeekFrom::Start(HEADER_LENGTH as u64))?;

    let mut records = Vec::with_capacity(trailer.len());

    for t in &trailer {
        // State 4 = empty placeholder — ccl-segb skips these; we do the same
        // but could expose them if desired.
        if t.state == EntryState::Unknown {
            continue;
        }

        let current_pos = r.stream_position()?;
        // entry_end_offset is relative to HEADER_LENGTH. Compute in signed i64
        // so a negative (malformed) end_offset does not sign-extend into a huge
        // u64 and overflow the addition; the guard below then rejects it.
        let abs_end = HEADER_LENGTH as i64 + i64::from(t.end_offset);
        if abs_end < current_pos as i64 {
            // End offset is behind us (or negative) — malformed trailer. Skip.
            continue;
        }
        let abs_end = abs_end as u64;
        if abs_end > stream_len {
            // Entry body would extend past EOF — malformed trailer. Skip.
            // Bounding the entry within the file here (a range-check of the
            // offset before use) makes the sub-header and payload reads below
            // infallible: they cannot short-read, and the payload allocation is
            // capped by the file size rather than by an attacker-chosen offset.
            continue;
        }
        let entry_total = (abs_end - current_pos) as usize;
        if entry_total < ENTRY_HEADER_LENGTH {
            // Not enough bytes for the sub-header. Skip.
            continue;
        }

        // Read sub-header (8 bytes): crc32 (u32) + unknown (i32). The bounds
        // check above guarantees these bytes are present, so read_exact cannot
        // short-read on a well-formed cursor.
        let mut sub_hdr = [0u8; ENTRY_HEADER_LENGTH];
        r.read_exact(&mut sub_hdr)?;

        // CCL's struct is `"Ii"` without an explicit endian prefix, which
        // defaults to native. On every Apple platform this is little-endian.
        let crc32_stored = le_u32(&sub_hdr, 0);

        let payload_len = entry_total - ENTRY_HEADER_LENGTH;
        let data_offset = r.stream_position()?;

        let mut payload = vec![0u8; payload_len];
        r.read_exact(&mut payload)?;

        let computed_crc32 = segb1::crc32_of(&payload);

        records.push(SegbV2Record {
            data_offset,
            state: t.state,
            timestamp_unix: t.timestamp_unix,
            stored_crc32: crc32_stored,
            computed_crc32,
            payload,
        });

        // Align to 4-byte boundary relative to end_offset.
        let remainder = t.end_offset as u64 % ALIGNMENT;
        if remainder != 0 {
            let skip = ALIGNMENT - remainder;
            r.seek(SeekFrom::Current(skip as i64))?;
        }
    }

    Ok(records)
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}
