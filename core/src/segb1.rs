//! SEGB v1 reader.
//!
//! # Layout (from `ccl_segb/ccl_segb1.py` by Alex Caithness / CCL Solutions)
//!
//! ## File header — 56 bytes (`HEADER_LENGTH = 56`)
//!
//! The magic `b"SEGB"` sits at the **last** 4 bytes of the header (offsets
//! 52–55). Offset 0 carries the `end_of_data_offset` as a little-endian `u32`.
//! The remaining 48 bytes of the header are not decoded by ccl-segb and are
//! treated as padding / unknown fields.
//!
//! ```text
//! Offset  Size  Type    Field
//! ------  ----  ------  -------------------
//!  0       4    u32LE   end_of_data_offset   (file offset where record data ends)
//!  4      48    bytes   unknown / padding
//! 52       4    bytes   magic = b"SEGB"
//! ```
//!
//! ## Per-record header — 32 bytes (`RECORD_HEADER_LENGTH = 32`)
//!
//! Python struct format: `"<iiddIi"` (little-endian)
//!
//! ```text
//! Offset  Size  Type    Field
//! ------  ----  ------  ------------------
//!  0       4    i32LE   record_length  (byte count of the payload that follows)
//!  4       4    i32LE   entry_state    (EntryState: 1=Written, 3=Deleted, 4=Unknown)
//!  8       8    f64LE   timestamp1     (Cocoa seconds since 2001-01-01)
//! 16       8    f64LE   timestamp2     (Cocoa seconds since 2001-01-01)
//! 24       4    u32LE   crc32          (zlib CRC-32 of the payload bytes)
//! 28       4    i32LE   unknown
//! ```
//!
//! Immediately after the header: `record_length` bytes of payload.
//!
//! After payload: the stream is padded to the next **8-byte boundary**
//! (`ALIGNMENT_BYTES_LENGTH = 8`).
//!
//! Records are read sequentially until `stream.tell() >= end_of_data_offset`.
//!
//! ## Version detection
//!
//! The SEGB v1 signature check (`stream_matches_segbv1_signature`) reads the
//! full 56-byte header and checks that `file_header[-4:] == b"SEGB"` — i.e.
//! the magic is at the **end** of the header, not the beginning.  This is how
//! v1 is distinguished from v2 (where magic is at offset 0).
//!
//! Source: `ccl_segb/ccl_segb1.py` (version 0.3)
//! <https://github.com/cclgroupltd/ccl-segb/blob/main/ccl_segb/ccl_segb1.py>

use std::io::{Read, Seek, SeekFrom};

use crate::{
    common::{cocoa_to_unix_secs, le_f64, le_i32, le_u32, EntryState, MAGIC},
    error::{Result, SegbError},
};

/// Total byte length of the SEGB v1 file header.
///
/// Source: `ccl_segb1.py:HEADER_LENGTH = 56`.
pub const HEADER_LENGTH: usize = 56;

/// Byte length of each per-record header.
///
/// Source: `ccl_segb1.py:RECORD_HEADER_LENGTH = 32`.
pub const RECORD_HEADER_LENGTH: usize = 32;

/// Records are padded to this alignment after their payload.
///
/// Source: `ccl_segb1.py:ALIGNMENT_BYTES_LENGTH = 8`.
pub const ALIGNMENT: u64 = 8;

/// A single decoded SEGB v1 record.
#[derive(Debug, Clone)]
pub struct SegbV1Record {
    /// File offset of the first byte of the payload (immediately after the
    /// per-record header).
    pub data_offset: u64,
    /// Logical state of this record.
    pub state: EntryState,
    /// First timestamp — Unix seconds (converted from Cocoa time).
    /// `None` if the stored `f64` is not finite.
    pub timestamp1_unix: Option<f64>,
    /// Second timestamp — Unix seconds (converted from Cocoa time).
    /// `None` if the stored `f64` is not finite.
    pub timestamp2_unix: Option<f64>,
    /// CRC-32 stored in the record header (zlib CRC-32 of the payload).
    pub stored_crc32: u32,
    /// CRC-32 computed over the payload bytes as we read them.
    pub computed_crc32: u32,
    /// The raw payload bytes (protobuf or other format).
    pub payload: Vec<u8>,
}

impl SegbV1Record {
    /// Returns `true` if the stored and computed CRC-32 values match.
    #[inline]
    pub fn crc_ok(&self) -> bool {
        self.stored_crc32 == self.computed_crc32
    }
}

/// Returns `true` when the stream begins with a valid SEGB v1 header.
///
/// Reads 56 bytes, checks that bytes 52–55 equal `b"SEGB"`, then rewinds the
/// stream to its original position. Returns `false` on any I/O error or short
/// read.
///
/// Source: `ccl_segb1.py:stream_matches_segbv1_signature`.
pub fn is_segb_v1<R: Read + Seek>(r: &mut R) -> bool {
    let start = match r.stream_position() {
        Ok(p) => p,
        Err(_) => return false,
    };
    let mut buf = [0u8; HEADER_LENGTH];
    let n = r.read(&mut buf).unwrap_or(0);
    let _ = r.seek(SeekFrom::Start(start));
    if n < HEADER_LENGTH {
        return false;
    }
    // In SEGB v1 the magic is at the LAST 4 bytes of the 56-byte header.
    buf[HEADER_LENGTH - 4..] == *MAGIC
}

/// Read all SEGB v1 records from `r` and return them in file order.
///
/// # Errors
///
/// Returns `Err` on I/O failure, bad magic, or a structurally invalid record
/// (negative length, truncated data). Unknown `EntryState` values yield
/// `SegbError::UnknownState`.
pub fn read_v1<R: Read + Seek>(r: &mut R) -> Result<Vec<SegbV1Record>> {
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

    // Magic check: last 4 bytes of the 56-byte header must be b"SEGB".
    if &header[HEADER_LENGTH - 4..] != MAGIC {
        return Err(SegbError::BadMagic {
            found: hex::encode(&header[HEADER_LENGTH - 4..]),
        });
    }

    // end_of_data_offset is stored at offset 0 as a little-endian u32.
    let end_of_data: u64 = u64::from(le_u32(&header, 0));

    // ------------------------------------------------------------------
    // Read records sequentially until end_of_data_offset.
    // ------------------------------------------------------------------
    let mut records = Vec::new();

    loop {
        let record_start = r.stream_position()?;
        if record_start >= end_of_data {
            break;
        }

        // Read the 32-byte per-record header.
        let mut rec_hdr = vec![0u8; RECORD_HEADER_LENGTH];
        let n = r.read(&mut rec_hdr)?;
        if n < RECORD_HEADER_LENGTH {
            if n == 0 {
                // EOF before end_of_data — truncated file; stop gracefully.
                break;
            }
            return Err(SegbError::TruncatedRecordHeader {
                offset: record_start,
                need: RECORD_HEADER_LENGTH,
                got: n,
            });
        }

        // struct "<iiddIi"
        let record_length = le_i32(&rec_hdr, 0);
        let entry_state_raw = le_i32(&rec_hdr, 4);
        let timestamp1_raw = le_f64(&rec_hdr, 8);
        let timestamp2_raw = le_f64(&rec_hdr, 16);
        let crc32_stored = le_u32(&rec_hdr, 24);
        // le_i32 at offset 28 = unknown field (not exposed in API)

        if record_length < 0 {
            return Err(SegbError::InvalidLength {
                offset: record_start,
                length: record_length,
            });
        }
        let payload_len = record_length as usize;

        let state = EntryState::from_raw(entry_state_raw)?;

        let data_offset = r.stream_position()?;

        // Read payload.
        let mut payload = vec![0u8; payload_len];
        let n = r.read(&mut payload)?;
        if n < payload_len {
            return Err(SegbError::TruncatedPayload {
                offset: data_offset,
                need: payload_len,
                got: n,
            });
        }

        let computed_crc32 = crc32_of(&payload);

        records.push(SegbV1Record {
            data_offset,
            state,
            timestamp1_unix: cocoa_to_unix_secs(timestamp1_raw),
            timestamp2_unix: cocoa_to_unix_secs(timestamp2_raw),
            stored_crc32: crc32_stored,
            computed_crc32,
            payload,
        });

        // Align to next 8-byte boundary.
        let pos = r.stream_position()?;
        let remainder = pos % ALIGNMENT;
        if remainder != 0 {
            let skip = ALIGNMENT - remainder;
            r.seek(SeekFrom::Current(skip as i64))?;
        }
    }

    Ok(records)
}

// ---------------------------------------------------------------------------
// CRC-32 (zlib/IEEE polynomial) — no external dep required.
// Source: RFC 1952 §8; matches Python's `zlib.crc32()`.
// ---------------------------------------------------------------------------

pub(crate) fn crc32_of(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            if crc & 1 == 1 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

/// Workaround: the `hex` crate is only used in the `BadMagic` error path.
/// To avoid adding a dep for a single line, we implement a tiny hex encoder.
mod hex {
    use std::fmt::Write as _;
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_known_value() {
        // Python: zlib.crc32(b"hello world") & 0xffffffff == 0x0d4a1185
        assert_eq!(crc32_of(b"hello world"), 0x0d4a_1185);
    }

    #[test]
    fn crc32_empty() {
        // Python: zlib.crc32(b"") & 0xffffffff == 0x00000000
        assert_eq!(crc32_of(b""), 0x0000_0000);
    }
}
