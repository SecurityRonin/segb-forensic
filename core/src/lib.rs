//! `segb-core` — panic-free reader for Apple SEGB container files.
//!
//! # What is SEGB?
//!
//! SEGB is Apple's container format used by the **Biome** subsystem on macOS
//! and iOS to store user-activity streams. Each Biome stream (e.g.
//! `~/Library/Biome/streams/restricted/App.MenuItem/local`) is a SEGB file
//! whose records carry a state flag, one or two timestamps, and a raw protobuf
//! payload.
//!
//! Two variants exist:
//!
//! | Variant | Magic location     | Header size | Alignment |
//! |---------|--------------------|-------------|-----------|
//! | SEGB v1 | Last 4 bytes of header (offset 52–55) | 56 bytes | 8 bytes |
//! | SEGB v2 | First 4 bytes (offset 0–3)            | 32 bytes | 4 bytes |
//!
//! # Quick start
//!
//! ```rust,no_run
//! use std::fs::File;
//! use std::io::BufReader;
//! use segb::{read_segb, SegbRecord, menuitem::decode_app_menu_item};
//!
//! let f = File::open("/path/to/App.MenuItem/local").unwrap();
//! let mut r = BufReader::new(f);
//! for record in read_segb(&mut r).unwrap() {
//!     let item = decode_app_menu_item(record.payload(), record.timestamp_unix()).unwrap();
//!     println!("{:?} → {:?}", item.application, item.menu_item);
//! }
//! ```
//!
//! # References
//!
//! - ccl-segb (Alex Caithness / CCL Solutions):
//!   <https://github.com/cclgroupltd/ccl-segb>
//! - Unit 42 research (Palo Alto Networks, 2026):
//!   <https://unit42.paloaltonetworks.com/new-macos-artifact-discovered/>
//! - forensicnomicon catalog entry `macos_biome_app_menuitem`

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod common;
pub mod error;
pub mod menuitem;
pub mod proto;
pub mod segb1;
pub mod segb2;

use std::io::{Read, Seek};

pub use common::EntryState;
pub use error::{Result, SegbError};

// Re-exports for convenience.
pub use segb1::SegbV1Record;
pub use segb2::SegbV2Record;

/// A version-neutral SEGB record, produced by [`read_segb`].
#[derive(Debug, Clone)]
pub enum SegbRecord {
    /// A record from a SEGB v1 file.
    V1(SegbV1Record),
    /// A record from a SEGB v2 file.
    V2(SegbV2Record),
}

impl SegbRecord {
    /// The logical state of this record.
    pub fn state(&self) -> EntryState {
        match self {
            Self::V1(r) => r.state,
            Self::V2(r) => r.state,
        }
    }

    /// The primary timestamp as Unix seconds (seconds since 1970-01-01T00:00:00Z).
    ///
    /// - For v1: `timestamp1`.
    /// - For v2: the trailer `creation` timestamp.
    ///
    /// Returns `None` if the stored `f64` is not finite.
    pub fn timestamp_unix(&self) -> Option<f64> {
        match self {
            Self::V1(r) => r.timestamp1_unix,
            Self::V2(r) => r.timestamp_unix,
        }
    }

    /// The raw protobuf (or other format) payload bytes.
    pub fn payload(&self) -> &[u8] {
        match self {
            Self::V1(r) => &r.payload,
            Self::V2(r) => &r.payload,
        }
    }

    /// File offset of the first byte of [`Self::payload`].
    pub fn data_offset(&self) -> u64 {
        match self {
            Self::V1(r) => r.data_offset,
            Self::V2(r) => r.data_offset,
        }
    }

    /// The CRC-32 stored in the record header.
    pub fn stored_crc32(&self) -> u32 {
        match self {
            Self::V1(r) => r.stored_crc32,
            Self::V2(r) => r.stored_crc32,
        }
    }

    /// The CRC-32 computed over the payload bytes as read.
    pub fn computed_crc32(&self) -> u32 {
        match self {
            Self::V1(r) => r.computed_crc32,
            Self::V2(r) => r.computed_crc32,
        }
    }

    /// Returns `true` if stored and computed CRC-32 values match.
    pub fn crc_ok(&self) -> bool {
        self.stored_crc32() == self.computed_crc32()
    }
}

/// Detect the SEGB variant in `r` and read all records.
///
/// The stream is rewound to position 0 before detection. This is the primary
/// entry point for callers that do not know which variant to expect.
///
/// # Errors
///
/// Returns `Err` if the stream is neither a valid SEGB v1 nor a valid SEGB v2
/// file, or if a lower-level parse error occurs.
pub fn read_segb<R: Read + Seek>(r: &mut R) -> Result<Vec<SegbRecord>> {
    r.seek(std::io::SeekFrom::Start(0))?;

    if segb1::is_segb_v1(r) {
        r.seek(std::io::SeekFrom::Start(0))?;
        let records = segb1::read_v1(r)?;
        return Ok(records.into_iter().map(SegbRecord::V1).collect());
    }

    r.seek(std::io::SeekFrom::Start(0))?;
    if segb2::is_segb_v2(r) {
        r.seek(std::io::SeekFrom::Start(0))?;
        let records = segb2::read_v2(r)?;
        return Ok(records.into_iter().map(SegbRecord::V2).collect());
    }

    Err(SegbError::BadMagic {
        found: "not SEGB v1 or v2".to_owned(),
    })
}
