//! `segb-core` — panic-free reader for Apple SEGB container files.
//!
//! **STUB state — RED commit.** The public API is defined; implementations
//! are stubs that error or return empty results. Tests are red.

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
pub use segb1::SegbV1Record;
pub use segb2::SegbV2Record;

/// A version-neutral SEGB record.
#[derive(Debug, Clone)]
pub enum SegbRecord {
    V1(SegbV1Record),
    V2(SegbV2Record),
}

impl SegbRecord {
    pub fn state(&self) -> EntryState {
        match self {
            Self::V1(r) => r.state,
            Self::V2(r) => r.state,
        }
    }

    pub fn timestamp_unix(&self) -> Option<f64> {
        match self {
            Self::V1(r) => r.timestamp1_unix,
            Self::V2(r) => r.timestamp_unix,
        }
    }

    pub fn payload(&self) -> &[u8] {
        match self {
            Self::V1(r) => &r.payload,
            Self::V2(r) => &r.payload,
        }
    }

    pub fn data_offset(&self) -> u64 {
        match self {
            Self::V1(r) => r.data_offset,
            Self::V2(r) => r.data_offset,
        }
    }

    pub fn stored_crc32(&self) -> u32 {
        match self {
            Self::V1(r) => r.stored_crc32,
            Self::V2(r) => r.stored_crc32,
        }
    }

    pub fn computed_crc32(&self) -> u32 {
        match self {
            Self::V1(r) => r.computed_crc32,
            Self::V2(r) => r.computed_crc32,
        }
    }

    pub fn crc_ok(&self) -> bool {
        self.stored_crc32() == self.computed_crc32()
    }
}

/// STUB: always errors (RED).
pub fn read_segb<R: Read + Seek>(_r: &mut R) -> Result<Vec<SegbRecord>> {
    Err(SegbError::BadMagic { found: "stub".to_owned() })
}
