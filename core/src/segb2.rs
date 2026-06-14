//! SEGB v2 reader — STUB (RED state).

use std::io::{Read, Seek, SeekFrom};
use crate::{common::{EntryState, MAGIC}, error::{Result, SegbError}};

pub const HEADER_LENGTH: usize = 32;
pub const ENTRY_HEADER_LENGTH: usize = 8;
pub const TRAILER_ENTRY_LENGTH: usize = 16;
pub const ALIGNMENT: u64 = 4;

#[derive(Debug, Clone)]
pub struct SegbV2Record {
    pub data_offset: u64,
    pub state: EntryState,
    pub timestamp_unix: Option<f64>,
    pub stored_crc32: u32,
    pub computed_crc32: u32,
    pub payload: Vec<u8>,
}

impl SegbV2Record {
    #[inline]
    pub fn crc_ok(&self) -> bool { self.stored_crc32 == self.computed_crc32 }
}

/// STUB: always returns false (RED).
pub fn is_segb_v2<R: Read + Seek>(_r: &mut R) -> bool { false }

/// STUB: always errors (RED).
pub fn read_v2<R: Read + Seek>(_r: &mut R) -> Result<Vec<SegbV2Record>> {
    Err(SegbError::BadMagic { found: "stub".to_owned() })
}
