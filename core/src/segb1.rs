//! SEGB v1 reader — STUB (RED state).

use std::io::{Read, Seek, SeekFrom};
use crate::{common::{EntryState, MAGIC}, error::{Result, SegbError}};

pub const HEADER_LENGTH: usize = 56;
pub const RECORD_HEADER_LENGTH: usize = 32;
pub const ALIGNMENT: u64 = 8;

#[derive(Debug, Clone)]
pub struct SegbV1Record {
    pub data_offset: u64,
    pub state: EntryState,
    pub timestamp1_unix: Option<f64>,
    pub timestamp2_unix: Option<f64>,
    pub stored_crc32: u32,
    pub computed_crc32: u32,
    pub payload: Vec<u8>,
}

impl SegbV1Record {
    #[inline]
    pub fn crc_ok(&self) -> bool { self.stored_crc32 == self.computed_crc32 }
}

/// STUB: always returns false (RED).
pub fn is_segb_v1<R: Read + Seek>(_r: &mut R) -> bool { false }

/// STUB: always errors (RED).
pub fn read_v1<R: Read + Seek>(_r: &mut R) -> Result<Vec<SegbV1Record>> {
    Err(SegbError::BadMagic { found: "stub".to_owned() })
}

pub(crate) fn crc32_of(_data: &[u8]) -> u32 { 0 }
