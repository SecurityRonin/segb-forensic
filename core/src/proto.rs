//! Protobuf field walker — STUB (RED state).

use crate::error::{Result, SegbError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireType {
    Varint = 0,
    Bit64 = 1,
    LengthDelimited = 2,
    Bit32 = 5,
}

#[derive(Debug, Clone)]
pub struct Field<'a> {
    pub field_number: u32,
    pub wire_type: WireType,
    pub raw: &'a [u8],
}

/// STUB: yields an error immediately (RED).
pub fn iter_fields(_buf: &[u8]) -> impl Iterator<Item = Result<Field<'_>>> {
    std::iter::once(Err(SegbError::MalformedVarint { offset: 0 }))
}

#[inline]
pub fn as_str(_raw: &[u8]) -> Option<&str> { None }
