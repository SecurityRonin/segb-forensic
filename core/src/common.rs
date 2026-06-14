//! Shared types used by both SEGB v1 and v2 decoders.

use crate::error::{Result, SegbError};

/// The 4-byte ASCII magic shared by both SEGB variants.
pub const MAGIC: &[u8; 4] = b"SEGB";

/// Mac Absolute Time epoch offset — Unix seconds to add to a Cocoa timestamp.
pub const COCOA_EPOCH_UNIX_SECS: f64 = 978_307_200.0;

/// The state of a SEGB record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EntryState {
    /// Normal, live record. Value = 1.
    Written,
    /// Logically deleted record. Value = 3.
    Deleted,
    /// Empty placeholder (primarily SEGB v2). Value = 4.
    Unknown,
}

impl EntryState {
    /// Decode from the raw `i32` on-disk value.
    pub fn from_raw(v: i32) -> Result<Self> {
        Err(SegbError::UnknownState(v)) // STUB: RED — not yet implemented
    }

    /// Return `true` if this is a live (`Written`) record.
    #[inline]
    pub fn is_live(self) -> bool {
        self == Self::Written
    }
}

/// Convert a Cocoa `f64` timestamp to Unix seconds. Returns `None` if not finite.
#[inline]
pub fn cocoa_to_unix_secs(_cocoa: f64) -> Option<f64> {
    None // STUB: RED
}

#[inline]
pub(crate) fn le_i32(data: &[u8], off: usize) -> i32 {
    let mut b = [0u8; 4];
    if let Some(s) = data.get(off..off + 4) { b.copy_from_slice(s); }
    i32::from_le_bytes(b)
}

#[inline]
pub(crate) fn le_u32(data: &[u8], off: usize) -> u32 {
    let mut b = [0u8; 4];
    if let Some(s) = data.get(off..off + 4) { b.copy_from_slice(s); }
    u32::from_le_bytes(b)
}

#[inline]
pub(crate) fn le_f64(data: &[u8], off: usize) -> f64 {
    let mut b = [0u8; 8];
    if let Some(s) = data.get(off..off + 8) { b.copy_from_slice(s); } else { return f64::NAN; }
    f64::from_le_bytes(b)
}

#[inline]
pub(crate) fn le_i32_at(data: &[u8], off: usize) -> i32 {
    le_i32(data, off)
}
