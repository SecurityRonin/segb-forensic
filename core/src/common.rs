//! Shared types used by both SEGB v1 and v2 decoders.
//!
//! # References
//!
//! `ccl_segb/ccl_segb_common.py` — Alex Caithness / CCL Solutions
//! <https://github.com/cclgroupltd/ccl-segb/blob/main/ccl_segb/ccl_segb_common.py>

use crate::error::{Result, SegbError};

/// The 4-byte ASCII magic shared by both SEGB variants.
pub const MAGIC: &[u8; 4] = b"SEGB";

/// Mac Absolute Time (Cocoa / `CFAbsoluteTime`) epoch — 2001-01-01T00:00:00Z.
///
/// Timestamps in SEGB records are stored as `f64` seconds since this epoch.
/// Source: `ccl_segb_common.py:COCOA_EPOCH`.
pub const COCOA_EPOCH_UNIX_SECS: f64 = 978_307_200.0;

/// The state of a SEGB record.
///
/// Values are sourced from `ccl_segb_common.py:EntryState`:
///
/// | Value | Name    | Meaning                            |
/// |-------|---------|------------------------------------|
/// | 1     | Written | Normal, live record                |
/// | 3     | Deleted | Logically deleted record           |
/// | 4     | Unknown | Placeholder / empty record (v2)    |
///
/// `Unknown` (4) in SEGB v2 marks a slot the code skips; it is exposed here
/// so callers can observe it without the reader silently dropping the entry.
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
        match v {
            1 => Ok(Self::Written),
            3 => Ok(Self::Deleted),
            4 => Ok(Self::Unknown),
            _ => Err(SegbError::UnknownState(v)),
        }
    }

    /// Return `true` if this is a live (`Written`) record.
    #[inline]
    pub fn is_live(self) -> bool {
        self == Self::Written
    }
}

/// Convert a Cocoa `f64` timestamp (seconds since 2001-01-01) to seconds
/// since the Unix epoch (1970-01-01). Returns `None` if the value is not
/// finite (NaN / ±Inf).
///
/// Source: `ccl_segb_common.py:decode_cocoa_time`.
#[inline]
pub fn cocoa_to_unix_secs(cocoa: f64) -> Option<f64> {
    if cocoa.is_finite() {
        Some(cocoa + COCOA_EPOCH_UNIX_SECS)
    } else {
        None
    }
}

/// Read a little-endian `i32` from `data[off..off+4]`.
/// Returns 0 if the slice is shorter than required (bounds-safe).
#[inline]
pub(crate) fn le_i32(data: &[u8], off: usize) -> i32 {
    let mut b = [0u8; 4];
    if let Some(s) = data.get(off..off + 4) {
        b.copy_from_slice(s);
    }
    i32::from_le_bytes(b)
}

/// Read a little-endian `u32` from `data[off..off+4]`.
/// Returns 0 if the slice is shorter than required (bounds-safe).
#[inline]
pub(crate) fn le_u32(data: &[u8], off: usize) -> u32 {
    let mut b = [0u8; 4];
    if let Some(s) = data.get(off..off + 4) {
        b.copy_from_slice(s);
    }
    u32::from_le_bytes(b)
}

/// Read a little-endian `f64` from `data[off..off+8]`.
/// Returns `f64::NAN` if the slice is shorter than required (bounds-safe).
#[inline]
pub(crate) fn le_f64(data: &[u8], off: usize) -> f64 {
    let mut b = [0u8; 8];
    if let Some(s) = data.get(off..off + 8) {
        b.copy_from_slice(s);
    } else {
        return f64::NAN;
    }
    f64::from_le_bytes(b)
}

/// Read a little-endian `i64` (cast from `i32` pair) — used for `entries_count`
/// in the SEGB v2 header where the Python struct uses `"i"` (signed 32-bit).
#[inline]
pub(crate) fn le_i32_at(data: &[u8], off: usize) -> i32 {
    le_i32(data, off)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn le_f64_returns_nan_on_short_slice() {
        // Fewer than 8 bytes available at the offset — the bounds-safe reader
        // must return NaN rather than panic.
        assert!(le_f64(&[0u8; 4], 0).is_nan());
        assert!(le_f64(&[], 0).is_nan());
        // A full 8-byte slice decodes normally.
        assert_eq!(le_f64(&1.5f64.to_le_bytes(), 0).to_bits(), 1.5f64.to_bits());
    }

    #[test]
    fn is_live_only_for_written() {
        assert!(EntryState::Written.is_live());
        assert!(!EntryState::Deleted.is_live());
        assert!(!EntryState::Unknown.is_live());
    }
}
