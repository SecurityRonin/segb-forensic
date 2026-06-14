//! Minimal protobuf field walker — varint + length-delimited types only.
//!
//! The App.MenuItem Biome stream carries a protobuf payload whose schema Apple
//! has not published. Based on the forensicnomicon catalog and the Unit 42
//! research (<https://unit42.paloaltonetworks.com/new-macos-artifact-discovered/>),
//! the payload encodes at minimum:
//!
//! - **field 1** (wire type 2 = length-delimited): the application name, e.g.
//!   `"Finder"`, `"TextEdit"`.
//! - **field 2** (wire type 2 = length-delimited): the exact menu-item text
//!   selected by the user, e.g. `"Move to Trash"`, `"Compress \"stolendata\""`.
//!
//! # Caveat
//!
//! The field numbers above are inferred from the published research output (the
//! Unit 42 article shows `application` and `menu_item` as the two meaningful
//! fields) and from the forensicnomicon field schema. No canonical `.proto`
//! file has been published by Apple. Validation against a real Tahoe 26 sample
//! is **pending** — see `docs/validation.md`.
//!
//! # Design choice — hand-rolled varint walker vs. `prost`
//!
//! `prost` requires a `.proto` schema or hand-authored derive macros. Neither
//! is available here (Apple has not published a schema). Pulling in `prost` to
//! parse two string fields would add a build-script dependency and a generated
//! file for no concrete benefit. A tiny varint + wire-type walker is 60 lines,
//! has no external dependencies, is easier to audit for panic-freedom, and
//! stays correct by construction. If a full schema is ever published this
//! module can be replaced with generated `prost` types with no API change.

use crate::error::{Result, SegbError};

/// Wire types as defined in the protobuf encoding spec (§5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireType {
    /// Varint (int32, int64, uint32, uint64, sint32, sint64, bool, enum).
    Varint = 0,
    /// 64-bit (fixed64, sfixed64, double).
    Bit64 = 1,
    /// Length-delimited (string, bytes, embedded messages, packed repeated).
    LengthDelimited = 2,
    /// 32-bit (fixed32, sfixed32, float).
    Bit32 = 5,
}

impl WireType {
    fn from_u64(v: u64) -> Option<Self> {
        match v {
            0 => Some(Self::Varint),
            1 => Some(Self::Bit64),
            2 => Some(Self::LengthDelimited),
            5 => Some(Self::Bit32),
            _ => None,
        }
    }
}

/// A single decoded protobuf field.
#[derive(Debug, Clone)]
pub struct Field<'a> {
    /// Field number (1-based, as in the `.proto` definition).
    pub field_number: u32,
    /// Wire type of this field.
    pub wire_type: WireType,
    /// The raw bytes of this field's value (slice into the original buffer).
    pub raw: &'a [u8],
}

/// Read a protobuf-encoded varint from `data` starting at `*pos`.
/// Updates `*pos` past the varint. Returns `None` if the buffer is
/// exhausted before the varint terminates.
///
/// Varints are encoded little-endian, 7 bits per byte, MSB = continuation.
/// The encoding is at most 10 bytes for a 64-bit value.
fn read_varint(data: &[u8], pos: &mut usize) -> Result<u64> {
    let start = *pos;
    let mut result: u64 = 0;
    let mut shift = 0u32;

    loop {
        if *pos >= data.len() {
            return Err(SegbError::MalformedVarint { offset: start });
        }
        // Safety: bounds-checked above.
        let byte = data[*pos];
        *pos += 1;

        let low_7 = u64::from(byte & 0x7F);
        // A shift of ≥ 64 would overflow; 10 bytes × 7 bits = 70 bits, but
        // the 10th byte may only contribute bits 63-56 (7 bits), so shift
        // reaches at most 63. Guard anyway for malformed >10-byte encodings.
        if shift < 64 {
            result |= low_7 << shift;
        }
        shift += 7;

        if byte & 0x80 == 0 {
            // Continuation bit clear — this is the last byte.
            return Ok(result);
        }
        if shift >= 70 {
            // More than 10 continuation bytes — malformed.
            return Err(SegbError::MalformedVarint { offset: start });
        }
    }
}

/// Iterate over all protobuf fields in `buf`, yielding each as a [`Field`].
///
/// Unknown wire types (groups, deprecated) are skipped; malformed varints or
/// overflowing length-delimited payloads are returned as errors — never panics.
pub fn iter_fields(buf: &[u8]) -> impl Iterator<Item = Result<Field<'_>>> {
    FieldIter { buf, pos: 0 }
}

struct FieldIter<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for FieldIter<'a> {
    type Item = Result<Field<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.buf.len() {
            return None;
        }

        // Decode tag: (field_number << 3) | wire_type
        let tag = match read_varint(self.buf, &mut self.pos) {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };

        let wire_type_raw = tag & 0x07;
        let field_number = (tag >> 3) as u32;

        let wire_type = if let Some(wt) = WireType::from_u64(wire_type_raw) {
            wt
        } else {
            // Groups (3/4) and unknown wire types: skip rest of buffer
            // (we cannot know the length to skip) and stop iteration.
            self.pos = self.buf.len();
            return None;
        };

        let raw: &'a [u8] = match wire_type {
            WireType::Varint => {
                let start = self.pos;
                match read_varint(self.buf, &mut self.pos) {
                    Ok(_) => &self.buf[start..self.pos],
                    Err(e) => return Some(Err(e)),
                }
            }
            WireType::Bit64 => {
                let start = self.pos;
                if self.pos + 8 > self.buf.len() {
                    return Some(Err(SegbError::ProtobufOverflow {
                        offset: start,
                        length: 8,
                        remaining: self.buf.len() - self.pos,
                    }));
                }
                self.pos += 8;
                &self.buf[start..self.pos]
            }
            WireType::LengthDelimited => {
                let len_pos = self.pos;
                let length = match read_varint(self.buf, &mut self.pos) {
                    Ok(v) => v as usize,
                    Err(e) => return Some(Err(e)),
                };
                let start = self.pos;
                let remaining = self.buf.len() - self.pos;
                if length > remaining {
                    return Some(Err(SegbError::ProtobufOverflow {
                        offset: len_pos,
                        length,
                        remaining,
                    }));
                }
                self.pos += length;
                &self.buf[start..self.pos]
            }
            WireType::Bit32 => {
                let start = self.pos;
                if self.pos + 4 > self.buf.len() {
                    return Some(Err(SegbError::ProtobufOverflow {
                        offset: start,
                        length: 4,
                        remaining: self.buf.len() - self.pos,
                    }));
                }
                self.pos += 4;
                &self.buf[start..self.pos]
            }
        };

        Some(Ok(Field {
            field_number,
            wire_type,
            raw,
        }))
    }
}

/// Decode a length-delimited field value as a UTF-8 string, returning `None`
/// if the bytes are not valid UTF-8 (lossy conversion is intentionally avoided
/// — the caller decides how to handle encoding failures).
#[inline]
pub fn as_str(raw: &[u8]) -> Option<&str> {
    std::str::from_utf8(raw).ok()
}
