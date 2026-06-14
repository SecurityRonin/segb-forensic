//! App.MenuItem protobuf payload decoder.
//!
//! The `App.MenuItem` Biome stream (`~/Library/Biome/streams/restricted/App.MenuItem/local`)
//! was introduced in macOS Tahoe 26. Each SEGB record's payload is a protobuf-encoded
//! message whose meaningful fields are:
//!
//! | Field | Wire type          | Interpretation              |
//! |-------|--------------------|-----------------------------|
//! | 1     | 2 (length-delimited) | Application name (UTF-8)  |
//! | 2     | 2 (length-delimited) | Menu-item text (UTF-8)    |
//!
//! # Field number provenance
//!
//! Apple has not published a `.proto` schema for `App.MenuItem`. The field
//! numbers above are **inferred** from:
//!
//! 1. The forensicnomicon catalog (`macos_biome_app_menuitem`) which names
//!    `application` and `menu_item` as the two meaningful text fields.
//! 2. The Unit 42 research article (Palo Alto Networks, 2026):
//!    <https://unit42.paloaltonetworks.com/new-macos-artifact-discovered/>
//!    which describes the payload as capturing "the application name" and
//!    "the exact text of menu items selected by the user."
//! 3. Standard protobuf practice: a two-field string message with no nesting
//!    assigns field 1 to the first semantic attribute and field 2 to the second.
//!
//! **Validation against a real macOS Tahoe 26 sample is PENDING** — see
//! `docs/validation.md`.
//!
//! # Fallback
//!
//! Fields whose numbers are not 1 or 2 are silently skipped — the decoder is
//! forward-compatible with additional fields Apple may add. If field 1 or 2
//! contains bytes that are not valid UTF-8 they are not decoded (returned as
//! `None`); the caller can inspect the raw bytes if needed.

use crate::{
    error::Result,
    proto::{as_str, iter_fields, WireType},
};

/// A decoded `App.MenuItem` payload.
#[derive(Debug, Clone)]
pub struct AppMenuItemRecord {
    /// The application whose menu was used (e.g. `"Finder"`, `"TextEdit"`).
    /// `None` if field 1 is absent or not valid UTF-8.
    pub application: Option<String>,
    /// The exact text of the menu item the user selected
    /// (e.g. `"Move to Trash"`, `"Compress \"stolendata\""`).
    /// `None` if field 2 is absent or not valid UTF-8.
    pub menu_item: Option<String>,
    /// Unix timestamp (seconds since 1970-01-01). Comes from the SEGB record
    /// header, not from the protobuf payload; pass it through here for
    /// convenience.
    pub timestamp_unix: Option<f64>,
}

/// Decode an `App.MenuItem` protobuf payload.
///
/// `payload` is the raw bytes from a [`crate::SegbRecord`] payload.
/// `timestamp_unix` is forwarded from the SEGB record's timestamp field.
///
/// # Errors
///
/// Returns `Err` only on a structurally malformed protobuf (truncated varint,
/// overflowing length-delimited field). An absent field 1 or 2 is **not** an
/// error — `application` / `menu_item` will be `None`.
pub fn decode_app_menu_item(
    payload: &[u8],
    timestamp_unix: Option<f64>,
) -> Result<AppMenuItemRecord> {
    let mut application: Option<String> = None;
    let mut menu_item: Option<String> = None;

    for field_result in iter_fields(payload) {
        let field = field_result?;
        match (field.field_number, field.wire_type) {
            (1, WireType::LengthDelimited) => {
                application = as_str(field.raw).map(ToOwned::to_owned);
            }
            (2, WireType::LengthDelimited) => {
                menu_item = as_str(field.raw).map(ToOwned::to_owned);
            }
            // Additional or unknown fields: skip for forward compatibility.
            _ => {}
        }
    }

    Ok(AppMenuItemRecord {
        application,
        menu_item,
        timestamp_unix,
    })
}

/// Decode a collection of raw SEGB payloads into `AppMenuItemRecord`s.
///
/// `records` is an iterator over `(payload: &[u8], timestamp_unix: Option<f64>)` pairs.
/// Errors from individual records are returned immediately (fail-fast).
pub fn decode_all<'a, I>(records: I) -> Result<Vec<AppMenuItemRecord>>
where
    I: IntoIterator<Item = (&'a [u8], Option<f64>)>,
{
    records
        .into_iter()
        .map(|(payload, ts)| decode_app_menu_item(payload, ts))
        .collect()
}

/// An error variant used when the payload cannot be decoded because the
/// protobuf structure does not match the expected `App.MenuItem` message.
///
/// Currently this is surfaced as `SegbError::MalformedVarint` or
/// `SegbError::ProtobufOverflow` from [`iter_fields`] — this function wraps
/// those cleanly.
pub fn is_valid_app_menu_item_payload(payload: &[u8]) -> bool {
    for field_result in iter_fields(payload) {
        if field_result.is_err() {
            return false;
        }
    }
    true
}
