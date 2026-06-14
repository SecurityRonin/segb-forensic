//! App.MenuItem decoder — STUB (RED state).

use crate::error::Result;

#[derive(Debug, Clone)]
pub struct AppMenuItemRecord {
    pub application: Option<String>,
    pub menu_item: Option<String>,
    pub timestamp_unix: Option<f64>,
}

/// STUB: always returns empty record with no fields (RED — tests will fail).
pub fn decode_app_menu_item(
    _payload: &[u8],
    timestamp_unix: Option<f64>,
) -> Result<AppMenuItemRecord> {
    Ok(AppMenuItemRecord {
        application: None,
        menu_item: None,
        timestamp_unix,
    })
}

pub fn decode_all<'a, I>(records: I) -> Result<Vec<AppMenuItemRecord>>
where
    I: IntoIterator<Item = (&'a [u8], Option<f64>)>,
{
    records.into_iter().map(|(p, ts)| decode_app_menu_item(p, ts)).collect()
}

pub fn is_valid_app_menu_item_payload(_payload: &[u8]) -> bool { false }
