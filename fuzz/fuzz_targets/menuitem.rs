#![no_main]
//! App.MenuItem payload decode over arbitrary bytes.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = segb::menuitem::is_valid_app_menu_item_payload(data);
    let _ = segb::menuitem::decode_app_menu_item(data, Some(0.0));
    let _ = segb::menuitem::decode_app_menu_item(data, None);
});
