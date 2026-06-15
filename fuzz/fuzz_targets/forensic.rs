#![no_main]
//! Full pipeline: `read_segb` → `segb_forensic::audit` over arbitrary bytes.
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    let mut r = Cursor::new(data);
    if let Ok(records) = segb::read_segb(&mut r) {
        let _ = segb_forensic::audit(&records);
    }
});
