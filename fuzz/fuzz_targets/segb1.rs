#![no_main]
//! SEGB v1 container + record framing over arbitrary bytes.
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    let mut r = Cursor::new(data);
    let _ = segb::segb1::is_segb_v1(&mut r);
    let mut r = Cursor::new(data);
    let _ = segb::segb1::read_v1(&mut r);
});
