#![no_main]
//! SEGB v2 container + trailer + record framing over arbitrary bytes.
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    let mut r = Cursor::new(data);
    let _ = segb::segb2::is_segb_v2(&mut r);
    let mut r = Cursor::new(data);
    let _ = segb::segb2::read_v2(&mut r);
});
